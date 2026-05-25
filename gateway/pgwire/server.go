// Package pgwire implements a PostgreSQL wire-protocol front-end for Tankada.
//
// An agent points a stock Postgres driver at this proxy (it only changes the
// connection string) and every statement is run through the same enforcement
// pipeline as the HTTP gateway: analyzer (sqlglot) -> OPA policy -> execution
// against the real database, with PII masking applied to the rows on the way
// back. Identity travels in the password field as a Tankada JWT.
//
// The proxy speaks the wire protocol to the client with pgproto3 and talks to
// the real database with pgconn (which handles auth, parameters, and types).
// Results are normalized to text format so masking can rewrite cells uniformly.
package pgwire

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/tankada/gateway/client"
	mw "github.com/tankada/gateway/middleware"
)

// Identity modes for the wire-proxy (D.1.c). Two ways an agent proves who it is,
// trading friction against strength:
//
//   - AuthJWT (default, strong): the agent supplies a signed Tankada JWT in the
//     connection password. Identity, tenant, and scopes are cryptographically
//     verified, exactly like the HTTP gateway.
//   - AuthTrust (weak, frictionless): no password. The agent's id and (optionally)
//     tenant come from the connection's application_name / user; scopes, roles, and
//     (when configured) the tenant are decided by the deployment, not the client.
//     Appropriate only where the network perimeter is the trust boundary
//     (single-tenant or fully trusted agents). It does NOT cryptographically
//     authenticate the caller.
const (
	AuthJWT   = "jwt"
	AuthTrust = "trust"
)

// Config holds the wire-proxy settings, normally populated from the environment.
type Config struct {
	ListenAddr  string // TCP address to listen on, e.g. ":5433"
	JWTSecret   string // HMAC secret used to validate the agent JWT (the password)
	AnalyzerURL string // base URL of the analyzer service
	OPAURL      string // base URL of the OPA service
	DatabaseURL string // DSN of the real Postgres the proxy fronts
	AppRole     string // role to SET for RLS scoping (e.g. "tankada_app"); empty to skip

	// Identity mode. AuthJWT (default) or AuthTrust. See the constants above.
	AuthMode string
	// Trust-mode defaults. The deployment owns these so a frictionless client
	// cannot grant itself authority.
	TrustTenant string   // forces the tenant for every trust connection; if empty, the client may declare it via application_name (tenant=...)
	TrustScopes []string // scopes granted to trust connections (e.g. ["customers:read"])
	TrustRoles  []string // roles granted to trust connections (usually empty)
}

// Server is a Tankada PostgreSQL wire-protocol proxy.
type Server struct {
	cfg      Config
	analyzer *client.AnalyzerClient
	opa      *client.OPAClient
}

// New builds a Server with analyzer and OPA clients pointed at the configured URLs.
func New(cfg Config) *Server {
	return &Server{
		cfg:      cfg,
		analyzer: client.NewAnalyzer(cfg.AnalyzerURL),
		opa:      client.NewOPA(cfg.OPAURL),
	}
}

// ListenAndServe accepts connections until the listener fails.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("pgwire listen: %w", err)
	}
	log.Printf("pgwire (Postgres wire-proxy) listening on %s", s.cfg.ListenAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("pgwire accept error: %v", err)
			continue
		}
		go s.serveConn(conn)
	}
}

func (s *Server) serveConn(nc net.Conn) {
	defer nc.Close()
	be := pgproto3.NewBackend(nc, nc)

	startup, err := s.handleStartup(be, nc)
	if err != nil {
		return
	}

	claims, err := s.authenticate(be, startup)
	if err != nil {
		sendFatal(be, "28P01", "authentication failed: "+err.Error())
		return
	}

	ctx := context.Background()
	pg, err := pgconn.Connect(ctx, s.cfg.DatabaseURL)
	if err != nil {
		sendFatal(be, "08006", "backend database connection failed")
		return
	}
	defer pg.Close(ctx)

	if err := scopeConnection(ctx, pg, claims.TenantID, s.cfg.AppRole); err != nil {
		sendFatal(be, "08006", "failed to apply tenant scoping on the backend connection")
		return
	}

	if err := s.completeAuth(be, pg); err != nil {
		return
	}

	sess := &connSession{
		srv: s,
		be:  be,
		pg:  pg,
		agent: client.OPAAgent{
			AgentID:     claims.AgentID,
			OwnerUserID: claims.OwnerUserID,
			TenantID:    claims.TenantID,
			Roles:       claims.Roles,
			Scopes:      claims.Scopes,
		},
		statements: map[string]*statement{},
		portals:    map[string]*portal{},
	}
	sess.loop(ctx)
}

// handleStartup consumes the startup handshake and returns the StartupMessage
// (whose parameters carry user / application_name). TLS/GSS are declined (the
// proxy terminates plaintext for the MVP); the loop repeats until the real
// StartupMessage arrives.
func (s *Server) handleStartup(be *pgproto3.Backend, nc net.Conn) (*pgproto3.StartupMessage, error) {
	for {
		msg, err := be.ReceiveStartupMessage()
		if err != nil {
			return nil, err
		}
		switch m := msg.(type) {
		case *pgproto3.StartupMessage:
			return m, nil
		case *pgproto3.SSLRequest, *pgproto3.GSSEncRequest:
			if _, err := nc.Write([]byte{'N'}); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unsupported startup message %T", msg)
		}
	}
}

// authenticate resolves the agent identity according to the configured mode.
// In trust mode no password is requested (frictionless); in JWT mode a cleartext
// password is requested and validated as a Tankada JWT.
func (s *Server) authenticate(be *pgproto3.Backend, startup *pgproto3.StartupMessage) (*mw.AgentClaims, error) {
	if s.cfg.AuthMode == AuthTrust {
		return s.trustIdentity(startup)
	}
	return s.authenticateJWT(be)
}

// authenticateJWT requests a cleartext password and validates it as a Tankada JWT.
func (s *Server) authenticateJWT(be *pgproto3.Backend) (*mw.AgentClaims, error) {
	be.Send(&pgproto3.AuthenticationCleartextPassword{})
	if err := be.Flush(); err != nil {
		return nil, err
	}
	if err := be.SetAuthType(pgproto3.AuthTypeCleartextPassword); err != nil {
		return nil, err
	}
	msg, err := be.Receive()
	if err != nil {
		return nil, err
	}
	pw, ok := msg.(*pgproto3.PasswordMessage)
	if !ok {
		return nil, fmt.Errorf("expected PasswordMessage, got %T", msg)
	}
	return mw.ParseAndResolve(s.cfg.JWTSecret, strings.TrimSpace(pw.Password))
}

// scopeConnection pins the backend connection to the non-superuser app role and
// sets app.tenant_id so PostgreSQL RLS isolates this session to the agent's
// tenant, mirroring what the HTTP proxy does per transaction.
func scopeConnection(ctx context.Context, pg *pgconn.PgConn, tenantID, appRole string) error {
	if appRole != "" {
		if _, err := pg.Exec(ctx, "SET ROLE "+quoteIdent(appRole)).ReadAll(); err != nil {
			return err
		}
	}
	if tenantID != "" {
		rr := pg.ExecParams(ctx, "SELECT set_config('app.tenant_id', $1, false)",
			[][]byte{[]byte(tenantID)}, nil, nil, nil)
		if _, err := rr.Close(); err != nil {
			return err
		}
	}
	return nil
}

// completeAuth tells the client authentication succeeded and forwards the
// server's parameter statuses so drivers can configure themselves.
func (s *Server) completeAuth(be *pgproto3.Backend, pg *pgconn.PgConn) error {
	be.Send(&pgproto3.AuthenticationOk{})
	for _, k := range []string{
		"server_version", "server_encoding", "client_encoding", "DateStyle",
		"IntervalStyle", "TimeZone", "integer_datetimes", "standard_conforming_strings",
	} {
		if v := pg.ParameterStatus(k); v != "" {
			be.Send(&pgproto3.ParameterStatus{Name: k, Value: v})
		}
	}
	be.Send(&pgproto3.BackendKeyData{ProcessID: 0, SecretKey: 0})
	be.Send(&pgproto3.ReadyForQuery{TxStatus: pg.TxStatus()})
	return be.Flush()
}

// policyDecision is the per-statement enforcement outcome.
type policyDecision struct {
	allow     bool
	reasons   []string
	mask      []string
	maskValue string
	isWrite   bool
}

// enforce runs the analyzer and OPA on a single statement, the same pipeline the
// HTTP gateway uses. A non-nil error means an upstream is unreachable and the
// caller must fail closed.
func (s *Server) enforce(ctx context.Context, agent client.OPAAgent, sql string) (policyDecision, error) {
	analysis, err := s.analyzer.Analyze(ctx, sql)
	if err != nil {
		return policyDecision{}, err
	}
	res, err := s.opa.Evaluate(ctx, client.OPAInput{Agent: agent, Analysis: analysis})
	if err != nil {
		return policyDecision{}, err
	}
	return policyDecision{
		allow:     res.Allow,
		reasons:   res.Deny,
		mask:      res.Mask,
		maskValue: res.MaskValue,
		isWrite:   analysis.IsWrite,
	}, nil
}

func sendFatal(be *pgproto3.Backend, code, msg string) {
	be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: code, Message: msg})
	_ = be.Flush()
}

func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}
