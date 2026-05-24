package pgwire

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/tankada/gateway/client"
)

// statement is a parsed (extended-protocol) prepared statement plus the policy
// decision taken for it at Parse time.
type statement struct {
	sql       string
	class     stmtClass
	denied    bool   // policy denied, write-blocked, or backend prepare failed
	denyMsg   string // error text when denied
	mask      []string
	maskValue string
	fields    []pgconn.FieldDescription // result columns (from backend Prepare)
	paramOIDs []uint32
}

// portal is a Bound statement ready to Execute.
type portal struct {
	stmtName     string
	params       [][]byte
	paramFormats []int16
}

// connSession holds the per-connection state for the duration of one client
// connection: the client-facing backend, the server-facing connection, the
// fixed agent identity, and the extended-protocol statement/portal registries.
type connSession struct {
	srv   *Server
	be    *pgproto3.Backend
	pg    *pgconn.PgConn
	agent client.OPAAgent

	statements map[string]*statement
	portals    map[string]*portal

	// skip is set after an error in the extended protocol; subsequent messages
	// are ignored until the next Sync, per the wire protocol.
	skip bool
}

func (s *connSession) loop(ctx context.Context) {
	for {
		msg, err := s.be.Receive()
		if err != nil {
			return // client disconnected or protocol error
		}
		switch m := msg.(type) {
		case *pgproto3.Query:
			s.skip = false
			s.handleSimpleQuery(ctx, m.String)
		case *pgproto3.Parse:
			s.handleParse(ctx, m)
		case *pgproto3.Bind:
			s.handleBind(m)
		case *pgproto3.Describe:
			s.handleDescribe(m)
		case *pgproto3.Execute:
			s.handleExecute(ctx, m)
		case *pgproto3.Sync:
			s.skip = false
			s.ready()
		case *pgproto3.Close:
			s.handleClose(m)
		case *pgproto3.Flush:
			s.flush()
		case *pgproto3.Terminate:
			return
		default:
			s.errorAndSkip("0A000", fmt.Sprintf("unsupported protocol message: %T", m))
		}
	}
}

// ── Simple query protocol ('Q') ───────────────────────────────────────────────

func (s *connSession) handleSimpleQuery(ctx context.Context, sql string) {
	if strings.TrimSpace(sql) == "" {
		s.send(&pgproto3.EmptyQueryResponse{})
		s.ready()
		return
	}

	var ms *maskSpec
	switch classify(sql) {
	case classBlocked:
		s.sendError("42501", "session-control statements are not permitted via the Tankada wire-proxy")
		s.ready()
		return
	case classEnforce:
		dec, err := s.srv.enforce(ctx, s.agent, sql)
		if err != nil {
			s.sendError("57P01", "policy engine unavailable: failing closed")
			s.ready()
			return
		}
		if dec.isWrite {
			s.sendError("42501", "write operations are not permitted via the Tankada wire-proxy (read-only)")
			s.ready()
			return
		}
		if !dec.allow {
			s.sendError("42501", denyMessage(dec.reasons))
			s.ready()
			return
		}
		if len(dec.mask) > 0 {
			ms = &maskSpec{cols: dec.mask, value: dec.maskValue}
		}
	}

	mrr := s.pg.Exec(ctx, sql)
	for mrr.NextResult() {
		s.streamResult(mrr.ResultReader(), ms, true)
	}
	if err := mrr.Close(); err != nil {
		s.sendError(pgErrCode(err), pgErrMessage(err))
	}
	s.ready()
}

// ── Extended query protocol (P/B/D/E/S/C) ─────────────────────────────────────

func (s *connSession) handleParse(ctx context.Context, m *pgproto3.Parse) {
	if s.skip {
		return
	}
	st := &statement{sql: m.Query, class: classify(m.Query)}
	s.statements[m.Name] = st

	switch st.class {
	case classBlocked:
		st.denied = true
		st.denyMsg = "session-control statements are not permitted via the Tankada wire-proxy"
		s.errorAndSkip("42501", st.denyMsg)
		return
	case classEnforce:
		dec, err := s.srv.enforce(ctx, s.agent, m.Query)
		if err != nil {
			st.denied = true
			st.denyMsg = "policy engine unavailable: failing closed"
			s.errorAndSkip("57P01", st.denyMsg)
			return
		}
		if dec.isWrite {
			st.denied = true
			st.denyMsg = "write operations are not permitted via the Tankada wire-proxy (read-only)"
			s.errorAndSkip("42501", st.denyMsg)
			return
		}
		if !dec.allow {
			st.denied = true
			st.denyMsg = denyMessage(dec.reasons)
			s.errorAndSkip("42501", st.denyMsg)
			return
		}
		st.mask = dec.mask
		st.maskValue = dec.maskValue
	}

	// Allowed (or passthrough): prepare on the backend so Bind/Execute work and
	// we learn the result column descriptions for Describe and masking.
	sd, err := s.pg.Prepare(ctx, m.Name, m.Query, m.ParameterOIDs)
	if err != nil {
		st.denied = true
		st.denyMsg = pgErrMessage(err)
		s.errorAndSkip(pgErrCode(err), st.denyMsg)
		return
	}
	st.fields = sd.Fields
	st.paramOIDs = sd.ParamOIDs
	s.send(&pgproto3.ParseComplete{})
}

func (s *connSession) handleBind(m *pgproto3.Bind) {
	if s.skip {
		return
	}
	st := s.statements[m.PreparedStatement]
	if st == nil || st.denied {
		s.errorAndSkip("26000", "prepared statement does not exist or was rejected")
		return
	}
	s.portals[m.DestinationPortal] = &portal{
		stmtName:     m.PreparedStatement,
		params:       m.Parameters,
		paramFormats: m.ParameterFormatCodes,
	}
	s.send(&pgproto3.BindComplete{})
}

func (s *connSession) handleDescribe(m *pgproto3.Describe) {
	if s.skip {
		return
	}
	var st *statement
	switch m.ObjectType {
	case 'S':
		st = s.statements[m.Name]
		if st == nil || st.denied {
			s.errorAndSkip("26000", "prepared statement does not exist or was rejected")
			return
		}
		s.send(&pgproto3.ParameterDescription{ParameterOIDs: st.paramOIDs})
	case 'P':
		p := s.portals[m.Name]
		if p == nil {
			s.errorAndSkip("34000", "portal does not exist")
			return
		}
		st = s.statements[p.stmtName]
		if st == nil || st.denied {
			s.errorAndSkip("26000", "prepared statement does not exist or was rejected")
			return
		}
	default:
		s.errorAndSkip("08P01", "invalid Describe target")
		return
	}
	if len(st.fields) == 0 {
		s.send(&pgproto3.NoData{})
		return
	}
	s.send(rowDescription(st.fields))
}

func (s *connSession) handleExecute(ctx context.Context, m *pgproto3.Execute) {
	if s.skip {
		return
	}
	p := s.portals[m.Portal]
	if p == nil {
		s.errorAndSkip("34000", "portal does not exist")
		return
	}
	st := s.statements[p.stmtName]
	if st == nil || st.denied {
		s.errorAndSkip("26000", "prepared statement does not exist or was rejected")
		return
	}
	// nil resultFormats => all columns returned in text format, which keeps
	// masking uniform across types.
	rr := s.pg.ExecPrepared(ctx, p.stmtName, p.params, p.paramFormats, nil)
	var ms *maskSpec
	if len(st.mask) > 0 {
		ms = &maskSpec{cols: st.mask, value: st.maskValue}
	}
	// Extended Execute does not re-send RowDescription (the client got it from
	// Describe); only DataRows + CommandComplete.
	s.streamResult(rr, ms, false)
}

func (s *connSession) handleClose(m *pgproto3.Close) {
	if s.skip {
		return
	}
	if m.ObjectType == 'S' {
		delete(s.statements, m.Name)
	} else {
		delete(s.portals, m.Name)
	}
	s.send(&pgproto3.CloseComplete{})
}

// ── Result streaming + masking ────────────────────────────────────────────────

// streamResult relays one result set from the backend to the client, redacting
// masked columns. withRowDescription controls whether a RowDescription is sent
// first (true for the simple protocol, false for extended Execute).
func (s *connSession) streamResult(rr *pgconn.ResultReader, ms *maskSpec, withRowDescription bool) {
	fields := rr.FieldDescriptions()
	if withRowDescription && len(fields) > 0 {
		s.send(rowDescription(fields))
	}

	var idxs []int
	if ms != nil {
		idxs = maskedIndices(fieldNames(fields), ms.cols)
	}

	for rr.NextRow() {
		vals := rr.Values()
		if len(idxs) > 0 {
			applyRowMask(vals, idxs, ms.value)
		}
		s.send(&pgproto3.DataRow{Values: vals})
	}

	ct, err := rr.Close()
	if err != nil {
		s.sendError(pgErrCode(err), pgErrMessage(err))
		return
	}
	s.send(&pgproto3.CommandComplete{CommandTag: []byte(ct.String())})
}

// ── Wire helpers ──────────────────────────────────────────────────────────────

func (s *connSession) send(m pgproto3.BackendMessage) { s.be.Send(m) }
func (s *connSession) flush()                         { _ = s.be.Flush() }

func (s *connSession) ready() {
	s.send(&pgproto3.ReadyForQuery{TxStatus: s.pg.TxStatus()})
	s.flush()
}

// sendError reports a non-fatal error without a ReadyForQuery (the caller adds
// one in the simple protocol; the next Sync adds one in the extended protocol).
func (s *connSession) sendError(code, msg string) {
	s.send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: code, Message: msg})
}

// errorAndSkip reports an error and enters skip mode: in the extended protocol
// every message up to the next Sync is ignored after an error.
func (s *connSession) errorAndSkip(code, msg string) {
	s.sendError(code, msg)
	s.skip = true
}

func rowDescription(fields []pgconn.FieldDescription) *pgproto3.RowDescription {
	out := make([]pgproto3.FieldDescription, len(fields))
	for i, f := range fields {
		out[i] = pgproto3.FieldDescription{
			Name:                 []byte(f.Name),
			TableOID:             f.TableOID,
			TableAttributeNumber: f.TableAttributeNumber,
			DataTypeOID:          f.DataTypeOID,
			DataTypeSize:         f.DataTypeSize,
			TypeModifier:         f.TypeModifier,
			Format:               0, // results are normalized to text for uniform masking
		}
	}
	return &pgproto3.RowDescription{Fields: out}
}

func fieldNames(fields []pgconn.FieldDescription) []string {
	names := make([]string, len(fields))
	for i, f := range fields {
		names[i] = f.Name
	}
	return names
}

func denyMessage(reasons []string) string {
	if len(reasons) == 0 {
		return "query denied by Tankada policy"
	}
	return "Tankada policy denied this query: " + strings.Join(reasons, "; ")
}

func pgErrCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return "XX000"
}

func pgErrMessage(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Message
	}
	return err.Error()
}
