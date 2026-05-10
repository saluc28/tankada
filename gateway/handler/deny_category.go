package handler

import "strings"

// Deny categories returned in QueryResponse.DenyCategories so client integrators
// can decide programmatically how to react to a deny without parsing free-text reasons.
//
// Categories split into three behavioural buckets — clients should branch on this:
//
//   1. Non-recoverable (semantic deny — agent must ABORT the task and inform the user):
//      missing_scope, pii_violation, tenant_violation, injection, destructive_op,
//      schema_enum, parse_error
//
//   2. Recoverable by query reformulation (agent MAY rewrite and retry):
//      tautology, select_star, missing_where, high_limit
//
//   3. Transient (agent MAY retry after backoff):
//      rate_limit, infrastructure
//
//   4. Composite / ambiguous (rarely useful to retry — usually means rule 1 elsewhere):
//      risk_score, unknown
const (
	CatRateLimit       = "rate_limit"
	CatInfrastructure  = "infrastructure"
	CatParseError      = "parse_error"
	CatInjection       = "injection"
	CatSchemaEnum      = "schema_enum"
	CatTenantViolation = "tenant_violation"
	CatDestructiveOp   = "destructive_op"
	CatTautology       = "tautology"
	CatPIIViolation    = "pii_violation"
	CatSelectStar      = "select_star"
	CatHighLimit       = "high_limit"
	CatMissingWhere    = "missing_where"
	CatMissingScope    = "missing_scope"
	CatRiskScore       = "risk_score"
	CatUnknown         = "unknown"
)

// categorize maps free-text deny reasons (produced by Rego rules in policies/query.rego
// and by the gateway itself for fail-closed/rate-limit) into the enum above.
//
// Returns one category per reason, in the same order. Duplicates are removed while
// preserving first-seen order so a multi-reason deny like
// ["query accesses PII columns ...", "WHERE clause is a tautology ..."] becomes
// ["pii_violation", "tautology"] and clients can see the most severe one first.
//
// MUST stay in sync with the deny rule reasons in policies/query.rego. When a new
// deny rule is added, add a corresponding case here.
func categorize(reasons []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(reasons))
	for _, r := range reasons {
		c := categoryFor(r)
		if seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}

func categoryFor(reason string) string {
	switch {
	case strings.HasPrefix(reason, "rate limit exceeded"):
		return CatRateLimit
	case strings.HasSuffix(reason, "failing closed"):
		return CatInfrastructure
	case strings.HasPrefix(reason, "query parse failed"):
		return CatParseError
	case strings.HasPrefix(reason, "multi-statement query blocked"):
		return CatInjection
	case strings.HasPrefix(reason, "schema enumeration query blocked"),
		strings.HasPrefix(reason, "repeated schema enumeration"):
		return CatSchemaEnum
	case strings.HasPrefix(reason, "query must filter by tenant_id"):
		return CatTenantViolation
	case strings.HasPrefix(reason, "destructive operation"):
		return CatDestructiveOp
	case reason == "WHERE clause is a tautology (e.g. 1=1)":
		return CatTautology
	case strings.HasPrefix(reason, "query accesses PII columns"):
		return CatPIIViolation
	case strings.HasPrefix(reason, "SELECT * is not allowed"):
		return CatSelectStar
	case strings.HasPrefix(reason, "query LIMIT exceeds maximum"):
		return CatHighLimit
	case reason == "SELECT without WHERE clause on a named table":
		return CatMissingWhere
	case strings.Contains(reason, "requires scope"),
		strings.HasPrefix(reason, "access to table"):
		return CatMissingScope
	case strings.HasPrefix(reason, "risk score"):
		return CatRiskScore
	default:
		return CatUnknown
	}
}
