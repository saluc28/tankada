package pgwire

import "strings"

// stmtClass tells the connection loop how to treat an incoming SQL statement.
type stmtClass int

const (
	// classEnforce: a data statement (SELECT and friends). Run the analyzer +
	// OPA policy and, for reads, apply masking. Writes are rejected separately.
	classEnforce stmtClass = iota
	// classPassthrough: a benign utility statement a real driver needs
	// (transaction control, safe SET/RESET, SHOW, ...). Forward as-is, no policy.
	classPassthrough
	// classBlocked: a session-control statement that could let the client
	// escape the tenant role/RLS scoping (SET ROLE, RESET ALL, DISCARD, ...).
	classBlocked
)

// classify decides how a statement is handled by the wire-proxy based on its
// leading keyword(s). It is deliberately conservative: anything it does not
// recognise as a safe utility statement falls through to classEnforce, where the
// analyzer and OPA make the real decision (and unparseable input fails closed).
func classify(sql string) stmtClass {
	up := strings.ToUpper(strings.TrimSpace(sql))
	up = strings.TrimLeft(up, "(")
	up = strings.TrimSpace(up)

	kw := leadingWord(up)
	rest := strings.TrimSpace(up[len(kw):])

	switch kw {
	case "SET":
		// SET ROLE / SET SESSION AUTHORIZATION change the effective role and
		// would defeat the tenant scoping applied at session start.
		if startsWithWord(rest, "ROLE") || startsWith(rest, "SESSION AUTHORIZATION") {
			return classBlocked
		}
		return classPassthrough
	case "RESET":
		// RESET ROLE / RESET ALL / RESET SESSION AUTHORIZATION revert the role
		// and tenant GUC back to the privileged login defaults.
		if startsWithWord(rest, "ROLE") || startsWithWord(rest, "ALL") || startsWith(rest, "SESSION AUTHORIZATION") {
			return classBlocked
		}
		return classPassthrough
	case "DISCARD":
		// DISCARD ALL (and DISCARD by itself in practice) resets session state
		// including the SET ROLE applied for tenant scoping.
		return classBlocked
	case "BEGIN", "START", "COMMIT", "END", "ROLLBACK", "ABORT", "SAVEPOINT",
		"RELEASE", "SHOW", "DEALLOCATE", "LISTEN", "UNLISTEN", "FETCH", "MOVE",
		"CLOSE", "PREPARE", "EXPLAIN":
		return classPassthrough
	default:
		return classEnforce
	}
}

// leadingWord returns the leading run of ASCII letters in s (already upper-cased
// by the caller), e.g. "SELECT" from "SELECT 1".
func leadingWord(s string) string {
	end := 0
	for end < len(s) {
		c := s[end]
		if c >= 'A' && c <= 'Z' {
			end++
			continue
		}
		break
	}
	return s[:end]
}

// startsWithWord reports whether s begins with word followed by a word boundary
// (end of string or a non-letter), so "ROLE" matches "ROLE" and "ROLE foo" but
// not "ROLEX".
func startsWithWord(s, word string) bool {
	if !strings.HasPrefix(s, word) {
		return false
	}
	if len(s) == len(word) {
		return true
	}
	c := s[len(word)]
	return !(c >= 'A' && c <= 'Z')
}

func startsWith(s, prefix string) bool {
	return strings.HasPrefix(s, prefix)
}
