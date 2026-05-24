package pgwire

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		sql  string
		want stmtClass
	}{
		// Data statements -> enforce.
		{"SELECT id FROM customers WHERE tenant_id = 't1'", classEnforce},
		{"  select 1", classEnforce},
		{"(SELECT id FROM customers)", classEnforce},
		{"WITH x AS (SELECT 1) SELECT * FROM x", classEnforce},
		{"INSERT INTO t VALUES (1)", classEnforce},
		{"UPDATE t SET a = 1", classEnforce},
		{"DELETE FROM t", classEnforce},

		// Benign utility statements -> passthrough.
		{"BEGIN", classPassthrough},
		{"COMMIT", classPassthrough},
		{"ROLLBACK", classPassthrough},
		{"SET search_path TO public", classPassthrough},
		{"set extra_float_digits = 3", classPassthrough},
		{"SHOW transaction_isolation", classPassthrough},
		{"RESET statement_timeout", classPassthrough},

		// Session-control escapes -> blocked.
		{"SET ROLE postgres", classBlocked},
		{"set role admin", classBlocked},
		{"SET SESSION AUTHORIZATION postgres", classBlocked},
		{"RESET ROLE", classBlocked},
		{"RESET ALL", classBlocked},
		{"RESET SESSION AUTHORIZATION", classBlocked},
		{"DISCARD ALL", classBlocked},
		{"discard all", classBlocked},
	}
	for _, c := range cases {
		if got := classify(c.sql); got != c.want {
			t.Errorf("classify(%q) = %d, want %d", c.sql, got, c.want)
		}
	}
}

func TestStartsWithWord(t *testing.T) {
	if !startsWithWord("ROLE", "ROLE") {
		t.Error("ROLE should match word ROLE")
	}
	if !startsWithWord("ROLE FOO", "ROLE") {
		t.Error("ROLE FOO should match word ROLE")
	}
	if startsWithWord("ROLEX", "ROLE") {
		t.Error("ROLEX must not match word ROLE")
	}
}
