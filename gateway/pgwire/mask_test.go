package pgwire

import (
	"bytes"
	"reflect"
	"testing"
)

func TestMaskedIndices(t *testing.T) {
	fields := []string{"id", "Email", "name", "SSN"}
	got := maskedIndices(fields, []string{"email", "ssn"})
	want := []int{1, 3}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("maskedIndices = %v, want %v", got, want)
	}
}

func TestMaskedIndices_EmptyMask(t *testing.T) {
	if got := maskedIndices([]string{"email"}, nil); got != nil {
		t.Fatalf("expected nil for empty mask, got %v", got)
	}
}

func TestMaskedIndices_NoMatch(t *testing.T) {
	if got := maskedIndices([]string{"id", "name"}, []string{"email"}); got != nil {
		t.Fatalf("expected nil when nothing matches, got %v", got)
	}
}

func TestApplyRowMask(t *testing.T) {
	row := [][]byte{[]byte("1"), []byte("a@x.com"), []byte("Alice")}
	applyRowMask(row, []int{1}, "***")
	if !bytes.Equal(row[1], []byte("***")) {
		t.Fatalf("masked cell = %q, want ***", row[1])
	}
	if !bytes.Equal(row[0], []byte("1")) || !bytes.Equal(row[2], []byte("Alice")) {
		t.Fatalf("non-masked cells mutated: %q %q", row[0], row[2])
	}
}

func TestApplyRowMask_DefaultValue(t *testing.T) {
	row := [][]byte{[]byte("secret")}
	applyRowMask(row, []int{0}, "")
	if !bytes.Equal(row[0], []byte("***")) {
		t.Fatalf("expected default ***, got %q", row[0])
	}
}

func TestApplyRowMask_DistinctCopies(t *testing.T) {
	// Two rows masked with the same value must not share a backing array.
	r1 := [][]byte{[]byte("a@x.com")}
	r2 := [][]byte{[]byte("b@x.com")}
	applyRowMask(r1, []int{0}, "X")
	applyRowMask(r2, []int{0}, "X")
	r1[0][0] = 'Y'
	if r2[0][0] == 'Y' {
		t.Fatal("masked cells alias the same backing array across rows")
	}
}

func TestApplyRowMask_OutOfRangeIgnored(t *testing.T) {
	row := [][]byte{[]byte("1")}
	applyRowMask(row, []int{5}, "***") // must not panic
	if !bytes.Equal(row[0], []byte("1")) {
		t.Fatalf("row mutated unexpectedly: %q", row[0])
	}
}
