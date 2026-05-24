package pgwire

import "strings"

// maskSpec carries the columns the policy asked to redact and the placeholder
// to substitute. A nil maskSpec (or empty Cols) means no redaction.
type maskSpec struct {
	cols  []string
	value string
}

// maskedIndices returns the positions in fieldNames that must be redacted given
// the set of column names the policy asked to mask. Matching is case-insensitive
// on the result's own column names, identical to the HTTP gateway's applyMask so
// both front-ends redact the same fields.
func maskedIndices(fieldNames []string, mask []string) []int {
	if len(mask) == 0 {
		return nil
	}
	want := make(map[string]bool, len(mask))
	for _, c := range mask {
		want[strings.ToLower(c)] = true
	}
	var idxs []int
	for i, name := range fieldNames {
		if want[strings.ToLower(name)] {
			idxs = append(idxs, i)
		}
	}
	return idxs
}

// applyRowMask replaces, in place, the values at the given column indices with
// the mask placeholder. maskValue defaults to "***" when empty. Each masked
// cell gets its own copy of the placeholder so callers never alias a shared
// backing array across rows.
func applyRowMask(values [][]byte, idxs []int, maskValue string) {
	if len(idxs) == 0 {
		return
	}
	if maskValue == "" {
		maskValue = "***"
	}
	for _, i := range idxs {
		if i >= 0 && i < len(values) {
			b := make([]byte, len(maskValue))
			copy(b, maskValue)
			values[i] = b
		}
	}
}
