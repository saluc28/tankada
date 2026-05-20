package client

import "testing"

func TestAnalysisCache_GetPut(t *testing.T) {
	c := newAnalysisCache(2)

	if _, ok := c.get("q1"); ok {
		t.Fatal("expected miss on empty cache")
	}

	a1 := &AnalysisResult{QueryType: "SELECT"}
	c.put("q1", a1)

	got, ok := c.get("q1")
	if !ok {
		t.Fatal("expected hit after put")
	}
	if got != a1 {
		t.Fatal("expected the same pointer back (read-only sharing)")
	}
}

func TestAnalysisCache_LRUEviction(t *testing.T) {
	c := newAnalysisCache(2)
	c.put("q1", &AnalysisResult{QueryType: "A"})
	c.put("q2", &AnalysisResult{QueryType: "B"})

	// Touch q1 so q2 becomes the least-recently-used entry.
	if _, ok := c.get("q1"); !ok {
		t.Fatal("q1 should still be cached")
	}

	// Inserting a third entry must evict q2 (LRU), not q1.
	c.put("q3", &AnalysisResult{QueryType: "C"})

	if _, ok := c.get("q2"); ok {
		t.Fatal("q2 should have been evicted as least-recently-used")
	}
	if _, ok := c.get("q1"); !ok {
		t.Fatal("q1 should be retained")
	}
	if _, ok := c.get("q3"); !ok {
		t.Fatal("q3 should be present")
	}
}

func TestAnalysisCache_Update(t *testing.T) {
	c := newAnalysisCache(2)
	c.put("q1", &AnalysisResult{QueryType: "OLD"})
	updated := &AnalysisResult{QueryType: "NEW"}
	c.put("q1", updated)

	got, ok := c.get("q1")
	if !ok || got != updated {
		t.Fatal("expected updated value for existing key")
	}
}

func TestAnalysisCache_NilDisabled(t *testing.T) {
	var c *analysisCache = newAnalysisCache(0) // disabled
	if c != nil {
		t.Fatal("capacity 0 should produce a nil (disabled) cache")
	}
	// nil cache must be safe to use.
	if _, ok := c.get("q1"); ok {
		t.Fatal("nil cache must always miss")
	}
	c.put("q1", &AnalysisResult{}) // must not panic
}
