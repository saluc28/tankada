package client

import (
	"container/list"
	"sync"
)

// analysisCache is a small, thread-safe, fixed-capacity LRU cache mapping a SQL
// query string to its AnalysisResult.
//
// The analyzer is a pure function of the query string (same query in -> same
// analysis out), so serving a repeated query from this cache is behaviourally
// identical to calling the analyzer every time, while skipping the out-of-process
// HTTP round trip and the SQL parse. Agents that loop or retry tend to reissue
// identical queries, so this removes the analyzer hop from the hot path on those.
//
// Cached entries are treated as read-only by callers and MUST NOT be mutated:
// the same *AnalysisResult pointer is shared across all hits for a given query.
// All current consumers (query + explain handlers) only read the result and pass
// it to OPA as a marshalled value, so this invariant holds.
type analysisCache struct {
	mu       sync.Mutex
	capacity int
	ll       *list.List // front = most recently used
	items    map[string]*list.Element
}

type cacheEntry struct {
	key   string
	value *AnalysisResult
}

// newAnalysisCache returns a cache of the given capacity, or nil if capacity <= 0
// (a nil cache disables caching; get/put are safe no-ops on it).
func newAnalysisCache(capacity int) *analysisCache {
	if capacity <= 0 {
		return nil
	}
	return &analysisCache{
		capacity: capacity,
		ll:       list.New(),
		items:    make(map[string]*list.Element, capacity),
	}
}

func (c *analysisCache) get(key string) (*AnalysisResult, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.ll.MoveToFront(el)
		return el.Value.(*cacheEntry).value, true
	}
	return nil, false
}

func (c *analysisCache) put(key string, value *AnalysisResult) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.ll.MoveToFront(el)
		el.Value.(*cacheEntry).value = value
		return
	}
	el := c.ll.PushFront(&cacheEntry{key: key, value: value})
	c.items[key] = el
	if c.ll.Len() > c.capacity {
		if oldest := c.ll.Back(); oldest != nil {
			c.ll.Remove(oldest)
			delete(c.items, oldest.Value.(*cacheEntry).key)
		}
	}
}
