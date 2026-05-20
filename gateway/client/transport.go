package client

import (
	"net/http"
	"time"
)

// sharedHTTPClient returns an *http.Client tuned for low-latency, high-reuse
// calls to the internal analyzer and OPA services.
//
// Go's http.DefaultTransport caps idle (keep-alive) connections per host at 2.
// Under concurrent load that forces fresh TCP connection setup on every request
// beyond the first two, adding latency to the p95/p99 tail. Raising the idle
// connection limits lets warm connections be reused. For reuse to actually
// happen, callers must fully drain and close the response body.
func sharedHTTPClient(timeout time.Duration) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 100
	t.MaxIdleConnsPerHost = 100
	t.IdleConnTimeout = 90 * time.Second
	return &http.Client{
		Timeout:   timeout,
		Transport: t,
	}
}
