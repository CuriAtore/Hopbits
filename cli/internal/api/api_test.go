package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNetworkTolerantDecoding(t *testing.T) {
	shapes := []string{
		`{"online_nodes": 5, "countries": [{"country": "DE", "nodes_online": 3}, {"country": "US", "nodes": 2}]}`,
		`{"online": "4", "countries": [{"country": "LT", "count": "1", "nodes": 1}, {"country": "RO", "count": "3", "nodes": 3}]}`,
		`{"countries": {"DE": 2, "NL": "3"}}`,
	}
	wantTotals := []int{5, 4, 5}

	for i, raw := range shapes {
		var n Network
		if err := json.Unmarshal([]byte(raw), &n); err != nil {
			t.Fatalf("shape[%d] unmarshal failed: %v", i, err)
		}
		if n.OnlineNodes != wantTotals[i] || len(n.Countries) != 2 {
			t.Fatalf("shape[%d] unexpected Network: %+v", i, n)
		}
	}
}

func TestClientRetriesIdempotentOnly(t *testing.T) {
	var getHits, postHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/credits" {
			n := getHits.Add(1)
			if n == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"total_available":1200,"currency":"credits"}`))
			return
		}
		if r.URL.Path == "/v1/measurements" {
			postHits.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
	}))
	defer srv.Close()

	c := New(srv.URL, "hb_test", "hopbits-cli/0.1.0", srv.Client())
	c.RetryWait = 5 * time.Millisecond

	bal, err := c.Credits(context.Background())
	if err != nil || bal.TotalAvailable != 1200 || getHits.Load() != 2 {
		t.Fatalf("expected idempotent GET retry to succeed on attempt 2: err=%v bal=%+v hits=%d", err, bal, getHits.Load())
	}

	_, err = c.CreateMeasurement(context.Background(), MeasurementRequest{Type: "http", Target: "example.com"})
	if err == nil || postHits.Load() != 1 {
		t.Fatalf("non-idempotent POST /v1/measurements must NOT retry: err=%v hits=%d", err, postHits.Load())
	}
}
