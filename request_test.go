package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
)

type rewriteTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	cloned.URL.Scheme = t.target.Scheme
	cloned.URL.Host = t.target.Host
	return t.base.RoundTrip(cloned)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func TestConcurrentAuthRequestRefreshesOnlyOnce(t *testing.T) {
	var refreshCount atomic.Int32
	currentToken := "valid-token-1"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/open/refreshToken":
			n := refreshCount.Add(1)
			if n > 1 {
				// Second+ refresh: 115 rejects because RT already consumed
				writeJSON(w, map[string]any{
					"code":    40140120,
					"message": "refresh token error",
				})
				return
			}
			currentToken = "valid-token-2"
			writeJSON(w, map[string]any{
				"state": 1,
				"code":  0,
				"data": map[string]any{
					"access_token":  currentToken,
					"refresh_token": "new-rt",
					"expires_in":    7200,
				},
			})

		case "/open/ufile/files":
			tok := r.Header.Get("Authorization")
			if tok != "Bearer "+currentToken {
				// Expired token
				writeJSON(w, map[string]any{
					"state":   false,
					"code":    40100000,
					"message": "参数错误！",
				})
				return
			}
			writeJSON(w, map[string]any{
				"state": true,
				"data":  []any{},
				"count": 0,
			})

		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	target, _ := url.Parse(server.URL)
	client := New(
		WithAccessToken("expired-token"),
		WithRefreshToken("old-rt"),
	)
	client.SetHttpClient(&http.Client{
		Transport: &rewriteTransport{target: target, base: http.DefaultTransport},
	})

	// Fire 10 concurrent requests, all hitting expired token
	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errors := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			_, err := client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil)
			errors[idx] = err
		}(i)
	}
	wg.Wait()

	// With proper singleflight protection, refresh should be called exactly once.
	// All 10 goroutines should succeed (using the refreshed token).
	if n := refreshCount.Load(); n != 1 {
		t.Fatalf("RefreshToken called %d times, want exactly 1", n)
	}

	for i, err := range errors {
		if err != nil {
			t.Errorf("goroutine %d failed: %v", i, err)
		}
	}
}

func ctx(t *testing.T) context.Context {
	t.Helper()
	return context.Background()
}
