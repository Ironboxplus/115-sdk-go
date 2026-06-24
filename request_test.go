package sdk

import (
	"context"
	"encoding/json"
	"errors"
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

func TestAuthRequestReturnsErrDataEmptyForEmptyArray(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 115 API returns empty array when path does not exist
		writeJSON(w, map[string]any{
			"state": true,
			"code":  0,
			"data":  []any{},
		})
	}))
	defer server.Close()

	target, _ := url.Parse(server.URL)
	client := New(WithAccessToken("valid-token"))
	client.SetHttpClient(&http.Client{
		Transport: &rewriteTransport{target: target, base: http.DefaultTransport},
	})

	type FolderInfo struct {
		FileID   string `json:"file_id"`
		FileName string `json:"file_name"`
	}
	var resp FolderInfo
	_, err := client.AuthRequest(ctx(t), server.URL+"/open/folder/info", http.MethodGet, &resp)

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrDataEmpty) {
		t.Fatalf("expected ErrDataEmpty, got: %v", err)
	}
}

func TestAuthRequestReturnsErrDataEmptyForNull(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"state": true,
			"code":  0,
			"data":  nil,
		})
	}))
	defer server.Close()

	target, _ := url.Parse(server.URL)
	client := New(WithAccessToken("valid-token"))
	client.SetHttpClient(&http.Client{
		Transport: &rewriteTransport{target: target, base: http.DefaultTransport},
	})

	type FolderInfo struct {
		FileID string `json:"file_id"`
	}
	var resp FolderInfo
	_, err := client.AuthRequest(ctx(t), server.URL+"/open/folder/info", http.MethodGet, &resp)

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrDataEmpty) {
		t.Fatalf("expected ErrDataEmpty, got: %v", err)
	}
}

func TestAuthRequestSucceedsForValidObject(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"state": true,
			"code":  0,
			"data": map[string]any{
				"file_id":   "12345",
				"file_name": "test_folder",
			},
		})
	}))
	defer server.Close()

	target, _ := url.Parse(server.URL)
	client := New(WithAccessToken("valid-token"))
	client.SetHttpClient(&http.Client{
		Transport: &rewriteTransport{target: target, base: http.DefaultTransport},
	})

	type FolderInfo struct {
		FileID   string `json:"file_id"`
		FileName string `json:"file_name"`
	}
	var resp FolderInfo
	_, err := client.AuthRequest(ctx(t), server.URL+"/open/folder/info", http.MethodGet, &resp)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.FileID != "12345" || resp.FileName != "test_folder" {
		t.Fatalf("unexpected resp: %+v", resp)
	}
}

func ctx(t *testing.T) context.Context {
	t.Helper()
	return context.Background()
}

// newTestClient wires a client to a local test server via the rewrite transport.
func newTestClient(serverURL string, opts ...Option) *Client {
	target, _ := url.Parse(serverURL)
	c := New(opts...)
	c.SetHttpClient(&http.Client{
		Transport: &rewriteTransport{target: target, base: http.DefaultTransport},
	})
	return c
}

// A successful authenticated request must fire onTokenValid (and not invalid):
// the token in use is proven good.
func TestOnTokenValidFiresOnSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"state": true, "data": []any{}, "count": 0})
	}))
	defer server.Close()

	var valid, invalid atomic.Int32
	client := newTestClient(server.URL,
		WithAccessToken("good-token"),
		WithOnTokenValid(func() { valid.Add(1) }),
		WithOnTokenInvalid(func() { invalid.Add(1) }),
	)
	if _, err := client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if valid.Load() != 1 {
		t.Fatalf("onTokenValid fired %d times, want 1", valid.Load())
	}
	if invalid.Load() != 0 {
		t.Fatalf("onTokenInvalid fired %d times, want 0", invalid.Load())
	}
}

// When the API rejects us directly with a dead refresh_token, onTokenInvalid
// must fire so the caller can recover (re-auth / pull from a peer).
func TestOnTokenInvalidFiresOnDirectDeadRefreshToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"state": false, "code": CodeRefreshTokenError, "message": "refresh token error"})
	}))
	defer server.Close()

	var valid, invalid atomic.Int32
	client := newTestClient(server.URL,
		WithAccessToken("dead"), WithRefreshToken("dead-rt"),
		WithOnTokenValid(func() { valid.Add(1) }),
		WithOnTokenInvalid(func() { invalid.Add(1) }),
	)
	_, err := client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if invalid.Load() != 1 {
		t.Fatalf("onTokenInvalid fired %d times, want 1", invalid.Load())
	}
	if valid.Load() != 0 {
		t.Fatalf("onTokenValid fired %d times, want 0", valid.Load())
	}
}

// When the access_token is expired and the refresh attempt then fails with a
// dead refresh_token, onTokenInvalid must fire.
func TestOnTokenInvalidFiresWhenRefreshDies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/open/refreshToken":
			writeJSON(w, map[string]any{"code": CodeRefreshTokenError, "message": "refresh token error"})
		default: // expired access token → triggers a refresh attempt
			writeJSON(w, map[string]any{"state": false, "code": 40100000, "message": "expired"})
		}
	}))
	defer server.Close()

	var invalid atomic.Int32
	client := newTestClient(server.URL,
		WithAccessToken("expired"), WithRefreshToken("dead-rt"),
		WithOnTokenInvalid(func() { invalid.Add(1) }),
	)
	if _, err := client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil); err == nil {
		t.Fatal("expected error, got nil")
	}
	if invalid.Load() != 1 {
		t.Fatalf("onTokenInvalid fired %d times, want 1", invalid.Load())
	}
}

// Refresh throttling (CodeRefreshFrequently) is transient — the refresh_token is
// NOT dead — so onTokenInvalid must NOT fire.
func TestOnTokenInvalidDoesNotFireOnThrottle(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/open/refreshToken":
			writeJSON(w, map[string]any{"code": CodeRefreshFrequently, "message": "refresh frequently"})
		default:
			writeJSON(w, map[string]any{"state": false, "code": 40100000, "message": "expired"})
		}
	}))
	defer server.Close()

	var invalid atomic.Int32
	client := newTestClient(server.URL,
		WithAccessToken("expired"), WithRefreshToken("live-rt"),
		WithOnTokenInvalid(func() { invalid.Add(1) }),
	)
	_, _ = client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil)
	if invalid.Load() != 0 {
		t.Fatalf("onTokenInvalid fired %d times on throttle, want 0", invalid.Load())
	}
}

// A refresh must complete even if the API request that triggered it is
// canceled mid-refresh (e.g. a video player aborting a seek). Otherwise the
// one-time refresh_token is consumed server-side while its replacement is
// lost in the aborted response.
func TestRefreshSurvivesCallerCancellation(t *testing.T) {
	var refreshCount atomic.Int32
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/open/refreshToken":
			refreshCount.Add(1)
			close(refreshStarted)
			<-releaseRefresh // hold the refresh in flight while caller cancels
			writeJSON(w, map[string]any{
				"state": 1,
				"code":  0,
				"data": map[string]any{
					"access_token":  "fresh-token",
					"refresh_token": "fresh-rt",
					"expires_in":    7200,
				},
			})
		case "/open/ufile/files":
			if r.Header.Get("Authorization") == "Bearer fresh-token" {
				writeJSON(w, map[string]any{"state": true, "data": []any{}, "count": 0})
				return
			}
			writeJSON(w, map[string]any{
				"state":   false,
				"code":    40100000,
				"message": "token expired",
			})
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	target, _ := url.Parse(server.URL)
	var savedAccess, savedRefresh string
	client := New(
		WithAccessToken("expired-token"),
		WithRefreshToken("old-rt"),
		WithOnRefreshToken(func(at, rt string) { savedAccess, savedRefresh = at, rt }),
	)
	client.SetHttpClient(&http.Client{
		Transport: &rewriteTransport{target: target, base: http.DefaultTransport},
	})

	callerCtx, cancelCaller := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := client.AuthRequest(callerCtx, ApiBaseURL+"/open/ufile/files", http.MethodGet, nil)
		done <- err
	}()

	<-refreshStarted // refresh request is now in flight
	cancelCaller()   // caller bails out mid-refresh
	close(releaseRefresh)
	<-done // the outer request may fail (caller ctx is dead) — that is fine

	// The refresh itself must have completed and the rotated tokens persisted.
	if savedAccess != "fresh-token" || savedRefresh != "fresh-rt" {
		t.Fatalf("rotated tokens lost: access=%q refresh=%q", savedAccess, savedRefresh)
	}
	if got := refreshCount.Load(); got != 1 {
		t.Fatalf("RefreshToken called %d times, want 1", got)
	}
}

// Refresh-endpoint failure codes must not trigger another refresh:
// 40140117 means rate-limited (access_token is not the problem) and
// 40140120 means the refresh_token is dead (retry cannot help).
func TestRefreshEndpointErrorsDoNotTriggerRefresh(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int64
		msg  string
	}{
		{"refresh frequently", 40140117, "refresh frequently"},
		{"refresh token error", 40140120, "refresh token error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var refreshCount atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/open/refreshToken":
					refreshCount.Add(1)
					writeJSON(w, map[string]any{"code": tc.code, "message": tc.msg})
				case "/open/ufile/files":
					writeJSON(w, map[string]any{
						"state":   false,
						"code":    tc.code,
						"message": tc.msg,
					})
				default:
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
			}))
			defer server.Close()

			target, _ := url.Parse(server.URL)
			client := New(WithAccessToken("some-token"), WithRefreshToken("some-rt"))
			client.SetHttpClient(&http.Client{
				Transport: &rewriteTransport{target: target, base: http.DefaultTransport},
			})

			_, err := client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			var apiErr *Error
			if !errors.As(err, &apiErr) || apiErr.Code != tc.code {
				t.Fatalf("expected API error code %d, got: %v", tc.code, err)
			}
			if got := refreshCount.Load(); got != 0 {
				t.Fatalf("RefreshToken called %d times, want 0", got)
			}
		})
	}
}
