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
	"time"
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
	// atomic.Value, not a bare string: the httptest server handles each
	// concurrent connection on its own goroutine, so the refresh path's
	// write here races with the ufile path's read on every other goroutine.
	var currentToken atomic.Value
	currentToken.Store("valid-token-1")

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
			currentToken.Store("valid-token-2")
			writeJSON(w, map[string]any{
				"state": 1,
				"code":  0,
				"data": map[string]any{
					"access_token":  currentToken.Load().(string),
					"refresh_token": "new-rt",
					"expires_in":    7200,
				},
			})

		case "/open/ufile/files":
			tok := r.Header.Get("Authorization")
			if tok != "Bearer "+currentToken.Load().(string) {
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

// After a 40140117 throttle on the refresh endpoint, subsequent requests must
// fail fast WITHOUT hitting the passport endpoint again (cooldown gate). This
// is the "frequent refresh" bug: a retrying caller (video player at ~1 req/s)
// re-triggered a refresh per request and kept 115's limiter tripped forever.
func TestRefreshCooldownStopsRepeatedRefreshAttempts(t *testing.T) {
	var refreshCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/open/refreshToken":
			refreshCount.Add(1)
			writeJSON(w, map[string]any{"code": CodeRefreshFrequently, "message": "refresh frequently"})
		default: // expired access token → wants a refresh
			writeJSON(w, map[string]any{"state": false, "code": 40100000, "message": "expired"})
		}
	}))
	defer server.Close()

	client := newTestClient(server.URL, WithAccessToken("expired"), WithRefreshToken("live-rt"))

	// First request: allowed to try the refresh once, gets throttled.
	_, err := client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := refreshCount.Load(); got != 1 {
		t.Fatalf("RefreshToken called %d times after first request, want 1", got)
	}

	// Hammer 20 more requests (a seeking player). None may touch the passport
	// endpoint during the cooldown; each fails fast with the API error.
	for i := 0; i < 20; i++ {
		_, err := client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil)
		if err == nil {
			t.Fatalf("request %d: expected error, got nil", i)
		}
	}
	if got := refreshCount.Load(); got != 1 {
		t.Fatalf("RefreshToken called %d times total, want 1 (cooldown must block retries)", got)
	}
	if client.refreshDead {
		t.Fatal("40140117 latched a retryable credential pair dead")
	}

	// Once the cooldown elapses, the same refresh chain is eligible for one
	// more attempt. Move the clock gate instead of sleeping for five minutes.
	client.gateMu.Lock()
	client.refreshBlockedUntil = time.Now().Add(-time.Second)
	client.gateMu.Unlock()
	_, _ = client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil)
	if got := refreshCount.Load(); got != 2 {
		t.Fatalf("RefreshToken called %d times after cooldown, want 2", got)
	}
	if client.refreshDead {
		t.Fatal("repeated 40140117 latched the credential pair dead")
	}
}

// After a 40140120 (dead refresh_token) the gate latches: no further refresh
// attempts ever — until a NEW refresh_token is injected, which re-opens it.
func TestDeadRefreshTokenLatchesUntilNewTokenInjected(t *testing.T) {
	var refreshCount atomic.Int32
	rtIsDead := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/open/refreshToken":
			refreshCount.Add(1)
			if rtIsDead {
				writeJSON(w, map[string]any{"code": CodeRefreshTokenError, "message": "refresh token error"})
				return
			}
			writeJSON(w, map[string]any{
				"state": 1, "code": 0,
				"data": map[string]any{"access_token": "fresh-at", "refresh_token": "fresh-rt", "expires_in": 7200},
			})
		case "/open/ufile/files":
			if r.Header.Get("Authorization") == "Bearer fresh-at" {
				writeJSON(w, map[string]any{"state": true, "data": []any{}, "count": 0})
				return
			}
			writeJSON(w, map[string]any{"state": false, "code": 40100000, "message": "expired"})
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := newTestClient(server.URL, WithAccessToken("expired"), WithRefreshToken("dead-rt"))

	// First request consumes the one allowed refresh attempt → dead latch.
	if _, err := client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil); err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := refreshCount.Load(); got != 1 {
		t.Fatalf("RefreshToken called %d times, want 1", got)
	}

	// Latched: further requests never touch the passport endpoint.
	for i := 0; i < 10; i++ {
		_, _ = client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil)
	}
	if got := refreshCount.Load(); got != 1 {
		t.Fatalf("RefreshToken called %d times while latched, want 1", got)
	}

	// Operator/cluster injects a fresh refresh_token → gate re-opens, refresh
	// succeeds, request completes.
	rtIsDead = false
	client.SetRefreshToken("new-rt")
	if _, err := client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil); err != nil {
		t.Fatalf("request after new RT injection failed: %v", err)
	}
	if got := refreshCount.Load(); got != 2 {
		t.Fatalf("RefreshToken called %d times after new RT, want 2", got)
	}
}

// A direct API answer of 40140120 (without going through a refresh attempt)
// must also latch the gate.
func TestDirectDeadRefreshTokenAnswerLatchesGate(t *testing.T) {
	var refreshCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/open/refreshToken":
			refreshCount.Add(1)
			writeJSON(w, map[string]any{"code": CodeRefreshTokenError, "message": "refresh token error"})
		default:
			// API answers the dead-RT code directly (115 does this on some endpoints).
			writeJSON(w, map[string]any{"state": false, "code": CodeRefreshTokenError, "message": "refresh token error"})
		}
	}))
	defer server.Close()

	client := newTestClient(server.URL, WithAccessToken("at"), WithRefreshToken("dead-rt"))

	// shouldRefreshToken(40140120) is false, so no refresh fires — but the gate
	// must still latch so a later 401-style error can't trigger one either.
	_, _ = client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil)
	if !client.refreshDead {
		t.Fatal("gate not latched after direct 40140120 answer")
	}
	if got := refreshCount.Load(); got != 0 {
		t.Fatalf("RefreshToken called %d times, want 0", got)
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

func TestOnAccessTokenValidReportsRefreshedToken(t *testing.T) {
	var refreshCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/open/refreshToken":
			refreshCount.Add(1)
			writeJSON(w, map[string]any{
				"state": 1,
				"code":  0,
				"data": map[string]any{
					"access_token":  "fresh-access",
					"refresh_token": "fresh-refresh",
					"expires_in":    7200,
				},
			})
		default:
			if r.Header.Get("Authorization") != "Bearer fresh-access" {
				writeJSON(w, map[string]any{"state": false, "code": 40140125, "message": "access_token invalid"})
				return
			}
			writeJSON(w, map[string]any{"state": true, "data": []any{}, "count": 0})
		}
	}))
	defer server.Close()

	var proven string
	client := newTestClient(server.URL,
		WithAccessToken("expired-access"),
		WithRefreshToken("live-refresh"),
		WithOnAccessTokenValid(func(accessToken string) { proven = accessToken }),
	)
	if _, err := client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil); err != nil {
		t.Fatalf("request after refresh failed: %v", err)
	}
	if refreshCount.Load() != 1 {
		t.Fatalf("refresh count = %d, want 1", refreshCount.Load())
	}
	if proven != "fresh-access" {
		t.Fatalf("proven access token = %q, want refreshed token", proven)
	}
}

func TestOnAccessTokenInvalidReportsCurrentRefreshedGeneration(t *testing.T) {
	var rejectFresh atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/open/refreshToken":
			writeJSON(w, map[string]any{
				"state": 1,
				"code":  0,
				"data": map[string]any{
					"access_token":  "fresh-access",
					"refresh_token": "fresh-refresh",
					"expires_in":    7200,
				},
			})
		default:
			if r.Header.Get("Authorization") != "Bearer fresh-access" {
				writeJSON(w, map[string]any{"state": false, "code": 40140125, "message": "access_token invalid"})
				return
			}
			if rejectFresh.Load() {
				writeJSON(w, map[string]any{"state": false, "code": CodeRefreshTokenError, "message": "refresh token error"})
				return
			}
			writeJSON(w, map[string]any{"state": true, "data": []any{}, "count": 0})
		}
	}))
	defer server.Close()

	var invalidAccess string
	client := newTestClient(server.URL,
		WithAccessToken("expired-access"),
		WithRefreshToken("live-refresh"),
		WithOnAccessTokenInvalid(func(accessToken string) { invalidAccess = accessToken }),
	)
	if _, err := client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil); err != nil {
		t.Fatalf("initial refresh/retry failed: %v", err)
	}
	rejectFresh.Store(true)
	if _, err := client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil); err == nil {
		t.Fatal("expected refreshed generation to be rejected")
	}
	if invalidAccess != "fresh-access" {
		t.Fatalf("invalid callback access token = %q, want current refreshed generation", invalidAccess)
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

// A refresh-endpoint 40140117 is a temporary throttle. It must not invalidate
// the access/refresh pair or ask cluster recovery to tombstone that pair.
func TestRefreshFrequentlyDoesNotInvalidateOrLatchPair(t *testing.T) {
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
	var invalidAccess atomic.Int32
	client := newTestClient(server.URL,
		WithAccessToken("expired"), WithRefreshToken("live-rt"),
		WithOnTokenInvalid(func() { invalid.Add(1) }),
		WithOnAccessTokenInvalid(func(string) { invalidAccess.Add(1) }),
	)
	_, _ = client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil)
	if invalid.Load() != 0 {
		t.Fatalf("onTokenInvalid fired %d times on 40140117, want 0", invalid.Load())
	}
	if invalidAccess.Load() != 0 {
		t.Fatalf("onAccessTokenInvalid fired %d times on 40140117, want 0", invalidAccess.Load())
	}
	if client.refreshDead {
		t.Fatal("40140117 latched the credential pair dead")
	}
	if !client.refreshBlockedUntil.After(time.Now()) {
		t.Fatal("40140117 did not arm the refresh cooldown")
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

// ---------------------------------------------------------------------------
// Bug 1: the refresh-gate short-circuit (request.go, "if !c.refreshAllowed()")
// must still report a terminal auth error before it fast-fails. Otherwise a
// client that hits the gate before ever reaching the isTerminalAuthError
// branch below it never tells anyone its credential is dead.
// ---------------------------------------------------------------------------

// White-box: force the dead latch directly (bypassing how it normally gets
// set) to isolate the short-circuit branch itself, and assert both the gate
// state and the callback behavior.
func TestGateClosedByDeadLatchStillFiresAccessTokenInvalid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/open/refreshToken" {
			// t.Error, not t.Fatal: this callback runs on the http server's
			// own goroutine, and FailNow (which Fatal calls) must only be
			// called from the test's own goroutine.
			t.Error("refresh endpoint must not be hit while the dead latch is set")
		}
		writeJSON(w, map[string]any{"state": false, "code": 40140125, "message": "access_token invalid"})
	}))
	defer server.Close()

	var invalidCount atomic.Int32
	var invalidAccess string
	client := newTestClient(server.URL,
		WithAccessToken("stuck-token"), WithRefreshToken("dead-rt"),
		WithOnAccessTokenInvalid(func(at string) { invalidAccess = at; invalidCount.Add(1) }),
	)
	client.gateMu.Lock()
	client.refreshDead = true
	client.gateMu.Unlock()

	if client.refreshAllowed() {
		t.Fatal("refreshAllowed() true with the dead latch set")
	}

	_, err := client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if invalidCount.Load() != 1 {
		t.Fatalf("onAccessTokenInvalid fired %d times, want 1", invalidCount.Load())
	}
	if invalidAccess != "stuck-token" {
		t.Fatalf("onAccessTokenInvalid token = %q, want %q", invalidAccess, "stuck-token")
	}
}

// Same short-circuit branch, reached via the cooldown timer instead of the
// dead latch.
func TestGateClosedByCooldownStillFiresAccessTokenInvalid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/open/refreshToken" {
			t.Error("refresh endpoint must not be hit while the cooldown is active")
		}
		writeJSON(w, map[string]any{"state": false, "code": 40140125, "message": "access_token invalid"})
	}))
	defer server.Close()

	var invalidCount atomic.Int32
	var invalidAccess string
	client := newTestClient(server.URL,
		WithAccessToken("cooling-token"), WithRefreshToken("live-rt"),
		WithOnAccessTokenInvalid(func(at string) { invalidAccess = at; invalidCount.Add(1) }),
	)
	client.gateMu.Lock()
	client.refreshBlockedUntil = time.Now().Add(time.Minute)
	client.gateMu.Unlock()

	if client.refreshAllowed() {
		t.Fatal("refreshAllowed() true during cooldown")
	}

	_, err := client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if invalidCount.Load() != 1 {
		t.Fatalf("onAccessTokenInvalid fired %d times, want 1", invalidCount.Load())
	}
	if invalidAccess != "cooling-token" {
		t.Fatalf("onAccessTokenInvalid token = %q, want %q", invalidAccess, "cooling-token")
	}
}

// Control case for the third gate state (neither latch nor cooldown set):
// the short-circuit branch is not even reached -- the request proceeds to a
// real refresh attempt. This is not expected to fail before the fix; it
// characterizes the boundary the other two tests are probing.
func TestGateOpenTakesRefreshPathNotShortCircuit(t *testing.T) {
	var refreshCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/open/refreshToken":
			refreshCount.Add(1)
			writeJSON(w, map[string]any{"code": CodeRefreshTokenError, "message": "refresh token error"})
		default:
			writeJSON(w, map[string]any{"state": false, "code": 40140125, "message": "access_token invalid"})
		}
	}))
	defer server.Close()

	client := newTestClient(server.URL, WithAccessToken("expired"), WithRefreshToken("live-rt"))

	if !client.refreshAllowed() {
		t.Fatal("refreshAllowed() false on a fresh client with no latch/cooldown")
	}

	_, err := client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := refreshCount.Load(); got != 1 {
		t.Fatalf("refresh endpoint hit %d times, want 1 (gate was open)", got)
	}
}

// ---------------------------------------------------------------------------
// Bug 2: fireAccessTokenInvalid must be level-triggered -- every rejected
// request reports, not just the one that flips markTokenDead's return value
// from true to false. A consumer with its own generation check can silently
// drop one delivery; if that is the only one ever sent, the client is muted
// for the rest of its process lifetime.
// ---------------------------------------------------------------------------

// Gray-box: gate pre-closed via the dead latch, then N consecutive 401s.
// Asserts the exact request sequence: zero hits on the refresh endpoint, and
// one onAccessTokenInvalid call per rejected request (not one total).
func TestGateClosedFiresAccessTokenInvalidOncePerRequestNotJustFirst(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/open/refreshToken" {
			t.Error("refresh endpoint must not be hit while the gate is closed")
		}
		writeJSON(w, map[string]any{"state": false, "code": 40140125, "message": "access_token invalid"})
	}))
	defer server.Close()

	var mu sync.Mutex
	var seenTokens []string
	client := newTestClient(server.URL,
		WithAccessToken("stuck-token"), WithRefreshToken("dead-rt"),
		WithOnAccessTokenInvalid(func(at string) {
			mu.Lock()
			seenTokens = append(seenTokens, at)
			mu.Unlock()
		}),
	)
	client.gateMu.Lock()
	client.refreshDead = true
	client.gateMu.Unlock()

	const n = 5
	for i := 0; i < n; i++ {
		if _, err := client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil); err == nil {
			t.Fatalf("request %d: expected error, got nil", i)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seenTokens) != n {
		t.Fatalf("onAccessTokenInvalid fired %d times, want %d (must fire once per rejected request, not just the first)", len(seenTokens), n)
	}
	for i, tok := range seenTokens {
		if tok != "stuck-token" {
			t.Fatalf("call %d token = %q, want %q", i, tok, "stuck-token")
		}
	}
}

// Gray-box, isolating the OTHER call site of fireAccessTokenInvalid
// (request.go's terminal-error block guarded by markTokenDead), reached
// without ever touching the gate-check branch: a direct 40140120 answer
// skips shouldRefreshToken (it excludes that code explicitly), so every one
// of these requests falls straight through to the markTokenDead gating this
// bug is about.
func TestDirectDeadRefreshTokenAnswerFiresOnEveryRequestNotJustFirst(t *testing.T) {
	var refreshCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/open/refreshToken" {
			refreshCount.Add(1)
		}
		writeJSON(w, map[string]any{"state": false, "code": CodeRefreshTokenError, "message": "refresh token error"})
	}))
	defer server.Close()

	var mu sync.Mutex
	var seenTokens []string
	client := newTestClient(server.URL,
		WithAccessToken("direct-dead-token"), WithRefreshToken("dead-rt"),
		WithOnAccessTokenInvalid(func(at string) {
			mu.Lock()
			seenTokens = append(seenTokens, at)
			mu.Unlock()
		}),
	)

	const n = 4
	for i := 0; i < n; i++ {
		if _, err := client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil); err == nil {
			t.Fatalf("request %d: expected error, got nil", i)
		}
	}

	if got := refreshCount.Load(); got != 0 {
		t.Fatalf("refresh endpoint hit %d times, want 0 (40140120 is excluded from shouldRefreshToken)", got)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seenTokens) != n {
		t.Fatalf("onAccessTokenInvalid fired %d times, want %d (must fire on every request, not just the one that flips the latch)", len(seenTokens), n)
	}
	for i, tok := range seenTokens {
		if tok != "direct-dead-token" {
			t.Fatalf("call %d token = %q, want %q", i, tok, "direct-dead-token")
		}
	}
}

// Concurrency: the level-triggered guarantee must hold under concurrent
// callers too -- every goroutine's rejected request produces exactly one
// callback call, with no lost or duplicated deliveries. Run with -race.
func TestConcurrentGateClosedFiresAccessTokenInvalidForEveryRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/open/refreshToken" {
			t.Error("refresh endpoint must not be hit while the gate is closed")
			return
		}
		writeJSON(w, map[string]any{"state": false, "code": 40140125, "message": "access_token invalid"})
	}))
	defer server.Close()

	var invalidCount atomic.Int32
	client := newTestClient(server.URL,
		WithAccessToken("stuck-token"), WithRefreshToken("dead-rt"),
		WithOnAccessTokenInvalid(func(string) { invalidCount.Add(1) }),
	)
	client.gateMu.Lock()
	client.refreshDead = true
	client.gateMu.Unlock()

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil)
		}()
	}
	wg.Wait()

	if got := invalidCount.Load(); got != goroutines {
		t.Fatalf("onAccessTokenInvalid fired %d times, want %d (one per rejected request)", got, goroutines)
	}
}

// ---------------------------------------------------------------------------
// Black-box: drives the client only through sdk.New(...) + AuthRequest,
// touching no unexported field. Covers both bugs together across a realistic
// end-to-end credential-death scenario.
// ---------------------------------------------------------------------------

// Full lifecycle: valid-looking initial token -> 401 -> refresh succeeds ->
// the refreshed token ALSO gets 401'd on retry (proving the pair, not just
// the access_token, is dead) -> latched -> every subsequent request must
// keep reporting onAccessTokenInvalid, not just the first.
func TestBlackBoxAccessTokenInvalidKeepsReportingAfterLatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/open/refreshToken":
			writeJSON(w, map[string]any{
				"state": 1, "code": 0,
				"data": map[string]any{"access_token": "new-at", "refresh_token": "new-rt", "expires_in": 7200},
			})
		default:
			// Both the original and the refreshed token are rejected: the
			// whole pair is dead, not just a stale access_token.
			writeJSON(w, map[string]any{"state": false, "code": 40140125, "message": "access_token invalid"})
		}
	}))
	defer server.Close()

	var mu sync.Mutex
	var seenTokens []string
	client := New(WithAccessToken("old-at"), WithRefreshToken("old-rt"),
		WithOnAccessTokenInvalid(func(at string) {
			mu.Lock()
			seenTokens = append(seenTokens, at)
			mu.Unlock()
		}),
	)
	target, _ := url.Parse(server.URL)
	client.SetHttpClient(&http.Client{Transport: &rewriteTransport{target: target, base: http.DefaultTransport}})

	// First call: 401 on old-at -> refresh succeeds -> retry with new-at ->
	// also 401 -> latches, fires once (retry=true path).
	if _, err := client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil); err == nil {
		t.Fatal("expected error, got nil")
	}

	// Further top-level calls must keep reporting even though the gate is
	// now closed (short-circuit path).
	const moreCalls = 4
	for i := 0; i < moreCalls; i++ {
		if _, err := client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil); err == nil {
			t.Fatalf("call %d: expected error, got nil", i)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	wantCalls := 1 + moreCalls
	if len(seenTokens) != wantCalls {
		t.Fatalf("onAccessTokenInvalid fired %d times, want %d (must keep reporting after the latch closes)", len(seenTokens), wantCalls)
	}
	for i, tok := range seenTokens {
		if tok != "new-at" {
			t.Fatalf("call %d token = %q, want %q", i, tok, "new-at")
		}
	}
}

// The refresh endpoint itself answering with the dead-refresh_token code
// must fire the callback with the token that was actually in use, and keep
// firing on later requests instead of going silent after the first.
func TestBlackBoxRefreshEndpointDeadTokenFiresCallbackWithCorrectToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/open/refreshToken":
			writeJSON(w, map[string]any{"code": CodeRefreshTokenError, "message": "refresh token error"})
		default:
			writeJSON(w, map[string]any{"state": false, "code": 40100000, "message": "expired"})
		}
	}))
	defer server.Close()

	var mu sync.Mutex
	var seenTokens []string
	client := New(WithAccessToken("expired-at"), WithRefreshToken("dead-rt"),
		WithOnAccessTokenInvalid(func(at string) {
			mu.Lock()
			seenTokens = append(seenTokens, at)
			mu.Unlock()
		}),
	)
	target, _ := url.Parse(server.URL)
	client.SetHttpClient(&http.Client{Transport: &rewriteTransport{target: target, base: http.DefaultTransport}})

	const calls = 3
	for i := 0; i < calls; i++ {
		if _, err := client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil); err == nil {
			t.Fatalf("call %d: expected error, got nil", i)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seenTokens) != calls {
		t.Fatalf("onAccessTokenInvalid fired %d times, want %d", len(seenTokens), calls)
	}
	for i, tok := range seenTokens {
		if tok != "expired-at" {
			t.Fatalf("call %d token = %q, want %q", i, tok, "expired-at")
		}
	}
}
