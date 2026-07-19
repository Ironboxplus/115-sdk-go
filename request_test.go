package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
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

func TestConcurrentAuthRequestOn401DoesNotRefresh(t *testing.T) {
	var refreshCount, invalid atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/open/refreshToken":
			refreshCount.Add(1)
			writeJSON(w, map[string]any{"state": 1, "code": 0})
		case "/open/ufile/files":
			writeJSON(w, map[string]any{"state": false, "code": 40140125, "message": "access_token invalid"})

		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	target, _ := url.Parse(server.URL)
	client := New(
		WithAccessToken("expired-token"),
		WithRefreshToken("old-rt"),
		WithOnTokenInvalid(func() { invalid.Add(1) }),
	)
	client.SetHttpClient(&http.Client{
		Transport: &rewriteTransport{target: target, base: http.DefaultTransport},
	})

	// Concurrent 401s must produce one recovery signal and no local passport hit.
	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			_, err := client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil)
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	if n := refreshCount.Load(); n != 0 {
		t.Fatalf("RefreshToken called %d times, want 0", n)
	}
	for i, err := range errs {
		var apiErr *Error
		if !errors.As(err, &apiErr) || apiErr.Code != 40140125 {
			t.Errorf("goroutine %d error = %v, want 40140125", i, err)
		}
	}
	if n := invalid.Load(); n != 1 {
		t.Fatalf("onTokenInvalid fired %d times, want 1", n)
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

// Any 401 must skip the passport endpoint, including a retrying video caller.
func TestAuthRequestNeverRefreshesAfter401(t *testing.T) {
	var refreshCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/open/refreshToken":
			refreshCount.Add(1)
			writeJSON(w, map[string]any{"code": CodeRefreshFrequently, "message": "refresh frequently"})
		default:
			writeJSON(w, map[string]any{"state": false, "code": 40100000, "message": "expired"})
		}
	}))
	defer server.Close()

	client := newTestClient(server.URL, WithAccessToken("expired"), WithRefreshToken("live-rt"))

	// The first 401 is immediately handed to peer recovery.
	_, err := client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := refreshCount.Load(); got != 0 {
		t.Fatalf("RefreshToken called %d times after first request, want 0", got)
	}

	// Hammer 20 more requests (a seeking player). None may touch passport.
	for i := 0; i < 20; i++ {
		_, err := client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil)
		if err == nil {
			t.Fatalf("request %d: expected error, got nil", i)
		}
	}
	if got := refreshCount.Load(); got != 0 {
		t.Fatalf("RefreshToken called %d times total, want 0", got)
	}
}

// A new peer-provided pair reopens the gate; AuthRequest still never refreshes.
func TestPeerCredentialPairReopensDeadGate(t *testing.T) {
	var refreshCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/open/refreshToken":
			refreshCount.Add(1)
			writeJSON(w, map[string]any{"state": 1, "code": 0})
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

	// First 401 latches without a refresh attempt.
	if _, err := client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil); err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := refreshCount.Load(); got != 0 {
		t.Fatalf("RefreshToken called %d times, want 0", got)
	}

	// Latched: further requests never touch the passport endpoint.
	for i := 0; i < 10; i++ {
		_, _ = client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil)
	}
	if got := refreshCount.Load(); got != 0 {
		t.Fatalf("RefreshToken called %d times while latched, want 0", got)
	}

	// Cluster injects the complete peer pair; no local refresh is needed.
	client.SetAccessToken("fresh-at")
	client.SetRefreshToken("new-rt")
	if _, err := client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil); err != nil {
		t.Fatalf("request after peer pair injection failed: %v", err)
	}
	if got := refreshCount.Load(); got != 0 {
		t.Fatalf("RefreshToken called %d times after peer pair injection, want 0", got)
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

	// Direct 40140120 latches the pair, so later requests cannot emit another
	// recovery cycle or call the passport endpoint.
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

// A 115 401xxxxx response means this access/refresh-token pair is unusable.
// AuthRequest must not make a local refresh attempt: the only recovery is to
// notify the caller once so it can pull a replacement pair from a peer.
func TestAny401LatchesPairAndNotifiesWithoutRefresh(t *testing.T) {
	for _, code := range []int64{40100000, CodeRefreshFrequently, CodeRefreshTokenError, 40140125, 40140126} {
		t.Run(strconv.FormatInt(code, 10), func(t *testing.T) {
			var refreshCount, invalid atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/open/refreshToken" {
					refreshCount.Add(1)
					writeJSON(w, map[string]any{"state": 1, "code": 0})
					return
				}
				writeJSON(w, map[string]any{"state": false, "code": code, "message": "token rejected"})
			}))
			defer server.Close()

			client := newTestClient(server.URL,
				WithAccessToken("rejected-at"),
				WithRefreshToken("rejected-rt"),
				WithOnTokenInvalid(func() { invalid.Add(1) }),
			)
			_, err := client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil)
			var apiErr *Error
			if !errors.As(err, &apiErr) || apiErr.Code != code {
				t.Fatalf("error = %v, want API code %d", err, code)
			}
			if got := refreshCount.Load(); got != 0 {
				t.Fatalf("RefreshToken called %d times, want 0", got)
			}
			if got := invalid.Load(); got != 1 {
				t.Fatalf("onTokenInvalid fired %d times, want 1", got)
			}
			if !client.refreshDead {
				t.Fatal("401 credential pair was not latched dead")
			}

			for i := 0; i < 5; i++ {
				_, _ = client.AuthRequest(ctx(t), ApiBaseURL+"/open/ufile/files", http.MethodGet, nil)
			}
			if got := refreshCount.Load(); got != 0 {
				t.Fatalf("RefreshToken called %d times after retries, want 0", got)
			}
			if got := invalid.Load(); got != 1 {
				t.Fatalf("onTokenInvalid fired %d times after retries, want 1", got)
			}

			client.SetRefreshToken("peer-replacement-rt")
			if client.refreshDead {
				t.Fatal("peer replacement did not reopen the credential gate")
			}
		})
	}
}

// A caller canceling an authenticated request cannot consume a refresh token:
// AuthRequest never launches a passport refresh in the first place.
func TestCanceledAuthRequestDoesNotStartRefresh(t *testing.T) {
	var refreshCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/open/refreshToken" {
			refreshCount.Add(1)
		}
		writeJSON(w, map[string]any{"state": false, "code": 40140125, "message": "access_token invalid"})
	}))
	defer server.Close()

	client := newTestClient(server.URL, WithAccessToken("rejected"), WithRefreshToken("rejected-rt"))
	callerCtx, cancelCaller := context.WithCancel(context.Background())
	cancelCaller()
	_, _ = client.AuthRequest(callerCtx, ApiBaseURL+"/open/ufile/files", http.MethodGet, nil)
	if got := refreshCount.Load(); got != 0 {
		t.Fatalf("RefreshToken called %d times after caller cancellation, want 0", got)
	}
}

// Direct refresh-endpoint errors are surfaced to an explicit RefreshToken caller;
// AuthRequest itself never calls that endpoint after a 401.
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
