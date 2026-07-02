package sdk

import (
	"context"
	"net/http"
	"sync"
	"time"

	"resty.dev/v3"
)

type Client struct {
	client *resty.Client

	accessToken    string
	refreshToken   string
	onRefreshToken func(string, string)
	// onTokenValid fires after any authenticated request succeeds, i.e. the token
	// in use is proven good. onTokenInvalid fires when the refresh_token is found
	// dead (CodeRefreshTokenError) and re-auth/peer-recovery is required. Both let
	// callers track token validity (e.g. cluster sync: only share a proven-valid
	// token; pull a fresh one from a peer when the local one dies).
	onTokenValid   func()
	onTokenInvalid func()
	refreshMu      sync.Mutex

	// Refresh gate — remembers refresh-endpoint failures across requests. Without
	// it, every incoming API call that sees an expired access_token re-attempts a
	// refresh; with a dead/rotated refresh_token that means one passport hit per
	// caller request (a seeking video player = 1/sec), which trips 115's limiter
	// (40140117) and then keeps it tripped indefinitely.
	//   - refreshBlockedUntil: cooldown after 40140117 (limiter needs quiet time);
	//   - refreshDead: latched after 40140120 (the refresh_token is gone — no
	//     retry can help) until a new refresh_token is injected via
	//     SetRefreshToken (manual re-auth or cluster credential sync).
	gateMu              sync.Mutex
	refreshBlockedUntil time.Time
	refreshDead         bool
}

func New(opts ...Option) *Client {
	c := &Client{
		client: resty.New(),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

func Default() *Client {
	return New()
}

func (w *Client) SetHttpClient(httpClient *http.Client) *Client {
	w.client = resty.NewWithClient(httpClient)
	return w
}

func (w *Client) SetUserAgent(userAgent string) *Client {
	w.client.SetHeader("User-Agent", userAgent)
	return w
}

func (w *Client) SetDebug(d bool) *Client {
	w.client.SetDebug(d)
	return w
}

func (w *Client) EnableTrace() *Client {
	w.client.EnableTrace()
	return w
}

func (w *Client) SetProxy(proxy string) *Client {
	w.client.SetProxy(proxy)
	return w
}

func (w *Client) SetAccessToken(token string) *Client {
	w.accessToken = token
	return w
}

func (w *Client) SetRefreshToken(token string) *Client {
	w.gateMu.Lock()
	// A new refresh_token is a fresh chain: clear the dead latch and cooldown so
	// the next expired access_token may refresh again.
	if token != w.refreshToken {
		w.refreshDead = false
		w.refreshBlockedUntil = time.Time{}
	}
	w.gateMu.Unlock()
	w.refreshToken = token
	return w
}

func (w *Client) SetOnRefreshToken(fn func(accessToken string, refreshToken string)) *Client {
	w.onRefreshToken = fn
	return w
}

func (w *Client) SetOnTokenValid(fn func()) *Client {
	w.onTokenValid = fn
	return w
}

func (w *Client) SetOnTokenInvalid(fn func()) *Client {
	w.onTokenInvalid = fn
	return w
}

func (w *Client) NewRequest(ctx context.Context) *resty.Request {
	return w.client.R().SetContext(ctx)
}
