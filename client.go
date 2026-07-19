package sdk

import (
	"context"
	"net/http"
	"sync"

	"resty.dev/v3"
)

type Client struct {
	client *resty.Client

	accessToken    string
	refreshToken   string
	onRefreshToken func(string, string)
	// onTokenValid fires after any authenticated request succeeds, i.e. the token
	// pair in use is proven good. onTokenInvalid fires once when 115 returns any
	// 401xxxxx response: that pair is not reusable and callers must recover a new
	// one (for example from a cluster peer) rather than refreshing it locally.
	onTokenValid   func()
	onTokenInvalid func()
	refreshMu      sync.Mutex

	// Credential gate — any 401xxxxx latches the complete pair as dead. We never
	// retry the passport refresh endpoint from AuthRequest; a new refresh_token
	// injected by re-authentication or cluster recovery is the only way to reopen
	// the gate.
	gateMu      sync.Mutex
	refreshDead bool
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
	// A new refresh_token is a fresh pair: clear the dead latch and cooldown so
	// authenticated requests may use it again.
	if token != w.refreshToken {
		w.refreshDead = false
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
