package sdk

import "resty.dev/v3"

type Option func(*Client)

func WithRestyClient(rc *resty.Client) Option {
	return func(c *Client) {
		c.client = rc
	}
}

func WithDebug() Option {
	return func(c *Client) {
		c.SetDebug(true)
	}
}

func WithTrace() Option {
	return func(c *Client) {
		c.EnableTrace()
	}
}

func WithProxy(proxy string) Option {
	return func(c *Client) {
		c.SetProxy(proxy)
	}
}

func WithAccessToken(token string) Option {
	return func(w *Client) {
		w.SetAccessToken(token)
	}
}

func WithRefreshToken(token string) Option {
	return func(w *Client) {
		w.SetRefreshToken(token)
	}
}

func WithOnRefreshToken(fn func(accessToken string, refreshToken string)) Option {
	return func(w *Client) {
		w.SetOnRefreshToken(fn)
	}
}

// WithOnTokenValid registers a callback fired whenever an authenticated request
// succeeds (the token in use is proven good).
func WithOnTokenValid(fn func()) Option {
	return func(w *Client) {
		w.SetOnTokenValid(fn)
	}
}

// WithOnTokenInvalid registers a callback fired when the refresh_token is found
// dead (CodeRefreshTokenError) — the credential cannot self-heal and must be
// re-authorized or recovered from a peer.
func WithOnTokenInvalid(fn func()) Option {
	return func(w *Client) {
		w.SetOnTokenInvalid(fn)
	}
}
