package sdk

import (
	"strings"

	"resty.dev/v3"
)

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

func WithOnAccessTokenValid(fn func(accessToken string)) Option {
	return func(w *Client) {
		w.SetOnAccessTokenValid(fn)
	}
}

func WithOnAccessTokenInvalid(fn func(accessToken string)) Option {
	return func(w *Client) {
		w.SetOnAccessTokenInvalid(fn)
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

// WithOnRefreshTokenEx is WithOnRefreshToken plus the lifetime (seconds) of the
// new access token, so callers can schedule a proactive refresh.
func WithOnRefreshTokenEx(fn func(accessToken, refreshToken string, expiresIn int64)) Option {
	return func(w *Client) {
		w.onRefreshTokenEx = fn
	}
}

// WithOnRefreshResult registers an observer fired for every refresh attempt
// (success or failure) and every automatic refresh skipped by the policy or the
// dead/cooldown gate. The event never carries token values.
func WithOnRefreshResult(fn func(RefreshEvent)) Option {
	return func(w *Client) {
		w.onRefreshResult = fn
	}
}

// WithRefreshPolicy registers a check consulted before an automatic refresh.
// When it returns false the client does not call passport: terminal 401s still
// fire the access-token-invalid notification and the API error is returned.
func WithRefreshPolicy(fn func() bool) Option {
	return func(w *Client) {
		w.refreshPolicy = fn
	}
}

// WithAPIBaseURL redirects file/user API calls (default ApiBaseURL), e.g. to a
// local test server.
func WithAPIBaseURL(base string) Option {
	return func(w *Client) {
		w.apiBase = strings.TrimRight(base, "/")
	}
}

// WithPassportBaseURL redirects passport/auth calls (default ApiAuthURL and
// the QR status host), e.g. to a local test server.
func WithPassportBaseURL(base string) Option {
	return func(w *Client) {
		w.passportBase = strings.TrimRight(base, "/")
	}
}
