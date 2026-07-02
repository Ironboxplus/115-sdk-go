package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"resty.dev/v3"
)

// refreshTimeout bounds a token refresh once it starts. The refresh must not
// inherit the caller's cancellation: 115 rotates the refresh_token server-side
// on every refresh call, so a request canceled mid-flight (e.g. a video player
// seeking) consumes the one-time token while the response carrying its
// replacement is lost — permanently bricking authentication.
const refreshTimeout = 30 * time.Second

// refreshCooldown is how long to refuse further refresh attempts after 115's
// passport endpoint answered 40140117 (refresh frequently). The limiter is
// keyed to recent call rate; hammering it once per incoming request keeps it
// tripped forever. During cooldown, callers fail fast with the original error.
const refreshCooldown = 5 * time.Minute

// shouldRefreshToken reports whether an API error code indicates a stale
// access_token that a refresh could fix. Refresh-endpoint errors are excluded:
//   - 40140117 (refresh frequently): rate-limited, the access_token is not the
//     problem and another refresh only feeds the limiter;
//   - 40140120 (refresh token error): the refresh_token itself is dead, only
//     re-authorization can recover.
func shouldRefreshToken(code int64) bool {
	if code == CodeRefreshFrequently || code == CodeRefreshTokenError {
		return false
	}
	return code == 99 || Is401Started(code)
}

func isEmptyData(data json.RawMessage) bool {
	d := bytes.TrimSpace(data)
	return len(d) == 0 || bytes.Equal(d, []byte("null"))
}

func (c *Client) Request(ctx context.Context, url string, method string, opts ...RestyOption) (*resty.Response, error) {
	req := c.NewRequest(ctx)
	for _, opt := range opts {
		opt(req)
	}
	return req.Execute(method, url)
}

func (c *Client) passportRequest(ctx context.Context, url, method string, respData any, opts ...RestyOption) (*resty.Response, error) {
	var resp AuthResp[any]
	if respData != nil {
		resp.Data = respData
	}
	response, err := c.Request(ctx, url, method, append(opts, ReqWithResp(&resp))...)
	if err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		// Typed so callers (e.g. RefreshToken) can detect CodeRefreshTokenError.
		return response, &Error{Code: int64(resp.Code), Message: resp.Message}
	}
	if resp.Error != "" {
		return response, fmt.Errorf("error: %s, errno: %d", resp.Error, resp.Errno)
	}
	return response, nil
}

// fireTokenValid / fireTokenInvalid invoke the validity callbacks if registered.
func (c *Client) fireTokenValid() {
	if c.onTokenValid != nil {
		c.onTokenValid()
	}
}

func (c *Client) fireTokenInvalid() {
	if c.onTokenInvalid != nil {
		c.onTokenInvalid()
	}
}

// notifyIfRefreshDead fires onTokenInvalid when a refresh attempt failed because
// the refresh_token itself is dead (CodeRefreshTokenError) — the only error a
// refresh cannot recover from. Throttling (CodeRefreshFrequently) is transient
// and must NOT be treated as a dead token.
func (c *Client) notifyIfRefreshDead(err error) {
	var e *Error
	if errors.As(err, &e) && e.Code == CodeRefreshTokenError {
		c.fireTokenInvalid()
	}
}

// refreshAllowed reports whether a refresh attempt may be made right now.
// It is false while the dead latch is set (refresh_token consumed/revoked)
// or within the cooldown window after a 40140117 throttle.
func (c *Client) refreshAllowed() bool {
	c.gateMu.Lock()
	defer c.gateMu.Unlock()
	if c.refreshDead {
		return false
	}
	return time.Now().After(c.refreshBlockedUntil)
}

// noteRefreshOutcome updates the refresh gate from a refresh attempt's result:
// success clears everything; 40140117 arms the cooldown; 40140120 latches dead.
func (c *Client) noteRefreshOutcome(err error) {
	c.gateMu.Lock()
	defer c.gateMu.Unlock()
	if err == nil {
		c.refreshDead = false
		c.refreshBlockedUntil = time.Time{}
		return
	}
	var e *Error
	if errors.As(err, &e) {
		switch e.Code {
		case CodeRefreshFrequently:
			c.refreshBlockedUntil = time.Now().Add(refreshCooldown)
		case CodeRefreshTokenError:
			c.refreshDead = true
		}
	}
}

func (c *Client) authRequest(ctx context.Context, url, method string, respData any, extractData, retry bool, opts ...RestyOption) (*resty.Response, error) {
	var resp Resp[json.RawMessage]
	c.refreshMu.Lock()
	usedToken := c.accessToken
	c.refreshMu.Unlock()
	response, err := c.Request(ctx, url, method, append(opts, ReqWithResp(&resp), func(request *resty.Request) {
		if usedToken != "" {
			request.SetAuthToken(usedToken)
		}
	})...)
	// fmt.Printf("%s->%s\n resp: %s\n", method, url, response.String())
	if err != nil {
		return nil, err
	}
	if !resp.State {
		if !retry && shouldRefreshToken(resp.Code) {
			// Gate check outside the lock: while the dead latch or throttle
			// cooldown is active, fail fast with the original API error instead
			// of hitting the passport endpoint again. This is what stops a
			// retrying caller (video player at 1 req/s) from feeding 115's
			// refresh limiter forever.
			if !c.refreshAllowed() {
				return response, &Error{Code: resp.Code, Message: resp.Message}
			}
			c.refreshMu.Lock()
			if c.accessToken != usedToken {
				c.refreshMu.Unlock()
			} else {
				// Detach from the caller's context: once a refresh request is
				// sent, it must run to completion or the rotated refresh_token
				// is lost (see refreshTimeout).
				refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshTimeout)
				_, err := c.RefreshToken(refreshCtx)
				cancel()
				c.refreshMu.Unlock()
				if err != nil {
					// The refresh_token is dead — signal callers to recover it
					// (re-auth / pull from a healthy peer) instead of looping.
					c.notifyIfRefreshDead(err)
					return response, err
				}
			}
			return c.authRequest(ctx, url, method, respData, extractData, true, opts...)
		}
		if resp.Code == CodeRefreshTokenError {
			// The API rejected us directly with a dead refresh_token — latch the
			// gate so no later request wastes a passport call on it.
			c.gateMu.Lock()
			c.refreshDead = true
			c.gateMu.Unlock()
			c.fireTokenInvalid()
		}
		return response, &Error{Code: resp.Code, Message: resp.Message}
	}
	// The request authenticated successfully: the token in use is proven good.
	c.fireTokenValid()
	if respData != nil {
		if extractData {
			if isEmptyData(resp.Data) {
				return response, ErrDataEmpty
			}
			err = json.Unmarshal(resp.Data, respData)
			if err != nil {
				if bytes.Equal(bytes.TrimSpace(resp.Data), []byte("[]")) {
					return response, ErrDataEmpty
				}
				return response, err
			}
		} else {
			err = json.Unmarshal(response.Bytes(), respData)
			if err != nil {
				return response, err
			}
		}
	}
	return response, nil
}

func (c *Client) AuthRequest(ctx context.Context, url, method string, respData any, opts ...RestyOption) (*resty.Response, error) {
	return c.authRequest(ctx, url, method, respData, true, false, opts...)
}

func (c *Client) AuthRequestRaw(ctx context.Context, url, method string, respData any, opts ...RestyOption) (*resty.Response, error) {
	return c.authRequest(ctx, url, method, respData, false, false, append(opts, func(request *resty.Request) {
		request.SetResponseBodyUnlimitedReads(true)
	})...)
}
