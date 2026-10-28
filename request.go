package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"resty.dev/v3"
)

// refreshTimeout bounds a token refresh once it starts. The refresh must not
// inherit the caller's cancellation: 115 rotates the refresh_token server-side
// on every refresh call, so a request canceled mid-flight (e.g. a video player
// seeking) consumes the one-time token while the response carrying its
// replacement is lost — permanently bricking authentication.
const refreshTimeout = 30 * time.Second

// refreshCooldown is how long to refuse another refresh after a transient
// transport/server failure or a 40140117 refresh-throttle response. Terminal
// refresh-endpoint 401s permanently latch the pair dead until a peer or
// operator replaces it.
const refreshCooldown = 5 * time.Minute

// shouldRefreshToken reports whether an API error code indicates a stale
// access_token that a refresh could fix. Refresh-endpoint errors are excluded:
//   - 40140117 (refresh frequently): the refresh endpoint is temporarily
//     throttled and the same pair may be retried after cooldown;
//   - 40140120 (refresh token error): the refresh_token itself is dead.
func shouldRefreshToken(code int64) bool {
	if code == CodeRefreshFrequently || code == CodeRefreshTokenError {
		return false
	}
	return code == 99 || Is401Started(code)
}

// isTerminalAuthError distinguishes a rejected credential chain from 115's
// temporary refresh throttle. A throttled refresh must not evict a pair that
// may still rotate successfully after the provider's cooldown window.
func isTerminalAuthError(code int64) bool {
	return code != CodeRefreshFrequently && Is401Started(code)
}

func isEmptyData(data json.RawMessage) bool {
	d := bytes.TrimSpace(data)
	return len(d) == 0 || bytes.Equal(d, []byte("null"))
}

// rewriteURL applies the base-URL overrides (WithAPIBaseURL, WithPassportBaseURL).
func (c *Client) rewriteURL(u string) string {
	if c.apiBase != "" && strings.HasPrefix(u, ApiBaseURL) {
		return c.apiBase + u[len(ApiBaseURL):]
	}
	if c.passportBase != "" {
		for _, host := range []string{ApiAuthURL, apiQrCodeHost} {
			if strings.HasPrefix(u, host) {
				return c.passportBase + u[len(host):]
			}
		}
	}
	return u
}

func (c *Client) Request(ctx context.Context, url string, method string, opts ...RestyOption) (*resty.Response, error) {
	url = c.rewriteURL(url)
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
func (c *Client) fireTokenValid(accessToken string) {
	if c.onTokenValid != nil {
		c.onTokenValid()
	}
	if c.onAccessTokenValid != nil {
		c.onAccessTokenValid(accessToken)
	}
}

func (c *Client) fireTokenInvalid() {
	if c.onTokenInvalid != nil {
		c.onTokenInvalid()
	}
}

func (c *Client) fireAccessTokenInvalid(accessToken string) {
	if c.onAccessTokenInvalid != nil {
		c.onAccessTokenInvalid(accessToken)
	}
}

// markTokenDead latches one rejected pair and emits one recovery signal.
func (c *Client) markTokenDead() bool {
	c.gateMu.Lock()
	if c.refreshDead {
		c.gateMu.Unlock()
		return false
	}
	c.refreshDead = true
	c.refreshBlockedUntil = time.Time{}
	c.gateMu.Unlock()
	c.fireTokenInvalid()
	return true
}

// refreshAllowed reports whether a refresh attempt may be made right now.
// It is false while the dead latch is set or during transient-error cooldown.
func (c *Client) refreshAllowed() bool {
	c.gateMu.Lock()
	defer c.gateMu.Unlock()
	if c.refreshDead {
		return false
	}
	return time.Now().After(c.refreshBlockedUntil)
}

// noteRefreshOutcome keeps 40140117 retryable and treats the remaining
// refresh-endpoint 401s as proof that the complete pair is dead. Transport,
// server, and throttle failures only arm a cooldown.
func (c *Client) noteRefreshOutcome(err error) {
	if err == nil {
		c.gateMu.Lock()
		c.refreshDead = false
		c.refreshBlockedUntil = time.Time{}
		c.gateMu.Unlock()
		return
	}
	var e *Error
	if errors.As(err, &e) {
		if e.Code == CodeRefreshFrequently {
			c.gateMu.Lock()
			c.refreshBlockedUntil = time.Now().Add(refreshCooldown)
			c.gateMu.Unlock()
			return
		}
		if Is401Started(e.Code) {
			c.markTokenDead()
			return
		}
	}
	c.gateMu.Lock()
	c.refreshBlockedUntil = time.Now().Add(refreshCooldown)
	c.gateMu.Unlock()
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
			trigger := codeTrigger(resp.Code)
			if c.refreshPolicy != nil && !c.refreshPolicy() {
				// Not the refresher: never call passport. The rejected
				// credential still reaches recovery (peer pull).
				dead, cd := c.gateState()
				c.fireRefreshResult(RefreshEvent{Trigger: trigger, GateDead: dead, CooldownRemaining: cd, Outcome: RefreshSkippedPolicy})
				if isTerminalAuthError(resp.Code) {
					c.fireAccessTokenInvalid(usedToken)
				}
				return response, &Error{Code: resp.Code, Message: resp.Message}
			}
			if !c.refreshAllowed() {
				// The gate blocks another refresh *attempt*, not the
				// notification: this request's credential was still
				// rejected, and that must reach cluster recovery even
				// though no refresh runs. Without this, a caller gated
				// shut before its first delivery lands is stuck forever.
				dead, cd := c.gateState()
				outcome := RefreshSkippedCooldown
				if dead {
					outcome = RefreshSkippedDead
				}
				c.fireRefreshResult(RefreshEvent{Trigger: trigger, GateDead: dead, CooldownRemaining: cd, Outcome: outcome})
				if isTerminalAuthError(resp.Code) {
					c.fireAccessTokenInvalid(usedToken)
				}
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
				_, err := c.refreshWithTrigger(refreshCtx, trigger)
				cancel()
				c.refreshMu.Unlock()
				if err != nil {
					// RefreshToken already applied either the terminal dead latch
					// or the retryable 40140117 cooldown.
					var apiErr *Error
					if errors.As(err, &apiErr) && isTerminalAuthError(apiErr.Code) {
						c.fireAccessTokenInvalid(usedToken)
					}
					return response, err
				}
			}
			return c.authRequest(ctx, url, method, respData, extractData, true, opts...)
		}
		if isTerminalAuthError(resp.Code) {
			// A direct terminal auth error, or a second terminal 401 after
			// refresh, proves the complete pair unusable. A 40140117 throttle
			// remains retryable after cooldown.
			//
			// fireAccessTokenInvalid is level-triggered: every rejected
			// request reports, not just the one that flips the latch (that
			// is markTokenDead's return value, which we ignore here). The
			// consumer applies its own generation check and may drop a
			// stale delivery; if that were the only one ever sent, this
			// client would go silent for the rest of its process lifetime.
			// markTokenDead's internal fireTokenInvalid stays edge-triggered
			// on purpose -- that is a distinct one-shot "start cluster
			// recovery" signal, not a per-request status report.
			c.markTokenDead()
			c.fireAccessTokenInvalid(usedToken)
		}
		return response, &Error{Code: resp.Code, Message: resp.Message}
	}
	// The request authenticated successfully: the token in use is proven good.
	c.fireTokenValid(usedToken)
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
