package sdk

import (
	"bytes"
	"context"
	"encoding/json"
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
		return response, fmt.Errorf("code: %d, message: %s", resp.Code, resp.Message)
	}
	if resp.Error != "" {
		return response, fmt.Errorf("error: %s, errno: %d", resp.Error, resp.Errno)
	}
	return response, nil
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
					return response, err
				}
			}
			return c.authRequest(ctx, url, method, respData, extractData, true, opts...)
		}
		return response, &Error{Code: resp.Code, Message: resp.Message}
	}
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
