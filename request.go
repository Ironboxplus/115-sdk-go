package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"resty.dev/v3"
)

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

// markTokenInvalid latches the complete credential pair after a 115 401xxxxx
// response and invokes recovery exactly once. Repeating requests must not emit
// more callbacks or call the passport refresh endpoint; SetRefreshToken opens a
// new pair once a peer or the operator supplies it.
func (c *Client) markTokenInvalid() {
	c.gateMu.Lock()
	if c.refreshDead {
		c.gateMu.Unlock()
		return
	}
	c.refreshDead = true
	c.gateMu.Unlock()
	c.fireTokenInvalid()
}

func (c *Client) markTokenInvalidForError(err error) {
	var e *Error
	if errors.As(err, &e) && Is401Started(e.Code) {
		c.markTokenInvalid()
	}
}

func (c *Client) authRequest(ctx context.Context, url, method string, respData any, extractData bool, opts ...RestyOption) (*resty.Response, error) {
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
		if Is401Started(resp.Code) {
			c.markTokenInvalid()
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
	return c.authRequest(ctx, url, method, respData, true, opts...)
}

func (c *Client) AuthRequestRaw(ctx context.Context, url, method string, respData any, opts ...RestyOption) (*resty.Response, error) {
	return c.authRequest(ctx, url, method, respData, false, append(opts, func(request *resty.Request) {
		request.SetResponseBodyUnlimitedReads(true)
	})...)
}
