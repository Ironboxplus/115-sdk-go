package sdk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"
)

// Refresh outcomes reported in RefreshEvent.Outcome.
const (
	// RefreshOK: passport returned a new token pair.
	RefreshOK = "ok"
	// RefreshAPIError: passport answered with an error code (see ErrCode).
	RefreshAPIError = "api_error"
	// RefreshTransportError: the passport request failed before an API answer.
	RefreshTransportError = "transport_error"
	// RefreshSkippedDead: not attempted, the dead latch is set.
	RefreshSkippedDead = "skipped_dead"
	// RefreshSkippedCooldown: not attempted, a refresh cooldown is active.
	RefreshSkippedCooldown = "skipped_cooldown"
	// RefreshSkippedPolicy: not attempted, the refresh policy returned false.
	RefreshSkippedPolicy = "skipped_policy"
)

// RefreshTriggerProactive is the Trigger of a refresh that was not caused by a
// rejected request (see Client.RefreshProactive).
const RefreshTriggerProactive = "proactive"

// RefreshTriggerManual is the Trigger of a direct Client.RefreshToken call.
const RefreshTriggerManual = "manual"

// RefreshEvent describes one refresh attempt, or one automatic refresh that
// was skipped by a gate. It never contains token values; the *Hash fields are
// a short SHA-256 prefix, enough to correlate log lines across nodes.
type RefreshEvent struct {
	// Trigger is the API error code that caused the refresh (decimal string),
	// RefreshTriggerProactive or RefreshTriggerManual.
	Trigger string
	// Gate state observed before the attempt.
	GateDead          bool
	CooldownRemaining time.Duration
	// Outcome is one of the Refresh* constants.
	Outcome string
	// ErrCode is the API error code when Outcome == RefreshAPIError.
	ErrCode int64
	// Err is the error returned to the caller, if any.
	Err error
	// ExpiresIn is the lifetime in seconds of the new access token (ok only).
	ExpiresIn int64
	// Duration of the passport round trip (zero for skips).
	Duration time.Duration
	// Short hashes of the refresh_token that was spent and of the new one.
	OldRefreshHash string
	NewRefreshHash string
}

func tokenHash(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])[:8]
}

func codeTrigger(code int64) string { return strconv.FormatInt(code, 10) }

// gateState returns the dead latch and remaining cooldown.
func (c *Client) gateState() (dead bool, cooldown time.Duration) {
	c.gateMu.Lock()
	defer c.gateMu.Unlock()
	if d := time.Until(c.refreshBlockedUntil); d > 0 {
		cooldown = d
	}
	return c.refreshDead, cooldown
}

func (c *Client) fireRefreshResult(ev RefreshEvent) {
	if c.onRefreshResult != nil {
		c.onRefreshResult(ev)
	}
}

// RefreshProactive refreshes the token pair before the access token expires.
// It honours the dead latch and cooldown gates and serialises with automatic
// refreshes, but not the refresh policy: the caller is by definition the node
// that decided it should refresh. It returns ErrRefreshGated when blocked.
func (c *Client) RefreshProactive(ctx context.Context) (*RefreshTokenResp, error) {
	return c.RefreshWithTrigger(ctx, RefreshTriggerProactive)
}

// RefreshWithTrigger is RefreshProactive with a caller-chosen Trigger label in
// the RefreshEvent (e.g. a refresh performed on behalf of another node).
func (c *Client) RefreshWithTrigger(ctx context.Context, trigger string) (*RefreshTokenResp, error) {
	dead, cd := c.gateState()
	if dead || cd > 0 {
		outcome := RefreshSkippedCooldown
		if dead {
			outcome = RefreshSkippedDead
		}
		c.fireRefreshResult(RefreshEvent{Trigger: trigger, GateDead: dead, CooldownRemaining: cd, Outcome: outcome})
		return nil, ErrRefreshGated
	}
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshTimeout)
	defer cancel()
	return c.refreshWithTrigger(rctx, trigger)
}
