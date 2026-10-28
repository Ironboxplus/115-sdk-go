package sdk

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenListTeam/115-sdk-go/emu115"
)

// These tests run the real SDK HTTP code against the emu115 server (a real
// local HTTP server emulating 115 passport + API semantics).

type evLog struct {
	mu sync.Mutex
	ev []RefreshEvent
}

func (l *evLog) add(e RefreshEvent) { l.mu.Lock(); l.ev = append(l.ev, e); l.mu.Unlock() }
func (l *evLog) all() []RefreshEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]RefreshEvent(nil), l.ev...)
}

func newEmuClient(t *testing.T, cfg emu115.Config, opts ...Option) (*emu115.Server, *Client, *evLog) {
	t.Helper()
	emu := emu115.New(cfg)
	ts := httptest.NewServer(emu.Handler())
	t.Cleanup(ts.Close)
	a, r := emu.Tokens()
	log := &evLog{}
	base := []Option{
		WithAccessToken(a), WithRefreshToken(r),
		WithAPIBaseURL(ts.URL), WithPassportBaseURL(ts.URL),
		WithOnRefreshResult(log.add),
	}
	return emu, New(append(base, opts...)...), log
}

func TestEmulatorRefreshOnExpiryAndEvent(t *testing.T) {
	var gotExpires atomic.Int64
	emu, c, log := newEmuClient(t, emu115.Config{AccessTTL: 90 * time.Minute},
		WithOnRefreshTokenEx(func(_, _ string, exp int64) { gotExpires.Store(exp) }))
	ctx := context.Background()
	if _, err := c.UserInfo(ctx); err != nil {
		t.Fatalf("fresh token should work: %v", err)
	}
	emu.ExpireAccess()
	if _, err := c.UserInfo(ctx); err != nil {
		t.Fatalf("expired token should refresh transparently: %v", err)
	}
	if st := emu.Stats(); st.RefreshOK != 1 || st.RefreshCalls != 1 {
		t.Fatalf("want exactly one refresh, got %+v", st)
	}
	evs := log.all()
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	e := evs[0]
	if e.Outcome != RefreshOK || e.Trigger != "40140125" || e.ExpiresIn != 5400 || e.Duration <= 0 || e.NewRefreshHash == "" || e.OldRefreshHash == e.NewRefreshHash {
		t.Fatalf("bad event %+v", e)
	}
	if gotExpires.Load() != 5400 {
		t.Fatalf("OnRefreshTokenEx expires_in = %d", gotExpires.Load())
	}
}

func TestEmulatorSingleUseRefreshToken(t *testing.T) {
	emu, c, log := newEmuClient(t, emu115.Config{})
	// A second client holding the same (about to be spent) pair loses the race.
	a, r := emu.Tokens()
	ts := httptest.NewServer(emu.Handler())
	defer ts.Close()
	var deadFired atomic.Int32
	other := New(WithAccessToken(a), WithRefreshToken(r), WithAPIBaseURL(ts.URL), WithPassportBaseURL(ts.URL),
		WithOnTokenInvalid(func() { deadFired.Add(1) }))
	emu.ExpireAccess()
	if _, err := c.UserInfo(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err := other.UserInfo(context.Background())
	if err == nil {
		t.Fatal("stale pair must fail after the other client spent the refresh_token")
	}
	if deadFired.Load() == 0 {
		t.Fatal("dead latch should have fired for the loser")
	}
	if st := emu.Stats(); st.RefreshFail[emu115.CodeRefreshTokenError] != 1 {
		t.Fatalf("want one 40140120, got %+v", st.RefreshFail)
	}
	if evs := log.all(); len(evs) != 1 || evs[0].Outcome != RefreshOK {
		t.Fatalf("winner events: %+v", evs)
	}
}

func TestEmulatorDeadLatchStopsPassportCalls(t *testing.T) {
	emu, c, log := newEmuClient(t, emu115.Config{})
	emu.Kill()
	var invalid atomic.Int32
	c.SetOnAccessTokenInvalid(func(string) { invalid.Add(1) })
	for i := 0; i < 5; i++ {
		if _, err := c.UserInfo(context.Background()); err == nil {
			t.Fatal("killed chain must error")
		}
	}
	if st := emu.Stats(); st.RefreshCalls != 1 {
		t.Fatalf("dead latch must stop passport hits: %d calls", st.RefreshCalls)
	}
	if invalid.Load() != 5 {
		t.Fatalf("access-token-invalid is level triggered, got %d", invalid.Load())
	}
	evs := log.all()
	if len(evs) != 5 || evs[0].Outcome != RefreshAPIError || evs[0].ErrCode != CodeRefreshTokenError {
		t.Fatalf("events: %+v", evs)
	}
	for _, e := range evs[1:] {
		if e.Outcome != RefreshSkippedDead || !e.GateDead {
			t.Fatalf("later events should be skipped_dead: %+v", e)
		}
	}
	// A fresh pair injected from a peer clears the latch.
	a, r := emu.Tokens()
	c.SetAccessToken(a).SetRefreshToken(r)
	if _, err := c.UserInfo(context.Background()); err != nil {
		t.Fatalf("after peer injection: %v", err)
	}
}

func TestEmulatorThrottle40140117IsNotDead(t *testing.T) {
	emu, c, log := newEmuClient(t, emu115.Config{RefreshThrottle: time.Hour})
	ctx := context.Background()
	emu.ExpireAccess()
	if _, err := c.UserInfo(ctx); err != nil { // first refresh ok, starts throttle window
		t.Fatal(err)
	}
	emu.ExpireAccess()
	_, err := c.UserInfo(ctx)
	var ae *Error
	if err == nil || !asErr(err, &ae) || ae.Code != CodeRefreshFrequently {
		t.Fatalf("want 40140117, got %v", err)
	}
	dead, cd := c.gateState()
	if dead {
		t.Fatal("40140117 must NOT latch dead")
	}
	if cd <= 0 {
		t.Fatal("40140117 must arm the cooldown")
	}
	// Within cooldown no more passport hits.
	before := emu.Stats().RefreshCalls
	_, _ = c.UserInfo(ctx)
	if emu.Stats().RefreshCalls != before {
		t.Fatal("cooldown must suppress passport calls")
	}
	evs := log.all()
	last := evs[len(evs)-1]
	if last.Outcome != RefreshSkippedCooldown || last.CooldownRemaining <= 0 {
		t.Fatalf("last event %+v", last)
	}
}

func TestEmulatorRefreshPolicyBlocksAutoRefresh(t *testing.T) {
	var allow atomic.Bool
	var invalid atomic.Int32
	emu, c, log := newEmuClient(t, emu115.Config{},
		WithRefreshPolicy(func() bool { return allow.Load() }),
		WithOnAccessTokenInvalid(func(string) { invalid.Add(1) }))
	ctx := context.Background()
	emu.ExpireAccess()
	_, err := c.UserInfo(ctx)
	var ae *Error
	if err == nil || !asErr(err, &ae) || ae.Code != emu115.CodeAccessTokenInvalid {
		t.Fatalf("want the API error back, got %v", err)
	}
	if st := emu.Stats(); st.RefreshCalls != 0 {
		t.Fatalf("policy=false must never hit passport, got %d", st.RefreshCalls)
	}
	if invalid.Load() != 1 {
		t.Fatalf("invalid notification not fired: %d", invalid.Load())
	}
	if evs := log.all(); len(evs) != 1 || evs[0].Outcome != RefreshSkippedPolicy {
		t.Fatalf("events %+v", evs)
	}
	// Pair delivered by the refresher works with no refresh.
	allow.Store(true)
	if _, err := c.UserInfo(ctx); err != nil {
		t.Fatalf("policy=true should refresh: %v", err)
	}
	if emu.Stats().RefreshOK != 1 {
		t.Fatal("expected one refresh once allowed")
	}
}

func TestEmulatorRefreshProactive(t *testing.T) {
	emu, c, log := newEmuClient(t, emu115.Config{AccessTTL: time.Hour},
		WithRefreshPolicy(func() bool { return false })) // policy must not block proactive
	if _, err := c.RefreshProactive(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.UserInfo(context.Background()); err != nil {
		t.Fatalf("new token should work: %v", err)
	}
	evs := log.all()
	if len(evs) != 1 || evs[0].Trigger != RefreshTriggerProactive || evs[0].Outcome != RefreshOK || evs[0].ExpiresIn != 3600 {
		t.Fatalf("events %+v", evs)
	}
	emu.Kill()
	_, _ = c.RefreshProactive(context.Background()) // dead now
	if _, err := c.RefreshProactive(context.Background()); err != ErrRefreshGated {
		t.Fatalf("want ErrRefreshGated, got %v", err)
	}
}

func TestEmulatorEventsNeverContainTokens(t *testing.T) {
	emu, c, log := newEmuClient(t, emu115.Config{})
	a, r := emu.Tokens()
	emu.ExpireAccess()
	_, _ = c.UserInfo(context.Background())
	na, nr := emu.Tokens()
	for _, e := range log.all() {
		for _, s := range []string{e.OldRefreshHash, e.NewRefreshHash, e.Trigger, e.Outcome} {
			for _, tok := range []string{a, r, na, nr} {
				if s == tok {
					t.Fatalf("event leaks a token: %+v", e)
				}
			}
		}
		if len(e.OldRefreshHash) > 8 {
			t.Fatalf("hash too long")
		}
	}
}

func asErr(err error, target **Error) bool { return errors.As(err, target) }
