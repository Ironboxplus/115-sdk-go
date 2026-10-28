// Package emu115 is a small, real HTTP server emulating the parts of 115 Open
// that matter for token handling: passport refresh (single-use refresh_token,
// 40140117 throttle, 40140120 dead) and an authenticated API that rejects
// expired or superseded access tokens with 40140125.
//
// It exists so the SDK and the OpenList cluster can be tested against real
// network behaviour without touching a real 115 account. It is test tooling,
// never linked into production binaries.
package emu115

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Codes mirrored from the real service.
const (
	CodeAccessTokenInvalid = 40140125
	CodeRefreshFrequently  = 40140117
	CodeRefreshTokenError  = 40140120
)

// Config tunes the emulated service.
type Config struct {
	// AccessTTL is the lifetime of an issued access token (default 2h).
	AccessTTL time.Duration
	// RefreshThrottle: a refresh attempt arriving within this window after the
	// previous *successful* refresh is answered with 40140117 (0 = off).
	RefreshThrottle time.Duration
	// AccessToken / RefreshToken seed the first valid pair. Empty = random.
	AccessToken  string
	RefreshToken string
}

// Stats is a snapshot of call counters.
type Stats struct {
	RefreshCalls     int            `json:"refresh_calls"`
	RefreshOK        int            `json:"refresh_ok"`
	RefreshFail      map[int]int    `json:"refresh_fail"`
	APICalls         int            `json:"api_calls"`
	APIRejected      int            `json:"api_rejected"`
	CurrentRefresh   string         `json:"current_refresh_hash"`
	CurrentAccess    string         `json:"current_access_hash"`
	AccessExpiresIn  float64        `json:"access_expires_in"`
	RefreshCallTimes []time.Time    `json:"refresh_call_times"`
	Generation       int            `json:"generation"`
	TTLSeconds       int64          `json:"ttl_seconds"`
	Extra            map[string]any `json:"extra,omitempty"`
}

// Server is the emulator state; use Handler to serve it.
type Server struct {
	mu          sync.Mutex
	cfg         Config
	access      string
	refresh     string
	accessUntil time.Time
	lastRefresh time.Time
	gen         int
	st          Stats
}

// New builds an emulator with a valid initial pair.
func New(cfg Config) *Server {
	if cfg.AccessTTL <= 0 {
		cfg.AccessTTL = 2 * time.Hour
	}
	s := &Server{cfg: cfg}
	s.access, s.refresh = cfg.AccessToken, cfg.RefreshToken
	if s.access == "" {
		s.access = randHex()
	}
	if s.refresh == "" {
		s.refresh = randHex()
	}
	s.accessUntil = time.Now().Add(cfg.AccessTTL)
	s.st.RefreshFail = map[int]int{}
	return s
}

func randHex() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Tokens returns the current valid pair (test helper).
func (s *Server) Tokens() (access, refresh string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.access, s.refresh
}

// ExpireAccess makes the current access token expired now. The refresh_token
// stays valid, like a real access token running out.
func (s *Server) ExpireAccess() {
	s.mu.Lock()
	s.accessUntil = time.Now().Add(-time.Second)
	s.mu.Unlock()
}

// SetAccessTTL changes the lifetime of access tokens issued from now on.
func (s *Server) SetAccessTTL(d time.Duration) {
	s.mu.Lock()
	s.cfg.AccessTTL = d
	s.mu.Unlock()
}

// SetRefreshThrottle changes the 40140117 window.
func (s *Server) SetRefreshThrottle(d time.Duration) {
	s.mu.Lock()
	s.cfg.RefreshThrottle = d
	s.mu.Unlock()
}

// Kill invalidates the refresh_token chain (revoked server-side): every later
// refresh answers 40140120 and the API rejects the access token.
func (s *Server) Kill() {
	s.mu.Lock()
	s.refresh = "revoked-" + randHex()
	s.access = "revoked-" + randHex()
	s.mu.Unlock()
}

// Stats returns a counter snapshot.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.st
	st.RefreshFail = map[int]int{}
	for k, v := range s.st.RefreshFail {
		st.RefreshFail[k] = v
	}
	st.RefreshCallTimes = append([]time.Time(nil), s.st.RefreshCallTimes...)
	st.CurrentRefresh = short(s.refresh)
	st.CurrentAccess = short(s.access)
	st.AccessExpiresIn = time.Until(s.accessUntil).Seconds()
	st.Generation = s.gen
	st.TTLSeconds = int64(s.cfg.AccessTTL / time.Second)
	return st
}

func short(t string) string {
	if len(t) > 8 {
		return t[:8]
	}
	return t
}

// ResetStats zeroes counters (used between black-box scenarios).
func (s *Server) ResetStats() {
	s.mu.Lock()
	s.st = Stats{RefreshFail: map[int]int{}}
	s.mu.Unlock()
}

// Handler serves passport, API and /_emu control endpoints.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/open/refreshToken", s.handleRefresh)
	mux.HandleFunc("/_emu/stats", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.Stats()) })
	mux.HandleFunc("/_emu/reset", func(w http.ResponseWriter, r *http.Request) { s.ResetStats(); writeJSON(w, "ok") })
	mux.HandleFunc("/_emu/expire", func(w http.ResponseWriter, r *http.Request) { s.ExpireAccess(); writeJSON(w, "ok") })
	mux.HandleFunc("/_emu/kill", func(w http.ResponseWriter, r *http.Request) { s.Kill(); writeJSON(w, "ok") })
	mux.HandleFunc("/_emu/ttl", func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.Atoi(r.URL.Query().Get("sec"))
		if err != nil || n <= 0 {
			http.Error(w, "bad sec", http.StatusBadRequest)
			return
		}
		s.SetAccessTTL(time.Duration(n) * time.Second)
		writeJSON(w, "ok")
	})
	mux.HandleFunc("/_emu/throttle", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("sec"))
		s.SetRefreshThrottle(time.Duration(n) * time.Second)
		writeJSON(w, "ok")
	})
	mux.HandleFunc("/open/", s.handleAPI)
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	presented := r.PostForm.Get("refresh_token")
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.RefreshCalls++
	s.st.RefreshCallTimes = append(s.st.RefreshCallTimes, time.Now())
	fail := func(code int, msg string) {
		s.st.RefreshFail[code]++
		writeJSON(w, map[string]any{"state": 0, "code": code, "message": msg})
	}
	if s.cfg.RefreshThrottle > 0 && !s.lastRefresh.IsZero() && time.Since(s.lastRefresh) < s.cfg.RefreshThrottle {
		fail(CodeRefreshFrequently, "refresh frequently")
		return
	}
	// Single use: only the latest refresh_token works; anything else (already
	// spent, never issued) is dead.
	if presented == "" || presented != s.refresh {
		fail(CodeRefreshTokenError, "refresh token error")
		return
	}
	s.access, s.refresh = randHex(), randHex()
	s.accessUntil = time.Now().Add(s.cfg.AccessTTL)
	s.lastRefresh = time.Now()
	s.gen++
	s.st.RefreshOK++
	writeJSON(w, map[string]any{"state": 1, "code": 0, "message": "", "data": map[string]any{
		"access_token":  s.access,
		"refresh_token": s.refresh,
		"expires_in":    int64(s.cfg.AccessTTL / time.Second),
	}})
}

func (s *Server) handleAPI(w http.ResponseWriter, r *http.Request) {
	tok := ""
	if h := r.Header.Get("Authorization"); len(h) > 7 {
		tok = h[7:]
	}
	s.mu.Lock()
	s.st.APICalls++
	ok := tok != "" && tok == s.access && time.Now().Before(s.accessUntil)
	if !ok {
		s.st.APIRejected++
	}
	s.mu.Unlock()
	if !ok {
		writeJSON(w, map[string]any{"state": false, "code": CodeAccessTokenInvalid, "message": "access_token invalid"})
		return
	}
	switch r.URL.Path {
	case "/open/user/info":
		writeJSON(w, map[string]any{"state": true, "code": 0, "message": "", "data": map[string]any{
			"user_id": 1, "user_name": "emu",
			"rt_space_info": map[string]any{
				"all_total":  map[string]any{"size": 1 << 40, "size_format": "1TB"},
				"all_remain": map[string]any{"size": 1 << 39, "size_format": "512GB"},
				"all_use":    map[string]any{"size": 1 << 39, "size_format": "512GB"},
			},
		}})
	case "/open/ufile/files":
		writeJSON(w, map[string]any{"state": true, "code": 0, "message": "", "count": 0, "data": []any{},
			"path": []any{map[string]any{"file_id": "0", "file_name": "root"}}, "offset": 0, "limit": 1150})
	case "/open/folder/get_info":
		writeJSON(w, map[string]any{"state": true, "code": 0, "message": "", "data": map[string]any{
			"file_id": "0", "file_name": "root", "file_category": "0", "pick_code": "emu", "count": "0", "size": "0",
			"paths": []any{},
		}})
	default:
		writeJSON(w, map[string]any{"state": true, "code": 0, "message": "", "data": map[string]any{}})
	}
}
