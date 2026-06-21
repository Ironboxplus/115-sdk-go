package sdk

import (
	"encoding/json"
	"testing"
)

// 115's /open/video/play returns file_size/duration/width/height as quoted
// strings. The struct must unmarshal that without error (regression: "cannot
// unmarshal string into Go struct field VideoPlayResp.file_size of type int64").
func TestVideoPlayRespUnmarshalStringNumbers(t *testing.T) {
	raw := `{
		"file_id": "123",
		"file_name": "movie.mkv",
		"file_size": "36767958354",
		"duration": "1421",
		"width": "1920",
		"height": "1080",
		"video_url": [{"url": "https://cdn/x.m3u8", "definition": 4, "desc": "1080P"}]
	}`
	var resp VideoPlayResp
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal string-number response failed: %v", err)
	}
	if resp.FileSize != 36767958354 {
		t.Fatalf("FileSize = %d, want 36767958354", resp.FileSize)
	}
	if resp.Duration != 1421 || resp.Width != 1920 || resp.Height != 1080 {
		t.Fatalf("got duration=%d width=%d height=%d", resp.Duration, resp.Width, resp.Height)
	}
	if len(resp.VideoURL) != 1 || resp.VideoURL[0].Definition != 4 {
		t.Fatalf("video_url not parsed: %+v", resp.VideoURL)
	}
}

// The same struct must still accept bare JSON numbers (forward/backward compat).
func TestVideoPlayRespUnmarshalBareNumbers(t *testing.T) {
	raw := `{"file_id":"1","file_name":"a","file_size":100,"duration":10,"width":640,"height":480}`
	var resp VideoPlayResp
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal bare-number response failed: %v", err)
	}
	if resp.FileSize != 100 || resp.Duration != 10 {
		t.Fatalf("got file_size=%d duration=%d", resp.FileSize, resp.Duration)
	}
}

func TestFlexInt64EmptyAndNull(t *testing.T) {
	var v struct {
		A FlexInt64 `json:"a"`
		B FlexInt64 `json:"b"`
	}
	if err := json.Unmarshal([]byte(`{"a":"","b":null}`), &v); err != nil {
		t.Fatalf("unmarshal empty/null failed: %v", err)
	}
	if v.A != 0 || v.B != 0 {
		t.Fatalf("want 0/0, got %d/%d", v.A, v.B)
	}
}
