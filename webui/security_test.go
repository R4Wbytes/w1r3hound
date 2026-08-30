package main

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestHandleEventsHeartbeatAndStream covers the SSE idle heartbeat and live
// line streaming (TEST_PLAN.md §2.2). The 15s interval is shrunk via the test
// hook so the ": ping" path is exercised quickly.
func TestHandleEventsHeartbeatAndStream(t *testing.T) {
	old := sseHeartbeatInterval
	sseHeartbeatInterval = 20 * time.Millisecond
	defer func() { sseHeartbeatInterval = old }()

	s := newTestServer(t, "")
	job := &Job{ID: "live", Target: "127.0.0.1", Status: StatusRunning,
		subs: make(map[chan string]struct{}), logBuf: []string{"boot line"}}
	s.mgr.mu.Lock()
	s.mgr.jobs["live"] = job
	s.mgr.mu.Unlock()

	rec := httptest.NewRecorder()
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "/api/scans/live/events", nil).WithContext(ctx)
	req.SetPathValue("id", "live")

	done := make(chan struct{})
	go func() {
		s.handleEvents(rec, req)
		close(done)
	}()

	time.Sleep(90 * time.Millisecond) // let a few heartbeats fire
	job.appendLog("streamed-line")    // a live line must be pushed to the subscriber
	time.Sleep(60 * time.Millisecond)
	cancel()
	<-done

	body := rec.Body.String()
	if !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/event-stream") {
		t.Errorf("Content-Type = %q, want text/event-stream", rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(body, ": ping") {
		t.Errorf("expected an idle heartbeat (: ping); body=%q", body)
	}
	if !strings.Contains(body, "boot line") {
		t.Errorf("expected the buffered replay line; body=%q", body)
	}
	if !strings.Contains(body, "streamed-line") {
		t.Errorf("expected the live-streamed line; body=%q", body)
	}
}

// TestOriginGuardMutatingRequests extends the transport-guard battery to
// mutating (POST) requests (SECURITY_ASSESSMENT §5): a forged cross-origin /
// cross-site POST is rejected, a legitimate same-origin POST is not.
func TestOriginGuardMutatingRequests(t *testing.T) {
	s := newTestServer(t, "")
	body := func() string { return `{"target":"127.0.0.1","authorized":true,"passive":true}` }

	t.Run("foreign Origin POST -> 403", func(t *testing.T) {
		req := loopbackReq("POST", "/api/scan", strings.NewReader(body()))
		req.Header.Set("Origin", "http://evil.example.com")
		req.Header.Set("Content-Type", "text/plain")
		if rec := serve(t, s, req); rec.Code != 403 {
			t.Fatalf("code = %d, want 403", rec.Code)
		}
	})
	t.Run("cross-site POST -> 403", func(t *testing.T) {
		req := loopbackReq("POST", "/api/scan", strings.NewReader(body()))
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		if rec := serve(t, s, req); rec.Code != 403 {
			t.Fatalf("code = %d, want 403", rec.Code)
		}
	})
	t.Run("same-origin POST is accepted", func(t *testing.T) {
		req := loopbackReq("POST", "/api/scan", strings.NewReader(body()))
		req.Header.Set("Origin", "http://127.0.0.1:8737")
		if rec := serve(t, s, req); rec.Code == 403 {
			t.Fatalf("same-origin POST wrongly rejected (403)")
		}
	})
}

// TestRequireTokenSameLengthWrongTokenRejected demonstrates the token compare
// checks the full value (constant-time subtle.ConstantTimeCompare): a wrong
// token of the SAME length is still rejected.
func TestRequireTokenSameLengthWrongTokenRejected(t *testing.T) {
	s := newTestServer(t, "s3cr3t") // 6 chars
	req := loopbackReq("POST", "/api/scan", strings.NewReader(`{"target":"127.0.0.1","authorized":true}`))
	req.Header.Set("X-Auth-Token", "XXXXXX") // same length, wrong value
	if rec := serve(t, s, req); rec.Code != 401 {
		t.Fatalf("same-length wrong token: code = %d, want 401", rec.Code)
	}
}
