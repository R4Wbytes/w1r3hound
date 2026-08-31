package core

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestCancelBridge_AbortsInFlightRequest verifies that cfg.Cancel() tears down a
// request already in flight through the shared client — not just a pending dial.
// DoRequest builds requests with a Background context, so before the fix only
// the raw net.Dial paths (which derive cfg.Context) were interruptible; an
// in-flight request/body read would block until the full Client.Timeout. The
// server holds the response open here and the timeout is long, so only
// cfg.Cancel() can end the Get — and it must do so promptly.
func TestCancelBridge_AbortsInFlightRequest(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	defer close(release)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		// Hold the response open until the client disconnects (context done) or
		// the test tears down.
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.Target = srv.URL
	cfg.Timeout = 30 * time.Second // long on purpose: only Cancel() should end it
	client := NewHTTPClient(cfg)

	errCh := make(chan error, 1)
	go func() {
		resp, err := client.Get(srv.URL)
		if resp != nil {
			_ = resp.Body.Close()
		}
		errCh <- err
	}()

	<-started // the request has reached the server: it is in flight
	cfg.Cancel()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected the in-flight request to be aborted, got nil error")
		}
		if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "canceled") {
			t.Fatalf("expected a cancellation error well before the 30s timeout, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cfg.Cancel() did not abort the in-flight request within 5s")
	}
}

// TestCancelBridge_NormalRequestUnaffected guards against the bridge breaking the
// happy path: a request that completes before any cancellation must return its
// body intact, and closing the body must release the bridge cleanly (no hang).
func TestCancelBridge_NormalRequestUnaffected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok-body"))
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.Target = srv.URL
	body, status, err := FetchBody(NewHTTPClient(cfg), srv.URL, cfg.UserAgent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != 200 || body != "ok-body" {
		t.Fatalf("bridge altered a normal response: status=%d body=%q", status, body)
	}
}
