package core

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// N1: stripControl must remove ANSI escape sequences and other control bytes
// that a malicious server could smuggle through a banner / header / cert field.
func TestStripControl(t *testing.T) {
	evil := "nginx\x1b[2J\x1b[1;1H\x1b[31mPWNED\x1b[0m\nsecond-line\x07"
	got := stripControl(evil)
	if strings.ContainsRune(got, 0x1b) {
		t.Errorf("ESC (0x1b) survived sanitisation: %q", got)
	}
	if strings.ContainsRune(got, '\n') || strings.ContainsRune(got, '\r') {
		t.Errorf("newline survived (log-line forgery possible): %q", got)
	}
	if strings.ContainsRune(got, 0x07) {
		t.Errorf("BEL survived: %q", got)
	}
	if !strings.Contains(got, "nginx") || !strings.Contains(got, "PWNED") || !strings.Contains(got, "second-line") {
		t.Errorf("printable content should be preserved, got %q", got)
	}
	// Clean strings must pass through unchanged (fast path).
	if s := "Apache/2.4.53 (Ubuntu)"; stripControl(s) != s {
		t.Errorf("clean string altered: %q", stripControl(s))
	}
}

// N3: a huge -rate must not panic time.NewTicker(0).
func TestNewRateLimiter_HugeRPS(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("NewRateLimiter panicked on huge rps: %v", r)
		}
	}()
	for _, rps := range []int{1_000_000_001, 2_000_000_000, 1 << 30} {
		rl := NewRateLimiter(rps)
		if rl == nil {
			t.Fatalf("rps=%d should yield a limiter", rps)
		}
		rl.Wait() // must return promptly, not deadlock
		rl.Stop()
	}
}

// -resolver: an empty server yields the system resolver; a custom server is
// actually used by the dialer (a dead address must make lookups fail).
func TestNewResolver(t *testing.T) {
	if NewResolver("", time.Second) != net.DefaultResolver {
		t.Error("empty resolver should return the system default")
	}
	r := NewResolver("127.0.0.1:1", 500*time.Millisecond) // nothing listening on port 1
	if r == net.DefaultResolver {
		t.Fatal("custom resolver must not be the system default")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := r.LookupHost(ctx, "example.com"); err == nil {
		t.Error("lookup via a dead resolver address should fail, proving the custom dialer is used")
	}
}

// Configurable-limit defaults must be populated (so modules never see zero).
func TestDefaultConfig_Limits(t *testing.T) {
	c := DefaultConfig()
	if c.WaybackLimit != 5000 || c.CrawlMaxPages != 100 || c.MaxJSFiles != 50 {
		t.Errorf("unexpected limit defaults: %+v", c)
	}
	if c.Resolver == nil {
		t.Error("Resolver must default to non-nil (system resolver)")
	}
}

func TestNewHTTPClient_RequestHeadersOnRedirects(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("X-Bug-Bounty"))
		mu.Unlock()
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.RequestHeaders = map[string]string{"X-Bug-Bounty": "w1r3hound"}
	resp, err := NewHTTPClient(cfg).Get(srv.URL + "/start")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("expected initial and redirected requests, got %d", len(seen))
	}
	for i, value := range seen {
		if value != "w1r3hound" {
			t.Errorf("request %d X-Bug-Bounty = %q, want w1r3hound", i, value)
		}
	}
}

func TestNewHTTPClient_StopsTargetRedirectAtDifferentHost(t *testing.T) {
	var sinkHits int
	sink := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		sinkHits++
	}))
	defer sink.Close()
	crossHostURL := strings.Replace(sink.URL, "127.0.0.1", "localhost", 1)

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, crossHostURL, http.StatusFound)
	}))
	defer source.Close()

	cfg := DefaultConfig()
	cfg.Domain = "127.0.0.1"
	resp, err := NewHTTPClient(cfg).Get(source.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want original 302 redirect", resp.StatusCode)
	}
	if sinkHits != 0 {
		t.Fatalf("cross-host redirect was followed %d time(s)", sinkHits)
	}
}
