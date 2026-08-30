package core

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// TestRateLimiterZeroIsUnlimited covers `-rate 0` (and negative): no limiter is
// created and Wait() is a no-op, so calls are not paced.
func TestRateLimiterZeroIsUnlimited(t *testing.T) {
	if NewRateLimiter(0) != nil {
		t.Fatal("NewRateLimiter(0) should be nil (unlimited)")
	}
	if NewRateLimiter(-5) != nil {
		t.Fatal("NewRateLimiter(-5) should be nil (unlimited)")
	}
	start := time.Now()
	var rl *RateLimiter // nil
	for i := 0; i < 1000; i++ {
		rl.Wait()
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("nil limiter Wait() should be instant, took %s", elapsed)
	}
}

// TestRateLimiterPaces covers `-rate N`: a positive rate throttles calls.
func TestRateLimiterPaces(t *testing.T) {
	rl := NewRateLimiter(50) // ~20ms between tokens
	if rl == nil {
		t.Fatal("NewRateLimiter(50) should be non-nil")
	}
	defer rl.Stop()
	start := time.Now()
	for i := 0; i < 5; i++ {
		rl.Wait()
	}
	// 5 tokens at 50/s must take on the order of ~100ms; assert a safe lower bound.
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Fatalf("rate=50 should pace 5 waits to >=40ms, took %s", elapsed)
	}
}

// TestResolverDefaultVsCustom covers `-resolver`: empty uses the system
// resolver; a value returns a custom Go resolver.
func TestResolverDefaultVsCustom(t *testing.T) {
	if NewResolver("", time.Second) != net.DefaultResolver {
		t.Error("empty -resolver should return the system default resolver")
	}
	custom := NewResolver("1.2.3.4", time.Second)
	if custom == net.DefaultResolver || custom == nil {
		t.Error("custom -resolver should return a dedicated resolver")
	}
	if !custom.PreferGo {
		t.Error("custom resolver should PreferGo so the custom Dial is used")
	}
}

// TestResolverRoutesToConfiguredServer proves a custom `-resolver` actually
// sends queries to the configured server: a loopback UDP stub receives the DNS
// query for the looked-up name.
func TestResolverRoutesToConfiguredServer(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()

	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 512)
		_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
		if n, _, err := pc.ReadFrom(buf); err == nil {
			got <- append([]byte(nil), buf[:n]...)
		}
	}()

	res := NewResolver(pc.LocalAddr().String(), time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _ = res.LookupHost(ctx, "probe.example.") // response never sent; we only assert the query left

	select {
	case pkt := <-got:
		if !bytes.Contains(pkt, []byte("probe")) {
			t.Errorf("DNS query to the custom server did not contain the QNAME label 'probe': %q", pkt)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("custom resolver never queried the configured server")
	}
}

// captureStderr redirects os.Stderr for the duration of f and returns what was
// written. The Logger writes to os.Stderr directly, so this is how we observe
// verbose gating. Not safe for parallel use.
func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	f()
	_ = w.Close()
	os.Stderr = old
	return <-done
}

// TestLoggerVerboseGatesDebug covers `-v`: Debug lines are emitted only when
// verbose is on.
func TestLoggerVerboseGatesDebug(t *testing.T) {
	if out := captureStderr(t, func() { NewLogger(false).Debug("hidden %s", "line") }); strings.Contains(out, "hidden") {
		t.Errorf("verbose off must suppress Debug output, got %q", out)
	}
	if out := captureStderr(t, func() { NewLogger(true).Debug("shown %s", "line") }); !strings.Contains(out, "shown") {
		t.Errorf("verbose on must emit Debug output, got %q", out)
	}
}

// TestLoggerScrubsControlBytesInStringArgs verifies hostile ANSI/control bytes
// in log arguments are stripped, so a malicious banner/header/subdomain can't
// rewrite the analyst's terminal. Covers both string args and []string args
// (SECURITY_ASSESSMENT C-4, now fixed). The logger colorizes its own prefix
// (\x1b[32m ... \x1b[0m), so we assert the ARG's injected escape (red,
// \x1b[31m) and BEL are neutralized rather than requiring an ESC-free line.
func TestLoggerScrubsControlBytesInStringArgs(t *testing.T) {
	out := captureStderr(t, func() {
		NewLogger(false).Info("banner: %s", "evil\x1b[31mred\x1b[0m\x07")
	})
	if strings.Contains(out, "\x1b[31m") {
		t.Errorf("injected ANSI escape survived into the log line: %q", out)
	}
	if strings.ContainsRune(out, 0x07) {
		t.Errorf("BEL (0x07) survived into the log line: %q", out)
	}

	// C-4: a []string logged with %v must also be scrubbed element-wise.
	sliceOut := captureStderr(t, func() {
		NewLogger(false).Info("subdomains: %v", []string{"a\x1b[31mX", "b\x07c"})
	})
	if strings.Contains(sliceOut, "\x1b[31m") || strings.ContainsRune(sliceOut, 0x07) {
		t.Errorf("[]string arg not scrubbed (C-4): %q", sliceOut)
	}
}
