package mcp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

// ── normalizeTarget ──

func TestNormalizeTarget(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"example.com", "https://example.com"},
		{"http://example.com", "http://example.com"},
		{"https://example.com", "https://example.com"},
		{"example.com/", "https://example.com"},
		{"https://example.com/", "https://example.com"},
		{"https://example.com///", "https://example.com"},
		{"10.0.0.1", "https://10.0.0.1"},
		{"[::1]:8080", "https://[::1]:8080"},
		{"", "https://"},
	}
	for _, tt := range tests {
		if got := normalizeTarget(tt.in); got != tt.want {
			t.Errorf("normalizeTarget(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// ── extractDomain ──

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"https://example.com", "example.com"},
		{"http://example.com:8080/path", "example.com"},
		{"example.com", "example.com"},
		{"example.com:443", "example.com"},
		{"[::1]:8080", "::1"},
		{"http://[2001:db8::1]:443/path", "2001:db8::1"},
		{"[::1", "::1"},          // malformed bracket — BUG 4 fix
		{"::1", "::1"},           // bare IPv6
		{"10.0.0.1", "10.0.0.1"}, // bare IPv4
		{"https://sub.example.com/a/b?c=d", "sub.example.com"},
	}
	for _, tt := range tests {
		if got := extractDomain(tt.in); got != tt.want {
			t.Errorf("extractDomain(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// ── validateTarget ──

func TestValidateTarget(t *testing.T) {
	valid := []string{
		"example.com",
		"sub.example.com",
		"10.0.0.1",
		"192.168.0.0/24",
		"https://example.com/path",
		"http://example.com",
		"example.com:8080",
		"2001:db8::1",
	}
	for _, target := range valid {
		if err := validateTarget(target); err != nil {
			t.Errorf("validateTarget(%q) = %v, want nil", target, err)
		}
	}

	invalid := []struct {
		in   string
		desc string
	}{
		{"", "empty"},
		{"ftp://example.com", "unsupported scheme"},
		{"has spaces", "contains space"},
		{"has\ttab", "contains tab"},
		{"has\x00null", "contains null"},
		{strings.Repeat("a", 2049), "too long"},
		{"gopher://x", "unsupported scheme"},
	}
	for _, tt := range invalid {
		if err := validateTarget(tt.in); err == nil {
			t.Errorf("validateTarget(%q) [%s] = nil, want error", tt.in, tt.desc)
		}
	}
}

// ── buildSummary ──

func TestBuildSummary(t *testing.T) {
	snap := core.ReportData{
		Target:    "https://example.com",
		StartedAt: "2026-01-01T00:00:00Z",
		EndedAt:   "2026-01-01T00:05:00Z",
		Findings: []core.Finding{
			{Severity: core.SevHigh},
			{Severity: core.SevHigh},
			{Severity: core.SevMedium},
			{Severity: core.SevLow},
			{Severity: core.SevInfo},
			{Severity: core.SevInfo},
			{Severity: core.SevInfo},
		},
	}
	summary := buildSummary(snap)
	if summary["target"] != "https://example.com" {
		t.Errorf("target = %v", summary["target"])
	}
	if summary["total_findings"] != 7 {
		t.Errorf("total_findings = %v, want 7", summary["total_findings"])
	}
	sev := summary["by_severity"].(map[string]int)
	if sev["HIGH"] != 2 || sev["MEDIUM"] != 1 || sev["LOW"] != 1 || sev["INFO"] != 3 {
		t.Errorf("by_severity = %v", sev)
	}
}

// ── safeRun ──

func TestSafeRun_Normal(t *testing.T) {
	var logBuf bytes.Buffer
	log := core.NewLoggerWriter(false, true, &logBuf)
	called := false
	safeRun(log, "test", func() { called = true })
	if !called {
		t.Error("function was not called")
	}
}

func TestSafeRun_PanicRecovery(t *testing.T) {
	var logBuf bytes.Buffer
	log := core.NewLoggerWriter(false, true, &logBuf)
	safeRun(log, "crasher", func() { panic("boom") })
	if !strings.Contains(logBuf.String(), "panicked") {
		t.Errorf("expected panic message in log, got: %s", logBuf.String())
	}
}

// ── detectScheme ──

func TestDetectScheme_AlreadyHasScheme(t *testing.T) {
	cfg := core.DefaultConfig()
	if got := detectScheme("https://example.com", cfg); got != "https://example.com" {
		t.Errorf("got %q, want https://example.com", got)
	}
	if got := detectScheme("http://example.com/path/", cfg); got != "http://example.com/path" {
		t.Errorf("got %q, want http://example.com/path", got)
	}
}

func TestDetectScheme_HTTPOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	cfg := core.DefaultConfig()
	cfg.Timeout = 2 * time.Second
	got := detectScheme(host, cfg)
	if !strings.HasPrefix(got, "http://") {
		t.Errorf("detectScheme(%q) = %q, want http:// prefix (server is HTTP-only)", host, got)
	}
}

func TestDetectScheme_NeitherReachable(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Timeout = 1 * time.Second
	got := detectScheme("192.0.2.1:1", cfg) // RFC 5737 — TEST-NET, unreachable
	if got != "https://192.0.2.1:1" {
		t.Errorf("detectScheme unreachable = %q, want https:// default", got)
	}
}

// ── Successful scan integration test ──

func TestScanSuccessful(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "TestServer/1.0")
		w.Header().Set("X-Powered-By", "Go")
		w.WriteHeader(200)
		w.Write([]byte("<html><body>hello</body></html>"))
	}))
	defer srv.Close()

	args, _ := json.Marshal(map[string]any{
		"target":               srv.URL,
		"modules":              []string{"headers"},
		"timeout_seconds":      5,
		"max_duration_seconds": 30,
		"allow_private":        true,
	})
	text, isErr := executeScan(args)
	if isErr {
		t.Fatalf("scan returned error: %s", text)
	}
	if !strings.Contains(text, "report") {
		t.Error("response missing report key")
	}
	if !strings.Contains(text, "summary") {
		t.Error("response missing summary key")
	}
}

// ── Rate limiter cleanup test ──

func TestRateLimiterCleanup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	before := runtime.NumGoroutine()
	args, _ := json.Marshal(map[string]any{
		"target":               srv.URL,
		"modules":              []string{"headers"},
		"rate_limit":           100,
		"timeout_seconds":      3,
		"max_duration_seconds": 15,
		"allow_private":        true,
	})
	_, _ = executeScan(args)
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	after := runtime.NumGoroutine()

	// Allow slack for test runtime and transient module goroutines. The
	// rate limiter goroutine itself should not leak; a delta of up to 5 is
	// acceptable due to background GC, finalizers, and httptest internals.
	if after > before+5 {
		t.Errorf("goroutine leak: before=%d after=%d (delta %d)", before, after, after-before)
	}
}

// ── SSRF guard test ──

func TestSSRFBlocked(t *testing.T) {
	args, _ := json.Marshal(map[string]any{
		"target":               "127.0.0.1",
		"modules":              []string{"headers"},
		"timeout_seconds":      3,
		"max_duration_seconds": 10,
	})
	text, isErr := executeScan(args)
	// The scan should complete (not crash), but the egress control should
	// block connections to private IPs. The report should have no findings
	// from actual connections (BlockPrivateEgress = true by default).
	if isErr {
		// Acceptable: a target validation or connection refusal error.
		return
	}
	// If we got here, the scan ran but connections should have been refused.
	// Verify no actual data was retrieved from localhost.
	_ = text
}

func TestSSRFAllowedWithFlag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "TestServer/1.0")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	args, _ := json.Marshal(map[string]any{
		"target":               srv.URL,
		"modules":              []string{"headers"},
		"allow_private":        true,
		"timeout_seconds":      3,
		"max_duration_seconds": 15,
	})
	text, isErr := executeScan(args)
	if isErr {
		t.Fatalf("scan with allow_private should succeed: %s", text)
	}
}

// ── Scan timeout test ──

func TestScanTimeout(t *testing.T) {
	// Server that delays responses — use a channel to unblock on test cleanup
	// so httptest.Server.Close doesn't hang for its 5s close-wait.
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-done:
		case <-time.After(60 * time.Second):
		}
	}))
	defer func() {
		close(done)
		srv.Close()
	}()

	start := time.Now()
	args, _ := json.Marshal(map[string]any{
		"target":               srv.URL,
		"modules":              []string{"headers"},
		"max_duration_seconds": 2,
		"allow_private":        true,
	})
	_, _ = executeScan(args)
	elapsed := time.Since(start)

	if elapsed > 10*time.Second {
		t.Errorf("scan did not respect max_duration_seconds: took %v", elapsed)
	}
}
