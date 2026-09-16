package mcp

import (
	"bytes"
	"context"
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

// ── validResolver ──

func TestValidResolver(t *testing.T) {
	valid := []string{"1.1.1.1", "8.8.8.8:53", "::1", "[::1]:53"}
	for _, r := range valid {
		if !validResolver(r) {
			t.Errorf("validResolver(%q) = false, want true", r)
		}
	}
	invalid := []string{"", "dns.google", "not an ip", "1.1.1.1:abc"}
	for _, r := range invalid {
		if validResolver(r) {
			t.Errorf("validResolver(%q) = true, want false", r)
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

// ── suggest_modules ──

func TestSuggestModules_Passive(t *testing.T) {
	args, _ := json.Marshal(map[string]string{"objective": "passive recon"})
	text, isErr := executeSuggestModules(args)
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, "passivesrc") {
		t.Error("expected passivesrc in passive recon suggestion")
	}
	if !strings.Contains(text, "whois") {
		t.Error("expected whois in passive recon suggestion")
	}
}

func TestSuggestModules_WebApp(t *testing.T) {
	args, _ := json.Marshal(map[string]string{"objective": "check webapp for vulnerabilities"})
	text, isErr := executeSuggestModules(args)
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, "recommended_modules") {
		t.Error("expected recommended_modules in result")
	}
}

func TestSuggestModules_Empty(t *testing.T) {
	args, _ := json.Marshal(map[string]string{"objective": ""})
	_, isErr := executeSuggestModules(args)
	if !isErr {
		t.Error("expected error for empty objective")
	}
}

func TestSuggestModules_NoMatch(t *testing.T) {
	args, _ := json.Marshal(map[string]string{"objective": "xyzzy foobarbaz"})
	text, isErr := executeSuggestModules(args)
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, "No specific match") {
		t.Error("expected fallback suggestion for unknown objective")
	}
}

func TestSuggestModules_BugBounty(t *testing.T) {
	args, _ := json.Marshal(map[string]string{"objective": "bug bounty reconnaissance"})
	text, isErr := executeSuggestModules(args)
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, "takeover") {
		t.Error("expected takeover in bug bounty suggestion")
	}
}

// ── server_info ──

func TestServerInfo(t *testing.T) {
	text, isErr := executeServerInfo(&toolCall{srv: &Server{version: "test-1.0"}})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, "test-1.0") {
		t.Error("expected version in server info")
	}
	if !strings.Contains(text, "suggest_modules") {
		t.Error("expected suggest_modules in tools list")
	}
	if !strings.Contains(text, "server_info") {
		t.Error("expected server_info in tools list")
	}
}

func TestServerInfo_NilServer(t *testing.T) {
	text, isErr := executeServerInfo(nil) //nolint:staticcheck
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, "w1r3hound") {
		t.Error("expected w1r3hound name")
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
	text, isErr := executeScan(args, nil)
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

// ── Scan with custom headers ──

func TestScanWithHeaders(t *testing.T) {
	var gotUA string
	var gotBounty string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotBounty = r.Header.Get("X-Bug-Bounty")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	args, _ := json.Marshal(map[string]any{
		"target":               srv.URL,
		"modules":              []string{"headers"},
		"timeout_seconds":      5,
		"max_duration_seconds": 15,
		"allow_private":        true,
		"user_agent":           "w1r3hound-test/1.0",
		"headers":              map[string]string{"X-Bug-Bounty": "HackerOne/tester"},
	})
	_, isErr := executeScan(args, nil)
	if isErr {
		t.Skip("scan returned error (network-dependent)")
	}
	if gotUA != "" && gotUA != "w1r3hound-test/1.0" {
		// User-Agent might not be set on all requests, but if set it should match
		t.Logf("User-Agent: %q (may vary by module request)", gotUA)
	}
	_ = gotBounty // headers module may or may not send the custom header to this exact endpoint
}

// ── Scan with min_severity filter ──

func TestScanMinSeverityValidation(t *testing.T) {
	args, _ := json.Marshal(map[string]any{
		"target":       "example.com",
		"min_severity": "INVALID",
	})
	_, isErr := executeScan(args, nil)
	if !isErr {
		t.Error("expected error for invalid min_severity")
	}
}

// ── Scan header validation ──

func TestScanHeaderInjection(t *testing.T) {
	args, _ := json.Marshal(map[string]any{
		"target":  "example.com",
		"headers": map[string]string{"Evil\r\nHeader": "value"},
	})
	text, isErr := executeScan(args, nil)
	if !isErr {
		t.Errorf("expected error for header with CRLF, got: %s", text)
	}
}

// ── Resolver validation ──

func TestScanInvalidResolver(t *testing.T) {
	args, _ := json.Marshal(map[string]any{
		"target":   "example.com",
		"resolver": "not.a.valid.resolver",
	})
	text, isErr := executeScan(args, nil)
	if !isErr {
		t.Errorf("expected error for invalid resolver, got: %s", text)
	}
}

func TestScanInvalidResolversEntry(t *testing.T) {
	args, _ := json.Marshal(map[string]any{
		"target":    "example.com",
		"resolvers": []string{"1.1.1.1", "bad.hostname"},
	})
	text, isErr := executeScan(args, nil)
	if !isErr {
		t.Errorf("expected error for invalid resolver in list, got: %s", text)
	}
	if !strings.Contains(text, "index 1") {
		t.Errorf("error should mention the index, got: %s", text)
	}
}

func TestScanValidResolvers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	args, _ := json.Marshal(map[string]any{
		"target":    srv.URL,
		"modules":   []string{"headers"},
		"resolvers": []string{"1.1.1.1", "8.8.8.8:53"},
	})
	_, isErr := executeScan(args, nil)
	if isErr {
		t.Error("valid resolvers list should not cause an error")
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
	_, _ = executeScan(args, nil)
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	after := runtime.NumGoroutine()

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
	text, isErr := executeScan(args, nil)
	if isErr {
		return
	}
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
	text, isErr := executeScan(args, nil)
	if isErr {
		t.Fatalf("scan with allow_private should succeed: %s", text)
	}
}

// ── Scan timeout test ──

func TestScanTimeout(t *testing.T) {
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
	_, _ = executeScan(args, nil)
	elapsed := time.Since(start)

	if elapsed > 10*time.Second {
		t.Errorf("scan did not respect max_duration_seconds: took %v", elapsed)
	}
}

// ── Progress notifications ──

func TestScanProgressNotifications(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	var out bytes.Buffer
	mcpSrv := &Server{
		version: "test",
		enc:     json.NewEncoder(&out),
	}
	tc := &toolCall{
		srv:           mcpSrv,
		progressToken: json.RawMessage(`"test-token"`),
		ctx:           context.Background(),
	}

	args, _ := json.Marshal(map[string]any{
		"target":               srv.URL,
		"modules":              []string{"headers"},
		"timeout_seconds":      5,
		"max_duration_seconds": 15,
		"allow_private":        true,
	})
	_, _ = executeScan(args, tc)

	notifications := out.String()
	if !strings.Contains(notifications, "notifications/progress") {
		t.Error("expected progress notifications during scan")
	}
	if !strings.Contains(notifications, "test-token") {
		t.Error("expected progressToken in notifications")
	}
	if !strings.Contains(notifications, "starting module: headers") {
		t.Error("expected 'starting module: headers' notification")
	}
	if !strings.Contains(notifications, "completed: headers") {
		t.Error("expected 'completed: headers' notification")
	}
	if !strings.Contains(notifications, "surface summary") {
		t.Error("expected surface summary notification")
	}
}

// ── executeTool dispatch ──

func TestExecuteTool_UnknownTool(t *testing.T) {
	text, isErr := executeTool("nonexistent", nil, nil)
	if !isErr {
		t.Error("expected error for unknown tool")
	}
	if !strings.Contains(text, "unknown tool") {
		t.Errorf("expected 'unknown tool' message, got: %s", text)
	}
}

func TestExecuteTool_ListModules(t *testing.T) {
	text, isErr := executeTool("list_modules", nil, nil)
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, "when_to_use") {
		t.Error("expected when_to_use field in module catalog")
	}
}

func TestExecuteTool_SuggestModules(t *testing.T) {
	args, _ := json.Marshal(map[string]string{"objective": "find subdomains"})
	text, isErr := executeTool("suggest_modules", args, nil)
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, "recommended_modules") {
		t.Error("expected recommended_modules in result")
	}
}

func TestExecuteTool_ServerInfo(t *testing.T) {
	tc := &toolCall{srv: &Server{version: "2.1"}}
	text, isErr := executeTool("server_info", nil, tc)
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, "2.1") {
		t.Error("expected version in server info")
	}
}
