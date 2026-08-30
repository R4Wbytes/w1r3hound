package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const loopbackHost = "127.0.0.1:8737"

// serve runs one request through the full middleware chain (securityHeaders +
// originGuard + mux) exactly as production does.
func serve(t *testing.T, s *server, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	h, err := s.handler()
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func loopbackReq(method, target string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	req.Host = loopbackHost
	return req
}

func TestOriginGuard(t *testing.T) {
	s := newTestServer(t, "")

	t.Run("non-loopback Host -> 421", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/modules", nil)
		req.Host = "attacker.example.com"
		if rec := serve(t, s, req); rec.Code != http.StatusMisdirectedRequest {
			t.Fatalf("code = %d, want 421", rec.Code)
		}
	})
	t.Run("foreign Origin -> 403", func(t *testing.T) {
		req := loopbackReq("GET", "/api/modules", nil)
		req.Header.Set("Origin", "http://evil.example.com")
		if rec := serve(t, s, req); rec.Code != http.StatusForbidden {
			t.Fatalf("code = %d, want 403", rec.Code)
		}
	})
	t.Run("cross-site fetch -> 403", func(t *testing.T) {
		req := loopbackReq("GET", "/api/modules", nil)
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		if rec := serve(t, s, req); rec.Code != http.StatusForbidden {
			t.Fatalf("code = %d, want 403", rec.Code)
		}
	})
	t.Run("loopback Origin allowed", func(t *testing.T) {
		req := loopbackReq("GET", "/api/modules", nil)
		req.Header.Set("Origin", "http://127.0.0.1:8737")
		if rec := serve(t, s, req); rec.Code != http.StatusOK {
			t.Fatalf("code = %d, want 200", rec.Code)
		}
	})
	t.Run("plain loopback GET -> 200", func(t *testing.T) {
		if rec := serve(t, s, loopbackReq("GET", "/api/modules", nil)); rec.Code != http.StatusOK {
			t.Fatalf("code = %d, want 200", rec.Code)
		}
	})
}

func TestSecurityHeaders(t *testing.T) {
	s := newTestServer(t, "")

	rec := serve(t, s, loopbackReq("GET", "/", nil))
	h := rec.Header()
	csp := h.Get("Content-Security-Policy")
	if csp == "" || !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP on / = %q, want default-src 'self'", csp)
	}
	for _, directive := range []string{"base-uri 'none'", "object-src 'none'", "form-action 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP missing %q; got %q", directive, csp)
		}
	}
	if h.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", h.Get("X-Content-Type-Options"))
	}
	if h.Get("X-Frame-Options") != "DENY" {
		t.Errorf("X-Frame-Options = %q", h.Get("X-Frame-Options"))
	}
	if h.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("Referrer-Policy = %q", h.Get("Referrer-Policy"))
	}

	// The SSE route must NOT carry the CSP header (EventSource + CSP quirks).
	rec = serve(t, s, loopbackReq("GET", "/api/scans/whatever/events", nil))
	if got := rec.Header().Get("Content-Security-Policy"); got != "" {
		t.Errorf("CSP present on /events route = %q, want empty", got)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("non-CSP security headers should still be present on /events")
	}
}

// TestNewHTTPServerTimeouts guards F-4: the loopback server must carry read /
// idle timeouts (slowloris + idle-socket exhaustion) while leaving WriteTimeout
// unset so the long-lived SSE stream is not severed mid-scan.
func TestNewHTTPServerTimeouts(t *testing.T) {
	srv := newHTTPServer(nil)
	if srv.ReadHeaderTimeout <= 0 {
		t.Error("ReadHeaderTimeout must be set (slowloris guard)")
	}
	if srv.ReadTimeout <= 0 {
		t.Error("ReadTimeout must be set")
	}
	if srv.IdleTimeout <= 0 {
		t.Error("IdleTimeout must be set")
	}
	if srv.WriteTimeout != 0 {
		t.Error("WriteTimeout must remain 0 so SSE streams are not cut off")
	}
	if srv.Addr != listenAddr {
		t.Errorf("Addr = %q, want %q", srv.Addr, listenAddr)
	}
}

func TestRequireToken(t *testing.T) {
	s := newTestServer(t, "s3cr3t")
	body := `{"target":"127.0.0.1","authorized":true,"passive":true}`

	t.Run("missing token -> 401", func(t *testing.T) {
		rec := serve(t, s, loopbackReq("POST", "/api/scan", strings.NewReader(body)))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("code = %d, want 401", rec.Code)
		}
	})
	t.Run("wrong token -> 401", func(t *testing.T) {
		req := loopbackReq("POST", "/api/scan", strings.NewReader(body))
		req.Header.Set("X-Auth-Token", "nope")
		if rec := serve(t, s, req); rec.Code != http.StatusUnauthorized {
			t.Fatalf("code = %d, want 401", rec.Code)
		}
	})
	t.Run("cancel also requires token", func(t *testing.T) {
		rec := serve(t, s, loopbackReq("POST", "/api/scans/x/cancel", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("code = %d, want 401", rec.Code)
		}
	})
	t.Run("correct token -> 201", func(t *testing.T) {
		req := loopbackReq("POST", "/api/scan", strings.NewReader(body))
		req.Header.Set("X-Auth-Token", "s3cr3t")
		if rec := serve(t, s, req); rec.Code != http.StatusCreated {
			t.Fatalf("code = %d, want 201; body=%s", rec.Code, rec.Body.String())
		}
	})
}

func TestHandleModules(t *testing.T) {
	s := newTestServer(t, "")
	rec := serve(t, s, loopbackReq("GET", "/api/modules", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	var resp struct {
		Modules []ModuleInfo `json:"modules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Modules) != len(moduleCatalog) {
		t.Fatalf("module count = %d, want %d", len(resp.Modules), len(moduleCatalog))
	}
}

func TestHandleStartScan(t *testing.T) {
	s := newTestServer(t, "")

	t.Run("invalid JSON -> 400", func(t *testing.T) {
		rec := serve(t, s, loopbackReq("POST", "/api/scan", strings.NewReader("{not json")))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("code = %d, want 400", rec.Code)
		}
	})
	t.Run("unknown field -> 400", func(t *testing.T) {
		rec := serve(t, s, loopbackReq("POST", "/api/scan", strings.NewReader(`{"target":"x","authorized":true,"bogus":1}`)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("code = %d, want 400", rec.Code)
		}
	})
	t.Run("parity field accepted by decoder", func(t *testing.T) {
		// skip_tls_verify is now a first-class parity field: the strict decoder
		// accepts it (an explicit unique output name avoids an auto-name clash
		// with the "valid -> 201" case below).
		rec := serve(t, s, loopbackReq("POST", "/api/scan", strings.NewReader(`{"target":"127.0.0.1","authorized":true,"passive":true,"skip_tls_verify":false,"block_private_egress":true,"output":"parity_probe"}`)))
		if rec.Code != http.StatusCreated {
			t.Fatalf("code = %d, want 201; body=%s", rec.Code, rec.Body.String())
		}
	})
	t.Run("CRLF header injection -> 400", func(t *testing.T) {
		// Backtick raw string keeps the \r\n as JSON escapes, so the body is
		// valid JSON that decodes to a header value with real CR/LF; validateHeaders
		// must reject it in buildArgs (surfaced as 400) before any job is submitted.
		body := `{"target":"127.0.0.1","authorized":true,"headers":["X-Evil: a\r\nInjected: 1"]}`
		rec := serve(t, s, loopbackReq("POST", "/api/scan", strings.NewReader(body)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("code = %d, want 400 (header injection)", rec.Code)
		}
	})
	t.Run("authorized:false -> 400", func(t *testing.T) {
		rec := serve(t, s, loopbackReq("POST", "/api/scan", strings.NewReader(`{"target":"127.0.0.1","authorized":false}`)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("code = %d, want 400", rec.Code)
		}
	})
	t.Run("oversized body -> 400", func(t *testing.T) {
		huge := `{"target":"example.com","authorized":true,"user_agent":"` + strings.Repeat("x", 70000) + `"}`
		rec := serve(t, s, loopbackReq("POST", "/api/scan", strings.NewReader(huge)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("code = %d, want 400 (64KB limit)", rec.Code)
		}
	})
	t.Run("valid -> 201 with id+status", func(t *testing.T) {
		rec := serve(t, s, loopbackReq("POST", "/api/scan", strings.NewReader(`{"target":"127.0.0.1","authorized":true,"passive":true}`)))
		if rec.Code != http.StatusCreated {
			t.Fatalf("code = %d, want 201; body=%s", rec.Code, rec.Body.String())
		}
		var resp struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.ID == "" || resp.Status == "" {
			t.Fatalf("resp = %+v, want id+status", resp)
		}
	})
}

func TestConfinedResultFile(t *testing.T) {
	s := newTestServer(t, "")
	// A legitimate file inside results/.
	if err := os.WriteFile(filepath.Join(s.mgr.resultsDir, "ok.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := s.confinedResultFile("ok", ".json"); err != nil {
		t.Fatalf("valid id rejected: %v", err)
	}
	bad := []string{"../etc/passwd", "foo/bar", "..", "a/../../b", "%2f..%2f", ""}
	for _, id := range bad {
		if _, err := s.confinedResultFile(id, ".json"); err == nil {
			t.Errorf("confinedResultFile(%q) accepted, want error", id)
		}
	}
	// Missing (but syntactically valid) id.
	if _, err := s.confinedResultFile("nonexistent", ".json"); err == nil {
		t.Errorf("missing id accepted")
	}
}

func TestHandleReport(t *testing.T) {
	s := newTestServer(t, "")
	for _, ext := range []string{".json", ".md"} {
		if err := os.WriteFile(filepath.Join(s.mgr.resultsDir, "rep"+ext), []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("json download", func(t *testing.T) {
		rec := serve(t, s, loopbackReq("GET", "/api/scans/rep/report.json", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d, want 200", rec.Code)
		}
		if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "rep.json") {
			t.Fatalf("Content-Disposition = %q", cd)
		}
	})
	t.Run("md download", func(t *testing.T) {
		rec := serve(t, s, loopbackReq("GET", "/api/scans/rep/report.md", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d, want 200", rec.Code)
		}
	})
	t.Run("missing -> 404", func(t *testing.T) {
		rec := serve(t, s, loopbackReq("GET", "/api/scans/ghost/report.json", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("code = %d, want 404", rec.Code)
		}
	})
}

func TestHandleLog(t *testing.T) {
	s := newTestServer(t, "")

	t.Run("in-memory job log", func(t *testing.T) {
		j := &Job{ID: "live1", Target: "127.0.0.1", Status: StatusRunning,
			subs: make(map[chan string]struct{}), logBuf: []string{"alpha", "beta"}}
		s.mgr.mu.Lock()
		s.mgr.jobs["live1"] = j
		s.mgr.mu.Unlock()

		rec := serve(t, s, loopbackReq("GET", "/api/scans/live1/log", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d", rec.Code)
		}
		if body := rec.Body.String(); !strings.Contains(body, "alpha") || !strings.Contains(body, "beta") {
			t.Fatalf("log body = %q", body)
		}
	})

	t.Run("on-disk log", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(s.mgr.resultsDir, "old.log"), []byte("historic line\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		rec := serve(t, s, loopbackReq("GET", "/api/scans/old/log", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "historic line") {
			t.Fatalf("disk log body = %q", rec.Body.String())
		}
	})

	t.Run("missing -> 404", func(t *testing.T) {
		rec := serve(t, s, loopbackReq("GET", "/api/scans/ghost/log", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("code = %d, want 404", rec.Code)
		}
	})
}

func TestHandleEventsSSE(t *testing.T) {
	s := newTestServer(t, "")
	j := &Job{ID: "done1", Target: "127.0.0.1", Status: StatusDone,
		subs: make(map[chan string]struct{}), closed: true, logBuf: []string{"hello", "world"}}
	s.mgr.mu.Lock()
	s.mgr.jobs["done1"] = j
	s.mgr.mu.Unlock()

	rec := serve(t, s, loopbackReq("GET", "/api/scans/done1/events", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q", ct)
	}
	body := rec.Body.String()
	if strings.Count(body, "event: log") != 2 {
		t.Fatalf("expected 2 replayed log events; body=%q", body)
	}
	if !strings.Contains(body, "event: status") {
		t.Fatalf("missing final status event; body=%q", body)
	}

	t.Run("unknown scan -> 404", func(t *testing.T) {
		rec := serve(t, s, loopbackReq("GET", "/api/scans/ghost/events", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("code = %d, want 404", rec.Code)
		}
	})
}

func TestListAndGetScans(t *testing.T) {
	s := newTestServer(t, "")

	// One live (in-memory) job.
	j := &Job{ID: "mem1", Target: "10.0.0.1", Status: StatusRunning,
		subs: make(map[chan string]struct{})}
	s.mgr.mu.Lock()
	s.mgr.jobs["mem1"] = j
	s.mgr.mu.Unlock()

	// One recovered-from-disk report.
	report := `{"target":"disk.example.com","started_at":"2026-01-01T00:00:00Z","ended_at":"2026-01-01T00:01:00Z","findings":[{"severity":"HIGH"},{"severity":"LOW"}]}`
	if err := os.WriteFile(filepath.Join(s.mgr.resultsDir, "disk1.json"), []byte(report), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := serve(t, s, loopbackReq("GET", "/api/scans", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	var list struct {
		Scans []ScanSummary `json:"scans"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	found := map[string]ScanSummary{}
	for _, sm := range list.Scans {
		found[sm.ID] = sm
	}
	if _, ok := found["mem1"]; !ok {
		t.Errorf("live job mem1 missing from list")
	}
	disk, ok := found["disk1"]
	if !ok {
		t.Fatalf("disk-recovered scan missing from list")
	}
	if disk.Total != 2 || disk.Live {
		t.Errorf("disk summary = %+v, want total=2 live=false", disk)
	}

	t.Run("get in-memory", func(t *testing.T) {
		rec := serve(t, s, loopbackReq("GET", "/api/scans/mem1", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d", rec.Code)
		}
	})
	t.Run("get disk-recovered", func(t *testing.T) {
		rec := serve(t, s, loopbackReq("GET", "/api/scans/disk1", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d", rec.Code)
		}
	})
	t.Run("get missing -> 404", func(t *testing.T) {
		rec := serve(t, s, loopbackReq("GET", "/api/scans/ghost", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("code = %d, want 404", rec.Code)
		}
	})
}
