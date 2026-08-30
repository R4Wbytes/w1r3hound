package modules

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

func TestContent_OnlyQueuesTargetJavaScript(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app.js" {
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`console.log("app")`))
			return
		}
		_, _ = w.Write([]byte(`<html><title>scope test</title>` +
			`<meta name="csrf-token" content="super-secret-token-value">` +
			`<script src="/app.js?first=1&amp;second=2"></script>` +
			`<script src="https://third-party.invalid/tracker.js"></script></html>`))
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := core.DefaultConfig()
	cfg.Target = srv.URL
	cfg.Domain = u.Hostname()
	cfg.Timeout = 200 * time.Millisecond
	report := core.NewReport(srv.URL)

	RunContent(cfg, report, core.NewLogger(false))

	var result *ContentResult
	for i := range report.Findings {
		if data, ok := report.Findings[i].Data.(ContentResult); ok {
			result = &data
		}
	}
	if result == nil {
		t.Fatal("content result missing")
	}
	if len(result.JSFiles) != 1 {
		t.Fatalf("queued JavaScript files = %v, want only one target file", result.JSFiles)
	}
	if result.MetaTags["csrf-token"] != "[REDACTED]" {
		t.Fatalf("CSRF meta token was persisted: %q", result.MetaTags["csrf-token"])
	}
	if !strings.Contains(result.JSFiles[0], "first=1&second=2") || strings.Contains(result.JSFiles[0], "amp;") {
		t.Fatalf("HTML-escaped script URL was not decoded: %q", result.JSFiles[0])
	}

	gathered := gatherJSFiles(cfg, srv.URL)
	if len(gathered) != 1 || gathered[0] != result.JSFiles[0] {
		t.Fatalf("JS analysis scope differs from content scope: %v vs %v", gathered, result.JSFiles)
	}
}

func TestContent_DoesNotFollowRedirectOutsideTargetPath(t *testing.T) {
	var destinationHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/programs" {
			http.Redirect(w, r, "/engagements", http.StatusMovedPermanently)
			return
		}
		destinationHits++
		_, _ = w.Write([]byte(`<html><script>const api_key = "outside-scope-secret-value";</script></html>`))
	}))
	defer srv.Close()

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL + "/programs"
	cfg.Timeout = 200 * time.Millisecond
	report := core.NewReport(cfg.Target)

	RunContent(cfg, report, core.NewLogger(false))

	if destinationHits != 0 {
		t.Fatalf("out-of-path redirect destination was requested %d time(s)", destinationHits)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("out-of-path redirect content produced findings: %+v", report.Findings)
	}
	if got := gatherJSFiles(cfg, cfg.Target); len(got) != 0 {
		t.Fatalf("JS analysis gathered files through out-of-path redirect: %v", got)
	}
}

func TestContent_SkipsGenericErrorDocumentWithStatus200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<html><head><title>Example | Error</title></head>` +
			`<body>The requested page was not found. Our server returned HTTP status 404.` +
			`<script>const password = "S3cretValue!";</script></body></html>`))
	}))
	defer srv.Close()

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL
	report := core.NewReport(cfg.Target)
	RunContent(cfg, report, core.NewLogger(false))

	if len(report.Findings) != 0 {
		t.Fatalf("generic error document produced content findings: %+v", report.Findings)
	}
}
