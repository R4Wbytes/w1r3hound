package modules

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

// Iteration 10 (WSTG-INFO-08): the sentry/headers tech detection was header- and
// cookie-only, so a single-page app that advertises its framework solely in the
// markup was mislabelled. Juice Shop disables X-Powered-By and sets no framework
// cookies, so it was reported as "1 technology" (just the Feature-Policy header)
// while being an obvious Angular app (<app-root>). detectBodyTech reads the HTML.
func TestDetectBodyTech(t *testing.T) {
	cases := []struct {
		name         string
		body         string
		wantDetected []string
		wantAbsent   []string
	}{
		{
			"angular-spa",
			`<!DOCTYPE html><html><body><app-root></app-root><script src="main.js"></script></body></html>`,
			[]string{"Angular"}, []string{"React", "Vue.js", "WordPress"},
		},
		{
			"react", `<div id="root" data-reactroot=""></div>`,
			[]string{"React"}, []string{"Angular"},
		},
		{
			"nextjs", `<script id="__NEXT_DATA__" type="application/json">{}</script>`,
			[]string{"Next.js"}, nil,
		},
		{
			"vue-ssr", `<div id="app" data-server-rendered="true"></div>`,
			[]string{"Vue.js"}, nil,
		},
		{
			"wordpress", `<link rel="stylesheet" href="/wp-content/themes/x/style.css">`,
			[]string{"WordPress"}, []string{"Angular"},
		},
		{
			"legacy-libraries",
			`<script src="/js/vendor/jquery-3.6.0.min.js"></script><script src="/js/vendor/modernizr-3.6.0.min.js"></script>`,
			[]string{"jQuery", "Modernizr"}, []string{"Angular", "React"},
		},
		{
			"plain-html", `<html><head><title>Hello</title></head><body><h1>Hi</h1><p>catalog</p></body></html>`,
			nil, []string{"Angular", "React", "Vue.js", "WordPress", "jQuery", "Modernizr"},
		},
	}
	for _, c := range cases {
		names := map[string]bool{}
		for _, td := range detectBodyTech(c.body) {
			names[td.Name] = true
		}
		for _, w := range c.wantDetected {
			if !names[w] {
				t.Errorf("%s: expected %q detected, got %v", c.name, w, names)
			}
		}
		for _, a := range c.wantAbsent {
			if names[a] {
				t.Errorf("%s: %q must NOT be detected, got %v", c.name, a, names)
			}
		}
	}
}

func TestDetectBodyTech_AngularVersion(t *testing.T) {
	got := detectBodyTech(`<html><body><app-root ng-version="17.3.0"></app-root></body></html>`)
	for _, td := range got {
		if td.Name == "Angular" {
			if td.Value != "version 17.3.0" {
				t.Errorf("expected Angular value 'version 17.3.0', got %q", td.Value)
			}
			return
		}
	}
	t.Error("Angular not detected")
}

func TestDetectBodyTech_LibraryVersions(t *testing.T) {
	got := detectBodyTech(
		`<script src="/js/vendor/jquery-3.6.0.min.js"></script>` +
			`<script src="/js/vendor/modernizr-3.6.0.min.js"></script>`,
	)
	versions := map[string]string{}
	for _, td := range got {
		versions[td.Name] = td.Value
	}
	for name, want := range map[string]string{"jQuery": "version 3.6.0", "Modernizr": "version 3.6.0"} {
		if versions[name] != want {
			t.Errorf("%s value = %q, want %q", name, versions[name], want)
		}
	}
}

// End-to-end: RunHeaders must read the HTML body and surface the SPA framework
// in the technology stack (not just headers/cookies).
func TestRunHeaders_DetectsFrameworkFromBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>Shop</title></head>` +
			`<body><app-root></app-root><script src="main.js"></script></body></html>`))
	}))
	defer srv.Close()

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL
	report := core.NewReport(srv.URL)
	RunHeaders(cfg, report, core.NewLogger(false))

	for _, f := range report.Findings {
		if !strings.Contains(f.Title, "Technology stack") {
			continue
		}
		res, ok := f.Data.(HeadersResult)
		if !ok {
			t.Fatalf("tech-stack finding Data should be HeadersResult, got %T", f.Data)
		}
		for _, td := range res.Technologies {
			if td.Name == "Angular" && td.Source == "body" {
				return // success
			}
		}
		t.Errorf("Angular not detected from body; technologies=%+v", res.Technologies)
	}
	t.Fatal("no technology-stack finding produced")
}

func TestRunHeaders_CSPUnsafeDirectivesAreDefenseInDepth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self' 'unsafe-inline' 'unsafe-eval'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin")
		w.Header().Set("Permissions-Policy", "camera=()")
		_, _ = w.Write([]byte("<html><title>test</title></html>"))
	}))
	defer srv.Close()

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL
	report := core.NewReport(srv.URL)
	RunHeaders(cfg, report, core.NewLogger(false))

	count := 0
	for _, f := range report.Findings {
		if strings.HasPrefix(f.Title, "CSP ") && strings.Contains(f.Title, "unsafe-") {
			count++
			if f.Severity != core.SevLow {
				t.Errorf("%q severity = %s, want LOW", f.Title, f.Severity)
			}
		}
	}
	if count != 2 {
		t.Fatalf("expected two CSP unsafe-directive findings, got %d", count)
	}
}

func TestRunHeaders_SkipsRedirectOutsideTargetPath(t *testing.T) {
	var destinationHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/programs" {
			http.Redirect(w, r, "/engagements", http.StatusMovedPermanently)
			return
		}
		destinationHits++
		w.Header().Set("Content-Security-Policy", "script-src 'unsafe-inline'")
		_, _ = w.Write([]byte("<html><title>outside scope</title></html>"))
	}))
	defer srv.Close()

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL + "/programs"
	report := core.NewReport(cfg.Target)
	RunHeaders(cfg, report, core.NewLogger(false))

	if destinationHits != 0 {
		t.Fatalf("out-of-path redirect destination was requested %d time(s)", destinationHits)
	}
	if len(report.Findings) != 0 {
		t.Fatalf("redirect response produced findings: %+v", report.Findings)
	}
}

func TestRunHeaders_SkipsGenericErrorDocumentWithStatus200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<html><head><title>Example | Error</title></head>` +
			`<body>The requested page was not found. Our server returned HTTP status 404.</body></html>`))
	}))
	defer srv.Close()

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL
	report := core.NewReport(cfg.Target)
	RunHeaders(cfg, report, core.NewLogger(false))

	if len(report.Findings) != 0 {
		t.Fatalf("generic error document produced header findings: %+v", report.Findings)
	}
}

func TestRunHeaders_SkipsHTTPErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'self'")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<html><body><h1>403 Forbidden</h1></body></html>"))
	}))
	defer srv.Close()

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL
	report := core.NewReport(cfg.Target)
	RunHeaders(cfg, report, core.NewLogger(false))

	if len(report.Findings) != 0 {
		t.Fatalf("HTTP error response produced header findings: %+v", report.Findings)
	}
}

func TestRunHeaders_MissingHeadersAreInformational(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL
	report := core.NewReport(cfg.Target)
	RunHeaders(cfg, report, core.NewLogger(false))

	for _, finding := range report.Findings {
		if strings.Contains(finding.Title, "security headers missing") {
			if finding.Severity != core.SevInfo {
				t.Fatalf("missing-header baseline severity = %s, want INFO", finding.Severity)
			}
			return
		}
	}
	t.Fatal("missing-header audit finding not produced")
}

func TestNonStandardInfoHeaders_IgnoresInfrastructureHeaders(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Amz-Cf-Id", "cloudfront-request-id")
	headers.Set("X-Amz-Cf-Pop", "SEA900-P1")
	headers.Set("X-Amz-Id-2", "extended-request-id")
	headers.Set("X-Amz-Request-Id", "request-id")
	headers.Set("X-Timer", "S123.456,VS0,VE1")
	headers.Set("X-Debug-Build", "release-123")

	got := nonStandardInfoHeaders(headers)
	if len(got) != 1 || got[0][0] != "X-Debug-Build" {
		t.Fatalf("standard CDN/cloud headers were treated as custom leaks: %v", got)
	}
}
