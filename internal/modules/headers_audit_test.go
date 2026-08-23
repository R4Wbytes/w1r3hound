package modules

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/w1r3hound/w1r3hound/internal/core"
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
			"plain-html", `<html><head><title>Hello</title></head><body><h1>Hi</h1><p>catalog</p></body></html>`,
			nil, []string{"Angular", "React", "Vue.js", "WordPress", "jQuery"},
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
