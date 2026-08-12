package modules

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/w1r3hound/w1r3hound/internal/core"
)

// Iteration 11 (WSTG-ERRH-02): W1r3Hound had no error-handling coverage, yet
// apiscan already fetched the /api and /rest bodies, which on Juice Shop are
// Express `errorhandler` stack-trace pages leaking framework internals and the
// absolute /juice-shop/node_modules path. detectStackTrace surfaces those.
func TestDetectStackTrace(t *testing.T) {
	positives := map[string]struct {
		body string
		lang string
	}{
		"node-express": {
			`<html><head><title>Error: Unexpected path: /api</title></head><body>` +
				`<ul><li>at trim_prefix (/juice-shop/node_modules/express/lib/router/index.js:18:18)</li></ul></body></html>`,
			"Node.js",
		},
		"python": {
			"Traceback (most recent call last):\n  File \"/app/main.py\", line 42, in <module>\n    raise ValueError('x')",
			"Python",
		},
		"java": {
			`java.lang.NullPointerException` + "\n\tat com.example.Foo.bar(Foo.java:42)",
			"Java",
		},
		"php": {
			`<b>Fatal error</b>: Uncaught TypeError in /var/www/html/index.php on line 42`,
			"PHP",
		},
		"ruby": {
			"app.rb:24:in `block in <main>'",
			"Ruby",
		},
	}
	for name, c := range positives {
		got := detectStackTrace(c.body)
		if !contains(got, c.lang) {
			t.Errorf("%s: expected %q detected, got %v", name, c.lang, got)
		}
	}

	// Clean responses must never be flagged.
	for _, clean := range []string{
		`{"message":"Not Found","errors":[]}`,
		`{"status":"error","error":"invalid id 999"}`,
		`<!DOCTYPE html><html><head><title>OWASP Juice Shop</title></head>` +
			`<body><app-root></app-root><script src="main.js"></script></body></html>`,
	} {
		if got := detectStackTrace(clean); len(got) != 0 {
			t.Errorf("clean response must not be flagged, got %v", got)
		}
	}
}

// End-to-end: apiscan against a server whose /api and /rest return a stack-trace
// page must raise a MEDIUM WSTG-ERRH-02 finding.
func TestApiScan_StackTraceDisclosure(t *testing.T) {
	trace := `<html><head><title>Error: Unexpected path</title></head><body>` +
		`<pre>Error: Unexpected path<br>    at trim_prefix ` +
		`(/app/node_modules/express/lib/router/index.js:18:18)</pre></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api" || r.URL.Path == "/rest" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(500)
			_, _ = w.Write([]byte(trace))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL
	report := core.NewReport(srv.URL)
	RunAPI(cfg, report, core.NewLogger(false))

	var f *core.Finding
	for i := range report.Findings {
		if report.Findings[i].WSTG == "WSTG-ERRH-02" {
			f = &report.Findings[i]
			break
		}
	}
	if f == nil {
		t.Fatal("expected a WSTG-ERRH-02 stack-trace finding, got none")
	}
	if f.Severity != core.SevMedium {
		t.Errorf("stack-trace disclosure should be MEDIUM, got %s", f.Severity)
	}
}
