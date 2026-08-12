package modules

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/w1r3hound/w1r3hound/internal/core"
)

// Iteration 7 (WSTG-CONF-02, Juice Shop /metrics): dirbrute discovered /metrics
// but categorised findings by path string only ("actuator", "admin", …), so a
// live Prometheus endpoint — the exposedMetricsChallenge, leaking the Node.js
// version, app version and process internals — was buried in the generic INFO
// "N paths found" bucket. The fix classifies by response *content*. These tests
// lock in the content detector and the end-to-end dirbrute finding.

const samplePrometheusBody = `# HELP nodejs_version_info Node.js version info.
# TYPE nodejs_version_info gauge
nodejs_version_info{version="v24.19.0",major="24",minor="19",patch="0",app="juiceshop"} 1
# HELP juiceshop_version_info Release version of OWASP Juice Shop.
# TYPE juiceshop_version_info gauge
juiceshop_version_info{version="20.2.0"} 1
# HELP process_cpu_user_seconds_total Total user CPU time spent in seconds.
# TYPE process_cpu_user_seconds_total counter
process_cpu_user_seconds_total 0.42
# HELP http_requests_count Total HTTP request count grouped by status code.
# TYPE http_requests_count counter
http_requests_count{status_code="200"} 12
`

func TestIsPrometheusMetrics(t *testing.T) {
	if !isPrometheusMetrics(samplePrometheusBody) {
		t.Error("real Prometheus exposition body must be detected")
	}
	no := map[string]string{
		"html":     `<!DOCTYPE html><html><head><title>OWASP Juice Shop</title></head><body></body></html>`,
		"json":     `{"status":"ok","metrics":{"cpu":0.4,"type":"gauge"}}`,
		"markdown": "# Types of coffee\n\n# Type systems\n\nSome prose that mentions counter and gauge words.",
		"swagger":  `{"swagger":"2.0","info":{"title":"API"},"paths":{}}`,
	}
	for name, body := range no {
		if isPrometheusMetrics(body) {
			t.Errorf("%s must NOT be classified as Prometheus metrics", name)
		}
	}
}

func TestPrometheusExposure(t *testing.T) {
	count, leaks := prometheusExposure(samplePrometheusBody)
	if count != 4 {
		t.Errorf("expected 4 metrics (TYPE lines), got %d", count)
	}
	for _, want := range []string{
		"Node.js runtime version", "application version",
		"process CPU usage", "HTTP request statistics",
	} {
		if !contains(leaks, want) {
			t.Errorf("expected leak %q in %v", want, leaks)
		}
	}
}

// End-to-end: dirbrute against a server that answers the Prometheus body only at
// /metrics (and 404 everywhere else) must raise a MEDIUM WSTG-CONF-02 finding.
func TestDirBrute_PrometheusMetricsClassified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" {
			w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
			_, _ = w.Write([]byte(samplePrometheusBody))
			return
		}
		http.NotFound(w, r) // clean 404s ⇒ no soft-404 catch-all
	}))
	defer srv.Close()

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL
	cfg.Concurrency = 8
	report := core.NewReport(srv.URL)

	RunDirBrute(cfg, report, core.NewLogger(false))

	var prom *core.Finding
	for i := range report.Findings {
		if report.Findings[i].WSTG == "WSTG-CONF-02" &&
			strings.Contains(report.Findings[i].Title, "Prometheus") {
			prom = &report.Findings[i]
			break
		}
	}
	if prom == nil {
		t.Fatal("expected a WSTG-CONF-02 Prometheus finding, got none")
	}
	if prom.Severity != core.SevMedium {
		t.Errorf("Prometheus exposure should be MEDIUM, got %s", prom.Severity)
	}
	if !strings.Contains(prom.Title, "/metrics") {
		t.Errorf("finding should name /metrics, got %q", prom.Title)
	}
	if !strings.Contains(prom.Description, "Node.js runtime version") {
		t.Errorf("description should enumerate the leaked data, got %q", prom.Description)
	}
}

// Iteration 8 (WSTG-CONF-04): dirbrute categorised discovered paths by string
// only, so browsable directories NOT in robots.txt (Juice Shop /encryptionkeys,
// /support/logs, /infrastructure) were never flagged. It now detects listings by
// content. Here a wordlist path answers a serve-index listing and must be raised
// as a finding, rated by the sensitivity of the entries it exposes.
func TestDirBrute_DirectoryListingClassified(t *testing.T) {
	listing := `<!DOCTYPE html><html><head><title>listing directory /uploads/</title></head>` +
		`<body><h1><a href="/">/</a> <a href="/uploads">uploads</a></h1>` +
		`<ul id="files" class="view-tiles">` +
		`<li><a href="../" class="icon icon-directory">..</a></li>` +
		`<li><a href="backup.sql" class="icon icon-default" title="backup.sql">backup.sql</a></li>` +
		`<li><a href="readme.txt" class="icon icon-default" title="readme.txt">readme.txt</a></li>` +
		`</ul></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/uploads/" { // /uploads/ is in the embedded wordlist
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(listing))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL
	cfg.Concurrency = 8
	report := core.NewReport(srv.URL)
	RunDirBrute(cfg, report, core.NewLogger(false))

	var dl *core.Finding
	for i := range report.Findings {
		if report.Findings[i].WSTG == "WSTG-CONF-04" &&
			strings.Contains(report.Findings[i].Title, "/uploads/") {
			dl = &report.Findings[i]
			break
		}
	}
	if dl == nil {
		t.Fatal("expected a WSTG-CONF-04 directory-listing finding for /uploads/, got none")
	}
	if dl.Severity != core.SevHigh { // backup.sql present
		t.Errorf("listing exposing backup.sql must be HIGH, got %s", dl.Severity)
	}
	entries, _ := dl.Data.([]string)
	if !contains(entries, "backup.sql") || !contains(entries, "readme.txt") {
		t.Errorf("expected clean entries [backup.sql readme.txt], got %v", entries)
	}
	for _, bad := range entries {
		if bad == ".." || strings.HasPrefix(bad, "/") {
			t.Errorf("breadcrumb/parent link leaked into entries: %q", bad)
		}
	}
}

// The post-scan cluster filter must never drop a content-classified entry (a
// listing or Prometheus endpoint), even when its size sits inside the catch-all
// cluster — it was positively identified by its body, so it is not a soft-404.
func TestClusterFilter_KeepsContentClassified(t *testing.T) {
	shellHash := simpleHash([]byte("app-shell-body"))
	var entries []DirEntry
	for _, p := range []string{"/a", "/b", "/c", "/d", "/e", "/f", "/g", "/h", "/i"} {
		entries = append(entries, DirEntry{Path: p, StatusCode: 200, Size: 9000, bodyHash: shellHash})
	}
	// A real directory listing: same size as the shell cluster, distinct body,
	// positively classified.
	entries = append(entries, DirEntry{
		Path: "/encryptionkeys/", StatusCode: 200, Size: 9000,
		bodyHash: simpleHash([]byte("a-directory-listing")), Kind: "directory-listing",
	})

	kept := clusterFilterSoft404s(entries, soft404Baseline{status: 200, bodyLen: 9000}, core.NewLogger(false))

	survived := map[string]bool{}
	for _, e := range kept {
		survived[e.Path] = true
	}
	if !survived["/encryptionkeys/"] {
		t.Error("content-classified directory listing must survive cluster filtering")
	}
	if survived["/a"] || survived["/b"] {
		t.Error("the shell-identical cluster should have been filtered as soft-404s")
	}
}
