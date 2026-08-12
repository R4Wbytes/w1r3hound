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
