package modules

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

// TestSSRFOffHostCanaryNotFetched is the C-1 regression guard
// (SECURITY_ASSESSMENT §5): target-controlled URLs that point off-host
// (robots Sitemap, page <script>/<a> to another host) must never be fetched.
// The canary is served on 127.0.0.1 but referenced via "localhost" so it is a
// DIFFERENT host by name (isSameDomainURL) while still being reachable if a
// module wrongly dials it — turning any SSRF into a recorded hit.
func TestSSRFOffHostCanaryNotFetched(t *testing.T) {
	var canaryHits int32
	canary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&canaryHits, 1)
		_, _ = w.Write([]byte("CANARY"))
	}))
	defer canary.Close()

	cu, _ := url.Parse(canary.URL)
	offHost := "http://localhost:" + cu.Port() // same IP, different hostname => off-scope

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("User-agent: *\nSitemap: " + offHost + "/sitemap.xml\n"))
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!DOCTYPE html><html><head>` +
				`<script src="` + offHost + `/evil.js"></script>` +
				`</head><body><a href="` + offHost + `/page">off</a></body></html>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer target.Close()

	cfg := core.DefaultConfig()
	cfg.Target = target.URL
	cfg.Domain = "127.0.0.1"
	log := core.NewLogger(false)

	// Every module that fetches target-derived URLs must respect scope.
	RunMetafiles(cfg, core.NewReport(target.URL), log)
	RunContent(cfg, core.NewReport(target.URL), log)
	RunJSAnalysis(cfg, core.NewReport(target.URL), log)
	RunCrawler(cfg, core.NewReport(target.URL), log)
	RunAPI(cfg, core.NewReport(target.URL), log)

	if hits := atomic.LoadInt32(&canaryHits); hits != 0 {
		t.Fatalf("SSRF: off-host canary was fetched %d time(s) — scope guard (C-1) regressed", hits)
	}
}
