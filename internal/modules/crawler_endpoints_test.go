package modules

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

// TestCrawler_EndpointsDeduplicated locks the invariant behind the BUG-3 fix:
// an API-shaped path reachable from several pages is recorded exactly once, and
// result.Endpoints never carries duplicate strings. The dedup used to be a
// linear scan of result.Endpoints under lock on every crawled URL (O(n²) over a
// large crawl); it is now an O(1) map lookup that must preserve this behaviour.
func TestCrawler_EndpointsDeduplicated(t *testing.T) {
	home := `<!DOCTYPE html><html><head><title>Home</title></head><body>` +
		`<a href="/api/users">u1</a><a href="/api/users">u2</a>` +
		`<a href="/page2">p2</a>` + strings.Repeat("<!-- home -->", 20) + `</body></html>`
	page2 := `<!DOCTYPE html><html><head><title>Page2</title></head><body>` +
		`<a href="/api/users">again</a>` + strings.Repeat("<!-- page2 padding -->", 30) + `</body></html>`
	apiPage := `<!DOCTYPE html><html><head><title>Users</title></head><body>` +
		`users list` + strings.Repeat("<!-- api padding to differ in length -->", 15) + `</body></html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(home))
		case "/page2":
			_, _ = w.Write([]byte(page2))
		case "/api/users":
			_, _ = w.Write([]byte(apiPage))
		default:
			// Genuine 404 for unknown paths so calibration sees a non-catch-all
			// server and does not suppress real pages.
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL
	cfg.Concurrency = 4
	report := core.NewReport(srv.URL)

	RunCrawler(cfg, report, core.NewLogger(false))

	var res CrawlResult
	found := false
	for _, f := range report.Snapshot().Findings {
		if r, ok := f.Data.(CrawlResult); ok {
			res = r
			found = true
			break
		}
	}
	if !found {
		t.Fatal("crawler produced no CrawlResult finding")
	}

	// No duplicate endpoint strings, and /api/users recorded exactly once.
	seen := map[string]int{}
	for _, e := range res.Endpoints {
		seen[e]++
	}
	for e, n := range seen {
		if n > 1 {
			t.Errorf("endpoint %q recorded %d times; dedup broken", e, n)
		}
	}
	apiCount := 0
	for _, e := range res.Endpoints {
		if strings.Contains(e, "/api/users") {
			apiCount++
		}
	}
	if apiCount != 1 {
		t.Errorf("expected /api/users endpoint exactly once, got %d (endpoints=%v)", apiCount, res.Endpoints)
	}
}
