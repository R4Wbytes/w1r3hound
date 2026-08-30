package modules

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

// TestMaxJSFilesCap covers `-js-files`: JS analysis fetches at most MaxJSFiles
// of the discovered scripts.
func TestMaxJSFilesCap(t *testing.T) {
	var jsGets int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".js") {
			atomic.AddInt32(&jsGets, 1)
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte("// noop\n"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html></html>"))
	}))
	defer srv.Close()

	run := func(limit int) int32 {
		atomic.StoreInt32(&jsGets, 0)
		cfg := core.DefaultConfig()
		cfg.Target = srv.URL
		cfg.Domain = "127.0.0.1"
		cfg.MaxJSFiles = limit
		for i := 1; i <= 5; i++ {
			cfg.SharedJSFiles = append(cfg.SharedJSFiles, fmt.Sprintf("%s/j%d.js", srv.URL, i))
		}
		RunJSAnalysis(cfg, core.NewReport(srv.URL), core.NewLogger(false))
		return atomic.LoadInt32(&jsGets)
	}

	if got := run(2); got != 2 {
		t.Errorf("MaxJSFiles=2 fetched %d JS files, want 2", got)
	}
	if got := run(10); got != 5 { // only 5 exist
		t.Errorf("MaxJSFiles=10 fetched %d JS files, want 5 (all available)", got)
	}
}

// TestCrawlMaxPagesCap covers `-crawl-pages`: the crawler reports at most
// CrawlMaxPages pages even when more are linked.
func TestCrawlMaxPagesCap(t *testing.T) {
	page := func(links bool) string {
		var b strings.Builder
		b.WriteString("<html><head><title>page</title></head><body>")
		if links {
			for i := 1; i <= 6; i++ {
				b.WriteString(fmt.Sprintf(`<a href="/p%d">p%d</a>`, i, i))
			}
		}
		b.WriteString("</body></html>")
		return b.String()
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte(page(true)))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/p") {
			_, _ = w.Write([]byte(page(false)))
			return
		}
		http.NotFound(w, r) // real 404s so calibrateCatchAll finds no SPA shell
	}))
	defer srv.Close()

	crawl := func(maxPages int) int {
		cfg := core.DefaultConfig()
		cfg.Target = srv.URL
		cfg.Domain = "127.0.0.1"
		cfg.CrawlMaxPages = maxPages
		rep := core.NewReport(srv.URL)
		RunCrawler(cfg, rep, core.NewLogger(false))
		for _, f := range rep.Findings {
			if res, ok := f.Data.(CrawlResult); ok {
				return len(res.Pages)
			}
		}
		t.Fatal("no crawler result finding produced")
		return -1
	}

	if n := crawl(2); n != 2 {
		t.Errorf("CrawlMaxPages=2 crawled %d pages, want 2", n)
	}
	if n := crawl(50); n <= 2 { // root + 6 linked pages available
		t.Errorf("high cap should crawl more than 2 pages, got %d", n)
	}
}

// TestDirBruteWordlistAndExtensions covers `-dir-wordlist` + `-dir-ext`: the
// custom wordlist is loaded and each configured extension is appended.
func TestDirBruteWordlistAndExtensions(t *testing.T) {
	var (
		mu      sync.Mutex
		reqPath []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reqPath = append(reqPath, r.URL.Path)
		mu.Unlock()
		http.NotFound(w, r) // everything 404 -> clean soft-404 baseline, no findings
	}))
	defer srv.Close()

	wl := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wl, []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL
	cfg.Domain = "127.0.0.1"
	cfg.DirWordlist = wl
	cfg.DirExtensions = ".bak,.php"
	RunDirBrute(cfg, core.NewReport(srv.URL), core.NewLogger(false))

	mu.Lock()
	defer mu.Unlock()
	seen := strings.Join(reqPath, "\n")
	for _, want := range []string{"secret", "secret.bak", "secret.php"} {
		if !strings.Contains(seen, want) {
			t.Errorf("expected a request for %q from the custom wordlist+extensions; requested paths:\n%s", want, seen)
		}
	}
}
