package modules

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

// Iteration 5 (WSTG-INFO-06/07, Juice Shop crawler): the crawler used to run
// its HTML link/form/input regexes over every fetched body regardless of
// Content-Type, and had no SPA catch-all awareness. Against an Angular SPA this
// produced two classes of phantom findings:
//
//   - a "/{{href}}" page, mined out of a href="{{href}}" template literal that
//     lives inside scripts.js (application/javascript), then answered 200 by the
//     catch-all and counted as real;
//   - a "/sitemap.xml" page — a seeded path that does not exist but that the
//     single-page app answers 200 with the index.html shell.
//
// This test stands up a faux SPA with exactly those traits and asserts the
// crawler reports only genuine HTML pages, while still following real links and
// capturing their forms/params (no over-suppression).
func TestCrawler_SPACatchAllAndTemplateLiterals(t *testing.T) {
	// The app shell every unknown path returns (~350 bytes). Kept deliberately
	// distinct in length from the real pages below so catch-all calibration can
	// tell them apart.
	shell := "<!DOCTYPE html><html><head><title>Faux Shop</title></head><body>" +
		"<app-root></app-root>" + strings.Repeat("<!-- shell -->", 18) + "</body></html>"

	// Homepage links to a real HTML page and pulls in a JS bundle.
	home := "<!DOCTYPE html><html><head><title>Faux Shop</title></head><body>" +
		`<a href="/real?from=home">real</a><script src="/scripts.js"></script>` +
		strings.Repeat("<!-- home -->", 16) + "</body></html>"

	// A genuine second HTML page with a real form (must be crawled + parsed).
	realPage := "<!DOCTYPE html><html><head><title>Real Page</title></head><body>" +
		`<form method="POST" action="/submit"><input name="real_param" type="text"></form>` +
		strings.Repeat("<!-- real page padding to differ from the shell -->", 20) +
		"</body></html>"

	// The JS bundle carries an Angular template literal in an href attribute and
	// a ghost <form>/<input>. None of it must be parsed as HTML. Padded large so
	// it is not mistaken for the catch-all shell by body length.
	scriptsJS := `angular.module('x');var t='<a href="{{href}}"></a>' +` +
		`'<form><input name="js_ghost_param"></form>';` +
		strings.Repeat("/* padding to exceed catch-all tolerance */", 60)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(home))
		case "/real":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(realPage))
		case "/scripts.js":
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
			_, _ = w.Write([]byte(scriptsJS))
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin\n"))
		default:
			// Catch-all: every other path (calibration probes, /sitemap.xml, and
			// even /{{href}} if it ever leaked into the queue) gets the shell.
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(shell))
		}
	}))
	defer srv.Close()

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL
	cfg.Concurrency = 4
	report := core.NewReport(srv.URL)

	RunCrawler(cfg, report, core.NewLogger(false))

	// Pull the CrawlResult back out of the finding.
	var res CrawlResult
	found := false
	for _, f := range report.Findings {
		if r, ok := f.Data.(CrawlResult); ok {
			res = r
			found = true
			break
		}
	}
	if !found {
		t.Fatal("crawler produced no CrawlResult finding")
	}

	pagePaths := map[string]bool{}
	for _, p := range res.Pages {
		u, err := url.Parse(p.URL)
		if err != nil {
			t.Fatalf("unparsable page URL %q: %v", p.URL, err)
		}
		pagePaths[u.Path] = true
		if strings.ContainsAny(p.URL, "{}") {
			t.Errorf("phantom template-literal page crawled: %q", p.URL)
		}
		if strings.Contains(p.URL, "sitemap.xml") {
			t.Errorf("phantom catch-all /sitemap.xml counted as a real page: %q", p.URL)
		}
	}

	// Root is the real entry point and must survive catch-all suppression even
	// though it *is* the shell.
	if !pagePaths[""] && !pagePaths["/"] {
		t.Errorf("root page was dropped; pages=%v", pagePaths)
	}
	// The real second page must have been followed and recorded.
	if !pagePaths["/real"] {
		t.Errorf("real HTML page /real was not crawled; pages=%v", pagePaths)
	}
	// Static bundles must not consume the page budget; jsdeep owns JS fetching.
	if pagePaths["/scripts.js"] {
		t.Errorf("scripts.js was counted as a page; pages=%v", pagePaths)
	}

	// Params: the real form's input must be captured; the JS ghost must not.
	if !contains(res.Parameters, "real_param") {
		t.Errorf("real form parameter missing; params=%v", res.Parameters)
	}
	if !contains(res.Parameters, "from") {
		t.Errorf("query parameter from HTML link missing; params=%v", res.Parameters)
	}
	if contains(res.Parameters, "js_ghost_param") {
		t.Errorf("ghost parameter mined from JS bundle; params=%v", res.Parameters)
	}

	// Exactly the one real form, parsed from HTML only.
	if len(res.Forms) != 1 {
		t.Fatalf("expected 1 form (from /real), got %d: %+v", len(res.Forms), res.Forms)
	}
	if res.Forms[0].Method != "POST" || !strings.HasSuffix(res.Forms[0].Action, "/submit") {
		t.Errorf("real form parsed wrong: %+v", res.Forms[0])
	}
}

// isTemplateURL must reject client-side templating placeholders while leaving
// ordinary links (including query strings and encoded characters) untouched.
func TestIsTemplateURL(t *testing.T) {
	reject := []string{
		"{{href}}", "/user/{{id}}", "${path}", "/a/${x}/b",
		"<%= url %>", "/x<%end%>", "/p}", "/{q",
	}
	for _, u := range reject {
		if !isTemplateURL(u) {
			t.Errorf("expected %q to be treated as a template literal", u)
		}
	}
	keep := []string{
		"/rest/user/login", "/search?q=apples&sort=asc", "assets/i18n/en.json",
		"https://example.com/a/b", "/api/Products", "/x%7Bnot-a-brace%7D",
	}
	for _, u := range keep {
		if isTemplateURL(u) {
			t.Errorf("expected %q to be treated as a real link", u)
		}
	}
}

func TestIsCrawlablePageURL(t *testing.T) {
	for _, raw := range []string{"https://example.com/", "https://example.com/getting-started", "https://example.com/index.html"} {
		u, _ := url.Parse(raw)
		if !isCrawlablePageURL(u) {
			t.Errorf("document URL rejected: %s", raw)
		}
	}
	for _, raw := range []string{"https://example.com/app.js", "https://example.com/site.css", "https://example.com/favicon.ico", "https://example.com/changelog.rss"} {
		u, _ := url.Parse(raw)
		if isCrawlablePageURL(u) {
			t.Errorf("static asset accepted as page: %s", raw)
		}
	}
}
