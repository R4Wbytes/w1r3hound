package modules

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

// Iteration 6 (WSTG-CONF-04, Juice Shop /ftp): robots.txt Disallow entries are
// the site owner's own inventory of paths to hide, but the metafiles module
// only reported them and never verified them. Against Juice Shop that meant the
// bare "robots.txt disallows /ftp" note (LOW) never became the real finding —
// /ftp is a serve-index directory listing exposing *.bak backups and a KeePass
// DB (server.ts: robots Disallow '/ftp' + serveIndex('ftp')). This test stands
// up that exact shape and asserts the listing is discovered and rated HIGH.
func TestMetafiles_RobotsDisallowDirectoryListing(t *testing.T) {
	// serve-index style listing served at /ftp/. Includes an absolute breadcrumb
	// link (<a href="/ftp">) and a parent link that must NOT be counted as entries.
	ftpListing := `<!DOCTYPE html><html><head><title>listing directory /ftp/</title></head>` +
		`<body><h1><a href="/">/</a> <a href="/ftp">ftp</a></h1>` +
		`<ul id="files" class="view-tiles">` +
		`<li><a href="../" class="icon icon-directory">..</a></li>` +
		`<li><a href="quarantine/" class="icon icon-directory" title="quarantine">quarantine</a></li>` +
		`<li><a href="acquisitions.md" class="icon icon-default" title="acquisitions.md">acquisitions.md</a></li>` +
		`<li><a href="coupons_2013.md.bak" class="icon icon-default" title="coupons_2013.md.bak">coupons_2013.md.bak</a></li>` +
		`<li><a href="incident-support.kdbx" class="icon icon-default" title="incident-support.kdbx">incident-support.kdbx</a></li>` +
		`<li><a href="package.json.bak" class="icon icon-default" title="package.json.bak">package.json.bak</a></li>` +
		`<li><a href="legal.md" class="icon icon-default" title="legal.md">legal.md</a></li>` +
		`</ul></body></html>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /ftp\n"))
		case "/ftp/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(ftpListing))
		default:
			http.NotFound(w, r) // real 404s ⇒ calibrateCatchAll finds no shell
		}
	}))
	defer srv.Close()

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL
	report := core.NewReport(srv.URL)

	RunMetafiles(cfg, report, core.NewLogger(false))

	var dl *core.Finding
	var robots *core.Finding
	for i := range report.Findings {
		if strings.HasPrefix(report.Findings[i].Title, "robots.txt lists") {
			robots = &report.Findings[i]
		}
		if report.Findings[i].WSTG == "WSTG-CONF-04" &&
			strings.Contains(report.Findings[i].Title, "Directory listing") {
			dl = &report.Findings[i]
			break
		}
	}
	if dl == nil {
		t.Fatal("expected a WSTG-CONF-04 directory-listing finding for /ftp, got none")
	}
	if robots == nil || robots.Severity != core.SevInfo {
		t.Errorf("robots.txt directives should be informational hints, got %+v", robots)
	}
	if dl.Severity != core.SevHigh {
		t.Errorf("directory listing with backup files must be HIGH, got %s", dl.Severity)
	}
	if !strings.Contains(dl.Title, "/ftp") {
		t.Errorf("finding should name the /ftp path, got %q", dl.Title)
	}
	for _, want := range []string{"coupons_2013.md.bak", "incident-support.kdbx", "package.json.bak"} {
		if !strings.Contains(dl.Description, want) {
			t.Errorf("description should list sensitive file %q; got %q", want, dl.Description)
		}
	}

	entries, ok := dl.Data.([]string)
	if !ok {
		t.Fatalf("finding Data should be []string entries, got %T", dl.Data)
	}
	// Breadcrumb / parent links must not leak in as entries.
	for _, bad := range entries {
		if bad == "" || bad == ".." || bad == "/" || bad == "/ftp" || strings.HasPrefix(bad, "/") {
			t.Errorf("breadcrumb/parent link leaked into entries: %q", bad)
		}
	}
	if !contains(entries, "quarantine") || !contains(entries, "legal.md") {
		t.Errorf("expected real entries (quarantine, legal.md) in %v", entries)
	}
}

func TestIsDirectoryListing(t *testing.T) {
	yes := map[string]string{
		"serve-index": `<title>listing directory /ftp/</title><ul id="files">x</ul>`,
		"apache":      `<html><head><title>Index of /backup</title></head><body><h1>Index of /backup</h1></body></html>`,
		"serve-tiles": `<div><ul id="files" class="view-tiles"><li class="icon icon-directory">x</li></ul></div>`,
	}
	for name, body := range yes {
		if !isDirectoryListing(body) {
			t.Errorf("%s listing should be detected as a directory index", name)
		}
	}
	no := map[string]string{
		"spa-shell":  `<!DOCTYPE html><html><head><title>OWASP Juice Shop</title></head><body><app-root></app-root></body></html>`,
		"normal":     `<html><head><title>Contact Us</title></head><body><form></form></body></html>`,
		"plain-file": `{"version":3,"mappings":"AAAA"}`,
	}
	for name, body := range no {
		if isDirectoryListing(body) {
			t.Errorf("%s must NOT be flagged as a directory listing", name)
		}
	}
}

func TestSensitiveListingFiles(t *testing.T) {
	entries := []string{
		"legal.md", "acquisitions.md", "eastere.gg", "quarantine",
		"package.json.bak", "coupons_2013.md.bak", "incident-support.kdbx",
		"encrypt.pyc", "backup.sql", "keys.pem",
		// Logs, incl. rotated names where ".log" is not the final suffix
		// (Juice Shop /support/logs, the accessLogDisclosureChallenge).
		"error.log", "access.log.2026-08-11", "app.log.1",
		// Look-alikes that must NOT be mistaken for logs.
		"catalog.js", "blog.html", "changelog.md",
	}
	got := sensitiveListingFiles(entries)
	for _, want := range []string{
		"package.json.bak", "coupons_2013.md.bak", "incident-support.kdbx",
		"encrypt.pyc", "backup.sql", "keys.pem",
		"error.log", "access.log.2026-08-11", "app.log.1",
	} {
		if !contains(got, want) {
			t.Errorf("expected %q to be flagged sensitive; got %v", want, got)
		}
	}
	for _, safe := range []string{
		"legal.md", "acquisitions.md", "eastere.gg", "quarantine",
		"catalog.js", "blog.html", "changelog.md",
	} {
		if contains(got, safe) {
			t.Errorf("%q is not a backup/secret/log and must not be flagged", safe)
		}
	}
}

func TestMetafiles_ClientCredentialsAndReflectedWPPathNotFindings(t *testing.T) {
	var baseURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			_, _ = w.Write([]byte("Sitemap: " + baseURL + "/sitemap.xml\n"))
		case "/sitemap.xml":
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<urlset><url><loc>` + baseURL + `/</loc></url></urlset>`))
		case "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"grant_types_supported":["authorization_code","client_credentials"]}`))
		case "/wp-json/":
			// HackerOne-style claimed-handle profile: the requested path is
			// reflected repeatedly but this is not a WordPress REST response.
			_, _ = w.Write([]byte(`<html><meta property="og:title" content="profile - wp-json">` +
				`<meta property="og:url" content="` + baseURL + `/wp-json"></html>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	baseURL = srv.URL

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL
	cfg.Domain = "127.0.0.1"
	report := core.NewReport(srv.URL)
	RunMetafiles(cfg, report, core.NewLogger(false))

	var result *MetafilesResult
	for i := range report.Findings {
		f := &report.Findings[i]
		if strings.Contains(f.Title, "dangerous grant") {
			t.Errorf("client_credentials is a standard grant, got false finding %q", f.Title)
		}
		if strings.Contains(f.Title, "WordPress REST") {
			t.Errorf("reflected claimed handle produced false WordPress finding %q", f.Title)
		}
		if data, ok := f.Data.(MetafilesResult); ok {
			result = &data
		}
	}
	if result == nil {
		t.Fatal("metafiles result missing")
	}
	if len(result.Sitemaps) != 1 || result.Sitemaps[0] != srv.URL+"/sitemap.xml" {
		t.Fatalf("duplicate sitemap probes/results were not removed: %v", result.Sitemaps)
	}
}

func TestLooksLikeWordPressREST(t *testing.T) {
	if !looksLikeWordPressREST(`{"namespaces":["wp/v2"],"routes":{}}`, "/wp-json/") {
		t.Error("valid WordPress REST root rejected")
	}
	if looksLikeWordPressREST(`<html>profile wp-json</html>`, "/wp-json/") {
		t.Error("HTML reflecting the requested handle accepted as WordPress REST")
	}
	if !looksLikeWordPressREST(`[]`, "/wp-json/wp/v2/users") {
		t.Error("empty but valid WordPress users JSON response rejected")
	}
}
