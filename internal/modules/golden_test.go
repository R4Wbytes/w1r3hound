package modules

import (
	"bytes"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

// updateGolden regenerates the committed golden snapshots:
//
//	go test ./internal/modules/ -run TestGoldenFindings -update-golden
var updateGolden = flag.Bool("update-golden", false, "regenerate FP/FN golden snapshots")

// normFinding is the stable subset of a Finding we snapshot: detection + WSTG +
// severity. Volatile Data and the target's random host:port are excluded so the
// golden is deterministic across runs (see FALSE_POSITIVES_NEGATIVES.md §2.2).
type normFinding struct {
	Severity string `json:"severity"`
	Module   string `json:"module"`
	WSTG     string `json:"wstg_id,omitempty"`
	Title    string `json:"title"`
}

func normalizeFindings(rep *core.ReconReport, redact []string) []normFinding {
	out := make([]normFinding, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		title := f.Title
		for _, s := range redact {
			if s != "" {
				title = strings.ReplaceAll(title, s, "TARGET")
			}
		}
		out = append(out, normFinding{
			Severity: string(f.Severity),
			Module:   f.Module,
			WSTG:     f.WSTG,
			Title:    title,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity < out[j].Severity
		}
		if out[i].Module != out[j].Module {
			return out[i].Module < out[j].Module
		}
		return out[i].Title < out[j].Title
	})
	return out
}

// redactionsFor returns the substrings (target URL + host:port) to strip from
// finding titles so the snapshot doesn't capture the random test port.
func redactionsFor(rawURL string) []string {
	red := []string{rawURL}
	if u, err := url.Parse(rawURL); err == nil {
		red = append(red, u.Host)
	}
	return red
}

type goldenCase struct {
	name string
	// run stands up a fixture, runs the module(s), and returns the report plus
	// the substrings to redact from titles.
	run func(t *testing.T) (*core.ReconReport, []string)
}

// The serve-index /ftp fixture (WSTG-CONF-04) — a robots Disallow plus a
// directory listing exposing backup/secret files.
func ftpListingServer(t *testing.T) *httptest.Server {
	listing := `<!DOCTYPE html><html><head><title>listing directory /ftp/</title></head>` +
		`<body><ul id="files" class="view-tiles">` +
		`<li><a href="../" class="icon icon-directory">..</a></li>` +
		`<li><a href="coupons_2013.md.bak">coupons_2013.md.bak</a></li>` +
		`<li><a href="package.json.bak">package.json.bak</a></li>` +
		`<li><a href="incident-support.kdbx">incident-support.kdbx</a></li>` +
		`<li><a href="legal.md">legal.md</a></li>` +
		`</ul></body></html>`
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /ftp\n"))
		case "/ftp/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(listing))
		default:
			http.NotFound(w, r)
		}
	}))
}

var goldenCases = []goldenCase{
	{
		name: "metafiles_ftp_directory_listing",
		run: func(t *testing.T) (*core.ReconReport, []string) {
			srv := ftpListingServer(t)
			t.Cleanup(srv.Close)
			cfg := core.DefaultConfig()
			cfg.Target = srv.URL
			cfg.Domain = "127.0.0.1"
			rep := core.NewReport(srv.URL)
			RunMetafiles(cfg, rep, core.NewLogger(false))
			return rep, redactionsFor(srv.URL)
		},
	},
	{
		name: "api_stacktrace_disclosure",
		run: func(t *testing.T) (*core.ReconReport, []string) {
			trace := `<html><head><title>Error: Unexpected path</title></head><body>` +
				`<pre>Error: Unexpected path<br>    at trim_prefix ` +
				`(/app/node_modules/express/lib/router/index.js:18:18)</pre></body></html>`
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api" || r.URL.Path == "/rest" {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = w.Write([]byte(trace))
					return
				}
				http.NotFound(w, r)
			}))
			t.Cleanup(srv.Close)
			cfg := core.DefaultConfig()
			cfg.Target = srv.URL
			cfg.Domain = "127.0.0.1"
			rep := core.NewReport(srv.URL)
			RunAPI(cfg, rep, core.NewLogger(false))
			return rep, redactionsFor(srv.URL)
		},
	},
	{
		name: "headers_missing_security_headers",
		run: func(t *testing.T) (*core.ReconReport, []string) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write([]byte("<html><head><title>bare</title></head><body>hi</body></html>"))
			}))
			t.Cleanup(srv.Close)
			cfg := core.DefaultConfig()
			cfg.Target = srv.URL
			cfg.Domain = "127.0.0.1"
			rep := core.NewReport(srv.URL)
			RunHeaders(cfg, rep, core.NewLogger(false))
			return rep, redactionsFor(srv.URL)
		},
	},
	{
		name: "dirbrute_hidden_path_found",
		run: func(t *testing.T) (*core.ReconReport, []string) {
			// Proper 404s for unknown paths -> a clean soft-404 baseline, so the
			// single real 200 path is a true positive (not a soft-404 FP).
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/admin" {
					w.Header().Set("Content-Type", "text/html")
					_, _ = w.Write([]byte("<html><head><title>Admin</title></head><body>Admin Panel</body></html>"))
					return
				}
				http.NotFound(w, r)
			}))
			t.Cleanup(srv.Close)
			wl := filepath.Join(t.TempDir(), "words.txt")
			if err := os.WriteFile(wl, []byte("admin\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			cfg := core.DefaultConfig()
			cfg.Target = srv.URL
			cfg.Domain = "127.0.0.1"
			cfg.DirWordlist = wl
			rep := core.NewReport(srv.URL)
			RunDirBrute(cfg, rep, core.NewLogger(false))
			return rep, redactionsFor(srv.URL)
		},
	},
	{
		// A server that reflects any Origin back into Access-Control-Allow-Origin
		// AND allows credentials — the classic HIGH CORS misconfiguration
		// (WSTG-CLNT-07). Pins the reflected-origin-with-credentials detector.
		name: "cors_reflects_origin_with_credentials",
		run: func(t *testing.T) (*core.ReconReport, []string) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if origin := r.Header.Get("Origin"); origin != "" {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
				_, _ = w.Write([]byte("ok"))
			}))
			t.Cleanup(srv.Close)
			cfg := core.DefaultConfig()
			cfg.Target = srv.URL
			cfg.Domain = "127.0.0.1"
			rep := core.NewReport(srv.URL)
			RunCORS(cfg, rep, core.NewLogger(false))
			return rep, redactionsFor(srv.URL)
		},
	},
}

// TestGoldenFindings scans each hermetic fixture and diffs the normalized
// findings against a committed golden snapshot. Any detection or severity drift
// (an FP/FN, or a severity recalibration) fails until the golden is refreshed
// and reviewed.
func TestGoldenFindings(t *testing.T) {
	for _, c := range goldenCases {
		t.Run(c.name, func(t *testing.T) {
			rep, redact := c.run(t)
			got, err := json.MarshalIndent(normalizeFindings(rep, redact), "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("testdata", "golden", c.name+".json")

			if *updateGolden {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(got, '\n'), 0o644); err != nil {
					t.Fatal(err)
				}
				t.Logf("updated golden %s (%d findings)", path, len(rep.Findings))
				return
			}

			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("missing golden %s (run: go test ./internal/modules/ -run TestGoldenFindings -update-golden): %v", path, err)
			}
			if !bytes.Equal(bytes.TrimSpace(want), bytes.TrimSpace(got)) {
				t.Errorf("golden mismatch for %s (run -update-golden to refresh after reviewing):\n--- want ---\n%s\n--- got ---\n%s", c.name, want, got)
			}
		})
	}
}

// TestNegativeControlNoFalsePositives is the FP tripwire (FALSE_POSITIVES §2.1):
// a hardened, clean site must yield zero MEDIUM-or-higher findings across the
// highest-FP-risk detectors.
func TestNegativeControlNoFalsePositives(t *testing.T) {
	cleanHTML := `<!DOCTYPE html><html><head><title>Hardened</title></head>` +
		`<body><h1>Welcome</h1><p>Nothing to see here.</p></body></html>`
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Content-Security-Policy", "default-src 'self'")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "geolocation=(), microphone=()")
		if r.URL.Path == "/robots.txt" || strings.HasPrefix(r.URL.Path, "/ftp") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(cleanHTML))
	}))
	defer srv.Close()

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL // https; SkipSSLCheck defaults true so the self-signed cert is accepted
	cfg.Domain = "127.0.0.1"
	rep := core.NewReport(srv.URL)
	RunHeaders(cfg, rep, core.NewLogger(false))
	RunContent(cfg, rep, core.NewLogger(false))
	RunMetafiles(cfg, rep, core.NewLogger(false))

	for _, f := range rep.Findings {
		switch f.Severity {
		case core.SevMedium, core.SevHigh, core.SevCritical:
			t.Errorf("false positive on hardened site: [%s] %s (%s)", f.Severity, f.Title, f.Module)
		}
	}
}

// TestNegativeControlBroadNoFalsePositives widens the FP tripwire
// (FALSE_POSITIVES §2.1) to the CORS and API-doc detectors: a hardened site
// that 404s every unknown path (no open dirs, no api-docs, no CORS headers)
// with clean security headers must not trip ANY of these at MEDIUM-or-higher.
func TestNegativeControlBroadNoFalsePositives(t *testing.T) {
	clean := `<!DOCTYPE html><html><head><title>Hardened</title></head>` +
		`<body><h1>OK</h1><p>Nothing to see here.</p></body></html>`
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Content-Security-Policy", "default-src 'self'")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "geolocation=(), microphone=()")
		// Only the root exists; every other path (api-docs, admin, .git, …) 404s.
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(clean))
	}))
	defer srv.Close()

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL // https; SkipSSLCheck defaults true (self-signed accepted)
	cfg.Domain = "127.0.0.1"
	rep := core.NewReport(srv.URL)
	log := core.NewLogger(false)

	RunHeaders(cfg, rep, log)
	RunContent(cfg, rep, log)
	RunMetafiles(cfg, rep, log)
	RunAPI(cfg, rep, log)
	RunCORS(cfg, rep, log)

	for _, f := range rep.Findings {
		switch f.Severity {
		case core.SevMedium, core.SevHigh, core.SevCritical:
			t.Errorf("false positive on hardened site: [%s] %s (%s)", f.Severity, f.Title, f.Module)
		}
	}
}
