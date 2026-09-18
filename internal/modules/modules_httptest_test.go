package modules

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

// ── RunMetafiles ──

func TestRunMetafiles_RobotsTxtDisallowGeneratesFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin/\nDisallow: /backup/\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL
	cfg.Domain = "127.0.0.1"
	report := core.NewReport(cfg.Domain)
	RunMetafiles(cfg, report, core.NewLogger(false))

	found := false
	for _, f := range report.Snapshot().Findings {
		if f.Module == "metafiles" && strings.Contains(f.Title, "robots.txt") && strings.Contains(f.Title, "disallowed") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected a finding about robots.txt disallowed paths")
	}
}

func TestRunMetafiles_SecurityTxtBountyFinding(t *testing.T) {
	secTxt := "Contact: mailto:security@example.com\nExpires: 2099-01-01T00:00:00Z\nPolicy: https://example.com/bounty\nhackerone\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/security.txt" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(secTxt))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL
	cfg.Domain = "127.0.0.1"
	report := core.NewReport(cfg.Domain)
	RunMetafiles(cfg, report, core.NewLogger(false))

	found := false
	for _, f := range report.Snapshot().Findings {
		if strings.Contains(f.Title, "Bug bounty") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected a bug-bounty finding from security.txt")
	}
}

// ── RunWebServer ──

func TestRunWebServer_DetectsXPoweredBy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.21.0")
		w.Header().Set("X-Powered-By", "Express")
		if r.Method == "OPTIONS" {
			w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL
	cfg.Domain = "127.0.0.1"
	report := core.NewReport(cfg.Domain)
	RunWebServer(cfg, report, core.NewLogger(false))

	found := false
	for _, f := range report.Snapshot().Findings {
		if strings.Contains(f.Title, "X-Powered-By") && strings.Contains(f.Title, "Express") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected a finding for exposed X-Powered-By header")
	}
}

func TestRunWebServer_DetectsLeakyHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-AspNet-Version", "4.0.30319")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL
	cfg.Domain = "127.0.0.1"
	report := core.NewReport(cfg.Domain)
	RunWebServer(cfg, report, core.NewLogger(false))

	found := false
	for _, f := range report.Snapshot().Findings {
		if strings.Contains(f.Title, "X-AspNet-Version") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected a finding for X-AspNet-Version header")
	}
}

// ── RunAPI ──

func TestRunAPI_SkipsPassiveMode(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Passive = true
	report := core.NewReport("example.com")
	RunAPI(cfg, report, core.NewLogger(false))

	if len(report.Snapshot().Findings) != 0 {
		t.Fatal("expected no findings in passive mode")
	}
}

func TestRunAPI_DetectsGraphQLIntrospection(t *testing.T) {
	introspectionResp := `{"data":{"__schema":{"types":[{"name":"Query","kind":"OBJECT"},{"name":"User","kind":"OBJECT"},{"name":"Post","kind":"OBJECT"}],"queryType":{"name":"Query"},"mutationType":null}}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" {
			if r.Method == "POST" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(introspectionResp))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"errors":[{"message":"Must provide query string"}]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL
	cfg.Domain = "127.0.0.1"
	report := core.NewReport(cfg.Domain)
	RunAPI(cfg, report, core.NewLogger(false))

	found := false
	for _, f := range report.Snapshot().Findings {
		if strings.Contains(f.Title, "GraphQL introspection enabled") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected a GraphQL introspection finding")
	}
}

func TestRunAPI_DetectsSwaggerJSON(t *testing.T) {
	swaggerDoc := `{"swagger":"2.0","info":{"title":"Test","version":"1.0"},"paths":{"/users":{"get":{},"post":{}},"/items":{"get":{},"delete":{}}}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(swaggerDoc))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL
	cfg.Domain = "127.0.0.1"
	report := core.NewReport(cfg.Domain)
	RunAPI(cfg, report, core.NewLogger(false))

	found := false
	for _, f := range report.Snapshot().Findings {
		if strings.Contains(f.Title, "API documentation") || strings.Contains(f.Title, "Swagger") || strings.Contains(f.Title, "OpenAPI") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected a Swagger/API documentation finding")
	}
}

// ── RunHTTProbe ──

func TestRunHTTProbe_DetectsLiveHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "testserver")
		_, _ = w.Write([]byte(`<html><head><title>Test App</title></head><body>OK</body></html>`))
	}))
	defer srv.Close()

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL
	cfg.Domain = "127.0.0.1"
	report := core.NewReport(cfg.Domain)
	RunHTTProbe(cfg, report, core.NewLogger(false))

	snap := report.Snapshot()
	for _, f := range snap.Findings {
		if f.Module != "httprobe" {
			continue
		}
		probeRes, ok := f.Data.(ProbeResult)
		if !ok {
			continue
		}
		if len(probeRes.LiveHosts) == 0 {
			t.Fatal("expected at least one live host")
		}
		lh := probeRes.LiveHosts[0]
		if lh.StatusCode != 200 {
			t.Errorf("live host status = %d, want 200", lh.StatusCode)
		}
		if lh.Title != "Test App" {
			t.Errorf("live host title = %q, want %q", lh.Title, "Test App")
		}
		return
	}
	t.Fatal("expected an httprobe finding with ProbeResult data")
}

func TestRunHTTProbe_SkipsPassiveMode(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Passive = true
	report := core.NewReport("example.com")
	RunHTTProbe(cfg, report, core.NewLogger(false))

	if len(report.Snapshot().Findings) != 0 {
		t.Fatal("expected no findings in passive mode")
	}
}
