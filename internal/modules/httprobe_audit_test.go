package modules

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/w1r3hound/w1r3hound/internal/core"
)

func TestHTTProbe_ExactTargetReplacesBaseDefaultPorts(t *testing.T) {
	icon := []byte{0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x10, 0x10}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/assets/app.ico":
			w.Header().Set("Content-Type", "image/x-icon")
			_, _ = w.Write(icon)
		case "/favicon.ico":
			// SPA catch-all: this must never be hashed as the favicon.
			_, _ = fmt.Fprint(w, "<!doctype html><html><title>test app</title></html>")
		default:
			_, _ = fmt.Fprint(w, `<html><title>test app</title><link href="/assets/app.ico" rel="shortcut icon"></html>`)
		}
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := core.DefaultConfig()
	cfg.Target = srv.URL
	cfg.Domain = u.Hostname()
	cfg.Concurrency = 4
	cfg.Timeout = time.Second
	report := core.NewReport(srv.URL)

	RunHTTProbe(cfg, report, core.NewLogger(false))

	if len(report.Findings) != 1 {
		t.Fatalf("expected one HTTP probe finding, got %d", len(report.Findings))
	}
	result, ok := report.Findings[0].Data.(ProbeResult)
	if !ok {
		t.Fatalf("finding data type = %T, want ProbeResult", report.Findings[0].Data)
	}
	if result.TotalProbed != 1 || result.TotalLive != 1 {
		t.Fatalf("exact target should be one live logical host, got %d/%d", result.TotalLive, result.TotalProbed)
	}
	if len(result.LiveHosts) != 1 || result.LiveHosts[0].URL != srv.URL {
		t.Fatalf("unexpected live-host records: %+v", result.LiveHosts)
	}
	wantHash := fmt.Sprintf("%d", int32(murmur3Hash32(base64EncodeMime(icon))))
	if result.LiveHosts[0].FaviconHash != wantHash {
		t.Fatalf("favicon hash = %q, want %q", result.LiveHosts[0].FaviconHash, wantHash)
	}
	if result.FaviconHashes[u.Host] != wantHash {
		t.Fatalf("favicon map = %+v, want %s=%s", result.FaviconHashes, u.Host, wantHash)
	}
}

func TestComputeFaviconRejectsHTMLCatchAll(t *testing.T) {
	const page = "<!doctype html><html><title>SPA</title></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, page)
	}))
	defer srv.Close()

	cfg := core.DefaultConfig()
	cfg.Timeout = time.Second
	if got := computeFavicon(core.NewHTTPClient(cfg), srv.URL, page, cfg); got != "" {
		t.Fatalf("HTML catch-all produced bogus favicon hash %q", got)
	}
}

func TestHTTProbe_PreservesCrossHostRedirect(t *testing.T) {
	const destination = "https://www.example.test/"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination, http.StatusFound)
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL
	cfg.Domain = u.Hostname()
	cfg.Timeout = time.Second
	report := core.NewReport(srv.URL)
	RunHTTProbe(cfg, report, core.NewLogger(false))

	result := report.Findings[0].Data.(ProbeResult)
	if len(result.LiveHosts) != 1 {
		t.Fatalf("live hosts = %v", result.LiveHosts)
	}
	host := result.LiveHosts[0]
	if host.StatusCode != http.StatusFound || host.Redirect != destination {
		t.Fatalf("redirect metadata lost: %+v", host)
	}
}
