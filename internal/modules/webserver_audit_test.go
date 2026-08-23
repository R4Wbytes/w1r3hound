package modules

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/w1r3hound/w1r3hound/internal/core"
)

func TestWebServerProbeClientPreservesInitialRedirectFingerprint(t *testing.T) {
	var destinationHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			w.Header().Set("Server", "edge-proxy")
			http.Redirect(w, r, "/final", http.StatusMovedPermanently)
			return
		}
		destinationHits++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfg := core.DefaultConfig()
	cfg.Target = srv.URL
	resp, err := newWebServerProbeClient(cfg).Get(srv.URL + "/start")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want initial redirect", resp.StatusCode)
	}
	if got := resp.Header.Get("Server"); got != "edge-proxy" {
		t.Fatalf("initial Server header = %q, want edge-proxy", got)
	}
	if destinationHits != 0 {
		t.Fatalf("redirect destination was requested %d time(s)", destinationHits)
	}
}
