package core

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestValidateProxy(t *testing.T) {
	valid := []string{
		"http://127.0.0.1:8080",
		"https://proxy.local:3128",
		"socks5://127.0.0.1:1080",
		"socks5h://10.0.0.1:1080",
		"http://burp", // host without a port is accepted
	}
	for _, v := range valid {
		if _, err := ValidateProxy(v); err != nil {
			t.Errorf("ValidateProxy(%q) unexpected error: %v", v, err)
		}
	}
	invalid := []string{
		"",                   // empty
		"127.0.0.1:8080",     // no scheme
		"ftp://127.0.0.1:21", // unsupported scheme
		"http://",            // no host
		"://nope",            // no scheme, no host
	}
	for _, v := range invalid {
		if _, err := ValidateProxy(v); err == nil {
			t.Errorf("ValidateProxy(%q) expected an error, got nil", v)
		}
	}
}

// TestNewHTTPClientRoutesThroughProxy proves that, with cfg.Proxy set, requests
// are sent to the proxy rather than dialed directly: a forward proxy receives
// the absolute request URI, so the unresolvable target host is never dialed.
func TestNewHTTPClientRoutesThroughProxy(t *testing.T) {
	var hits int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.IsAbs() { // absolute URI == forward-proxied request
			atomic.AddInt32(&hits, 1)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer proxy.Close()

	cfg := DefaultConfig()
	cfg.Proxy = proxy.URL
	client := NewHTTPClient(cfg)

	resp, err := client.Get("http://example.invalid/recon")
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	_ = resp.Body.Close()
	if atomic.LoadInt32(&hits) == 0 {
		t.Fatal("request did not go through the configured proxy")
	}
}

// TestNewHTTPClientNoProxyByDefault confirms the default (no proxy) path dials
// the target directly and never touches a proxy.
func TestNewHTTPClientNoProxyByDefault(t *testing.T) {
	var proxyHits int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&proxyHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()

	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("direct"))
	}))
	defer direct.Close()

	cfg := DefaultConfig() // no proxy configured
	client := NewHTTPClient(cfg)
	resp, err := client.Get(direct.URL)
	if err != nil {
		t.Fatalf("direct request failed: %v", err)
	}
	_ = resp.Body.Close()
	if atomic.LoadInt32(&proxyHits) != 0 {
		t.Fatal("request was routed through a proxy even though none was configured")
	}
}

// TestEgressControlExemptsProxyHost verifies the -block-private-egress guard
// allows the dial to a loopback interception proxy while still blocking every
// other private/loopback destination.
func TestEgressControlExemptsProxyHost(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BlockPrivateEgress = true
	cfg.Proxy = "http://127.0.0.1:8080"
	ctrl := egressControl(cfg)
	if ctrl == nil {
		t.Fatal("egressControl returned nil with BlockPrivateEgress on")
	}
	if err := ctrl("tcp", "127.0.0.1:8080", nil); err != nil {
		t.Errorf("dial to the configured proxy was blocked: %v", err)
	}
	if err := ctrl("tcp", "127.0.0.1:9999", nil); err == nil {
		t.Error("expected a non-proxy loopback dial to be blocked")
	}
	if err := ctrl("tcp", "10.1.2.3:80", nil); err == nil {
		t.Error("expected a private-range dial to be blocked")
	}
}

func TestProxyCACertPool(t *testing.T) {
	if pool := proxyCACertPool(filepath.Join(t.TempDir(), "missing.pem")); pool != nil {
		t.Error("expected a nil pool for a missing CA file")
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if pool := proxyCACertPool(bad); pool != nil {
		t.Error("expected a nil pool for a non-PEM file")
	}
}
