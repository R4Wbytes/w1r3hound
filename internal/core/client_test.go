package core

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func clientTestCfg() *Config {
	c := DefaultConfig()
	c.Timeout = 5 * time.Second
	return c
}

// TestNewHTTPClientSkipTLSVerify covers the -skip-tls-verify flag effect: the
// shared client accepts a self-signed cert when SkipSSLCheck is on (the CLI
// default) and rejects it when verification is enforced.
func TestNewHTTPClientSkipTLSVerify(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := clientTestCfg()
	if !cfg.SkipSSLCheck {
		t.Fatal("DefaultConfig should default SkipSSLCheck=true (matches the CLI)")
	}
	resp, err := NewHTTPClient(cfg).Get(srv.URL)
	if err != nil {
		t.Fatalf("skip-verify on: unexpected error against self-signed server: %v", err)
	}
	resp.Body.Close()

	cfg2 := clientTestCfg()
	cfg2.SkipSSLCheck = false
	if _, err := NewHTTPClient(cfg2).Get(srv.URL); err == nil {
		t.Fatal("skip-verify off: expected a TLS verification error, got nil")
	} else if !strings.Contains(err.Error(), "x509") && !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected an x509/certificate error, got %v", err)
	}
}

// TestNewVerifiedHTTPClientAlwaysVerifies covers C-3: the verified client used
// for trusted third-party intel APIs (crt.sh, RDAP, Wayback, …) must reject an
// untrusted certificate even when the operator disabled TLS verification for the
// target traffic (SkipSSLCheck=true, the CLI default).
func TestNewVerifiedHTTPClientAlwaysVerifies(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := clientTestCfg()
	if !cfg.SkipSSLCheck {
		t.Fatal("DefaultConfig should default SkipSSLCheck=true (matches the CLI)")
	}
	// The target-traffic client honours the skip flag and accepts the self-signed cert.
	if resp, err := NewHTTPClient(cfg).Get(srv.URL); err != nil {
		t.Fatalf("target client: unexpected error against self-signed server: %v", err)
	} else {
		resp.Body.Close()
	}
	// The verified client must reject it regardless of SkipSSLCheck.
	if _, err := NewVerifiedHTTPClient(cfg).Get(srv.URL); err == nil {
		t.Fatal("verified client: expected a TLS verification error, got nil")
	} else if !strings.Contains(err.Error(), "x509") && !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected an x509/certificate error, got %v", err)
	}
}

// TestNewHTTPClientBlockPrivateEgress covers the -block-private-egress SSRF
// guard: with the guard on, a dial that resolves to loopback is refused; with
// it off (default), the same dial proceeds. Also satisfies SECURITY_ASSESSMENT
// §5 (C-2 re-verification).
func TestNewHTTPClientBlockPrivateEgress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := clientTestCfg()
	resp, err := NewHTTPClient(cfg).Get(srv.URL)
	if err != nil {
		t.Fatalf("egress guard off: unexpected error dialing loopback: %v", err)
	}
	resp.Body.Close()

	cfg2 := clientTestCfg()
	cfg2.BlockPrivateEgress = true
	if _, err := NewHTTPClient(cfg2).Get(srv.URL); err == nil {
		t.Fatal("egress guard on: expected the loopback dial to be blocked, got nil")
	} else if !strings.Contains(err.Error(), "block") && !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("expected an egress-blocked error, got %v", err)
	}
}

// TestNewHTTPClientRequestHeaders covers -header/-H: configured headers reach
// the wire on every request via requestHeaderTransport.
func TestNewHTTPClientRequestHeaders(t *testing.T) {
	var gotAuth, gotBB string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotBB = r.Header.Get("X-Bug-Bounty")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := clientTestCfg()
	cfg.RequestHeaders = map[string]string{
		"Authorization": "Bearer test-token",
		"X-Bug-Bounty":  "w1r3hound",
	}
	resp, err := NewHTTPClient(cfg).Get(srv.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if gotAuth != "Bearer test-token" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer test-token")
	}
	if gotBB != "w1r3hound" {
		t.Errorf("X-Bug-Bounty header = %q, want %q", gotBB, "w1r3hound")
	}
}
