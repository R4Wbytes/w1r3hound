package main

import "testing"

func TestBuildArgsEmitsProxy(t *testing.T) {
	req := &ScanRequest{Target: "example.com", Authorized: true, Proxy: "http://127.0.0.1:8080"}
	args, _, err := buildArgs(req, t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatalf("buildArgs error: %v", err)
	}
	if !proxyArgvHasPair(args, "-proxy", "http://127.0.0.1:8080") {
		t.Errorf("expected -proxy in argv, got %v", args)
	}
}

func TestBuildArgsRejectsBadProxy(t *testing.T) {
	req := &ScanRequest{Target: "example.com", Authorized: true, Proxy: "ftp://nope"}
	if _, _, err := buildArgs(req, t.TempDir(), t.TempDir()); err == nil {
		t.Fatal("expected an error for an unsupported proxy scheme")
	}
}

func TestBuildArgsNoProxyByDefault(t *testing.T) {
	req := &ScanRequest{Target: "example.com", Authorized: true}
	args, _, err := buildArgs(req, t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatalf("buildArgs error: %v", err)
	}
	for _, a := range args {
		if a == "-proxy" {
			t.Fatal("did not expect -proxy without a configured proxy")
		}
	}
}

func TestBuildMCPParamsCarriesProxy(t *testing.T) {
	req := &ScanRequest{Target: "example.com", Authorized: true, Source: "mcp", Proxy: "socks5://127.0.0.1:1080"}
	params, _, err := buildMCPParams(req, t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatalf("buildMCPParams error: %v", err)
	}
	if params.Proxy != "socks5://127.0.0.1:1080" {
		t.Errorf("expected proxy carried into MCP params, got %q", params.Proxy)
	}
}

func proxyArgvHasPair(args []string, flag, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}
