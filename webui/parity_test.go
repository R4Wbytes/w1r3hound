package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func boolPtr(b bool) *bool { return &b }

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// TestBuildArgsParityFullArgvExact pins the exact argv (and stable order) when
// every CLI-parity advanced option is set. This is the parity contract: if a
// flag's name, value formatting or ordering drifts, this fails.
func TestBuildArgsParityFullArgvExact(t *testing.T) {
	results := t.TempDir()
	wl := t.TempDir()

	dirWL := filepath.Join(wl, "dirs.txt")
	if err := os.WriteFile(dirWL, []byte("admin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	resFile := filepath.Join(wl, "resolvers.txt")
	if err := os.WriteFile(resFile, []byte("1.1.1.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	resolvedDirWL, _ := filepath.EvalSymlinks(dirWL)
	resolvedRes, _ := filepath.EvalSymlinks(resFile)

	args, base, err := buildArgs(&ScanRequest{
		Target:             "example.com",
		Authorized:         true,
		Output:             "out",
		DirWordlist:        "dirs.txt",
		DirExt:             ".bak,.php,~",
		Headers:            []string{"X-Api-Key: abc123", "Authorization: Bearer z"},
		SkipTLSVerify:      boolPtr(false), // opt into verification
		BlockPrivateEgress: true,
		Resolver:           "8.8.8.8:53",
		Resolvers:          "resolvers.txt",
		WaybackLimit:       1234,
		CrawlPages:         42,
		JSFiles:            7,
	}, wl, results)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if base != "out" {
		t.Fatalf("base = %q, want out", base)
	}
	want := []string{
		"-t", "example.com",
		"-dir-wordlist", resolvedDirWL,
		"-dir-ext", ".bak,.php,~",
		"-H", "X-Api-Key: abc123",
		"-H", "Authorization: Bearer z",
		"-skip-tls-verify=false",
		"-block-private-egress",
		"-resolver", "8.8.8.8:53",
		"-resolvers", resolvedRes,
		"-wayback-limit", "1234",
		"-crawl-pages", "42",
		"-js-files", "7",
		"-o", filepath.Join(results, "out"),
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args =\n%v\nwant\n%v", args, want)
	}
}

func TestValidateHeaders(t *testing.T) {
	ok, err := validateHeaders([]string{" X-A: 1 ", "", "   ", "Authorization: Bearer x"})
	if err != nil {
		t.Fatalf("valid headers rejected: %v", err)
	}
	if !reflect.DeepEqual(ok, []string{"X-A: 1", "Authorization: Bearer x"}) {
		t.Fatalf("canonicalised = %v", ok)
	}

	bad := [][]string{
		{"X-Evil: a\r\nInjected: 1"},          // CRLF header-splitting
		{"X-Evil: a\nInjected: 1"},            // bare LF
		{"X-Null: a\x00b"},                    // NUL
		{"NoColonHeader"},                     // missing colon
		{":novalue"},                          // empty name
		{"Bad Name: v"},                       // space in name (not a token)
		{"X-A:"},                              // empty value
		{strings.Repeat("N", 129) + ": v"},    // name too long (>128)
		{"X-A: " + strings.Repeat("v", 1025)}, // value too long (>1024)
	}
	for _, in := range bad {
		if _, err := validateHeaders(in); err == nil {
			t.Errorf("validateHeaders(%q) accepted, want error", in)
		}
	}

	many := make([]string, 33)
	for i := range many {
		many[i] = "X-A: 1"
	}
	if _, err := validateHeaders(many); err == nil {
		t.Error("33 headers accepted, want 'too many'")
	}
}

// TestBuildArgsHeaderInjectionRejected proves the injection sink is closed at
// the buildArgs boundary (the HTTP handler surfaces this as a 400).
func TestBuildArgsHeaderInjectionRejected(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := buildArgs(&ScanRequest{
		Target:     "example.com",
		Authorized: true,
		Headers:    []string{"X-Evil: a\r\nHost: evil.example.com"},
	}, dir, dir); err == nil {
		t.Fatal("CRLF header injection accepted by buildArgs")
	}
}

func TestValidResolver(t *testing.T) {
	good := []string{"1.1.1.1", "8.8.8.8:53", "::1", "2001:db8::1", "[2001:db8::1]:53", "192.168.0.1:5353"}
	for _, s := range good {
		if !validResolver(s) {
			t.Errorf("validResolver(%q) = false, want true", s)
		}
	}
	bad := []string{"", "example.com", "dns.google", "1.1.1.1:0", "1.1.1.1:99999", "1.2.3", "1.1.1.1:", ":53", "has space", "8.8.8.8:53 "}
	for _, s := range bad {
		if validResolver(s) {
			t.Errorf("validResolver(%q) = true, want false", s)
		}
	}
}

func TestBuildArgsResolverRejectsHostname(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := buildArgs(&ScanRequest{Target: "example.com", Authorized: true, Resolver: "evil.example.com"}, dir, dir); err == nil {
		t.Fatal("hostname resolver accepted (should be IP/ip:port only)")
	}
}

func TestBuildArgsDirExt(t *testing.T) {
	dir := t.TempDir()
	okv := []string{".bak,.php,.zip,~", "php", ".tar.gz", "bak,old"}
	for _, v := range okv {
		if _, _, err := buildArgs(&ScanRequest{Target: "example.com", Authorized: true, Output: "o", DirExt: v}, dir, dir); err != nil {
			t.Errorf("dir-ext %q rejected: %v", v, err)
		}
	}
	badv := []string{"bad ext", ".a\r\n", "x;rm -rf", "a|b", strings.Repeat("a", 257)}
	for _, v := range badv {
		if _, _, err := buildArgs(&ScanRequest{Target: "example.com", Authorized: true, Output: "o", DirExt: v}, dir, dir); err == nil {
			t.Errorf("dir-ext %q accepted, want reject", v)
		}
	}
}

// TestBuildArgsParityPathConfinement ensures dir_wordlist and resolvers cannot
// escape the wordlists confinement dir (traversal, absolute, symlink escape).
func TestBuildArgsParityPathConfinement(t *testing.T) {
	results := t.TempDir()
	wl := t.TempDir()
	outside := t.TempDir()
	evil := filepath.Join(outside, "evil.txt")
	if err := os.WriteFile(evil, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(evil, filepath.Join(wl, "escape.txt")); err != nil {
		t.Fatal(err)
	}

	bads := []string{evil, "../" + filepath.Base(outside) + "/evil.txt", "escape.txt", "nope.txt"}
	for _, field := range []string{"dir_wordlist", "resolvers"} {
		for _, bad := range bads {
			req := &ScanRequest{Target: "example.com", Authorized: true, Output: "o"}
			if field == "dir_wordlist" {
				req.DirWordlist = bad
			} else {
				req.Resolvers = bad
			}
			if _, _, err := buildArgs(req, wl, results); err == nil {
				t.Errorf("%s=%q escaped confinement (accepted)", field, bad)
			}
		}
	}
}

func TestBuildArgsSkipTLSVerify(t *testing.T) {
	dir := t.TempDir()
	base := ScanRequest{Target: "example.com", Authorized: true, Output: "o"}

	// nil pointer -> CLI default (skip) -> flag omitted.
	args, _, err := buildArgs(&base, dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	if containsArg(args, "-skip-tls-verify=false") {
		t.Error("nil SkipTLSVerify must not emit -skip-tls-verify=false")
	}

	// explicit true == default skip -> still omitted.
	req := base
	req.SkipTLSVerify = boolPtr(true)
	args, _, _ = buildArgs(&req, dir, dir)
	if containsArg(args, "-skip-tls-verify=false") {
		t.Error("SkipTLSVerify=true must not emit verify-on")
	}

	// explicit false -> verification ON.
	req = base
	req.SkipTLSVerify = boolPtr(false)
	args, _, _ = buildArgs(&req, dir, dir)
	if !containsArg(args, "-skip-tls-verify=false") {
		t.Error("SkipTLSVerify=false must emit -skip-tls-verify=false")
	}
}

func TestBuildArgsBlockPrivateEgress(t *testing.T) {
	dir := t.TempDir()
	args, _, _ := buildArgs(&ScanRequest{Target: "example.com", Authorized: true, Output: "o", BlockPrivateEgress: true}, dir, dir)
	if !containsArg(args, "-block-private-egress") {
		t.Error("block-private-egress not emitted when true")
	}
	args, _, _ = buildArgs(&ScanRequest{Target: "example.com", Authorized: true, Output: "o"}, dir, dir)
	if containsArg(args, "-block-private-egress") {
		t.Error("block-private-egress emitted when false")
	}
}

func TestBuildArgsParityIntCaps(t *testing.T) {
	dir := t.TempDir()
	bad := []ScanRequest{
		{Target: "example.com", Authorized: true, WaybackLimit: -1},
		{Target: "example.com", Authorized: true, WaybackLimit: 100001},
		{Target: "example.com", Authorized: true, CrawlPages: -1},
		{Target: "example.com", Authorized: true, CrawlPages: 5001},
		{Target: "example.com", Authorized: true, JSFiles: -1},
		{Target: "example.com", Authorized: true, JSFiles: 2001},
	}
	for i := range bad {
		if _, _, err := buildArgs(&bad[i], dir, dir); err == nil {
			t.Errorf("case %d: out-of-range int accepted", i)
		}
	}

	args, _, err := buildArgs(&ScanRequest{
		Target: "example.com", Authorized: true, Output: "o",
		WaybackLimit: 100000, CrawlPages: 5000, JSFiles: 2000,
	}, dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"-wayback-limit", "100000", "-crawl-pages", "5000", "-js-files", "2000"} {
		if !containsArg(args, want) {
			t.Errorf("missing %q in %v", want, args)
		}
	}

	// zero -> omitted (engine default).
	args, _, _ = buildArgs(&ScanRequest{Target: "example.com", Authorized: true, Output: "o"}, dir, dir)
	for _, unexpected := range []string{"-wayback-limit", "-crawl-pages", "-js-files"} {
		if containsArg(args, unexpected) {
			t.Errorf("zero-value emitted %q", unexpected)
		}
	}
}
