package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestValidateTarget(t *testing.T) {
	valid := []string{
		"example.com",
		"sub.domain.example.com",
		"example.com.", // trailing dot
		"127.0.0.1",
		"10.10.10.100",
		"::1",
		"2001:db8::1",
		"192.168.1.0/24",
		"10.0.0.0/8",
		"http://example.com",
		"https://example.com/path?q=1",
		"https://127.0.0.1:8080/app",
		"example.com:8443",
		"1.1.1.1:53",
	}
	for _, tc := range valid {
		if err := validateTarget(tc); err != nil {
			t.Errorf("validateTarget(%q) = %v, want nil", tc, err)
		}
	}

	invalid := []string{
		"",
		"   ",
		"has space",
		"tab\tinside",
		"null\x00byte",
		"line\nbreak",
		"-t",
		"-x",
		"--output=/etc/passwd",
		"http://user:pass@example.com", // userinfo not allowed
		"ftp://example.com",            // unsupported scheme
		"gopher://example.com",
		"http://",                 // empty host
		strings.Repeat("a", 2049), // too long
		"bad_host!",
	}
	for _, tc := range invalid {
		if err := validateTarget(tc); err == nil {
			t.Errorf("validateTarget(%q) = nil, want error", tc)
		}
	}
}

func TestNormalizeModules(t *testing.T) {
	t.Run("empty means all", func(t *testing.T) {
		out, err := normalizeModules(nil)
		if err != nil || out != nil {
			t.Fatalf("normalizeModules(nil) = %v, %v; want nil, nil", out, err)
		}
	})

	t.Run("alias and internal both resolve", func(t *testing.T) {
		out, err := normalizeModules([]string{"sentry"})
		if err != nil || !reflect.DeepEqual(out, []string{"headers"}) {
			t.Fatalf("alias resolve = %v, %v", out, err)
		}
		out, err = normalizeModules([]string{"headers"})
		if err != nil || !reflect.DeepEqual(out, []string{"headers"}) {
			t.Fatalf("internal resolve = %v, %v", out, err)
		}
	})

	t.Run("dedupe alias+internal", func(t *testing.T) {
		out, err := normalizeModules([]string{"sentry", "headers"})
		if err != nil || !reflect.DeepEqual(out, []string{"headers"}) {
			t.Fatalf("dedupe = %v, %v; want [headers]", out, err)
		}
	})

	t.Run("catalog order regardless of input order", func(t *testing.T) {
		out, err := normalizeModules([]string{"takeover", "recon", "portscan"})
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		want := []string{"whois", "portscan", "takeover"} // catalog order
		if !reflect.DeepEqual(out, want) {
			t.Fatalf("order = %v, want %v", out, want)
		}
	})

	t.Run("case-insensitive and trimmed", func(t *testing.T) {
		out, err := normalizeModules([]string{"  SENTRY ", "PortScan"})
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if !reflect.DeepEqual(out, []string{"headers", "portscan"}) {
			t.Fatalf("normalized = %v", out)
		}
	})

	t.Run("unknown rejected", func(t *testing.T) {
		if _, err := normalizeModules([]string{"definitely-not-a-module"}); err == nil {
			t.Fatal("unknown module accepted")
		}
	})

	t.Run("too many rejected", func(t *testing.T) {
		many := make([]string, len(moduleCatalog)+1)
		for i := range many {
			many[i] = "portscan"
		}
		if _, err := normalizeModules(many); err == nil {
			t.Fatal("too-many list accepted")
		}
	})
}

func TestResolveWordlist(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()

	// A regular file inside the confinement dir is accepted.
	good := filepath.Join(dir, "subs.txt")
	if err := os.WriteFile(good, []byte("a\nb\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A file outside the confinement dir (for traversal/absolute/symlink cases).
	out := filepath.Join(outside, "evil.txt")
	if err := os.WriteFile(out, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A subdirectory (non-regular) inside the confinement dir.
	if err := os.MkdirAll(filepath.Join(dir, "adir"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A symlink inside the dir pointing outside.
	link := filepath.Join(dir, "escape.txt")
	if err := os.Symlink(out, link); err != nil {
		t.Fatal(err)
	}

	t.Run("empty is a no-op", func(t *testing.T) {
		got, err := resolveWordlist(dir, "")
		if err != nil || got != "" {
			t.Fatalf("empty = %q, %v", got, err)
		}
	})
	t.Run("in-dir regular file ok", func(t *testing.T) {
		got, err := resolveWordlist(dir, "subs.txt")
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if resolved, _ := filepath.EvalSymlinks(good); got != resolved {
			t.Fatalf("got %q, want %q", got, resolved)
		}
	})
	t.Run("parent traversal rejected", func(t *testing.T) {
		if _, err := resolveWordlist(dir, "../"+filepath.Base(outside)+"/evil.txt"); err == nil {
			t.Fatal("traversal accepted")
		}
	})
	t.Run("absolute outside rejected", func(t *testing.T) {
		if _, err := resolveWordlist(dir, out); err == nil {
			t.Fatal("absolute outside accepted")
		}
	})
	t.Run("symlink escape rejected", func(t *testing.T) {
		if _, err := resolveWordlist(dir, "escape.txt"); err == nil {
			t.Fatal("symlink escape accepted")
		}
	})
	t.Run("non-regular rejected", func(t *testing.T) {
		if _, err := resolveWordlist(dir, "adir"); err == nil {
			t.Fatal("directory accepted as wordlist")
		}
	})
	t.Run("missing rejected", func(t *testing.T) {
		if _, err := resolveWordlist(dir, "nope.txt"); err == nil {
			t.Fatal("missing file accepted")
		}
	})
	t.Run("NUL byte rejected", func(t *testing.T) {
		if _, err := resolveWordlist(dir, "a\x00b"); err == nil {
			t.Fatal("NUL path accepted")
		}
	})
}

func TestBuildArgsAuthorizationGate(t *testing.T) {
	dir := t.TempDir()
	_, _, err := buildArgs(&ScanRequest{Target: "example.com", Authorized: false}, dir, dir)
	if err == nil || !strings.Contains(err.Error(), "authorized") {
		t.Fatalf("unauthorized buildArgs err = %v, want authorization error", err)
	}
}

func TestBuildArgsMinimal(t *testing.T) {
	results := t.TempDir()
	wl := t.TempDir()
	args, base, err := buildArgs(&ScanRequest{
		Target:     "example.com",
		Output:     "rep",
		Authorized: true,
	}, wl, results)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if base != "rep" {
		t.Fatalf("base = %q, want rep", base)
	}
	want := []string{"-t", "example.com", "-o", filepath.Join(results, "rep")}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args = %v\nwant %v", args, want)
	}
}

func TestBuildArgsFullArgvExact(t *testing.T) {
	results := t.TempDir()
	wl := t.TempDir()
	wlFile := filepath.Join(wl, "subs.txt")
	if err := os.WriteFile(wlFile, []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	resolvedWL, _ := filepath.EvalSymlinks(wlFile)

	args, base, err := buildArgs(&ScanRequest{
		Target:      "https://t.example.com",
		Modules:     []string{"sentry", "portscan"}, // -> headers,portscan in catalog order
		Concurrency: 50,
		Ports:       "full",
		Wordlist:    "subs.txt",
		Passive:     true,
		Rate:        100,
		TimeoutSec:  15,
		UserAgent:   "w1r3/1.0",
		Verbose:     true,
		Output:      "out",
		Authorized:  true,
	}, wl, results)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if base != "out" {
		t.Fatalf("base = %q, want out", base)
	}
	want := []string{
		"-t", "https://t.example.com",
		"-m", "headers,portscan",
		"-c", "50",
		"-p", "full",
		"-w", resolvedWL,
		"-passive",
		"-rate", "100",
		"-timeout", "15s",
		"-ua", "w1r3/1.0",
		"-v",
		"-o", filepath.Join(results, "out"),
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args =\n%v\nwant\n%v", args, want)
	}
}

func TestBuildArgsAutoOutputName(t *testing.T) {
	results := t.TempDir()
	wl := t.TempDir()
	args, base, err := buildArgs(&ScanRequest{
		Target:     "https://example.com/some/path",
		Authorized: true,
	}, wl, results)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !strings.HasPrefix(base, "w1r3hound_example_com_") {
		t.Fatalf("auto base = %q, want w1r3hound_example_com_ prefix", base)
	}
	if len(args) < 2 || args[len(args)-2] != "-o" || args[len(args)-1] != filepath.Join(results, base) {
		t.Fatalf("output arg = %v, want -o %s", args[len(args)-2:], filepath.Join(results, base))
	}
}

func TestBuildArgsOutputNameAllowList(t *testing.T) {
	dir := t.TempDir()
	bad := []string{
		"has space",
		"bad!name",
		"../escape",
		"nested/name",
		"..",
		".hidden", // must start with alnum
	}
	for _, name := range bad {
		if _, _, err := buildArgs(&ScanRequest{Target: "example.com", Output: name, Authorized: true}, dir, dir); err == nil {
			t.Errorf("output name %q accepted, want rejected", name)
		}
	}
	ok := []string{"report", "scan_01", "my-report.v2", "A1"}
	for _, name := range ok {
		if _, _, err := buildArgs(&ScanRequest{Target: "example.com", Output: name, Authorized: true}, dir, dir); err != nil {
			t.Errorf("output name %q rejected: %v", name, err)
		}
	}
}

func TestBuildArgsNumericAndValueBounds(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		req  ScanRequest
	}{
		{"concurrency too high", ScanRequest{Target: "example.com", Concurrency: 501, Authorized: true}},
		{"concurrency negative", ScanRequest{Target: "example.com", Concurrency: -1, Authorized: true}},
		{"rate too high", ScanRequest{Target: "example.com", Rate: 10001, Authorized: true}},
		{"timeout too high", ScanRequest{Target: "example.com", TimeoutSec: 301, Authorized: true}},
		{"bad ports", ScanRequest{Target: "example.com", Ports: "1-99999", Authorized: true}},
		{"ua too long", ScanRequest{Target: "example.com", UserAgent: strings.Repeat("x", 257), Authorized: true}},
		{"ua with CRLF", ScanRequest{Target: "example.com", UserAgent: "bad\r\nInjected: 1", Authorized: true}},
		{"invalid target", ScanRequest{Target: "-notatarget!", Authorized: true}},
	}
	for _, c := range cases {
		if _, _, err := buildArgs(&c.req, dir, dir); err == nil {
			t.Errorf("%s: buildArgs accepted, want error", c.name)
		}
	}
}

func TestSanitizeAndDomainHelpers(t *testing.T) {
	if got := sanitizeForFilename("a.b/c:d"); got != "a_b_c_d" {
		t.Fatalf("sanitizeForFilename = %q", got)
	}
	cases := map[string]string{
		"https://example.com/path": "example.com",
		"http://10.0.0.1:8080":     "10.0.0.1",
		"example.com":              "example.com",
		"[2001:db8::1]:443":        "2001:db8::1",
	}
	for in, want := range cases {
		if got := domainOfTarget(in); got != want {
			t.Errorf("domainOfTarget(%q) = %q, want %q", in, got, want)
		}
	}
}
