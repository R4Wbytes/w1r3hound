package modules

import (
	"testing"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

// N15: a WAF/CDN edge that returns a uniform 403 block page for every path must
// be filtered as a catch-all, not reported as N sensitive-path findings. Shape
// taken from the real hollisterco.com scan (24 paths, all 149-byte 403s).
func TestFilterCatchAll403s_UniformBlockDropped(t *testing.T) {
	var entries []DirEntry
	for _, p := range []string{
		"/admin/config", "/admin/", "/.env", "/.env.old", "/settings.php",
		"/.env.backup", "/wp-config.php.bak", "/wp-config.php", "/wp-config.php.old",
		"/backup.sql", "/db.sql", "/database.sql", "/dump.sql", "/backup.sql.gz",
		"/data.sql", "/.git/index", "/.svn/wc.db", "/.git/HEAD", "/.svn/entries",
		"/.htpasswd", "/.git/config", "/.htaccess", "/wp-content/debug.log",
		"/.DS_Store", "/cgi-bin/test",
	} {
		entries = append(entries, DirEntry{Path: p, StatusCode: 403, Size: 149})
	}
	// A real 200 must survive.
	entries = append(entries, DirEntry{Path: "/error", StatusCode: 200, Size: 0})
	// A 403 whose body size is an outlier (a path-specific access-denied page,
	// not the blanket block) must survive.
	entries = append(entries, DirEntry{Path: "/private-app", StatusCode: 403, Size: 4096})

	kept := filterCatchAll403s(entries, core.NewLogger(false))
	survived := map[string]bool{}
	for _, e := range kept {
		survived[e.Path] = true
	}

	if survived["/.env"] || survived["/wp-config.php"] || survived["/.git/config"] {
		t.Error("uniform 149-byte 403s must be filtered as a catch-all WAF/CDN block")
	}
	if !survived["/error"] {
		t.Error("non-403 entries must always survive")
	}
	if !survived["/private-app"] {
		t.Error("an outlier-sized 403 (path-specific) must survive")
	}
}

// N15: too few 403s → never filtered (each could be individually meaningful).
func TestFilterCatchAll403s_FewKept(t *testing.T) {
	entries := []DirEntry{
		{Path: "/.env", StatusCode: 403, Size: 149},
		{Path: "/.git/config", StatusCode: 403, Size: 149},
	}
	if kept := filterCatchAll403s(entries, core.NewLogger(false)); len(kept) != 2 {
		t.Errorf("with <5 forbidden entries nothing should be filtered, got %d", len(kept))
	}
}

// N15: 403s with varied sizes (no dominant block) are all kept.
func TestFilterCatchAll403s_NoDominantCluster(t *testing.T) {
	entries := []DirEntry{
		{Path: "/a", StatusCode: 403, Size: 100},
		{Path: "/b", StatusCode: 403, Size: 900},
		{Path: "/c", StatusCode: 403, Size: 2500},
		{Path: "/d", StatusCode: 403, Size: 6000},
		{Path: "/e", StatusCode: 403, Size: 12000},
		{Path: "/f", StatusCode: 403, Size: 40000},
	}
	if kept := filterCatchAll403s(entries, core.NewLogger(false)); len(kept) != 6 {
		t.Errorf("varied-size 403s (no dominant block) must all be kept, got %d", len(kept))
	}
}

// N4: a reversed or oversized -p range must never panic or OOM.
func TestSelectPorts_RangeSafety(t *testing.T) {
	// Reversed range → previously `make([]int, 0, negative)` panicked.
	if got := selectPorts("1000-10"); len(got) == 0 {
		t.Error("reversed range should fall back to a non-empty default, not panic/empty")
	}
	// Absurd upper bound → previously allocated ~terabytes (OOM). Must clamp.
	got := selectPorts("1-70000000000")
	if len(got) != 65535 {
		t.Errorf("huge range clamped to 65535 ports, got %d", len(got))
	}
	if got[0] != 1 || got[len(got)-1] != 65535 {
		t.Errorf("clamped range should be 1..65535, got %d..%d", got[0], got[len(got)-1])
	}
	// A sane range still works exactly.
	if n := len(selectPorts("80-90")); n != 11 {
		t.Errorf("range 80-90 = %d ports, want 11", n)
	}
	// Lower bound below 1 is clamped to 1.
	if got := selectPorts("0-2"); got[0] != 1 {
		t.Errorf("lower bound clamped to 1, got %d", got[0])
	}
}

// encodeDNSName writes a DNS wire-format name (length-prefixed labels + root).
func encodeDNSName(name string) []byte {
	var out []byte
	for _, label := range splitLabels(name) {
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	out = append(out, 0x00)
	return out
}

func splitLabels(name string) []string {
	var labels []string
	cur := ""
	for _, r := range name {
		if r == '.' {
			labels = append(labels, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		labels = append(labels, cur)
	}
	return labels
}

// N7: extractDNSNames must require a real label boundary. "notexample.com"
// merely shares the suffix of "example.com" and must NOT be extracted, while
// "api.example.com" must be.
func TestExtractDNSNames_SuffixBoundary(t *testing.T) {
	msg := make([]byte, 12) // 12-byte header
	msg = append(msg, encodeDNSName("api.example.com")...)
	msg = append(msg, encodeDNSName("notexample.com")...)
	msg = append(msg, encodeDNSName("staging.example.com")...)

	names := extractDNSNames(msg, "example.com")

	has := func(n string) bool {
		for _, x := range names {
			if x == n {
				return true
			}
		}
		return false
	}
	if !has("api.example.com") {
		t.Errorf("api.example.com must be extracted, got %v", names)
	}
	if !has("staging.example.com") {
		t.Errorf("staging.example.com must be extracted, got %v", names)
	}
	if has("notexample.com") {
		t.Errorf("notexample.com shares only the suffix and MUST NOT be extracted, got %v", names)
	}
}

// N6: host extraction must handle IPv6 literals instead of truncating them.
func TestExtractHost_IPv6(t *testing.T) {
	cases := []struct{ in, want string }{
		{"http://[::1]:8080", "::1"},
		{"https://[2001:db8::1]:443", "2001:db8::1"},
		{"http://example.com:8080", "example.com"},
		{"https://example.com", "example.com"},
	}
	for _, c := range cases {
		if got := extractHost(c.in); got != c.want {
			t.Errorf("extractHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// N6: hostPort must produce a dialable host:port for IPv6 too.
func TestHostPort_IPv6(t *testing.T) {
	cases := []struct {
		in       string
		wantAddr string
		wantTLS  bool
	}{
		{"https://[::1]:8443", "[::1]:8443", true},
		{"https://example.com", "example.com:443", true},
		{"http://example.com", "example.com:80", false},
		{"http://[2001:db8::1]", "[2001:db8::1]:80", false},
	}
	for _, c := range cases {
		addr, isTLS := hostPort(c.in)
		if addr != c.wantAddr || isTLS != c.wantTLS {
			t.Errorf("hostPort(%q) = (%q,%v), want (%q,%v)", c.in, addr, isTLS, c.wantAddr, c.wantTLS)
		}
	}
}

// N13: short secrets must not be mostly revealed by maskSecret.
func TestMaskSecret_ShortNotOverRevealed(t *testing.T) {
	nine := "ABCDEFGHI" // 9 chars
	got := maskSecret(nine)
	if got != "AB*******" {
		t.Errorf("maskSecret(9-char) = %q, want %q (only a 2-char prefix revealed)", got, "AB*******")
	}
	if len(got) != len(nine) {
		t.Errorf("masked length %d != original %d", len(got), len(nine))
	}
	// Long secret keeps prefix+suffix reveal.
	long := "AKIAIOSFODNN7EXAMPLE" // 20 chars
	gl := maskSecret(long)
	if gl[:4] != "AKIA" || gl[len(gl)-4:] != "MPLE" {
		t.Errorf("maskSecret(long) should reveal first-4/last-4, got %q", gl)
	}
}
