package modules

import (
	"testing"

	"github.com/w1r3hound/w1r3hound/internal/core"
)

// TestMurmur3Canonical verifies our MurmurHash3 x86_32 matches the
// canonical seed-0 test vector, ensuring Shodan favicon-hash compatibility.
func TestMurmur3Canonical(t *testing.T) {
	cases := []struct {
		in   string
		want uint32
	}{
		{"", 0},
		{"The quick brown fox jumps over the lazy dog", 776992547},
	}
	for _, c := range cases {
		if got := murmur3Hash32([]byte(c.in)); got != c.want {
			t.Errorf("murmur3Hash32(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestBase64EncodeMime verifies the Python-compatible base64 encoding
// (76-char lines + trailing newline) used for favicon hashing.
func TestBase64EncodeMime(t *testing.T) {
	got := string(base64EncodeMime([]byte("hello")))
	want := "aGVsbG8=\n"
	if got != want {
		t.Errorf("base64EncodeMime(hello) = %q, want %q", got, want)
	}
}

// TestIsNoiseEndpoint checks that JS endpoint filtering rejects asset files
// but keeps real API paths.
func TestIsNoiseEndpoint(t *testing.T) {
	cases := []struct {
		ep    string
		noise bool
	}{
		{"/api/v1/users", false},
		{"/graphql", false},
		{"/static/logo.png", true},
		{"/fonts/roboto.woff2", true},
		{"/app.css", true},
		{"//www.w3.org/2000/svg", true},
		{"/api/admin/config", false},
		{"/x", true}, // too short
	}
	for _, c := range cases {
		if got := isNoiseEndpoint(c.ep); got != c.noise {
			t.Errorf("isNoiseEndpoint(%q) = %v, want %v", c.ep, got, c.noise)
		}
	}
}

// TestAllIPsMatch verifies the wildcard-filter logic used to avoid
// discarding legitimate subdomains.
func TestAllIPsMatch(t *testing.T) {
	wildcard := map[string]bool{"1.2.3.4": true, "1.2.3.5": true}
	cases := []struct {
		ips  []string
		want bool
	}{
		{[]string{"1.2.3.4"}, true},             // matches wildcard → filter
		{[]string{"1.2.3.4", "1.2.3.5"}, true},  // all match → filter
		{[]string{"9.9.9.9"}, false},            // different IP → keep
		{[]string{"1.2.3.4", "9.9.9.9"}, false}, // partial → keep
	}
	for _, c := range cases {
		if got := allIPsMatch(c.ips, wildcard); got != c.want {
			t.Errorf("allIPsMatch(%v) = %v, want %v", c.ips, got, c.want)
		}
	}
	// Empty wildcard set never matches
	if allIPsMatch([]string{"1.2.3.4"}, nil) {
		t.Error("allIPsMatch with nil wildcard should be false")
	}
}

// TestIsPrintableDNS validates the AXFR name sanitizer.
func TestIsPrintableDNS(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"api.example.com", true},
		{"sub-domain.example.com", true},
		{"_dmarc.example.com", true},
		{"bad\x00name.com", false},
		{"with space.com", false},
	}
	for _, c := range cases {
		if got := isPrintableDNS(c.in); got != c.want {
			t.Errorf("isPrintableDNS(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestBuildDNSQuery ensures the AXFR query packet has correct structure.
func TestBuildDNSQuery(t *testing.T) {
	q := buildDNSQuery("example.com", 252)
	// Header is 12 bytes; QNAME for "example.com" = 1+7 + 1+3 + 1 (root) = 13; +4 for type/class
	wantLen := 12 + 13 + 4
	if len(q) != wantLen {
		t.Errorf("buildDNSQuery length = %d, want %d", len(q), wantLen)
	}
	// QDCOUNT should be 1
	if q[4] != 0x00 || q[5] != 0x01 {
		t.Errorf("QDCOUNT = %d,%d, want 0,1", q[4], q[5])
	}
	// QTYPE should be 252 (AXFR) at the end minus class
	qtype := uint16(q[len(q)-4])<<8 | uint16(q[len(q)-3])
	if qtype != 252 {
		t.Errorf("QTYPE = %d, want 252", qtype)
	}
}

// TestIsSameDomainURL verifies JS endpoint domain filtering (BUG 7 fix):
// third-party URLs (Sentry, Wistia) are rejected, same-domain kept.
func TestIsSameDomainURL(t *testing.T) {
	domain := "hackerone.com"
	cases := []struct {
		url  string
		want bool
	}{
		{"https://docs.hackerone.com/api", true},
		{"https://www.hackerone.com/graphql", true},
		{"//api.hackerone.com/v1", true},
		{"https://browser.sentry-cdn.com/bundle.js", false},
		{"https://distillery.wistia.com/x", false},
		{"https://a3591ba5@o4505.ingest.us.sentry.io/123", false},
		{"https://evilhackerone.com/x", false}, // suffix trick
	}
	for _, c := range cases {
		if got := isSameDomainURL(c.url, domain); got != c.want {
			t.Errorf("isSameDomainURL(%q) = %v, want %v", c.url, got, c.want)
		}
	}
}

// TestIsAlwaysKeepPath verifies critical files are never filtered by the
// cluster analysis, even when same-sized as the catch-all shell.
func TestIsAlwaysKeepPath(t *testing.T) {
	keep := []string{"/.env", "/.git/config", "/wp-config.php", "/.ssh/id_rsa", "/backup.sql"}
	for _, p := range keep {
		if !isAlwaysKeepPath(p) {
			t.Errorf("isAlwaysKeepPath(%q) = false, want true", p)
		}
	}
	drop := []string{"/wp-admin", "/swagger", "/about", "/login"}
	for _, p := range drop {
		if isAlwaysKeepPath(p) {
			t.Errorf("isAlwaysKeepPath(%q) = true, want false", p)
		}
	}
}

// TestClusterFilterSPA verifies the catch-all/SPA soft-404 filter (BUG 2 fix).
// Simulates HackerOne: baseline returns 404, but dictionary words return
// 200 + app shell (~2618 bytes). The dominant cluster must be filtered while
// outliers, criticals, and 403s survive.
func TestClusterFilterSPA(t *testing.T) {
	entries := []DirEntry{
		{Path: "/wp-admin", StatusCode: 200, Size: 2817}, {Path: "/phpmyadmin", StatusCode: 200, Size: 2827},
		{Path: "/swagger", StatusCode: 200, Size: 2618}, {Path: "/actuator", StatusCode: 200, Size: 2743},
		{Path: "/api-docs", StatusCode: 200, Size: 2618}, {Path: "/backup", StatusCode: 200, Size: 2613},
		{Path: "/login", StatusCode: 200, Size: 2618}, {Path: "/admin", StatusCode: 200, Size: 2620},
		{Path: "/config", StatusCode: 200, Size: 2618}, {Path: "/test", StatusCode: 200, Size: 2610},
		{Path: "/dev", StatusCode: 200, Size: 2613}, {Path: "/staging", StatusCode: 200, Size: 2618},
		{Path: "/404", StatusCode: 200, Size: 1694}, {Path: "/500", StatusCode: 200, Size: 1716}, // outliers → keep
		{Path: "/.env", StatusCode: 200, Size: 2620},                                                           // critical → always keep
		{Path: "/.git/config", StatusCode: 200, Size: 2618},                                                    // critical → always keep
		{Path: "/adminer", StatusCode: 403, Size: 5635}, {Path: "/server-status", StatusCode: 403, Size: 5656}, // 403 → keep
	}
	baseline := soft404Baseline{status: 404, bodyLen: 2600} // SPA returns real 404 for random
	log := core.NewLogger(false)
	result := clusterFilterSoft404s(entries, baseline, log)

	survived := make(map[string]bool)
	for _, e := range result {
		survived[e.Path] = true
	}
	// Must keep outliers, criticals, 403s
	mustKeep := []string{"/404", "/500", "/.env", "/.git/config", "/adminer", "/server-status"}
	for _, p := range mustKeep {
		if !survived[p] {
			t.Errorf("cluster filter dropped %q, should keep", p)
		}
	}
	// Must drop the cluster false-positives
	mustDrop := []string{"/wp-admin", "/swagger", "/actuator", "/phpmyadmin"}
	for _, p := range mustDrop {
		if survived[p] {
			t.Errorf("cluster filter kept %q, should drop (SPA false positive)", p)
		}
	}
}

// TestCatchAllMatches verifies the API scanner's catch-all rejection (BUG 4).
func TestCatchAllMatches(t *testing.T) {
	sig := catchAllSignature{isCatchAll: true, status: 200, bodyLen: 2600}
	// Same status + similar size = catch-all shell → reject
	if !sig.matches(200, 2650) {
		t.Error("catchAll.matches(200, 2650) = false, want true (within tolerance)")
	}
	// Different size (real swagger doc) = not catch-all → accept
	if sig.matches(200, 15000) {
		t.Error("catchAll.matches(200, 15000) = true, want false (too different)")
	}
	// Non-catch-all server never matches
	empty := catchAllSignature{}
	if empty.matches(200, 2600) {
		t.Error("empty catchAll should never match")
	}
}

// TestDetectCDNByIP verifies CDN range detection (BUG 3 context).
func TestDetectCDNByIP(t *testing.T) {
	cases := []struct {
		ip  string
		cdn string
	}{
		{"172.64.151.42", "Cloudflare"}, // the actual HackerOne IP from the scan
		{"104.16.1.1", "Cloudflare"},
		{"151.101.1.1", "Fastly"},
		{"8.8.8.8", ""}, // not a CDN
	}
	for _, c := range cases {
		if got := detectCDNByIP(c.ip); got != c.cdn {
			t.Errorf("detectCDNByIP(%q) = %q, want %q", c.ip, got, c.cdn)
		}
	}
}
