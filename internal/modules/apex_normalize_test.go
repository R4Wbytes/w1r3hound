package modules

import "testing"

// N20: extractApexDomain must strip subdomains but preserve compound TLDs.
// Regression for BUG-20 (hackerone.com, 2026-08-11): passing "-t
// www.hackerone.com" made every DNS query target `www.hackerone.com`, which
// has no NS/MX records and inherits a misleading "v=spf1 -all" TXT, hiding
// the apex's real infrastructure.
func TestExtractApexDomain(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// Plain apex — unchanged.
		{"hackerone.com", "hackerone.com"},
		{"example.com", "example.com"},
		// Single-label subdomain stripped.
		{"www.hackerone.com", "hackerone.com"},
		{"api.hackerone.com", "hackerone.com"},
		{"docs.hackerone.com", "hackerone.com"},
		// Multi-label subdomain stripped to 2-label apex.
		{"api.staging.example.com", "example.com"},
		{"a.b.c.example.com", "example.com"},
		// Compound TLDs preserved.
		{"www.example.co.uk", "example.co.uk"},
		{"api.staging.example.co.uk", "example.co.uk"},
		{"shop.example.com.au", "example.com.au"},
		{"www.example.co.jp", "example.co.jp"},
		// URL-style input (should strip scheme/path).
		{"https://www.hackerone.com/path", "hackerone.com"},
		{"http://www.hackerone.com/", "hackerone.com"},
		// Edge cases.
		{"", ""},
		{"localhost", "localhost"},
		{"example", "example"},
		// Mixed case and trailing whitespace.
		{"  WWW.HackerOne.COM  ", "hackerone.com"},
	}
	for _, c := range cases {
		got := extractApexDomain(c.in)
		if got != c.want {
			t.Errorf("extractApexDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
