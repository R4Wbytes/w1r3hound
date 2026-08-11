package modules

import "testing"

// extractApexDomain must strip subdomains but preserve compound TLDs.
// Returns the apex (eTLD+1) of a domain. For "www.example.com" it returns
// "example.com". For "api.staging.example.co.uk" it returns
// "example.co.uk". Returns the input unchanged when it already looks like
// an apex (≤ 2 labels) or when it cannot be stripped safely.
func TestExtractApexDomain(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// Plain apex — unchanged.
		{"example.com", "example.com"},
		{"example.org", "example.org"},
		// Single-label subdomain stripped.
		{"www.example.com", "example.com"},
		{"api.example.com", "example.com"},
		{"docs.example.com", "example.com"},
		// Multi-label subdomain stripped to 2-label apex.
		{"api.staging.example.com", "example.com"},
		{"a.b.c.example.com", "example.com"},
		// Compound TLDs preserved.
		{"www.example.co.uk", "example.co.uk"},
		{"api.staging.example.co.uk", "example.co.uk"},
		{"shop.example.com.au", "example.com.au"},
		{"www.example.co.jp", "example.co.jp"},
		// URL-style input (should strip scheme/path).
		{"https://www.example.com/path", "example.com"},
		{"http://www.example.com/", "example.com"},
		// Edge cases.
		{"", ""},
		{"localhost", "localhost"},
		{"example", "example"},
		// Mixed case and trailing whitespace.
		{"  WWW.Example.COM  ", "example.com"},
	}
	for _, c := range cases {
		got := extractApexDomain(c.in)
		if got != c.want {
			t.Errorf("extractApexDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
