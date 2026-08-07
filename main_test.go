package main

import "testing"

// N6: extractDomain must not truncate IPv6 literals to "[" or "".
func TestExtractDomain_IPv6(t *testing.T) {
	cases := []struct{ in, want string }{
		{"http://[::1]:8080", "::1"},
		{"https://[2001:db8::1]:443/path", "2001:db8::1"},
		{"[::1]", "::1"},
		{"http://example.com:8080/x", "example.com"},
		{"https://example.com", "example.com"},
		{"example.com", "example.com"},
		{"::1", "::1"}, // bare IPv6 without brackets is left intact, not truncated
	}
	for _, c := range cases {
		if got := extractDomain(c.in); got != c.want {
			t.Errorf("extractDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
