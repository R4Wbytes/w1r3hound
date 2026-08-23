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

func TestHeaderFlags(t *testing.T) {
	headers := headerFlags{}
	if err := headers.Set("X-Bug-Bounty: w1r3hound"); err != nil {
		t.Fatal(err)
	}
	if got := headers["X-Bug-Bounty"]; got != "w1r3hound" {
		t.Fatalf("X-Bug-Bounty = %q, want w1r3hound", got)
	}
	if err := headers.Set("Authorization: Bearer value:with:colons"); err != nil {
		t.Fatal(err)
	}
	if got := headers["Authorization"]; got != "Bearer value:with:colons" {
		t.Fatalf("Authorization = %q", got)
	}

	for _, raw := range []string{
		"missing-colon",
		"Bad Header: value",
		"X-Test:\r\nInjected: yes",
	} {
		if err := headers.Set(raw); err == nil {
			t.Errorf("headerFlags.Set(%q) unexpectedly succeeded", raw)
		}
	}
}
