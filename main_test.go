package main

import "testing"

// TestMapProtocolResolves covers the -m/-protocols resolution: themed aliases
// and legacy aliases map to internal names, and internal names pass through.
func TestMapProtocolResolves(t *testing.T) {
	cases := map[string]string{
		// themed aliases
		"recon": "whois", "traceroute": "asnmap", "passivewatch": "passivesrc",
		"fingerprinter": "dns", "archaeology": "wayback", "diversify": "permute",
		"heartbeat": "httprobe", "probescan": "webserver", "metadata": "metafiles",
		"sentry": "headers", "deepdive": "content", "corstrace": "cors",
		"cloudsniff": "cloud", "bruteforce": "dirbrute",
		// legacy aliases still accepted
		"osint": "whois", "spider": "crawler", "breach": "apiscan", "hijack": "takeover",
		// internal names pass through unchanged
		"headers": "headers", "portscan": "portscan", "endprobe": "endprobe",
		"dns": "dns", "takeover": "takeover",
	}
	for in, want := range cases {
		if got := mapProtocol(in); got != want {
			t.Errorf("mapProtocol(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestMapProtocolAliasesAreKnownModules guards that every alias resolves to a
// name main() will actually accept (knownModules[mapped] must be true), so a
// documented alias can never be rejected as "Unknown protocol".
func TestMapProtocolAliasesAreKnownModules(t *testing.T) {
	aliases := []string{
		"recon", "traceroute", "passivewatch", "fingerprinter", "archaeology",
		"diversify", "heartbeat", "probescan", "metadata", "sentry", "deepdive",
		"portscan", "corstrace", "cloudsniff", "bruteforce", "apiscan", "saasenum",
		"crawler", "jsdeep", "endprobe", "takeover",
		// legacy
		"osint", "backtrace", "ghosts", "profile", "timewarp", "spider", "breach", "hijack",
	}
	for _, a := range aliases {
		if mapped := mapProtocol(a); !knownModules[mapped] {
			t.Errorf("alias %q maps to %q which is not a known module", a, mapped)
		}
	}
}

func TestSanitize(t *testing.T) {
	cases := map[string]string{
		"example.com":            "example_com",
		"https://host:8080/path": "https___host_8080_path",
		"10.0.0.1":               "10_0_0_1",
		"a.b/c:d":                "a_b_c_d",
		"plain":                  "plain",
	}
	for in, want := range cases {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

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
	if err := headers.Set("X-HackerOne: R4Wbytes"); err != nil {
		t.Fatal(err)
	}
	name, identifier := configuredResearchIdentifier(headers)
	if name != "X-HackerOne" || identifier != "R4Wbytes" {
		t.Fatalf("research identifier = %q: %q, want X-HackerOne: R4Wbytes", name, identifier)
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
