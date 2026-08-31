package modules

import (
	"net/url"
	"testing"
)

// TestBuildProbeURL covers the C-13 fix: JS-discovered endpoints in relative,
// protocol-relative and absolute forms must all resolve to a well-formed URL
// rooted at the exact target host — and anything resolving off-host (or to a
// non-HTTP scheme) must be rejected rather than concatenated into a malformed
// request.
func TestBuildProbeURL(t *testing.T) {
	base, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}

	cases := []struct {
		endpoint string
		wantOK   bool
		wantURL  string
	}{
		{"/admin", true, "https://example.com/admin"},
		{"/rest/admin/application-configuration", true, "https://example.com/rest/admin/application-configuration"},
		{"https://example.com/admin", true, "https://example.com/admin"},
		{"//example.com/config", true, "https://example.com/config"},
		// Off-host: third-party absolute, subdomain, and protocol-relative subdomain.
		{"https://evil.com/admin", false, ""},
		{"https://api.example.com/admin", false, ""},
		{"//cdn.example.com/config", false, ""},
		// Non-HTTP schemes must be rejected.
		{"javascript:alert(1)", false, ""},
		{"mailto:x@example.com", false, ""},
	}

	for _, c := range cases {
		got, ok := buildProbeURL(base, c.endpoint)
		if ok != c.wantOK {
			t.Errorf("buildProbeURL(%q): ok=%v, want %v", c.endpoint, ok, c.wantOK)
			continue
		}
		if ok && got != c.wantURL {
			t.Errorf("buildProbeURL(%q): got %q, want %q", c.endpoint, got, c.wantURL)
		}
	}
}
