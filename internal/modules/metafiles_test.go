package modules

import (
	"testing"
	"time"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

// TestParseSecurityTxtExpires covers the RFC 9116 date-format fix: the spec
// requires RFC 3339, which the old RFC 1123-only parser never accepted, so the
// expiry check silently never fired.
func TestParseSecurityTxtExpires(t *testing.T) {
	ok := []string{
		"2025-12-31T23:59:59Z",     // RFC 3339 (the spec format)
		"2025-12-31T23:59:59.000Z", // RFC 3339 with fractional seconds
		"2025-12-31T23:59:59+02:00",
		"2025-12-31",                    // date only (lenient fallback)
		"Mon, 02 Jan 2006 15:04:05 MST", // RFC 1123 (legacy fallback)
	}
	for _, v := range ok {
		if _, err := parseSecurityTxtExpires(v); err != nil {
			t.Errorf("expected %q to parse, got error: %v", v, err)
		}
	}
	if _, err := parseSecurityTxtExpires("not a date"); err == nil {
		t.Error("expected an error for a non-date value")
	}
}

// TestAnalyzeSecurityTxt_ExpiredFires is the regression test proving the expiry
// finding now actually fires for a spec-compliant (RFC 3339) past date — the
// exact case the old RFC 1123 parser silently dropped.
func TestAnalyzeSecurityTxt_ExpiredFires(t *testing.T) {
	body := "Contact: mailto:security@example.com\n" +
		"Expires: 2020-01-01T00:00:00Z\n"
	report := core.NewReport("example.com")
	cfg := core.DefaultConfig()
	cfg.Domain = "example.com"

	analyzeSecurityTxt(body, "https://example.com", cfg, report, core.NewLogger(false))

	found := false
	for _, f := range report.Snapshot().Findings {
		if f.Title == "security.txt has expired" {
			found = true
		}
	}
	if !found {
		t.Error("expected an 'security.txt has expired' finding for a past RFC 3339 Expires date")
	}
}

// TestAnalyzeSecurityTxt_ValidDoesNotFire guards the other direction: a future
// Expires must not be reported as expired.
func TestAnalyzeSecurityTxt_ValidDoesNotFire(t *testing.T) {
	future := time.Now().AddDate(1, 0, 0).UTC().Format(time.RFC3339)
	body := "Contact: mailto:security@example.com\nExpires: " + future + "\n"
	report := core.NewReport("example.com")
	cfg := core.DefaultConfig()
	cfg.Domain = "example.com"

	analyzeSecurityTxt(body, "https://example.com", cfg, report, core.NewLogger(false))

	for _, f := range report.Snapshot().Findings {
		if f.Title == "security.txt has expired" {
			t.Error("a future Expires date must not be reported as expired")
		}
	}
}
