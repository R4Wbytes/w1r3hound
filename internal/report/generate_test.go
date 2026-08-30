package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

// TestGenerateReportWritesJSONAndMarkdown covers `-o`: GenerateReport writes
// both <base>.json and <base>.md, and the JSON round-trips.
func TestGenerateReportWritesJSONAndMarkdown(t *testing.T) {
	r := core.NewReport("https://example.com")
	r.Add(core.Finding{Module: "headers", WSTG: "WSTG-INFO-08", Title: "Missing CSP", Severity: core.SevMedium})

	base := filepath.Join(t.TempDir(), "out")
	GenerateReport(r, base, core.NewLogger(false))

	jsonPath := base + ".json"
	mdPath := base + ".md"
	if _, err := os.Stat(jsonPath); err != nil {
		t.Fatalf("expected %s: %v", jsonPath, err)
	}
	if _, err := os.Stat(mdPath); err != nil {
		t.Fatalf("expected %s: %v", mdPath, err)
	}

	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	var rep core.ReconReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("report JSON invalid: %v", err)
	}
	if rep.Target != "https://example.com" || len(rep.Findings) != 1 {
		t.Fatalf("round-trip mismatch: target=%q findings=%d", rep.Target, len(rep.Findings))
	}

	md, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(md) == 0 {
		t.Fatal("markdown report is empty")
	}
}
