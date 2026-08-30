package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

// TestReportJSONContractMatchesFrontend locks the report JSON schema that the
// web console consumes. The SPA (webui/static/js/app.js) reads finding fields
// module / wstg_id / title / description / severity / data, and the webui
// backend (jobs.go countSeverities + parseReportHeader) reads the top-level
// target / started_at / ended_at / findings and each finding's severity. If a
// key is renamed here, the dashboard silently breaks, so assert the wire shape
// from the real generation path (core.ReconReport.SaveJSON).
func TestReportJSONContractMatchesFrontend(t *testing.T) {
	r := core.NewReport("https://example.com")
	r.Add(core.Finding{
		Module:      "headers",
		WSTG:        "WSTG-INFO-08",
		Title:       "Missing security headers",
		Description: "Content-Security-Policy not set",
		Severity:    core.SevMedium,
		Data:        map[string]string{"header": "Content-Security-Policy"},
	})
	r.Finalize()

	path := filepath.Join(t.TempDir(), "rep.json")
	if err := r.SaveJSON(path); err != nil {
		t.Fatalf("SaveJSON: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	for _, k := range []string{"target", "started_at", "ended_at", "findings"} {
		if _, ok := top[k]; !ok {
			t.Errorf("report JSON missing top-level key %q (consumed by webui)", k)
		}
	}

	var rep struct {
		Findings []map[string]json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("unmarshal findings: %v", err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("findings len = %d, want 1", len(rep.Findings))
	}
	f := rep.Findings[0]
	// Keys always present, consumed by js/app.js and jobs.go.
	for _, k := range []string{"module", "title", "severity", "wstg_id", "description", "data"} {
		if _, ok := f[k]; !ok {
			t.Errorf("finding JSON missing key %q consumed by the frontend", k)
		}
	}

	// Severity is emitted UPPERCASE; the frontend's Utils.sevKey lowercases it.
	var sev string
	if err := json.Unmarshal(f["severity"], &sev); err != nil {
		t.Fatalf("severity decode: %v", err)
	}
	if sev != "MEDIUM" {
		t.Errorf("severity = %q, want MEDIUM", sev)
	}
}

// TestReportOmitsEmptyOptionalKeys documents the omitempty behavior the webui
// tolerates: wstg_id / description / data are dropped when empty, and the SPA
// guards each with a fallback (f.wstg_id || "").
func TestReportOmitsEmptyOptionalKeys(t *testing.T) {
	r := core.NewReport("example.com")
	r.Add(core.Finding{Module: "portscan", Title: "Open port 80", Severity: core.SevInfo})
	r.Finalize()

	path := filepath.Join(t.TempDir(), "rep.json")
	if err := r.SaveJSON(path); err != nil {
		t.Fatalf("SaveJSON: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var rep struct {
		Findings []map[string]json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	f := rep.Findings[0]
	for _, k := range []string{"module", "title", "severity"} {
		if _, ok := f[k]; !ok {
			t.Errorf("required key %q missing", k)
		}
	}
	for _, k := range []string{"wstg_id", "description", "data"} {
		if _, ok := f[k]; ok {
			t.Errorf("empty optional key %q should be omitted", k)
		}
	}
}
