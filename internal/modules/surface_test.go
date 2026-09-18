package modules

import (
	"bytes"
	"testing"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

func TestRunSurfaceSummaryEmpty(t *testing.T) {
	cfg := core.DefaultConfig()
	report := core.NewReport("example.com")
	log := core.NewLoggerWriter(false, true, &bytes.Buffer{})

	RunSurfaceSummary(cfg, report, log)

	snap := report.Snapshot()
	if len(snap.Findings) != 0 {
		t.Fatalf("expected no findings for empty context, got %d", len(snap.Findings))
	}
}

func TestRunSurfaceSummaryWithData(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.SharedParams = []string{"id", "token", "id"}
	cfg.SharedEndpoints = []string{"/api/users", "/api/users", "/api/admin"}
	cfg.SharedURLs = []string{"https://example.com/login"}
	cfg.SharedIPs = []string{"10.0.0.1/24"}

	report := core.NewReport("example.com")
	log := core.NewLoggerWriter(false, true, &bytes.Buffer{})

	RunSurfaceSummary(cfg, report, log)

	snap := report.Snapshot()
	if len(snap.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(snap.Findings))
	}
	f := snap.Findings[0]
	if f.Module != "surface" {
		t.Fatalf("module = %q, want surface", f.Module)
	}
	sum, ok := f.Data.(SurfaceSummary)
	if !ok {
		t.Fatalf("finding data is not SurfaceSummary: %T", f.Data)
	}
	if len(sum.Parameters) != 2 {
		t.Fatalf("expected 2 deduped params, got %d: %v", len(sum.Parameters), sum.Parameters)
	}
	if len(sum.Endpoints) != 2 {
		t.Fatalf("expected 2 deduped endpoints, got %d: %v", len(sum.Endpoints), sum.Endpoints)
	}
}
