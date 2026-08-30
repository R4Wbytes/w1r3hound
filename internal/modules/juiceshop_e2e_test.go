//go:build juiceshop

// Juice Shop end-to-end (TEST_PLAN.md §4.2). Requires a running OWASP Juice
// Shop on 127.0.0.1:3000 (or W1R3HOUND_JUICE_URL). Not part of the default
// hermetic suite — run via `make e2e-juiceshop`, which starts/stops the
// container and passes -tags juiceshop.
package modules

import (
	"os"
	"strings"
	"testing"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

func juiceTarget() string {
	if u := os.Getenv("W1R3HOUND_JUICE_URL"); u != "" {
		return u
	}
	return "http://127.0.0.1:3000"
}

// TestJuiceShopPhaseC reproduces the audit's Phase C against real content: the
// robots-disallowed /ftp directory listing (HIGH), the Express stack-trace
// disclosure (MEDIUM), and the Swagger /api-docs surface.
func TestJuiceShopPhaseC(t *testing.T) {
	target := juiceTarget()

	cfg := core.DefaultConfig()
	cfg.Target = target
	cfg.Domain = "127.0.0.1"
	rep := core.NewReport(target)
	log := core.NewLogger(false)

	// The full-pipeline subset from TEST_PLAN.md §4.2.
	RunMetafiles(cfg, rep, log)
	RunAPI(cfg, rep, log)
	RunContent(cfg, rep, log)
	RunHeaders(cfg, rep, log)
	RunWebServer(cfg, rep, log)
	RunCrawler(cfg, rep, log)

	var ftpHigh, stackMedium, apiDocs bool
	for _, f := range rep.Findings {
		title := strings.ToLower(f.Title)
		blob := strings.ToLower(f.Title + " " + f.Description)
		if f.WSTG == "WSTG-CONF-04" && f.Severity == core.SevHigh && strings.Contains(title, "ftp") {
			ftpHigh = true
		}
		if f.WSTG == "WSTG-ERRH-02" && f.Severity == core.SevMedium {
			stackMedium = true
		}
		if strings.Contains(blob, "api-docs") || strings.Contains(blob, "swagger") || strings.Contains(blob, "openapi") {
			apiDocs = true
		}
	}

	t.Logf("Juice Shop produced %d findings", len(rep.Findings))
	if !ftpHigh {
		t.Errorf("expected a HIGH /ftp directory-listing finding (WSTG-CONF-04)")
	}
	if !stackMedium {
		t.Errorf("expected a MEDIUM stack-trace disclosure finding (WSTG-ERRH-02)")
	}
	// /api-docs presence varies slightly by Juice Shop version; treat as a
	// soft signal rather than a hard failure.
	if !apiDocs {
		t.Logf("note: /api-docs (Swagger/OpenAPI) surface not detected on this Juice Shop build")
	}
}
