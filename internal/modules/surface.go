package modules

import (
	"fmt"
	"sort"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

// ══════════════════════════════════════════════
//  ATTACK-SURFACE SUMMARY (shared-context consumer)
//  Closes the "data feedback" loop: several modules
//  publish parameters, endpoints, URLs and IP ranges
//  into the shared context, but nothing consumed
//  SharedParams / SharedEndpoints / SharedURLs /
//  SharedIPs (they were write-only / dead). This
//  aggregates them into a single deduplicated INFO
//  finding so the discovered surface is actually
//  reported. Runs last, after every producer.
// ══════════════════════════════════════════════

type SurfaceSummary struct {
	Parameters []string `json:"parameters,omitempty"`
	Endpoints  []string `json:"endpoints,omitempty"`
	URLs       []string `json:"urls,omitempty"`
	IPRanges   []string `json:"ip_ranges,omitempty"`
}

// RunSurfaceSummary consumes the aggregated shared context and emits a summary.
func RunSurfaceSummary(cfg *core.Config, report *core.ReconReport, log *core.Logger) {
	cfg.SharedMu.Lock()
	sum := SurfaceSummary{
		Parameters: dedupSorted(cfg.SharedParams),
		Endpoints:  dedupSorted(cfg.SharedEndpoints),
		URLs:       dedupSorted(cfg.SharedURLs),
		IPRanges:   dedupSorted(cfg.SharedIPs),
	}
	cfg.SharedMu.Unlock()

	total := len(sum.Parameters) + len(sum.Endpoints) + len(sum.URLs) + len(sum.IPRanges)
	if total == 0 {
		return
	}

	log.Module("SURFACE // Aggregated Attack Surface")
	log.Info("Parameters: %d · Endpoints/routes: %d · URLs: %d · IP ranges: %d",
		len(sum.Parameters), len(sum.Endpoints), len(sum.URLs), len(sum.IPRanges))

	report.Add(core.Finding{
		Module:      "surface",
		WSTG:        "WSTG-INFO-06",
		Title:       fmt.Sprintf("Attack surface: %d params, %d endpoints, %d URLs, %d IP ranges", len(sum.Parameters), len(sum.Endpoints), len(sum.URLs), len(sum.IPRanges)),
		Severity:    core.SevInfo,
		Description: "Aggregated parameters, endpoints, URLs and IP ranges discovered across all modules.",
		Data:        sum,
	})
}

func dedupSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
