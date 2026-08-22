package modules

import (
	"fmt"
	"strings"

	"github.com/w1r3hound/w1r3hound/internal/core"
)

// ══════════════════════════════════════════════
//  ENDPOINT PROBE
//  Checks JS-discovered API endpoints for
//  unauthenticated access to admin/config data.
//  Runs after jsdeep to consume SharedEndpoints.
//  (WSTG-ATHZ-02, WSTG-CONF-05)
// ══════════════════════════════════════════════

var sensitiveEndpointPatterns = []string{
	"/admin", "/config", "/internal", "/debug",
	"/management", "/actuator", "/settings",
	"/application-configuration", "/server-info",
	"/system", "/env",
}

func isSensitiveEndpoint(ep string) bool {
	lower := strings.ToLower(ep)
	for _, p := range sensitiveEndpointPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

type unauthHit struct {
	Path     string `json:"path"`
	Status   int    `json:"status"`
	BodySize int    `json:"body_size"`
}

func RunEndpointProbe(cfg *core.Config, report *core.ReconReport, log *core.Logger) {
	log.Module("ENDPROBE // Sensitive Endpoint Authorization Check")

	if cfg.Passive {
		log.Info("Skipping endpoint probe in passive mode")
		return
	}

	cfg.SharedMu.Lock()
	endpoints := make([]string, len(cfg.SharedEndpoints))
	copy(endpoints, cfg.SharedEndpoints)
	cfg.SharedMu.Unlock()

	if len(endpoints) == 0 {
		log.Info("No API endpoints from JS analysis — nothing to probe")
		return
	}

	client := core.NewHTTPClient(cfg)
	target := normalizeTarget(cfg.Target)
	catchAll := calibrateCatchAll(client, target, cfg)

	var candidates []string
	seen := make(map[string]bool)

	// Collect API base paths (endpoints with /api/, /rest/, etc. that return non-200)
	var apiPrefixes []string
	for _, ep := range endpoints {
		path := stripQuery(ep)
		lower := strings.ToLower(path)
		if strings.Contains(lower, "/api/") || strings.Contains(lower, "/rest/") ||
			strings.Contains(lower, "/v1/") || strings.Contains(lower, "/v2/") {
			apiPrefixes = append(apiPrefixes, path)
		}
	}

	for _, ep := range endpoints {
		path := stripQuery(ep)
		if !isSensitiveEndpoint(path) || seen[path] {
			continue
		}
		seen[path] = true
		candidates = append(candidates, path)

		// For short sensitive paths (like /application-configuration), also try
		// them under each API prefix that itself looks like a namespace.
		// JS often splits "/rest/admin" + "/application-configuration".
		if strings.Count(path, "/") <= 1 {
			for _, prefix := range apiPrefixes {
				combined := strings.TrimRight(prefix, "/") + path
				if !seen[combined] {
					seen[combined] = true
					candidates = append(candidates, combined)
				}
			}
		}
	}

	if len(candidates) == 0 {
		log.Info("No sensitive-looking endpoints found among %d endpoints", len(endpoints))
		return
	}

	log.Info("Probing %d sensitive endpoint candidate(s)...", len(candidates))

	var hits []unauthHit
	for _, path := range candidates {
		url := target + path
		body, status, err := core.FetchBodyRL(client, url, cfg.UserAgent, cfg.RL)
		if err != nil || status == 404 || status == 405 || status >= 500 {
			continue
		}
		if catchAll.matches(status, len(body)) {
			continue
		}
		if status == 401 || status == 403 {
			log.Debug("  %s → %d (auth required)", path, status)
			continue
		}
		if status == 200 && len(body) > 200 {
			hits = append(hits, unauthHit{Path: path, Status: status, BodySize: len(body)})
			log.Warn("Unauthenticated access: %s [%d] (%d bytes)", path, status, len(body))
		}
	}

	if len(hits) > 0 {
		var paths []string
		for _, h := range hits {
			paths = append(paths, fmt.Sprintf("%s [%d] (%d bytes)", h.Path, h.Status, h.BodySize))
		}
		report.Add(core.Finding{
			Module:   "endprobe",
			WSTG:     "WSTG-ATHZ-02",
			Title:    fmt.Sprintf("Unauthenticated access to %d sensitive endpoint(s)", len(hits)),
			Severity: core.SevHigh,
			Description: fmt.Sprintf(
				"JS-discovered API endpoints responding with data without authentication: %s. "+
					"Admin/config endpoints should require authentication.",
				strings.Join(paths, "; ")),
			Data: hits,
		})
	} else {
		log.Info("All sensitive endpoints require authentication or are not accessible")
	}
}

func stripQuery(ep string) string {
	if i := strings.IndexByte(ep, '?'); i >= 0 {
		return ep[:i]
	}
	return ep
}
