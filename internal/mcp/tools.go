package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/R4Wbytes/w1r3hound/internal/core"
	"github.com/R4Wbytes/w1r3hound/internal/modules"
)

// moduleEntry maps a module name to its runner, in phase-execution order.
type moduleEntry struct {
	Name   string
	Fn     func(*core.Config, *core.ReconReport, *core.Logger)
	Active bool // skipped in passive mode
}

var moduleRegistry = []moduleEntry{
	// Phase 0: Passive OSINT
	{"whois", modules.RunWhois, false},
	{"asnmap", modules.RunASN, false},
	{"passivesrc", modules.RunPassive, false},
	// Phase 1: DNS & Subdomains
	{"dns", modules.RunDNS, false},
	{"wayback", modules.RunWayback, false},
	{"permute", modules.RunPermute, true},
	// Phase 2: Live Detection
	{"httprobe", modules.RunHTTProbe, true},
	// Phase 3: Active Fingerprinting
	{"webserver", modules.RunWebServer, true},
	{"metafiles", modules.RunMetafiles, true},
	{"headers", modules.RunHeaders, true},
	{"content", modules.RunContent, true},
	// Phase 4: Attack Surface
	{"portscan", modules.RunPortScan, true},
	{"cors", modules.RunCORS, true},
	{"cloud", modules.RunCloudStorage, true},
	{"dirbrute", modules.RunDirBrute, true},
	{"apiscan", modules.RunAPI, true},
	{"saasenum", modules.RunSaaS, true},
	{"crawler", modules.RunCrawler, true},
	// Phase 5: JS & Takeover
	{"jsdeep", modules.RunJSAnalysis, true},
	{"endprobe", modules.RunEndpointProbe, true},
	{"takeover", modules.RunTakeover, true},
}

var knownModuleSet = func() map[string]bool {
	m := make(map[string]bool, len(moduleRegistry))
	for _, e := range moduleRegistry {
		m[e.Name] = true
	}
	return m
}()

// moduleCatalog is the JSON representation returned by list_modules.
type moduleCatalogEntry struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Desc     string `json:"description"`
	Active   bool   `json:"active_probing"`
}

var moduleCatalog = []moduleCatalogEntry{
	{"whois", "Passive OSINT", "WHOIS/RDAP domain intelligence", false},
	{"asnmap", "Passive OSINT", "ASN / CIDR range discovery via BGP", false},
	{"passivesrc", "Passive OSINT", "Passive subdomains (CT logs, 6 sources)", false},
	{"dns", "DNS & Subdomains", "DNS enum, AXFR, SRV, SPF/DMARC, takeover", false},
	{"wayback", "DNS & Subdomains", "Wayback Machine URL & parameter harvesting", false},
	{"permute", "DNS & Subdomains", "Subdomain permutation & resolution", true},
	{"httprobe", "Live Detection", "HTTP probe + favicon hash (Shodan pivoting)", true},
	{"webserver", "Fingerprinting", "Server fingerprint, TLS cert, HTTP methods", true},
	{"metafiles", "Fingerprinting", "robots.txt, sitemap, security.txt, .well-known", true},
	{"headers", "Fingerprinting", "Security headers audit, tech fingerprinting", true},
	{"content", "Fingerprinting", "HTML comments, JS secrets, source maps, leaks", true},
	{"portscan", "Attack Surface", "TCP port scan with service ID & banner grab", true},
	{"cors", "Attack Surface", "CORS misconfiguration testing", true},
	{"cloud", "Attack Surface", "S3/Azure/GCS/Firebase/DigitalOcean buckets", true},
	{"dirbrute", "Attack Surface", "Hidden paths, admin panels, backups, configs", true},
	{"apiscan", "Attack Surface", "GraphQL introspection, Swagger/OpenAPI, REST, WS", true},
	{"saasenum", "Attack Surface", "SaaS enum (Zendesk/JIRA/Okta/Salesforce +15)", true},
	{"crawler", "Attack Surface", "Web crawl for forms, params, entry points", true},
	{"jsdeep", "Deep Analysis", "JS endpoint extraction (LinkFinder style)", true},
	{"endprobe", "Deep Analysis", "Unauthenticated access on JS-discovered endpoints", true},
	{"takeover", "Deep Analysis", "Subdomain takeover via HTTP fingerprints (37 services)", true},
}

// toolDefinitions returns the MCP tool list for tools/list.
func toolDefinitions() []map[string]any {
	return []map[string]any{
		{
			"name":        "list_modules",
			"description": "List all available w1r3hound recon modules with their categories and descriptions. Use this to discover what modules are available before running a scan.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name":        "scan",
			"description": "Run w1r3hound recon modules against a target. Returns structured findings aligned to the OWASP WSTG framework with severity ratings (CRITICAL/HIGH/MEDIUM/LOW/INFO). Select specific modules for focused fast results, or omit modules to run all (may take several minutes).",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"target":               map[string]any{"type": "string", "description": "Target: hostname, IP, CIDR, or http(s) URL"},
					"modules":              map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Module names to run (omit for all). Use list_modules to see available names."},
					"passive":              map[string]any{"type": "boolean", "description": "Passive-only mode: no active probing of the target"},
					"concurrency":          map[string]any{"type": "integer", "description": "Parallel connections per module (default 20, max 500)"},
					"timeout_seconds":      map[string]any{"type": "integer", "description": "Per-request timeout in seconds (default 10, max 120)"},
					"ports":                map[string]any{"type": "string", "enum": []string{"top100", "1-1024", "full"}, "description": "Port range for portscan module"},
					"rate_limit":           map[string]any{"type": "integer", "description": "Max requests/second (0 = unlimited)"},
					"max_duration_seconds": map[string]any{"type": "integer", "description": "Overall scan timeout in seconds (default 300, max 600)"},
					"allow_private":        map[string]any{"type": "boolean", "description": "Allow scanning private/internal IPs (default false — SSRF guard)"},
					"verbose":              map[string]any{"type": "boolean", "description": "Include debug-level output"},
				},
				"required": []string{"target"},
			},
		},
	}
}

// executeTool dispatches a tool call by name and returns the result text and
// whether the result represents an error.
func executeTool(name string, argsRaw json.RawMessage) (text string, isErr bool) {
	switch name {
	case "list_modules":
		return executeListModules()
	case "scan":
		return executeScan(argsRaw)
	default:
		return fmt.Sprintf("unknown tool: %q", name), true
	}
}

func executeListModules() (string, bool) {
	data, _ := json.MarshalIndent(moduleCatalog, "", "  ")
	return string(data), false
}

type scanParams struct {
	Target             string   `json:"target"`
	Modules            []string `json:"modules"`
	Passive            bool     `json:"passive"`
	Concurrency        int      `json:"concurrency"`
	TimeoutSeconds     int      `json:"timeout_seconds"`
	Ports              string   `json:"ports"`
	RateLimit          int      `json:"rate_limit"`
	MaxDurationSeconds int      `json:"max_duration_seconds"`
	AllowPrivate       bool     `json:"allow_private"`
	Verbose            bool     `json:"verbose"`
}

func executeScan(argsRaw json.RawMessage) (string, bool) {
	var p scanParams
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &p); err != nil {
			return "invalid scan arguments: " + err.Error(), true
		}
	}
	if p.Target == "" {
		return "target is required", true
	}
	if err := validateTarget(p.Target); err != nil {
		return err.Error(), true
	}

	// Validate requested modules.
	selected := map[string]bool{}
	if len(p.Modules) > 0 {
		for _, m := range p.Modules {
			m = strings.ToLower(strings.TrimSpace(m))
			if !knownModuleSet[m] {
				return fmt.Sprintf("unknown module: %q — use list_modules to see available names", m), true
			}
			selected[m] = true
		}
	}

	// Build Config.
	cfg := core.DefaultConfig()
	cfg.BlockPrivateEgress = !p.AllowPrivate
	cfg.Domain = extractDomain(p.Target)
	cfg.RootDomains = []string{cfg.Domain}
	cfg.Passive = p.Passive

	if p.Concurrency > 0 && p.Concurrency <= 500 {
		cfg.Concurrency = p.Concurrency
	}
	if p.TimeoutSeconds > 0 && p.TimeoutSeconds <= 120 {
		cfg.Timeout = time.Duration(p.TimeoutSeconds) * time.Second
	}
	switch p.Ports {
	case "top100", "1-1024", "full":
		cfg.Ports = p.Ports
	}
	if p.RateLimit > 0 {
		cfg.RateLimit = p.RateLimit
		cfg.RL = core.NewRateLimiter(p.RateLimit)
		defer cfg.RL.Stop()
	}

	// Overall scan timeout (default 5 min, max 10 min).
	maxDur := 300 * time.Second
	if p.MaxDurationSeconds > 0 && p.MaxDurationSeconds <= 600 {
		maxDur = time.Duration(p.MaxDurationSeconds) * time.Second
	}
	scanCtx, scanCancel := context.WithTimeout(context.Background(), maxDur)
	defer scanCancel()
	cfg.SetContext(scanCtx, scanCancel)

	// Set up resolver.
	cfg.Resolver = core.NewResolver("", cfg.Timeout)

	// Detect scheme before normalizing — matches CLI flow.
	cfg.Target = detectScheme(p.Target, cfg)

	// Capture log output into a buffer.
	var logBuf bytes.Buffer
	log := core.NewLoggerWriter(p.Verbose, true, &logBuf)

	report := core.NewReport(cfg.Target)

	shouldRun := func(name string) bool {
		if len(selected) > 0 {
			return selected[name]
		}
		return true
	}

	// Execute modules in phase order.
	for _, mod := range moduleRegistry {
		if !shouldRun(mod.Name) {
			continue
		}
		if cfg.Passive && mod.Active {
			continue
		}
		safeRun(log, mod.Name, func() {
			mod.Fn(cfg, report, log)
		})
	}

	// Always run surface summary.
	safeRun(log, "surface", func() {
		modules.RunSurfaceSummary(cfg, report, log)
	})

	report.Finalize()
	snap := report.Snapshot()

	result := map[string]any{
		"report":  snap,
		"log":     logBuf.String(),
		"summary": buildSummary(snap),
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "failed to serialize report: " + err.Error(), true
	}
	return string(data), false
}

func buildSummary(snap core.ReportData) map[string]any {
	counts := map[string]int{}
	for _, f := range snap.Findings {
		counts[string(f.Severity)]++
	}
	return map[string]any{
		"target":         snap.Target,
		"total_findings": len(snap.Findings),
		"by_severity":    counts,
		"started_at":     snap.StartedAt,
		"ended_at":       snap.EndedAt,
	}
}

func safeRun(log *core.Logger, name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("Module %q panicked and was skipped: %v", name, r)
		}
	}()
	fn()
}

// normalizeTarget ensures the target has a scheme.
func normalizeTarget(target string) string {
	target = strings.TrimRight(target, "/")
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return "https://" + target
	}
	return target
}

// extractDomain pulls the hostname from a target string.
func extractDomain(target string) string {
	t := strings.TrimPrefix(target, "https://")
	t = strings.TrimPrefix(t, "http://")
	t = strings.Split(t, "/")[0]
	if strings.HasPrefix(t, "[") {
		if i := strings.Index(t, "]"); i != -1 {
			return t[1:i]
		}
		return t[1:]
	}
	if i := strings.LastIndex(t, ":"); i != -1 && !strings.Contains(t[:i], ":") {
		t = t[:i]
	}
	return t
}

// detectScheme probes the target to determine the best scheme. If the target
// already has a scheme it is returned after normalization. Otherwise HTTPS is
// tried first; if that fails, HTTP; if both fail, default to HTTPS. Uses
// core.NewHTTPClient so the egress-control dial hook is respected.
func detectScheme(target string, cfg *core.Config) string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return normalizeTarget(target)
	}
	client := core.NewHTTPClient(cfg)
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if resp, err := client.Head("https://" + target); err == nil {
		resp.Body.Close()
		return "https://" + target
	}
	if resp, err := client.Head("http://" + target); err == nil {
		resp.Body.Close()
		return "http://" + target
	}
	return "https://" + target
}

// validateTarget checks that the target is a valid hostname, IP, CIDR or URL.
func validateTarget(raw string) error {
	if len(raw) > 2048 {
		return fmt.Errorf("target too long")
	}
	if strings.ContainsAny(raw, " \t\r\n\x00") {
		return fmt.Errorf("target cannot contain spaces or control characters")
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return fmt.Errorf("invalid target URL")
		}
		return nil
	}
	if strings.Contains(raw, "://") {
		return fmt.Errorf("unsupported scheme (only http/https or hostname/IP/CIDR)")
	}
	if _, _, err := net.ParseCIDR(raw); err == nil {
		return nil
	}
	if ip := net.ParseIP(raw); ip != nil {
		return nil
	}
	// host[:port]
	h := raw
	if host, _, err := net.SplitHostPort(raw); err == nil {
		h = host
	}
	if net.ParseIP(h) != nil {
		return nil
	}
	if len(h) > 0 && len(h) <= 253 {
		return nil
	}
	return fmt.Errorf("invalid target: must be a hostname, IP, CIDR or http(s) URL")
}
