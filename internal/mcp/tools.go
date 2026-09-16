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
	Name      string `json:"name"`
	Category  string `json:"category"`
	Desc      string `json:"description"`
	Active    bool   `json:"active_probing"`
	WhenToUse string `json:"when_to_use"`
}

var moduleCatalog = []moduleCatalogEntry{
	{"whois", "Passive OSINT", "WHOIS/RDAP domain intelligence", false,
		"Identify registrant, registrar, nameservers and creation/expiry dates. First step in any recon."},
	{"asnmap", "Passive OSINT", "ASN / CIDR range discovery via BGP", false,
		"Map the target's IP space and find adjacent assets sharing the same ASN."},
	{"passivesrc", "Passive OSINT", "Passive subdomains (CT logs, 6 sources)", false,
		"Discover subdomains without touching the target. Safe for stealthy recon or when probing is not yet authorized."},
	{"dns", "DNS & Subdomains", "DNS enum, AXFR, SRV, SPF/DMARC, takeover", false,
		"Comprehensive DNS enumeration. Run early — discovered subdomains feed into later active modules."},
	{"wayback", "DNS & Subdomains", "Wayback Machine URL & parameter harvesting", false,
		"Mine historical URLs and parameters for hidden endpoints, old admin panels and forgotten API routes."},
	{"permute", "DNS & Subdomains", "Subdomain permutation & resolution", true,
		"Generate subdomain permutations from discovered names. Best after passivesrc/dns have built a base list."},
	{"httprobe", "Live Detection", "HTTP probe + favicon hash (Shodan pivoting)", true,
		"Check which discovered subdomains actually resolve and serve HTTP. Favicon hash enables Shodan pivoting."},
	{"webserver", "Fingerprinting", "Server fingerprint, TLS cert, HTTP methods", true,
		"Identify web server software, TLS configuration and allowed HTTP methods for targeted attacks."},
	{"metafiles", "Fingerprinting", "robots.txt, sitemap, security.txt, .well-known", true,
		"Check publicly exposed meta files for hidden paths, disclosure policies and API documentation."},
	{"headers", "Fingerprinting", "Security headers audit, tech fingerprinting", true,
		"Audit security headers (CSP, HSTS, X-Frame-Options) and fingerprint technologies from response headers."},
	{"content", "Fingerprinting", "HTML comments, JS secrets, source maps, leaks", true,
		"Scan page source for leaked secrets, API keys in JS, HTML comments with internal info, source maps."},
	{"portscan", "Attack Surface", "TCP port scan with service ID & banner grab", true,
		"Discover open ports and running services. Use with -ports flag (top100, 1-1024, full)."},
	{"cors", "Attack Surface", "CORS misconfiguration testing", true,
		"Test for exploitable CORS misconfigurations that could allow cross-origin data theft."},
	{"cloud", "Attack Surface", "S3/Azure/GCS/Firebase/DigitalOcean buckets", true,
		"Enumerate cloud storage buckets associated with the target domain for public access or misconfigurations."},
	{"dirbrute", "Attack Surface", "Hidden paths, admin panels, backups, configs", true,
		"Brute-force directories and files for admin panels, backups, config files. Use -dir-wordlist for custom lists."},
	{"apiscan", "Attack Surface", "GraphQL introspection, Swagger/OpenAPI, REST, WS", true,
		"Detect exposed API documentation, GraphQL introspection, WebSocket endpoints and REST API patterns."},
	{"saasenum", "Attack Surface", "SaaS enum (Zendesk/JIRA/Okta/Salesforce +15)", true,
		"Enumerate third-party SaaS platforms associated with the target for misconfigurations and data exposure."},
	{"crawler", "Attack Surface", "Web crawl for forms, params, entry points", true,
		"Crawl the web application to discover forms, URL parameters and entry points for further testing."},
	{"jsdeep", "Deep Analysis", "JS endpoint extraction (LinkFinder style)", true,
		"Extract API endpoints, paths and secrets from JavaScript files. Best after content/crawler."},
	{"endprobe", "Deep Analysis", "Unauthenticated access on JS-discovered endpoints", true,
		"Test JS-discovered endpoints for unauthenticated access. Runs after jsdeep."},
	{"takeover", "Deep Analysis", "Subdomain takeover via HTTP fingerprints (37 services)", true,
		"Check dangling DNS records for subdomain takeover across 37 service providers."},
}

// suggestMap maps keywords/objectives to recommended module sets.
var suggestMap = []struct {
	keywords []string
	modules  []string
	desc     string
}{
	{[]string{"passive", "osint", "stealth", "safe", "no-touch"},
		[]string{"whois", "asnmap", "passivesrc", "dns", "wayback"},
		"Passive-only recon: no traffic to the target"},
	{[]string{"subdomain", "subdomains", "dns", "enumerate"},
		[]string{"passivesrc", "dns", "wayback", "permute", "httprobe", "takeover"},
		"Subdomain discovery and validation"},
	{[]string{"web", "webapp", "website", "http", "fingerprint"},
		[]string{"webserver", "metafiles", "headers", "content", "cors", "dirbrute", "crawler"},
		"Web application fingerprinting and analysis"},
	{[]string{"vuln", "vulnerability", "vulnerabilities", "exploit", "attack"},
		[]string{"headers", "cors", "cloud", "apiscan", "takeover", "content", "endprobe"},
		"Vulnerability-focused assessment"},
	{[]string{"api", "graphql", "swagger", "openapi", "rest", "websocket"},
		[]string{"apiscan", "jsdeep", "endprobe", "content"},
		"API endpoint discovery and analysis"},
	{[]string{"cloud", "bucket", "s3", "azure", "gcs", "storage"},
		[]string{"cloud", "dns", "passivesrc"},
		"Cloud storage bucket enumeration"},
	{[]string{"port", "ports", "service", "services", "network", "tcp"},
		[]string{"portscan", "webserver"},
		"Port scanning and service identification"},
	{[]string{"js", "javascript", "secret", "key", "leak", "credential"},
		[]string{"content", "jsdeep", "endprobe"},
		"JavaScript analysis and secret discovery"},
	{[]string{"directory", "dir", "path", "admin", "backup", "brute"},
		[]string{"dirbrute", "metafiles", "crawler"},
		"Directory and file brute-forcing"},
	{[]string{"takeover", "dangling", "cname"},
		[]string{"dns", "passivesrc", "takeover"},
		"Subdomain takeover assessment"},
	{[]string{"full", "comprehensive", "everything", "complete", "all"},
		nil,
		"Full recon: all modules (may take several minutes)"},
	{[]string{"bbp", "bug bounty", "bounty", "hackerone", "bugcrowd"},
		[]string{"passivesrc", "dns", "wayback", "headers", "cors", "cloud", "apiscan", "content", "jsdeep", "endprobe", "takeover"},
		"Bug bounty recon: high-signal modules for rapid assessment"},
	{[]string{"saas", "third-party", "vendor", "zendesk", "jira", "okta"},
		[]string{"saasenum", "dns", "passivesrc"},
		"SaaS and third-party service enumeration"},
	{[]string{"crawl", "spider", "form", "parameter", "param"},
		[]string{"crawler", "wayback", "content"},
		"Web crawling for forms and parameters"},
}

// toolCall carries per-invocation context from the server to tool execution.
type toolCall struct {
	srv           *Server
	progressToken json.RawMessage
	ctx           context.Context
}

// readOnly is the annotation set for tools that don't modify any state.
var readOnly = map[string]any{
	"readOnlyHint":    true,
	"destructiveHint": false,
	"idempotentHint":  true,
	"openWorldHint":   false,
}

// toolDefinitions returns the MCP tool list for tools/list.
func toolDefinitions() []map[string]any {
	return []map[string]any{
		{
			"name":        "list_modules",
			"title":       "List Recon Modules",
			"description": "List all available w1r3hound recon modules with their categories, descriptions and usage hints. Use this to discover what modules are available before running a scan.",
			"annotations": readOnly,
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name":        "suggest_modules",
			"title":       "Suggest Modules",
			"description": "Given a recon objective or task description, return the recommended modules to run. Use this when you know what you want to achieve but not which specific modules to select.",
			"annotations": readOnly,
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"objective": map[string]any{
						"type":        "string",
						"description": "What you want to accomplish (e.g. 'find subdomains', 'check for vulnerabilities', 'passive recon only', 'full bug bounty assessment').",
					},
				},
				"required": []string{"objective"},
			},
		},
		{
			"name":        "server_info",
			"title":       "Server Info",
			"description": "Return server version, capabilities and available module count. Use this to verify the MCP server is operational and check its configuration.",
			"annotations": readOnly,
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name":  "scan",
			"title": "Run Scan",
			"description": "Run w1r3hound recon modules against a target. Returns structured findings aligned to the OWASP WSTG framework with severity ratings (CRITICAL/HIGH/MEDIUM/LOW/INFO). " +
				"Select specific modules for focused fast results, or omit modules to run all (may take several minutes). " +
				"Pass a progressToken in _meta to receive progress notifications as each module completes.",
			"annotations": map[string]any{
				"readOnlyHint":    true,
				"destructiveHint": false,
				"idempotentHint":  true,
				"openWorldHint":   true,
			},
			"outputSchema": scanOutputSchema(),
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
					"user_agent":           map[string]any{"type": "string", "description": "Custom User-Agent string for HTTP requests"},
					"headers":              map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "Custom HTTP headers as key-value pairs (e.g. {\"X-Bug-Bounty\": \"HackerOne/username\", \"Authorization\": \"Bearer token\"})"},
					"wordlist":             map[string]any{"type": "string", "description": "Path to a subdomain wordlist file for brute-force enumeration"},
					"dir_wordlist":         map[string]any{"type": "string", "description": "Path to a directory/file bruteforce wordlist (default: embedded list)"},
					"dir_extensions":       map[string]any{"type": "string", "description": "Comma-separated extensions for dirbrute (e.g. '.bak,.php,.zip,~')"},
					"skip_tls_verify":      map[string]any{"type": "boolean", "description": "Skip TLS certificate verification (default true — recon targets often have broken/self-signed TLS)"},
					"resolver":             map[string]any{"type": "string", "description": "Custom DNS resolver IP or ip:port (e.g. '1.1.1.1', '8.8.8.8:53')"},
					"resolvers":            map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "List of DNS resolver IPs (ip or ip:port). Enables the raw-UDP brute-force engine rotating across the list. Alternative to passing a file path — the agent provides the list directly."},
					"wayback_limit":        map[string]any{"type": "integer", "description": "Max URLs to pull from the Wayback CDX API (default 5000)"},
					"crawl_pages":          map[string]any{"type": "integer", "description": "Max pages for the crawler (default 100)"},
					"js_files":             map[string]any{"type": "integer", "description": "Max JavaScript files to analyse (default 50)"},
					"min_severity":         map[string]any{"type": "string", "enum": []string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}, "description": "Minimum severity to include in results (default: all)"},
				},
				"required": []string{"target"},
			},
		},
	}
}

// ── Prompts ──

func promptDefinitions() []map[string]any {
	return []map[string]any{
		{
			"name":        "bug_bounty_recon",
			"description": "Run a bug-bounty-focused recon workflow against a target. Selects high-signal modules for rapid vulnerability discovery.",
			"arguments": []map[string]any{
				{"name": "target", "description": "Target hostname, IP or URL", "required": true},
			},
		},
		{
			"name":        "passive_recon",
			"description": "Passive-only reconnaissance — no traffic touches the target. Safe for pre-authorization or stealth assessment.",
			"arguments": []map[string]any{
				{"name": "target", "description": "Target hostname, IP or URL", "required": true},
			},
		},
		{
			"name":        "subdomain_takeover_check",
			"description": "Discover subdomains and check for takeover opportunities via dangling DNS records.",
			"arguments": []map[string]any{
				{"name": "target", "description": "Target hostname or URL", "required": true},
			},
		},
		{
			"name":        "full_recon",
			"description": "Comprehensive recon with all 21 modules. May take several minutes.",
			"arguments": []map[string]any{
				{"name": "target", "description": "Target hostname, IP or URL", "required": true},
				{"name": "passive_only", "description": "Set to 'true' to skip active modules", "required": false},
			},
		},
		{
			"name":        "web_assessment",
			"description": "Web application security assessment: fingerprinting, header audit, CORS, directory brute-force and API discovery.",
			"arguments": []map[string]any{
				{"name": "target", "description": "Target URL or hostname", "required": true},
			},
		},
	}
}

func buildPrompt(name string, args map[string]string) ([]map[string]any, bool) {
	if args == nil {
		args = map[string]string{}
	}
	target := args["target"]
	if target == "" {
		target = "{{target}}"
	}

	var instruction string
	var modules string
	var extra string

	switch name {
	case "bug_bounty_recon":
		instruction = "Run a bug-bounty-focused recon against " + target + ". Focus on high-signal findings: subdomain takeover, CORS misconfig, exposed APIs, cloud storage, leaked secrets."
		modules = `["passivesrc","dns","wayback","headers","cors","cloud","apiscan","content","jsdeep","endprobe","takeover"]`
	case "passive_recon":
		instruction = "Run passive-only recon against " + target + ". Do NOT send any traffic to the target — use only public data sources."
		modules = `["whois","asnmap","passivesrc","dns","wayback"]`
		extra = `, "passive": true`
	case "subdomain_takeover_check":
		instruction = "Discover subdomains of " + target + " and check each for takeover opportunities."
		modules = `["passivesrc","dns","wayback","permute","httprobe","takeover"]`
	case "full_recon":
		instruction = "Run a comprehensive recon against " + target + " using all modules."
		if args["passive_only"] == "true" {
			extra = `, "passive": true`
		}
	case "web_assessment":
		instruction = "Assess the web application at " + target + " for security issues: server fingerprint, security headers, CORS, hidden paths, APIs."
		modules = `["webserver","metafiles","headers","content","cors","dirbrute","apiscan","crawler"]`
	default:
		return nil, false
	}

	scanCall := fmt.Sprintf(`{"target": %q`, target)
	if modules != "" {
		scanCall += fmt.Sprintf(`, "modules": %s`, modules)
	}
	scanCall += extra + "}"

	messages := []map[string]any{
		{
			"role": "user",
			"content": map[string]any{
				"type": "text",
				"text": instruction + "\n\nUse the scan tool with these arguments:\n" + scanCall,
			},
		},
	}
	return messages, true
}

// ── Completions ──

func completeArgument(refType, refName, argName, prefix string) []string {
	prefix = strings.ToLower(prefix)

	switch {
	case refType == "ref/tool" && refName == "scan" && argName == "modules":
		return filterPrefix(allModuleNames(), prefix)

	case refType == "ref/tool" && refName == "scan" && argName == "ports":
		return filterPrefix([]string{"top100", "1-1024", "full"}, prefix)

	case refType == "ref/tool" && refName == "scan" && argName == "min_severity":
		return filterPrefix([]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}, prefix)

	case refType == "ref/tool" && refName == "suggest_modules" && argName == "objective":
		return filterPrefix([]string{
			"passive recon", "subdomain discovery", "web assessment",
			"vulnerability scan", "bug bounty", "api discovery",
			"cloud storage enumeration", "port scanning", "full scan",
		}, prefix)

	case argName == "name" && refType == "ref/prompt":
		return filterPrefix([]string{
			"bug_bounty_recon", "passive_recon", "subdomain_takeover_check",
			"full_recon", "web_assessment",
		}, prefix)
	}

	return []string{}
}

func allModuleNames() []string {
	names := make([]string, len(moduleRegistry))
	for i, e := range moduleRegistry {
		names[i] = e.Name
	}
	return names
}

func filterPrefix(items []string, prefix string) []string {
	if prefix == "" {
		return items
	}
	var out []string
	for _, item := range items {
		if strings.HasPrefix(strings.ToLower(item), prefix) {
			out = append(out, item)
		}
	}
	return out
}

// toolResult holds the output of a tool execution.
type toolResult struct {
	Text              string
	IsError           bool
	StructuredContent any
}

// executeTool dispatches a tool call by name.
func executeTool(name string, argsRaw json.RawMessage, tc *toolCall) toolResult {
	switch name {
	case "list_modules":
		text, isErr := executeListModules()
		return toolResult{Text: text, IsError: isErr}
	case "suggest_modules":
		text, isErr := executeSuggestModules(argsRaw)
		return toolResult{Text: text, IsError: isErr}
	case "server_info":
		text, isErr := executeServerInfo(tc)
		return toolResult{Text: text, IsError: isErr}
	case "scan":
		return executeScan(argsRaw, tc)
	default:
		return toolResult{Text: fmt.Sprintf("unknown tool: %q", name), IsError: true}
	}
}

func executeListModules() (string, bool) {
	data, _ := json.MarshalIndent(moduleCatalog, "", "  ")
	return string(data), false
}

func executeSuggestModules(argsRaw json.RawMessage) (string, bool) {
	var params struct {
		Objective string `json:"objective"`
	}
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &params); err != nil {
			return "invalid arguments: " + err.Error(), true
		}
	}
	if params.Objective == "" {
		return "objective is required", true
	}

	obj := strings.ToLower(params.Objective)
	type match struct {
		Modules []string `json:"modules"`
		Desc    string   `json:"description"`
		Score   int      `json:"match_score"`
	}
	var matches []match
	for _, sm := range suggestMap {
		score := 0
		for _, kw := range sm.keywords {
			if strings.Contains(obj, kw) {
				score++
			}
		}
		if score > 0 {
			mods := sm.modules
			if mods == nil {
				mods = make([]string, 0, len(moduleRegistry))
				for _, e := range moduleRegistry {
					mods = append(mods, e.Name)
				}
			}
			matches = append(matches, match{Modules: mods, Desc: sm.desc, Score: score})
		}
	}

	if len(matches) == 0 {
		result := map[string]any{
			"suggestion": "No specific match found. Here are common starting points:",
			"options": []map[string]any{
				{"objective": "passive recon", "modules": []string{"whois", "asnmap", "passivesrc", "dns", "wayback"}},
				{"objective": "web assessment", "modules": []string{"webserver", "headers", "content", "cors", "dirbrute"}},
				{"objective": "full scan", "modules": "omit the modules parameter to run all"},
			},
		}
		data, _ := json.MarshalIndent(result, "", "  ")
		return string(data), false
	}

	// Return the best match (highest score)
	best := matches[0]
	for _, m := range matches[1:] {
		if m.Score > best.Score {
			best = m
		}
	}
	result := map[string]any{
		"recommended_modules": best.Modules,
		"description":         best.Desc,
		"usage":               fmt.Sprintf("Run scan with modules: %s", strings.Join(best.Modules, ", ")),
	}
	data, _ := json.MarshalIndent(result, "", "  ")
	return string(data), false
}

func executeServerInfo(tc *toolCall) (string, bool) {
	ver := ""
	if tc != nil && tc.srv != nil {
		ver = tc.srv.version
	}
	info := map[string]any{
		"name":                "w1r3hound",
		"version":             ver,
		"protocol":            "2025-06-18",
		"supportedVersions":   []string{"2025-06-18", "2026-07-28"},
		"total_modules":       len(moduleRegistry),
		"tools":               []string{"list_modules", "suggest_modules", "server_info", "scan"},
		"ssrf_guard":          "enabled by default (set allow_private=true to override)",
		"scan_timeout":        "default 300s, max 600s",
		"progress":            "notifications/progress sent when progressToken provided in _meta",
		"logging":             "notifications/message streamed during scan; control with logging/setLevel",
		"findings_format":     "OWASP WSTG aligned, severity: CRITICAL/HIGH/MEDIUM/LOW/INFO",
		"content_annotations": true,
	}
	data, _ := json.MarshalIndent(info, "", "  ")
	return string(data), false
}

type scanParams struct {
	Target             string            `json:"target"`
	Modules            []string          `json:"modules"`
	Passive            bool              `json:"passive"`
	Concurrency        int               `json:"concurrency"`
	TimeoutSeconds     int               `json:"timeout_seconds"`
	Ports              string            `json:"ports"`
	RateLimit          int               `json:"rate_limit"`
	MaxDurationSeconds int               `json:"max_duration_seconds"`
	AllowPrivate       bool              `json:"allow_private"`
	Verbose            bool              `json:"verbose"`
	UserAgent          string            `json:"user_agent"`
	Headers            map[string]string `json:"headers"`
	Wordlist           string            `json:"wordlist"`
	DirWordlist        string            `json:"dir_wordlist"`
	DirExtensions      string            `json:"dir_extensions"`
	SkipTLSVerify      *bool             `json:"skip_tls_verify"`
	Resolver           string            `json:"resolver"`
	Resolvers          []string          `json:"resolvers"`
	WaybackLimit       int               `json:"wayback_limit"`
	CrawlPages         int               `json:"crawl_pages"`
	JSFiles            int               `json:"js_files"`
	MinSeverity        string            `json:"min_severity"`
}

var severityOrder = map[string]int{
	"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
}

// logTee captures log output into a buffer and streams complete lines as
// MCP logging notifications (notifications/message).
type logTee struct {
	buf     bytes.Buffer
	srv     *Server
	partial string
}

func (t *logTee) Write(p []byte) (int, error) {
	n, err := t.buf.Write(p)
	t.partial += string(p)
	for {
		idx := strings.IndexByte(t.partial, '\n')
		if idx < 0 {
			break
		}
		line := t.partial[:idx]
		t.partial = t.partial[idx+1:]
		if strings.TrimSpace(line) != "" && t.srv != nil {
			t.srv.notifyLog("info", "scan", line)
		}
	}
	return n, err
}

func scanOutputSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"report": map[string]any{
				"type":        "object",
				"description": "Full scan report with target, timing and findings",
				"properties": map[string]any{
					"target":     map[string]any{"type": "string"},
					"started_at": map[string]any{"type": "string", "format": "date-time"},
					"ended_at":   map[string]any{"type": "string", "format": "date-time"},
					"findings": map[string]any{
						"type": "array",
						"items": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"severity":    map[string]any{"type": "string", "enum": []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}},
								"category":    map[string]any{"type": "string"},
								"title":       map[string]any{"type": "string"},
								"description": map[string]any{"type": "string"},
								"evidence":    map[string]any{"type": "string"},
								"reference":   map[string]any{"type": "string"},
							},
						},
					},
				},
			},
			"log": map[string]any{
				"type":        "string",
				"description": "Full scan execution log",
			},
			"summary": map[string]any{
				"type":        "object",
				"description": "Scan summary with finding counts by severity",
				"properties": map[string]any{
					"target":         map[string]any{"type": "string"},
					"total_findings": map[string]any{"type": "integer"},
					"by_severity":    map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "integer"}},
					"started_at":     map[string]any{"type": "string", "format": "date-time"},
					"ended_at":       map[string]any{"type": "string", "format": "date-time"},
				},
			},
		},
		"required": []string{"report", "log", "summary"},
	}
}

func executeScan(argsRaw json.RawMessage, tc *toolCall) toolResult {
	scanErr := func(msg string) toolResult {
		return toolResult{Text: msg, IsError: true}
	}

	var p scanParams
	if len(argsRaw) > 0 {
		if err := json.Unmarshal(argsRaw, &p); err != nil {
			return scanErr("invalid scan arguments: " + err.Error())
		}
	}
	if p.Target == "" {
		return scanErr("target is required")
	}
	if err := validateTarget(p.Target); err != nil {
		return scanErr(err.Error())
	}

	// Validate requested modules.
	selected := map[string]bool{}
	if len(p.Modules) > 0 {
		for _, m := range p.Modules {
			m = strings.ToLower(strings.TrimSpace(m))
			if !knownModuleSet[m] {
				return scanErr(fmt.Sprintf("unknown module: %q — use list_modules to see available names", m))
			}
			selected[m] = true
		}
	}

	// Validate min_severity.
	minSev := -1
	if p.MinSeverity != "" {
		sev, ok := severityOrder[strings.ToUpper(p.MinSeverity)]
		if !ok {
			return scanErr(fmt.Sprintf("invalid min_severity: %q — must be INFO, LOW, MEDIUM, HIGH or CRITICAL", p.MinSeverity))
		}
		minSev = sev
	}

	// Validate headers.
	if len(p.Headers) > 32 {
		return scanErr("too many headers (max 32)")
	}
	for name, value := range p.Headers {
		if strings.ContainsAny(name, " \t\r\n\x00") || strings.ContainsAny(value, "\r\n\x00") {
			return scanErr(fmt.Sprintf("invalid header %q: must not contain control characters", name))
		}
	}

	// Validate resolver(s).
	if p.Resolver != "" {
		if !validResolver(p.Resolver) {
			return scanErr("invalid resolver: must be a bare IP or ip:port (e.g. '1.1.1.1' or '8.8.8.8:53')")
		}
	}
	for i, r := range p.Resolvers {
		if !validResolver(r) {
			return scanErr(fmt.Sprintf("invalid resolver at index %d: %q — must be a bare IP or ip:port", i, r))
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

	// Apply parameters.
	if p.UserAgent != "" {
		cfg.UserAgent = p.UserAgent
	}
	if len(p.Headers) > 0 {
		cfg.RequestHeaders = p.Headers
	}
	if p.Wordlist != "" {
		cfg.Wordlist = p.Wordlist
	}
	if p.DirWordlist != "" {
		cfg.DirWordlist = p.DirWordlist
	}
	if p.DirExtensions != "" {
		cfg.DirExtensions = p.DirExtensions
	}
	if p.SkipTLSVerify != nil {
		cfg.SkipSSLCheck = *p.SkipTLSVerify
	}
	if p.Resolver != "" {
		cfg.Resolver = core.NewResolver(p.Resolver, cfg.Timeout)
	}
	if len(p.Resolvers) > 0 {
		cfg.Resolvers = p.Resolvers
	}
	if p.WaybackLimit > 0 && p.WaybackLimit <= 100000 {
		cfg.WaybackLimit = p.WaybackLimit
	}
	if p.CrawlPages > 0 && p.CrawlPages <= 5000 {
		cfg.CrawlMaxPages = p.CrawlPages
	}
	if p.JSFiles > 0 && p.JSFiles <= 2000 {
		cfg.MaxJSFiles = p.JSFiles
	}

	// Overall scan timeout (default 5 min, max 10 min).
	// Layer the timeout on top of the parent context (which may carry cancellation).
	maxDur := 300 * time.Second
	if p.MaxDurationSeconds > 0 && p.MaxDurationSeconds <= 600 {
		maxDur = time.Duration(p.MaxDurationSeconds) * time.Second
	}
	parentCtx := context.Background()
	if tc != nil && tc.ctx != nil {
		parentCtx = tc.ctx
	}
	scanCtx, scanCancel := context.WithTimeout(parentCtx, maxDur)
	defer scanCancel()
	cfg.SetContext(scanCtx, scanCancel)

	if p.Resolver == "" {
		cfg.Resolver = core.NewResolver("", cfg.Timeout)
	}

	cfg.Target = detectScheme(p.Target, cfg)

	// Capture log output; stream lines as notifications/message.
	var srv *Server
	if tc != nil {
		srv = tc.srv
	}
	tee := &logTee{srv: srv}
	log := core.NewLoggerWriter(p.Verbose, false, tee)

	report := core.NewReport(cfg.Target)

	shouldRun := func(name string) bool {
		if len(selected) > 0 {
			return selected[name]
		}
		return true
	}

	// Count modules to run for progress tracking.
	total := 0
	for _, mod := range moduleRegistry {
		if !shouldRun(mod.Name) {
			continue
		}
		if cfg.Passive && mod.Active {
			continue
		}
		total++
	}

	// Determine the progressToken (only send progress if client requested it).
	var progressToken json.RawMessage
	if tc != nil {
		progressToken = tc.progressToken
	}

	// Execute modules in phase order with progress notifications.
	progress := 0
	for _, mod := range moduleRegistry {
		if !shouldRun(mod.Name) {
			continue
		}
		if cfg.Passive && mod.Active {
			continue
		}
		if srv != nil {
			srv.notifyProgress(progressToken, progress, total+1,
				fmt.Sprintf("starting module: %s", mod.Name))
		}
		safeRun(log, mod.Name, func() {
			mod.Fn(cfg, report, log)
		})
		progress++
		if srv != nil {
			snap := report.Snapshot()
			srv.notifyProgress(progressToken, progress, total+1,
				fmt.Sprintf("completed: %s (%d findings so far)", mod.Name, len(snap.Findings)))
		}
	}

	// Always run surface summary.
	if srv != nil {
		srv.notifyProgress(progressToken, progress, total+1, "running surface summary")
	}
	safeRun(log, "surface", func() {
		modules.RunSurfaceSummary(cfg, report, log)
	})

	report.Finalize()
	snap := report.Snapshot()

	// Apply severity filter if requested.
	if minSev > 0 {
		filtered := make([]core.Finding, 0, len(snap.Findings))
		for _, f := range snap.Findings {
			if severityOrder[string(f.Severity)] >= minSev {
				filtered = append(filtered, f)
			}
		}
		snap.Findings = filtered
	}

	structured := map[string]any{
		"report":  snap,
		"log":     tee.buf.String(),
		"summary": buildSummary(snap),
	}
	data, err := json.MarshalIndent(structured, "", "  ")
	if err != nil {
		return toolResult{Text: "failed to serialize report: " + err.Error(), IsError: true}
	}
	return toolResult{Text: string(data), StructuredContent: structured}
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

// validResolver accepts a bare IP (v4/v6) or an ip:port.
func validResolver(s string) bool {
	if s == "" || strings.ContainsAny(s, " \t\r\n\x00") {
		return false
	}
	if ip := net.ParseIP(s); ip != nil {
		return true
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}
	if net.ParseIP(host) == nil {
		return false
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(port) > 0
}
