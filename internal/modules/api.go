package modules

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

// ══════════════════════════════════════════════
//  API RECONNAISSANCE
//  GraphQL introspection, Swagger/OpenAPI docs,
//  REST versioning, WebSocket endpoints.
//  (Checklist Fase 4.3: API reconnaissance)
// ══════════════════════════════════════════════

type APIResult struct {
	GraphQLEndpoints []GraphQLFinding `json:"graphql_endpoints,omitempty"`
	SwaggerDocs      []SwaggerFinding `json:"api_docs,omitempty"`
	RESTVersions     []string         `json:"rest_versions_found,omitempty"`
	WebSocketHints   []string         `json:"websocket_hints,omitempty"`
}

type GraphQLFinding struct {
	URL             string `json:"url"`
	IntrospectionOn bool   `json:"introspection_enabled"`
	TypeCount       int    `json:"type_count,omitempty"`
}

type SwaggerFinding struct {
	URL       string `json:"url"`
	Type      string `json:"type"` // swagger, openapi, graphql-playground
	Endpoints int    `json:"endpoint_count,omitempty"`
}

// Common GraphQL endpoint paths
var graphqlPaths = []string{
	"/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/v2/graphql",
	"/query", "/api/query", "/gql", "/api/gql", "/graphql/console",
	"/graphql-explorer", "/altair", "/playground", "/subscriptions",
	"/.netlify/functions/graphql", "/index.php?graphql",
}

// Common API documentation paths
var apiDocPaths = []struct {
	Path string
	Type string
}{
	{"", "api-docs"},
	{"/swagger.json", "swagger"},
	{"/swagger/v1/swagger.json", "swagger"},
	{"/swagger-ui.html", "swagger-ui"},
	{"/swagger-ui/", "swagger-ui"},
	{"/api/swagger.json", "swagger"},
	{"/api-docs", "swagger"},
	{"/api/api-docs", "swagger"},
	{"/v2/api-docs", "swagger"},
	{"/v3/api-docs", "openapi"},
	{"/openapi.json", "openapi"},
	{"/openapi.yaml", "openapi"},
	{"/api/openapi.json", "openapi"},
	{"/redoc", "redoc"},
	{"/api/redoc", "redoc"},
	{"/docs", "api-docs"},
	{"/api/docs", "api-docs"},
	{"/api/v1/docs", "api-docs"},
	{"/swagger/index.html", "swagger-ui"},
	{"/apidocs", "api-docs"},
	{"/api-explorer", "api-docs"},
	{"/graphql/schema.json", "graphql-schema"},
}

// The standard GraphQL introspection query
const introspectionQuery = `{"query":"query IntrospectionQuery { __schema { types { name kind } queryType { name } mutationType { name } } }"}`

func RunAPI(cfg *core.Config, report *core.ReconReport, log *core.Logger) {
	log.Module("APISCAN // GraphQL, Swagger & REST Discovery")

	if cfg.Passive {
		log.Info("Skipping API scan in passive mode")
		return
	}

	client := core.NewHTTPClient(cfg)
	target := normalizeTarget(cfg.Target)
	result := APIResult{}

	// ── Catch-all calibration ──
	// SPAs and catch-all routers return 200 + the same app shell for ANY path,
	// which produces false positives for GraphQL/Swagger discovery. Probe two
	// random paths and record the signature so we can reject matches that look
	// identical to the catch-all response.
	catchAll := calibrateCatchAll(client, target, cfg)
	if catchAll.isCatchAll {
		log.Warn("Catch-all detected: server returns 200+shell (~%d bytes) for random paths — filtering API false positives", catchAll.bodyLen)
	}

	// ── 1. GraphQL endpoint discovery + introspection ──
	log.Info("Probing %d GraphQL endpoint candidates...", len(graphqlPaths))
	for _, path := range graphqlPaths {
		url := target + path
		// First a GET to see if it exists
		body, status, err := core.FetchBodyRL(client, url, cfg.UserAgent, cfg.RL)
		if err != nil || (status != 200 && status != 400 && status != 405) {
			continue
		}
		// Reject if it looks like the catch-all app shell
		if catchAll.matches(status, len(body)) {
			continue
		}

		// Try introspection via POST
		gf := GraphQLFinding{URL: url}
		introspected := postGraphQL(client, url, cfg)
		if introspected > 0 {
			gf.IntrospectionOn = true
			gf.TypeCount = introspected
			log.Warn("GraphQL introspection ENABLED: %s (%d types)", url, introspected)
			report.Add(core.Finding{
				Module:      "apiscan",
				WSTG:        "WSTG-INFO-06",
				Title:       fmt.Sprintf("GraphQL introspection enabled: %s", url),
				Severity:    core.SevMedium,
				Description: fmt.Sprintf("Full schema exposed (%d types). Attackers can map the entire API.", introspected),
			})
			result.GraphQLEndpoints = append(result.GraphQLEndpoints, gf)
		} else if status == 400 {
			// A 400 to a plain GET is a stronger GraphQL signal than 200
			// (GraphQL servers reject GET without a query). 200 alone on a
			// catch-all server is meaningless.
			log.Info("GraphQL endpoint found (introspection off): %s", url)
			result.GraphQLEndpoints = append(result.GraphQLEndpoints, gf)
		} else if strings.Contains(body, "__schema") ||
			strings.Contains(body, "\"graphql\"") ||
			strings.Contains(strings.ToLower(body), "graphql") {
			// 200 + GraphQL markers in the body: the endpoint exists but
			// introspection is off/blocked (e.g. Apollo landing page, Yoga,
			// gateways answering 200 with an error envelope). Previously this
			// fell through both branches and the endpoint was never reported —
			// a false negative on exactly the hardened targets where knowing
			// the endpoint exists still matters.
			log.Info("GraphQL endpoint found (introspection off): %s", url)
			result.GraphQLEndpoints = append(result.GraphQLEndpoints, gf)
		}
	}

	// ── 2. Swagger / OpenAPI documentation discovery ──
	log.Info("Probing %d API documentation paths...", len(apiDocPaths))
	for _, doc := range apiDocPaths {
		url := target + doc.Path
		resp, err := core.DoRequestRL(client, "GET", url, cfg.UserAgent, cfg.RL)
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}
		bodyBytes := core.ReadBodyLimit(resp, 10*1024*1024)
		resp.Body.Close()
		body := bodyBytes
		status := 200

		// Skip if we were redirected to a different domain — a redirect
		// to an external docs site is not an API spec exposure on the target.
		if resp.Request != nil && resp.Request.URL != nil {
			finalHost := resp.Request.URL.Hostname()
			apex := extractApexDomain(cfg.Domain)
			if finalHost != cfg.Domain && !strings.HasSuffix(finalHost, "."+apex) && finalHost != apex {
				log.Debug("API doc path %s redirected to %s (off-target), skipping", doc.Path, finalHost)
				continue
			}
		}

		// Reject catch-all app shell
		if catchAll.matches(status, len(body)) {
			continue
		}

		// Validate it's actually API docs, not a generic page
		lower := strings.ToLower(body)
		isDoc := false
		switch doc.Type {
		case "swagger", "openapi":
			isDoc = strings.Contains(lower, "swagger") || strings.Contains(lower, "openapi") ||
				strings.Contains(body, "\"paths\"") || strings.Contains(body, "\"definitions\"")
		case "swagger-ui", "redoc":
			isDoc = strings.Contains(lower, "swagger") || strings.Contains(lower, "redoc") ||
				strings.Contains(lower, "openapi")
		case "api-docs":
			isDoc = strings.Contains(lower, "swagger") || strings.Contains(lower, "redoc") ||
				strings.Contains(lower, "openapi") ||
				(strings.Contains(body, "\"paths\"") && strings.Contains(body, "\"info\"")) ||
				looksLikeStaticAPIDocs(body)
		case "graphql-schema":
			isDoc = strings.Contains(body, "__schema") || strings.Contains(body, "\"types\"")
		}

		if isDoc {
			sf := SwaggerFinding{URL: url, Type: doc.Type}
			specBody := body
			// When the response is a Swagger UI HTML page (not a raw JSON
			// spec), the actual OpenAPI spec is embedded in a companion JS
			// file (swagger-ui-init.js) or loaded from a URL declared in the
			// page.  Counting operations in the HTML always yields 0 — fetch
			// the real spec so the endpoint count is accurate.
			if isSwaggerUIHTML(body) {
				if initSpec := fetchSwaggerUISpec(client, url, body, cfg); initSpec != "" {
					specBody = initSpec
				}
			}
			sf.Endpoints = countAPIOperations(specBody)
			result.SwaggerDocs = append(result.SwaggerDocs, sf)
			severity := core.SevLow
			description := fmt.Sprintf("%s spec accessible without auth — hands attackers the full endpoint list.", doc.Type)
			title := fmt.Sprintf("API documentation exposed: %s", url)
			if doc.Path == "" && looksLikeStaticAPIDocs(body) {
				severity = core.SevInfo
				description = "Public API documentation discovered at the target root."
				title = fmt.Sprintf("API documentation discovered: %s", url)
				log.Info("API documentation discovered at target root: %s", url)
			} else {
				log.Warn("API docs exposed [%s]: %s (%d operations)", doc.Type, url, sf.Endpoints)
			}
			report.Add(core.Finding{
				Module:      "apiscan",
				WSTG:        "WSTG-INFO-06",
				Title:       title,
				Severity:    severity,
				Description: description,
			})
		}
	}

	// ── 3. REST API versioning & base-path discovery ──
	log.Info("Probing REST API namespaces...")

	// Probe unversioned base paths first. When a base returns 500 (Express-style
	// framework error for missing entity), skip its versioned children — they
	// hit the same catch-all error handler and produce noise.
	type apiProbe struct {
		Path string
		Base string // parent prefix: if Base is live, skip this child
	}
	apiProbes := []apiProbe{
		// Base paths (no parent — always probed)
		{"/api", ""},
		{"/rest", ""},
		{"/b2b/v2", ""},
		// Versioned children (suppressed when parent base is live)
		{"/api/v1", "/api"},
		{"/api/v2", "/api"},
		{"/api/v3", "/api"},
		{"/api/v4", "/api"},
		{"/rest/v1", "/rest"},
		{"/rest/v2", "/rest"},
		{"/api/1.0", "/api"},
		{"/api/2.0", "/api"},
		// Top-level version prefixes (no parent)
		{"/v1", ""},
		{"/v2", ""},
		{"/v3", ""},
	}
	liveBase := make(map[string]bool) // which base paths responded as real APIs
	var stackTraceEndpoints []string
	stackTraceSeen := make(map[string]bool)
	for _, p := range apiProbes {
		if p.Base != "" && liveBase[p.Base] {
			log.Debug("Skipping %s (parent %s already detected)", p.Path, p.Base)
			continue
		}
		url := target + p.Path
		body, status, err := core.FetchBodyRL(client, url, cfg.UserAgent, cfg.RL)
		if err != nil {
			continue
		}
		// Verbose error / stack-trace disclosure (WSTG-ERRH). Framework error
		// handlers (e.g. Express's errorhandler on a missing entity) dump a full
		// stack trace with server-side paths — apiscan already has the body, so
		// inspect it here rather than re-fetching.
		if st := detectStackTrace(body); len(st) > 0 && !stackTraceSeen[p.Path] {
			stackTraceSeen[p.Path] = true
			stackTraceEndpoints = append(stackTraceEndpoints, fmt.Sprintf("%s [%d] (%s)", p.Path, status, strings.Join(st, ", ")))
		}
		exists := false
		switch status {
		case 401, 403:
			exists = true
		case 500:
			if !catchAll.matches(status, len(body)) {
				exists = true
			}
		case 200:
			if !catchAll.matches(status, len(body)) && looksLikeAPIResponse(body) {
				exists = true
			}
		}
		if exists {
			result.RESTVersions = append(result.RESTVersions, fmt.Sprintf("%s (%d)", p.Path, status))
			log.Info("REST API namespace: %s [%d]", p.Path, status)
			if p.Base == "" {
				liveBase[p.Path] = true
			}
		}
	}
	if len(result.RESTVersions) >= 2 {
		report.Add(core.Finding{
			Module:      "apiscan",
			WSTG:        "WSTG-INFO-06",
			Title:       fmt.Sprintf("Multiple API namespaces live: %d", len(result.RESTVersions)),
			Severity:    core.SevLow,
			Description: "Multiple API namespaces can indicate older/less-protected versions: " + strings.Join(result.RESTVersions, ", "),
		})
	}

	if len(stackTraceEndpoints) > 0 {
		log.Warn("Stack trace / verbose error disclosure on %d endpoint(s)", len(stackTraceEndpoints))
		report.Add(core.Finding{
			Module:      "apiscan",
			WSTG:        "WSTG-ERRH-02",
			Title:       fmt.Sprintf("Stack trace / verbose error disclosure (%d endpoint(s))", len(stackTraceEndpoints)),
			Severity:    core.SevMedium,
			Description: "Endpoints return a debug error page / stack trace that leaks the server-side framework, dependency paths and absolute filesystem locations: " + strings.Join(stackTraceEndpoints, ", ") + ". Production apps should return a generic error page instead (WSTG-ERRH).",
			Data:        stackTraceEndpoints,
		})
	}

	// ── 4. WebSocket hint detection (from main page JS) ──
	body, _, _ := core.FetchBodyRL(client, target, cfg.UserAgent, cfg.RL)
	wsPatterns := []string{"ws://", "wss://", "new WebSocket", "socket.io", "/socket.io/", "/ws", "/websocket"}
	wsSeen := make(map[string]bool)
	for _, p := range wsPatterns {
		if strings.Contains(body, p) && !wsSeen[p] {
			wsSeen[p] = true
			result.WebSocketHints = append(result.WebSocketHints, p)
		}
	}
	if len(result.WebSocketHints) > 0 {
		log.Info("WebSocket hints found: %v", result.WebSocketHints)
	}

	report.Add(core.Finding{
		Module:   "apiscan",
		WSTG:     "WSTG-INFO-06",
		Title:    fmt.Sprintf("API scan: %d GraphQL, %d docs, %d REST versions", len(result.GraphQLEndpoints), len(result.SwaggerDocs), len(result.RESTVersions)),
		Severity: core.SevInfo,
		Data:     result,
	})
}

// Stack-trace / verbose-error signatures. Kept specific so a normal JSON error
// envelope ({"message":"Not Found"}) never trips them.
var (
	stJSFrame   = regexp.MustCompile(`\.js:\d+:\d+`) // Node "file.js:line:col"
	stPyTrace   = regexp.MustCompile(`Traceback \(most recent call last\)`)
	stPHPTrace  = regexp.MustCompile(`(?i)(fatal error|parse error|uncaught \w+)[: ].*(on line \d+|\.php)`)
	stJavaFrame = regexp.MustCompile(`\bat [\w.$]+\([\w ]+\.java:\d+\)`)
	stRubyFrame = regexp.MustCompile(`\.rb:\d+:in `)
)

// detectStackTrace reports which server-side stack traces / verbose error dumps
// a response body reveals. It returns the language/framework labels detected
// (empty for a normal error envelope), requiring several stack-trace tokens
// together so a plain JSON {"error":...} can't trigger it. Such a dump leaks the
// framework, dependency paths and absolute server filesystem locations
// (WSTG-ERRH — e.g. Juice Shop's Express errorhandler on /api and /rest).
func detectStackTrace(body string) []string {
	if len(body) > 256*1024 {
		body = body[:256*1024]
	}
	var hits []string
	// A "file.js:line:col" position together with a server-side dependency path
	// or the Express errorhandler title is unambiguously a stack-trace/error
	// dump (the " at frame" text is HTML-wrapped in the errorhandler page, so it
	// isn't a reliable marker on its own).
	if stJSFrame.MatchString(body) &&
		(strings.Contains(body, "node_modules") || strings.Contains(body, "<title>Error:")) {
		hits = append(hits, "Node.js")
	}
	if stPyTrace.MatchString(body) {
		hits = append(hits, "Python")
	}
	if stPHPTrace.MatchString(body) {
		hits = append(hits, "PHP")
	}
	if stJavaFrame.MatchString(body) {
		hits = append(hits, "Java")
	}
	if stRubyFrame.MatchString(body) {
		hits = append(hits, "Ruby")
	}
	return hits
}

// looksLikeAPIResponse reports whether a 200 body resembles an API payload
// (JSON/XML/error envelope) rather than an HTML page (the catch-all shell).
func looksLikeAPIResponse(body string) bool {
	t := strings.TrimSpace(body)
	if t == "" {
		return false
	}
	head := t
	if len(head) > 2048 {
		head = head[:2048]
	}
	lower := strings.ToLower(head)
	if strings.Contains(lower, "<html") || strings.Contains(lower, "<!doctype") {
		return false
	}
	if t[0] == '{' || t[0] == '[' {
		return true // JSON
	}
	// Common REST error envelopes / hints served as text.
	for _, marker := range []string{"\"error\"", "\"message\"", "\"errors\"",
		"\"status\"", "application/json", "not found", "unauthorized", "<?xml"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// postGraphQL sends an introspection query and returns the type count (0 if disabled).
func postGraphQL(client *http.Client, url string, cfg *core.Config) int {
	if cfg.RL != nil {
		cfg.RL.Wait()
	}
	req, err := core.NewPostRequest(url, "application/json", introspectionQuery, cfg.UserAgent)
	if err != nil {
		return 0
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0
	}
	body := core.ReadBodyLimit(resp, 2*1024*1024)
	if !strings.Contains(body, "__schema") && !strings.Contains(body, "\"types\"") {
		return 0
	}
	// Rough type count
	return strings.Count(body, "\"name\":")
}

// ── Catch-all detection ──

type catchAllSignature struct {
	isCatchAll bool
	status     int
	bodyLen    int
}

// matches reports whether a response looks like the catch-all app shell.
func (c catchAllSignature) matches(status, bodyLen int) bool {
	if !c.isCatchAll {
		return false
	}
	if status != c.status {
		return false
	}
	tolerance := c.bodyLen * 15 / 100
	if tolerance < 150 {
		tolerance = 150
	}
	d := bodyLen - c.bodyLen
	if d < 0 {
		d = -d
	}
	return d <= tolerance
}

// calibrateCatchAll probes two random paths. If both return 200 with a
// similar body size, the server is a catch-all (SPA) and we record the shell.
func calibrateCatchAll(client *http.Client, target string, cfg *core.Config) catchAllSignature {
	randoms := []string{
		"/W1r3hound-api-probe-xq7k9m2z",
		"/W1r3hound-nonexistent-api-route-9z8w",
	}
	var lens []int
	var statuses []int
	for _, r := range randoms {
		body, status, err := core.FetchBodyRL(client, target+r, cfg.UserAgent, cfg.RL)
		if err != nil {
			continue
		}
		lens = append(lens, len(body))
		statuses = append(statuses, status)
	}
	if len(lens) < 2 {
		return catchAllSignature{}
	}
	if statuses[0] == 200 && statuses[1] == 200 {
		d := lens[0] - lens[1]
		if d < 0 {
			d = -d
		}
		avg := (lens[0] + lens[1]) / 2
		if avg > 0 && d <= avg*15/100 {
			return catchAllSignature{isCatchAll: true, status: 200, bodyLen: avg}
		}
	}
	return catchAllSignature{}
}

// countAPIOperations counts HTTP method operations in a JSON or JS-embedded
// OpenAPI/Swagger spec body.
func countAPIOperations(body string) int {
	return strings.Count(body, "\"get\":") + strings.Count(body, "\"post\":") +
		strings.Count(body, "\"put\":") + strings.Count(body, "\"delete\":") +
		strings.Count(body, "\"patch\":")
}

// isSwaggerUIHTML reports whether a response body is a Swagger UI HTML page
// (as opposed to a raw JSON/YAML spec).  Swagger UI pages contain
// characteristic markup that raw specs never do.
func isSwaggerUIHTML(body string) bool {
	lower := strings.ToLower(body)
	return (strings.Contains(lower, "<html") || strings.Contains(lower, "<!doctype")) &&
		(strings.Contains(lower, "swagger-ui") || strings.Contains(lower, "swagger ui"))
}

func looksLikeStaticAPIDocs(body string) bool {
	lower := strings.ToLower(body)
	titleMatch := probeTitleRe.FindStringSubmatch(body)
	hasAPITitle := len(titleMatch) > 1 && strings.Contains(strings.ToLower(titleMatch[1]), "api")
	hasDocsHeading := strings.Contains(lower, "api-documentation") ||
		strings.Contains(lower, "api documentation") ||
		strings.Contains(lower, "api reference")
	hasDocsNavigation := strings.Contains(lower, "toc-wrapper") ||
		strings.Contains(lower, "endpoint") ||
		strings.Contains(lower, "getting-started")
	return hasAPITitle && hasDocsHeading && hasDocsNavigation
}

// swaggerInitJSRe matches the script src that loads the embedded spec in
// common Swagger UI deployments (swagger-ui-init.js, swagger-initializer.js).
var swaggerInitJSRe = regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']([^"']*swagger-ui-init[^"']*\.js[^"']*)["']`)

// swaggerSpecURLRe extracts a spec URL from Swagger UI's SwaggerUIBundle config
// (e.g. `url: "/v2/api-docs"` or `url: "https://petstore.io/swagger.json"`).
var swaggerSpecURLRe = regexp.MustCompile(`(?i)url\s*:\s*["']([^"']+)["']`)

// fetchSwaggerUISpec attempts to retrieve the actual OpenAPI/Swagger spec from
// a Swagger UI HTML page. It tries two strategies:
//  1. Fetch the companion swagger-ui-init.js (contains the spec inline).
//  2. Extract the spec URL from the HTML/JS and fetch it.
func fetchSwaggerUISpec(client *http.Client, pageURL, pageBody string, cfg *core.Config) string {
	// Ensure the base URL ends with "/" so relative script paths like
	// "./swagger-ui-init.js" resolve against the directory, not the parent.
	// Without this, resolveURL("http://host/api-docs", "./swagger-ui-init.js")
	// produces "http://host/swagger-ui-init.js" (the SPA catch-all) instead
	// of "http://host/api-docs/swagger-ui-init.js".
	dirURL := pageURL
	if !strings.HasSuffix(dirURL, "/") {
		dirURL += "/"
	}

	// Strategy 1: look for swagger-ui-init.js script tag
	if m := swaggerInitJSRe.FindStringSubmatch(pageBody); len(m) > 1 {
		initURL := resolveURL(dirURL, m[1])
		// C-1: the script src is attacker-controlled; only fetch it if it stays
		// on the target's own host (an absolute off-host URL would be SSRF).
		if isSameDomainURL(initURL, cfg.Domain) {
			initBody, status, err := core.FetchBodyRL(client, initURL, cfg.UserAgent, cfg.RL)
			if err == nil && status == 200 && len(initBody) > 100 && looksLikeSwaggerSpec(initBody) {
				return initBody
			}
		}
	}

	// Strategy 2: try common init JS filenames relative to the page
	for _, initPath := range []string{
		"swagger-ui-init.js",
		"swagger-initializer.js",
	} {
		initURL := resolveURL(dirURL, initPath)
		initBody, status, err := core.FetchBodyRL(client, initURL, cfg.UserAgent, cfg.RL)
		if err == nil && status == 200 && len(initBody) > 100 && looksLikeSwaggerSpec(initBody) {
			return initBody
		}
	}

	// Strategy 3: extract spec URL from the page body (SwaggerUIBundle config)
	if m := swaggerSpecURLRe.FindStringSubmatch(pageBody); len(m) > 1 {
		specURL := resolveURL(dirURL, m[1])
		// C-1: the spec URL is attacker-controlled; confine it to the target host.
		if isSameDomainURL(specURL, cfg.Domain) {
			specBody, status, err := core.FetchBodyRL(client, specURL, cfg.UserAgent, cfg.RL)
			if err == nil && status == 200 && strings.Contains(specBody, "\"paths\"") {
				return specBody
			}
		}
	}

	return ""
}

// looksLikeSwaggerSpec reports whether a body contains the hallmarks of an
// OpenAPI/Swagger spec (inline or wrapped in JS) rather than an SPA catch-all.
func looksLikeSwaggerSpec(body string) bool {
	return strings.Contains(body, "\"paths\"") ||
		strings.Contains(body, "swaggerDoc") ||
		strings.Contains(body, "SwaggerUIBundle") ||
		strings.Contains(body, "\"openapi\"") ||
		strings.Contains(body, "\"swagger\"")
}
