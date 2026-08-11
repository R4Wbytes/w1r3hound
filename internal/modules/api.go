package modules

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/w1r3hound/w1r3hound/internal/core"
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
				(strings.Contains(body, "\"paths\"") && strings.Contains(body, "\"info\""))
		case "graphql-schema":
			isDoc = strings.Contains(body, "__schema") || strings.Contains(body, "\"types\"")
		}

		if isDoc {
			sf := SwaggerFinding{URL: url, Type: doc.Type}
			// Count endpoints in JSON specs
			if doc.Type == "swagger" || doc.Type == "openapi" {
				sf.Endpoints = strings.Count(body, "\"get\":") + strings.Count(body, "\"post\":") +
					strings.Count(body, "\"put\":") + strings.Count(body, "\"delete\":") +
					strings.Count(body, "\"patch\":")
			}
			result.SwaggerDocs = append(result.SwaggerDocs, sf)
			log.Warn("API docs exposed [%s]: %s (%d operations)", doc.Type, url, sf.Endpoints)
			report.Add(core.Finding{
				Module:      "apiscan",
				WSTG:        "WSTG-INFO-06",
				Title:       fmt.Sprintf("API documentation exposed: %s", url),
				Severity:    core.SevLow,
				Description: fmt.Sprintf("%s spec accessible without auth — hands attackers the full endpoint list.", doc.Type),
			})
		}
	}

	// ── 3. REST API versioning discovery ──
	log.Info("Probing REST API versions...")
	versionPaths := []string{"/api/v1", "/api/v2", "/api/v3", "/api/v4",
		"/v1", "/v2", "/v3", "/rest/v1", "/rest/v2", "/api/1.0", "/api/2.0"}
	for _, vp := range versionPaths {
		url := target + vp
		body, status, err := core.FetchBodyRL(client, url, cfg.UserAgent, cfg.RL)
		if err != nil {
			continue
		}
		// A 401/403 is a strong signal the namespace exists and is protected.
		// A 200, however, is worthless on a catch-all/SPA server that serves the
		// same HTML shell for every path — require it to (a) not match the shell
		// and (b) actually look like an API response, not an HTML page.
		exists := false
		switch status {
		case 401, 403:
			exists = true
		case 200:
			if !catchAll.matches(status, len(body)) && looksLikeAPIResponse(body) {
				exists = true
			}
		}
		if exists {
			result.RESTVersions = append(result.RESTVersions, fmt.Sprintf("%s (%d)", vp, status))
			log.Info("REST version namespace: %s [%d]", vp, status)
		}
	}
	// Flag old versions coexisting with new — often less protected
	if len(result.RESTVersions) >= 2 {
		report.Add(core.Finding{
			Module:      "apiscan",
			WSTG:        "WSTG-INFO-06",
			Title:       fmt.Sprintf("Multiple API versions live: %d", len(result.RESTVersions)),
			Severity:    core.SevLow,
			Description: "Older API versions often have weaker auth and known bugs: " + strings.Join(result.RESTVersions, ", "),
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
