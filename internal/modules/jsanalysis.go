package modules

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/w1r3hound/w1r3hound/internal/core"
)

// ══════════════════════════════════════════════
//  JAVASCRIPT DEEP ANALYSIS (LinkFinder style)
//  Extracts API endpoints, routes, and paths from
//  JS bundles. Consistently one of the highest-
//  value recon activities.
//  (Checklist Fase 3.5: análisis profundo de JS)
// ══════════════════════════════════════════════

type JSAnalysisResult struct {
	JSFilesAnalyzed int      `json:"js_files_analyzed"`
	Endpoints       []string `json:"endpoints"`
	APIRoutes       []string `json:"api_routes"`
	Frameworks      []string `json:"spa_frameworks,omitempty"`
	CloudURLs       []string `json:"cloud_urls,omitempty"`
	InterestingVars []string `json:"interesting_vars,omitempty"`
}

// LinkFinder's proven regex for extracting endpoints from JS.
// Matches quoted strings that look like paths, URLs, or API routes.
// Extended with backtick template literals: modern frameworks (Angular/React/
// Vue minified bundles) build API routes as template strings. Juice Shop main.js
// holds `/api/Feedbacks`-style paths the quote-only regex missed entirely
// (2 endpoints found in a 1.2 MB bundle; dozens exist).
// Delimiter alternation for JS string literals: double quote, single quote,
// or backtick (template literals — Angular/React/Vue minified bundles build
// API routes as template strings; the quote-only original missed them all).
var linkFinderDelims = "\"|'|`"
var linkFinderRe = regexp.MustCompile("(?:" + linkFinderDelims + ")(" +
	`(?:(?:https?:)?//[^"'/]+)?` + // optional scheme+host
	`/[a-zA-Z0-9_\-/\.]+` + // path
	`(?:\?[a-zA-Z0-9_\-=&%\.]*)?` + // optional query
	")(?:" + linkFinderDelims + ")")

// tplInterpRe strips ${...} interpolations so `/api/${id}`-style template
// hits do not poison the endpoint list.
var tplInterpRe = regexp.MustCompile(`\$\{[^}]*\}`)

// Cloud resource URL patterns worth flagging
var cloudURLRe = regexp.MustCompile(`https?://[a-zA-Z0-9\.\-]+\.(?:s3[\.\-][a-z0-9\-]*\.amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com|firebaseio\.com|cloudfront\.net|digitaloceanspaces\.com)[^"'\s]*`)

// Interesting variable assignments (config, keys, tokens as var names)
var interestingVarRe = regexp.MustCompile(`(?i)(?:var|let|const)\s+([a-z_]*(?:api|key|token|secret|url|endpoint|config|host|password|auth)[a-z_]*)\s*=`)

func RunJSAnalysis(cfg *core.Config, report *core.ReconReport, log *core.Logger) {
	log.Module("JSDEEP // JavaScript Endpoint Extraction")

	if cfg.Passive {
		log.Info("Skipping JS analysis in passive mode")
		return
	}

	client := core.NewHTTPClient(cfg)
	target := normalizeTarget(cfg.Target)

	// Gather JS files: from shared context (populated by content module) + fetch main page
	jsFiles := gatherJSFiles(cfg, target)
	if len(jsFiles) == 0 {
		log.Info("No JavaScript files found to analyze")
		return
	}

	log.Info("Analyzing %d JavaScript files...", len(jsFiles))

	result := JSAnalysisResult{}
	endpointSet := make(map[string]bool)
	apiRouteSet := make(map[string]bool)
	cloudSet := make(map[string]bool)
	varSet := make(map[string]bool)
	fwSet := make(map[string]bool)

	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, cfg.Concurrency)
	)

	// Cap analysis at 50 JS files
	limit := cfg.MaxJSFiles // configurable via -js-files
	if limit <= 0 {
		limit = 50
	}
	if len(jsFiles) < limit {
		limit = len(jsFiles)
	}

	for i := 0; i < limit; i++ {
		jsURL := jsFiles[i]
		wg.Add(1)
		sem <- struct{}{}
		go func(jsURL string) {
			defer core.RecoverWorker(log, "jsdeep")
			defer wg.Done()
			defer func() { <-sem }()

			body, status, err := core.FetchBodyRL(client, jsURL, cfg.UserAgent, cfg.RL)
			if err != nil || status != 200 {
				return
			}

			// Extract endpoints via LinkFinder regex
			matches := linkFinderRe.FindAllStringSubmatch(body, -1)
			for _, m := range matches {
				if len(m) < 2 {
					continue
				}
				ep := tplInterpRe.ReplaceAllString(m[1], "")
				if isNoiseEndpoint(ep) {
					continue
				}
				// Skip third-party absolute URLs (Sentry, Wistia, Marketo, CDNs).
				// Keep relative paths and same-domain absolute URLs only.
				if strings.HasPrefix(ep, "http://") || strings.HasPrefix(ep, "https://") || strings.HasPrefix(ep, "//") {
					if !isSameDomainURL(ep, cfg.Domain) {
						continue
					}
				}
				mu.Lock()
				if !endpointSet[ep] {
					endpointSet[ep] = true
					// Classify API routes
					if strings.Contains(ep, "/api/") || strings.Contains(ep, "/v1/") ||
						strings.Contains(ep, "/v2/") || strings.Contains(ep, "/graphql") ||
						strings.Contains(ep, "/rest/") {
						apiRouteSet[ep] = true
					}
				}
				mu.Unlock()
			}

			// Cloud URLs
			for _, cu := range cloudURLRe.FindAllString(body, -1) {
				mu.Lock()
				cloudSet[cu] = true
				mu.Unlock()
			}

			// Interesting vars
			for _, m := range interestingVarRe.FindAllStringSubmatch(body, -1) {
				if len(m) > 1 {
					mu.Lock()
					varSet[m[1]] = true
					mu.Unlock()
				}
			}

			// SPA framework markers in JS
			jsFrameworks := map[string]string{
				"React.createElement": "React",
				"_angular":            "Angular",
				"Vue.component":       "Vue.js",
				"webpackJsonp":        "Webpack",
				"__webpack_require__": "Webpack",
				"regeneratorRuntime":  "Babel",
			}
			for marker, fw := range jsFrameworks {
				if strings.Contains(body, marker) {
					mu.Lock()
					fwSet[fw] = true
					mu.Unlock()
				}
			}
		}(jsURL)
	}
	wg.Wait()

	result.JSFilesAnalyzed = limit
	for e := range endpointSet {
		result.Endpoints = append(result.Endpoints, e)
	}
	for a := range apiRouteSet {
		result.APIRoutes = append(result.APIRoutes, a)
	}
	for c := range cloudSet {
		result.CloudURLs = append(result.CloudURLs, c)
	}
	for v := range varSet {
		result.InterestingVars = append(result.InterestingVars, v)
	}
	for f := range fwSet {
		result.Frameworks = append(result.Frameworks, f)
	}
	sort.Strings(result.Endpoints)
	sort.Strings(result.APIRoutes)

	log.Info("Extracted %d endpoints (%d API routes) from JS", len(result.Endpoints), len(result.APIRoutes))
	if len(result.APIRoutes) > 0 {
		log.Info("API routes found:")
		for _, r := range result.APIRoutes {
			log.Debug("  %s", r)
		}
	}
	if len(result.CloudURLs) > 0 {
		log.Warn("Cloud storage URLs in JS: %d", len(result.CloudURLs))
		for _, c := range result.CloudURLs {
			log.Warn("  %s", c)
		}
	}
	if len(result.Frameworks) > 0 {
		log.Info("SPA frameworks detected: %v", result.Frameworks)
	}

	// Extract query parameters from discovered endpoints (e.g.
	// "/rest/user/change-password?current=" → "current"). SPA targets
	// embed all their routing in JS, so the crawler (which only parses
	// HTML forms) finds 0 params — these are the only source.
	var jsParams []string
	for _, ep := range result.Endpoints {
		if i := strings.IndexByte(ep, '?'); i >= 0 {
			qs := ep[i+1:]
			for _, pair := range strings.Split(qs, "&") {
				key := strings.SplitN(pair, "=", 2)[0]
				key = strings.TrimSpace(key)
				if key != "" {
					jsParams = append(jsParams, key)
				}
			}
		}
	}
	cfg.AddSharedParams(jsParams)

	// Feed discovered endpoints into shared context for dirbrute/crawler
	cfg.SharedMu.Lock()
	cfg.SharedEndpoints = append(cfg.SharedEndpoints, result.APIRoutes...)
	cfg.SharedMu.Unlock()

	if len(result.CloudURLs) > 0 {
		report.Add(core.Finding{
			Module:      "jsdeep",
			WSTG:        "WSTG-INFO-05",
			Title:       fmt.Sprintf("Cloud storage URLs exposed in JS: %d", len(result.CloudURLs)),
			Severity:    core.SevMedium,
			Description: "Cloud bucket URLs hardcoded in client-side JavaScript.",
			Data:        result.CloudURLs,
		})
	}

	report.Add(core.Finding{
		Module:      "jsdeep",
		WSTG:        "WSTG-INFO-05",
		Title:       fmt.Sprintf("JS analysis: %d endpoints, %d API routes from %d files", len(result.Endpoints), len(result.APIRoutes), result.JSFilesAnalyzed),
		Severity:    core.SevInfo,
		Description: "Endpoints and routes extracted from JavaScript bundles.",
		Data:        result,
	})
}

// gatherJSFiles collects JS URLs from shared context and the main page.
func gatherJSFiles(cfg *core.Config, target string) []string {
	seen := make(map[string]bool)
	var jsFiles []string

	// From shared context (content module populates this)
	cfg.SharedMu.Lock()
	for _, js := range cfg.SharedJSFiles {
		if !seen[js] {
			seen[js] = true
			jsFiles = append(jsFiles, js)
		}
	}
	cfg.SharedMu.Unlock()

	// Also parse the main page directly
	hc := core.NewHTTPClient(cfg)
	body, status, err := core.FetchBodyRL(hc, target, cfg.UserAgent, cfg.RL)
	if err == nil && status == 200 {
		for _, m := range jsFilePattern.FindAllStringSubmatch(body, -1) {
			if len(m) > 1 {
				full := resolveURL(target, m[1])
				if !seen[full] {
					seen[full] = true
					jsFiles = append(jsFiles, full)
				}
			}
		}
	}
	return jsFiles
}

// isSameDomainURL returns true if the URL belongs to the target domain.
func isSameDomainURL(rawURL, domain string) bool {
	u := rawURL
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimPrefix(u, "//")
	host := strings.SplitN(u, "/", 2)[0]
	host = strings.SplitN(host, "?", 2)[0]
	host = strings.SplitN(host, "@", 2)[len(strings.SplitN(host, "@", 2))-1] // strip user:pass@
	return host == domain || strings.HasSuffix(host, "."+domain)
}

// isNoiseEndpoint filters out common false positives.
func isNoiseEndpoint(ep string) bool {
	// Too short
	if len(ep) < 4 {
		return true
	}
	noise := []string{
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
		".ttf", ".eot", ".css", ".map", "/w3.org", "/www.w3", "text/", "image/",
		"application/", "//schema.org", "charset", "//fonts.g",
	}
	lower := strings.ToLower(ep)
	for _, n := range noise {
		if strings.Contains(lower, n) {
			return true
		}
	}
	// Pure file extensions with no path depth
	if strings.Count(ep, "/") <= 1 && strings.Contains(ep, ".") {
		return true
	}
	return false
}
