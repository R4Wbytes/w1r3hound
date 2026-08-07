package modules

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/w1r3hound/w1r3hound/internal/core"
)

// ──────────────────────────────────────────────
//  WSTG-INFO-06/07 — Identify Entry Points &
//  Map Execution Paths. Lightweight spider that
//  discovers links, forms, parameters, and API
//  endpoints from the target.
// ──────────────────────────────────────────────

type CrawlResult struct {
	Pages         []CrawledPage `json:"pages"`
	Forms         []FormEntry   `json:"forms"`
	Parameters    []string      `json:"unique_parameters"`
	Endpoints     []string      `json:"api_endpoints,omitempty"`
	ExternalLinks []string      `json:"external_links,omitempty"`
}

type CrawledPage struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Title      string `json:"title,omitempty"`
}

type FormEntry struct {
	Action string   `json:"action"`
	Method string   `json:"method"`
	Inputs []string `json:"inputs"`
	Page   string   `json:"found_on"`
}

// Patterns
var (
	linkPattern     = regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']([^"'#]+)["']`)
	formPattern     = regexp.MustCompile(`(?is)<form\s([^>]*)>(.*?)</form>`)
	inputPattern    = regexp.MustCompile(`(?i)<input\s[^>]*name\s*=\s*["']([^"']+)["'][^>]*>`)
	titlePattern    = regexp.MustCompile(`(?is)<title>(.*?)</title>`)
	actionPattern   = regexp.MustCompile(`(?i)action\s*=\s*["']([^"']+)["']`)
	methodPattern   = regexp.MustCompile(`(?i)method\s*=\s*["']([^"']+)["']`)
	selectPattern   = regexp.MustCompile(`(?i)<select\s[^>]*name\s*=\s*["']([^"']+)["'][^>]*>`)
	textareaPattern = regexp.MustCompile(`(?i)<textarea\s[^>]*name\s*=\s*["']([^"']+)["'][^>]*>`)
)

func RunCrawler(cfg *core.Config, report *core.ReconReport, log *core.Logger) {
	log.Module("CRAWLER // Entry Point & Surface Mapping")

	if cfg.Passive {
		log.Info("Skipping crawler in passive mode")
		return
	}

	client := core.NewHTTPClient(cfg)
	target := normalizeTarget(cfg.Target)
	baseURL, err := url.Parse(target)
	if err != nil {
		log.Error("Invalid target URL: %v", err)
		return
	}

	result := CrawlResult{}
	maxPages := cfg.CrawlMaxPages // configurable via -crawl-pages
	if maxPages <= 0 {
		maxPages = 100
	}

	var (
		visited  = make(map[string]bool)
		queue    = []string{target}
		paramSet = make(map[string]bool)
		extLinks = make(map[string]bool)
	)

	log.Info("Starting crawl from %s (max %d pages)...", target, maxPages)

	// Seed the queue with the target and common paths found elsewhere
	queue = append(queue, target+"/", target+"/robots.txt", target+"/sitemap.xml")

	for len(queue) > 0 && len(visited) < maxPages {
		currentURL := queue[0]
		queue = queue[1:]

		// Normalize: strip trailing slashes for dedup but keep for requests
		cleanURL := strings.TrimRight(currentURL, "/")
		if visited[cleanURL] || visited[currentURL] {
			continue
		}
		visited[cleanURL] = true
		visited[currentURL] = true

		body, status, err := core.FetchBodyRL(client, currentURL, cfg.UserAgent, cfg.RL)
		if err != nil || status >= 400 || len(body) == 0 {
			continue
		}

		// Page info
		page := CrawledPage{URL: currentURL, StatusCode: status}
		if m := titlePattern.FindStringSubmatch(body); len(m) > 1 {
			page.Title = strings.TrimSpace(m[1])
		}
		result.Pages = append(result.Pages, page)

		// Extract parameters from URL
		if parsedURL, err := url.Parse(currentURL); err == nil {
			for param := range parsedURL.Query() {
				if !paramSet[param] {
					paramSet[param] = true
					result.Parameters = append(result.Parameters, param)
				}
			}
		}

		// Extract links
		links := linkPattern.FindAllStringSubmatch(body, -1)
		for _, lm := range links {
			href := strings.TrimSpace(lm[1])
			if href == "" || strings.HasPrefix(href, "javascript:") || strings.HasPrefix(href, "mailto:") {
				continue
			}

			resolved := resolveURL(currentURL, href)
			resolvedParsed, err := url.Parse(resolved)
			if err != nil {
				continue
			}

			// Same host?
			if resolvedParsed.Host == baseURL.Host {
				clean := resolvedParsed.Scheme + "://" + resolvedParsed.Host + resolvedParsed.Path
				if !visited[clean] && !visited[resolved] {
					queue = append(queue, clean)
				}
			} else if resolvedParsed.Host != "" {
				extLinks[resolved] = true
			}
		}

		// Extract forms
		forms := formPattern.FindAllStringSubmatch(body, -1)
		for _, fm := range forms {
			formAttrs := fm[1]
			formBody := fm[2]

			fe := FormEntry{Page: currentURL, Method: "GET"}

			if am := actionPattern.FindStringSubmatch(formAttrs); len(am) > 1 {
				fe.Action = resolveURL(currentURL, am[1])
			}
			if mm := methodPattern.FindStringSubmatch(formAttrs); len(mm) > 1 {
				fe.Method = strings.ToUpper(mm[1])
			}

			// Input fields
			for _, pat := range []*regexp.Regexp{inputPattern, selectPattern, textareaPattern} {
				inputs := pat.FindAllStringSubmatch(formBody, -1)
				for _, im := range inputs {
					if len(im) > 1 {
						fe.Inputs = append(fe.Inputs, im[1])
						if !paramSet[im[1]] {
							paramSet[im[1]] = true
							result.Parameters = append(result.Parameters, im[1])
						}
					}
				}
			}

			result.Forms = append(result.Forms, fe)
		}

		// Detect API endpoints
		apiPatterns := []string{"/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/"}
		for _, ap := range apiPatterns {
			if strings.Contains(currentURL, ap) {
				found := false
				for _, e := range result.Endpoints {
					if e == currentURL {
						found = true
						break
					}
				}
				if !found {
					result.Endpoints = append(result.Endpoints, currentURL)
				}
			}
		}
	}

	for link := range extLinks {
		result.ExternalLinks = append(result.ExternalLinks, link)
	}

	// Publish into the shared context so the pipeline's "data feedback" is real
	// and consistent with the other modules (not just stored in this result).
	cfg.AddSharedParams(result.Parameters)
	if len(result.Endpoints) > 0 {
		cfg.SharedMu.Lock()
		cfg.SharedEndpoints = append(cfg.SharedEndpoints, result.Endpoints...)
		cfg.SharedMu.Unlock()
	}
	var pageURLs []string
	for _, pg := range result.Pages {
		pageURLs = append(pageURLs, pg.URL)
	}
	cfg.AddSharedURLs(pageURLs)

	log.Info("Crawled %d pages, found %d forms, %d unique params, %d API endpoints",
		len(result.Pages), len(result.Forms), len(result.Parameters), len(result.Endpoints))

	if len(result.Forms) > 0 {
		log.Info("Forms discovered:")
		for _, f := range result.Forms {
			log.Info("  %s %s → inputs: %v", f.Method, truncate(f.Action, 60), f.Inputs)
		}
	}

	report.Add(core.Finding{
		Module:   "crawler",
		WSTG:     "WSTG-INFO-06",
		Title:    fmt.Sprintf("Crawl results: %d pages, %d forms, %d params", len(result.Pages), len(result.Forms), len(result.Parameters)),
		Severity: core.SevInfo,
		Data:     result,
	})
}

// ══════════════════════════════════════════════
//  WHOIS Lookup (supplementary recon)
// ══════════════════════════════════════════════

type WhoisResult struct {
	Domain      string   `json:"domain"`
	RawOutput   string   `json:"raw_output,omitempty"`
	Registrar   string   `json:"registrar,omitempty"`
	CreatedDate string   `json:"created_date,omitempty"`
	ExpiryDate  string   `json:"expiry_date,omitempty"`
	NameServers []string `json:"name_servers,omitempty"`
}

func RunWhois(cfg *core.Config, report *core.ReconReport, log *core.Logger) {
	log.Module("RECON // WHOIS Intelligence")

	// Use web-based WHOIS to avoid external deps
	client := core.NewHTTPClient(cfg)
	url := fmt.Sprintf("https://rdap.org/domain/%s", cfg.Domain)

	body, status, err := core.FetchBodyRL(client, url, cfg.UserAgent, cfg.RL)
	if err != nil || status != 200 {
		log.Debug("RDAP lookup failed, skipping WHOIS: %v", err)
		return
	}

	result := WhoisResult{Domain: cfg.Domain, RawOutput: truncate(body, 2000)}

	// Simple extraction from RDAP JSON
	if strings.Contains(body, "registrar") {
		log.Info("WHOIS data retrieved for %s", cfg.Domain)
	}

	report.Add(core.Finding{
		Module:   "whois",
		WSTG:     "WSTG-INFO-01",
		Title:    fmt.Sprintf("WHOIS/RDAP data for %s", cfg.Domain),
		Severity: core.SevInfo,
		Data:     result,
	})
}
