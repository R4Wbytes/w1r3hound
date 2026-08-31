package modules

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"

	"github.com/R4Wbytes/w1r3hound/internal/core"
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
	linkPattern     = regexp.MustCompile(`(?i)(?:href|action)\s*=\s*["']([^"'#]+)["']`)
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
	maxAttempts := maxPages*5 + 10

	var (
		visited     = make(map[string]bool)
		queue       = []string{target}
		paramSet    = make(map[string]bool)
		extLinks    = make(map[string]bool)
		endpointSet = make(map[string]bool)
	)

	log.Info("Starting crawl from %s (max %d pages)...", target, maxPages)

	// Calibrate the SPA/catch-all shell up front. Single-page apps answer 200
	// with the same app shell for every unknown path, so without this the
	// crawler counts phantom pages — a seeded but non-existent sitemap.xml, or
	// a template-literal link — as real. matches() is a no-op on servers that
	// return proper 404s, so non-SPA targets are unaffected.
	catchAll := calibrateCatchAll(client, target, cfg)
	if catchAll.isCatchAll {
		log.Warn("Catch-all/SPA detected (~%d bytes) — suppressing phantom pages", catchAll.bodyLen)
	}

	var (
		queueMu sync.Mutex
		visitMu sync.Mutex
		wg      sync.WaitGroup
		sem     = make(chan struct{}, cfg.Concurrency)
	)

	processURL := func(currentURL string) {
		defer wg.Done()
		defer func() { <-sem }()
		defer core.RecoverWorker(log, "crawler")

		cleanURL := strings.TrimRight(currentURL, "/")
		if cleanURL == "" {
			cleanURL = currentURL
		}
		visitMu.Lock()
		if visited[cleanURL] || len(visited) >= maxAttempts {
			visitMu.Unlock()
			return
		}
		visited[cleanURL] = true
		visitMu.Unlock()

		body, status, ct, err := core.FetchBodyCTRL(client, currentURL, cfg.UserAgent, cfg.RL)
		if err != nil || status >= 400 || len(body) == 0 {
			return
		}

		// SPA catch-all suppression: drop any non-root page whose response is
		// the app shell. This removes phantom pages such as a seeded but
		// non-existent /sitemap.xml that a single-page app answers 200 with
		// index.html. The target root itself is the real entry point and is
		// always kept, even though it *is* the shell.
		if cleanURL != target && catchAll.matches(status, len(body)) {
			return
		}

		// Only HTML documents carry crawlable links, forms and inputs. Running
		// the HTML regexes over JS/CSS/JSON bodies mines framework template
		// literals (href="{{...}}", src="${...}") and stray <input> strings,
		// fabricating phantom URLs, forms and parameters — jsdeep owns
		// JavaScript endpoint extraction, not the crawler.
		isHTML := isHTMLContentType(ct)

		// Query-string parameters are derived from the URL itself, so they are
		// collected regardless of the response Content-Type.
		if parsedURL, err := url.Parse(currentURL); err == nil {
			visitMu.Lock()
			for param := range parsedURL.Query() {
				if !paramSet[param] {
					paramSet[param] = true
					result.Parameters = append(result.Parameters, param)
				}
			}
			visitMu.Unlock()
		}
		if !isHTML {
			return
		}

		page := CrawledPage{URL: currentURL, StatusCode: status}
		if m := titlePattern.FindStringSubmatch(body); len(m) > 1 {
			page.Title = strings.TrimSpace(m[1])
		}

		visitMu.Lock()
		if len(result.Pages) >= maxPages {
			visitMu.Unlock()
			return
		}
		result.Pages = append(result.Pages, page)
		visitMu.Unlock()

		var newURLs []string
		links := linkPattern.FindAllStringSubmatch(body, -1)
		for _, lm := range links {
			href := strings.TrimSpace(lm[1])
			if href == "" || strings.HasPrefix(href, "javascript:") || strings.HasPrefix(href, "mailto:") {
				continue
			}
			// Reject client-side templating placeholders ({{...}}, ${...},
			// <%...%>) that appear verbatim in inline framework templates.
			if isTemplateURL(href) {
				continue
			}
			resolved := resolveURL(currentURL, href)
			resolvedParsed, err := url.Parse(resolved)
			if err != nil {
				continue
			}
			if resolvedParsed.Host == baseURL.Host {
				if !isCrawlablePageURL(resolvedParsed) {
					continue
				}
				clean := resolvedParsed.Scheme + "://" + resolvedParsed.Host + resolvedParsed.Path
				if resolvedParsed.RawQuery != "" {
					clean += "?" + resolvedParsed.RawQuery
				}
				visitMu.Lock()
				shouldAdd := !visited[clean] && !visited[resolved]
				visitMu.Unlock()
				if shouldAdd {
					newURLs = append(newURLs, clean)
				}
			} else if resolvedParsed.Host != "" {
				visitMu.Lock()
				extLinks[resolved] = true
				visitMu.Unlock()
			}
		}

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
			for _, pat := range []*regexp.Regexp{inputPattern, selectPattern, textareaPattern} {
				inputs := pat.FindAllStringSubmatch(formBody, -1)
				for _, im := range inputs {
					if len(im) > 1 {
						fe.Inputs = append(fe.Inputs, im[1])
						visitMu.Lock()
						if !paramSet[im[1]] {
							paramSet[im[1]] = true
							result.Parameters = append(result.Parameters, im[1])
						}
						visitMu.Unlock()
					}
				}
			}
			visitMu.Lock()
			result.Forms = append(result.Forms, fe)
			visitMu.Unlock()
		}

		apiPatterns := []string{"/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/"}
		isAPIEndpoint := false
		for _, ap := range apiPatterns {
			if strings.Contains(currentURL, ap) {
				isAPIEndpoint = true
				break
			}
		}
		if isAPIEndpoint {
			// O(1) dedup via endpointSet, matching visited/paramSet/extLinks. The
			// old linear scan over result.Endpoints ran under visitMu once per
			// crawled URL, so it was O(n) per call and O(n²) across a large crawl.
			visitMu.Lock()
			if !endpointSet[currentURL] {
				endpointSet[currentURL] = true
				result.Endpoints = append(result.Endpoints, currentURL)
			}
			visitMu.Unlock()
		}

		// Enqueue new URLs
		queueMu.Lock()
		queue = append(queue, newURLs...)
		queueMu.Unlock()
	}

	// Process initial queue
	for len(queue) > 0 {
		queueMu.Lock()
		if len(queue) == 0 {
			queueMu.Unlock()
			break
		}
		// Drain current queue batch
		batch := make([]string, len(queue))
		copy(batch, queue)
		queue = queue[:0]
		queueMu.Unlock()

		for _, u := range batch {
			visitMu.Lock()
			tooMany := len(result.Pages) >= maxPages
			visitMu.Unlock()
			if tooMany {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go processURL(u)
		}
		wg.Wait()

		// Check if we should stop
		visitMu.Lock()
		tooMany := len(result.Pages) >= maxPages
		visitMu.Unlock()
		queueMu.Lock()
		empty := len(queue) == 0
		queueMu.Unlock()
		if tooMany || empty {
			break
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

// isTemplateURL reports whether an href/src/action value is really a client-side
// templating placeholder rather than a link. Angular/Vue interpolation
// ({{href}}), JSX/ES template expressions (${path}) and ERB/JSP scriptlets
// (<%= url %>) appear verbatim in framework bundles and inline templates;
// resolving them yields phantom URLs like http://host/{{href}} that a catch-all
// SPA happily answers 200. Raw braces are not legal in a URL path unescaped
// (RFC 3986), so their presence is a reliable template-literal tell.
func isTemplateURL(href string) bool {
	return strings.ContainsAny(href, "{}") ||
		strings.Contains(href, "${") ||
		strings.Contains(href, "<%") ||
		strings.Contains(href, "%>")
}

func isCrawlablePageURL(u *url.URL) bool {
	switch strings.ToLower(path.Ext(u.Path)) {
	case "", ".html", ".htm", ".php", ".asp", ".aspx", ".jsp":
		return true
	default:
		return false
	}
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

	// Use web-based WHOIS to avoid external deps. rdap.org is a fixed trusted
	// third-party intel API, so verify its TLS (TLS 1.2+) regardless of the
	// operator's -skip-tls-verify flag — a MITM must not be able to feed forged
	// registrar/nameserver data into the report. Matches the C-3 hardening the
	// wayback/asn/passive sources already use.
	client := core.NewVerifiedHTTPClient(cfg)
	url := fmt.Sprintf("https://rdap.org/domain/%s", cfg.Domain)

	body, status, err := core.FetchBodyRL(client, url, cfg.UserAgent, cfg.RL)
	if err != nil || status != 200 {
		log.Debug("RDAP lookup failed, skipping WHOIS: %v", err)
		return
	}

	result := WhoisResult{Domain: cfg.Domain, RawOutput: truncate(body, 2000)}

	// Parse RDAP JSON response
	var rdap struct {
		Handle  string `json:"handle"`
		LDHName string `json:"ldhName"`
		Links   []struct {
			Href string `json:"href"`
		} `json:"links"`
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
		Entities []struct {
			Roles      []string `json:"roles"`
			VcardArray []any    `json:"vcardArray"`
			Handle     string   `json:"handle"`
		} `json:"entities"`
		Nameservers []struct {
			LDHName string `json:"ldhName"`
		} `json:"nameservers"`
	}
	if err := json.Unmarshal([]byte(body), &rdap); err == nil {
		for _, e := range rdap.Events {
			switch e.Action {
			case "registration":
				result.CreatedDate = e.Date
			case "expiration":
				result.ExpiryDate = e.Date
			}
		}
		for _, ent := range rdap.Entities {
			for _, role := range ent.Roles {
				if role == "registrar" {
					result.Registrar = ent.Handle
				}
			}
		}
		for _, ns := range rdap.Nameservers {
			result.NameServers = append(result.NameServers, strings.TrimSuffix(ns.LDHName, "."))
		}
		log.Info("WHOIS: Registrar=%s Created=%s Expires=%s NS=%d",
			result.Registrar, result.CreatedDate, result.ExpiryDate, len(result.NameServers))
	} else {
		log.Debug("RDAP JSON parse failed: %v", err)
	}

	report.Add(core.Finding{
		Module:   "whois",
		WSTG:     "WSTG-INFO-01",
		Title:    fmt.Sprintf("WHOIS/RDAP data for %s", cfg.Domain),
		Severity: core.SevInfo,
		Data:     result,
	})
}
