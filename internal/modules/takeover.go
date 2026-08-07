package modules

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/w1r3hound/w1r3hound/internal/core"
)

// ══════════════════════════════════════════════
//  SUBDOMAIN TAKEOVER (HTTP fingerprint based)
//  Goes beyond NXDOMAIN: most vulnerable services
//  (S3, GitHub Pages, Heroku) resolve fine but
//  return a characteristic error page.
//  (Checklist Fase 1.3: verificación por firma HTTP)
// ══════════════════════════════════════════════

type TakeoverResult struct {
	Vulnerable []TakeoverFinding `json:"vulnerable"`
	Checked    int               `json:"subdomains_checked"`
}

type TakeoverFinding struct {
	Subdomain  string `json:"subdomain"`
	Service    string `json:"service"`
	CNAME      string `json:"cname,omitempty"`
	Evidence   string `json:"evidence"`
	Confidence string `json:"confidence"`
}

// Service fingerprints: CNAME suffix + the error string in the HTTP body
// that signals the resource is unclaimed. Based on the can-i-take-over-xyz project.
// Generic strings like "404 Not Found" were REMOVED — they matched any CDN.
// Each signature now uses a service-specific error page string.
var takeoverSigs = []struct {
	Service      string
	CNAMEHint    string   // CNAME suffix (required for confirmation)
	BodySigs     []string // service-specific strings in response body
	RequireCNAME bool     // if true, only flag when CNAME matches (high precision)
}{
	{"GitHub Pages", "github.io", []string{"There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file"}, false},
	{"AWS S3", "amazonaws.com", []string{"NoSuchBucket", "The specified bucket does not exist"}, false},
	{"Heroku", "herokuapp.com", []string{"No such app", "herokucdn.com/error-pages/no-such-app.html"}, true},
	{"Shopify", "myshopify.com", []string{"Sorry, this shop is currently unavailable", "Only one step left!"}, true},
	{"Fastly", "fastly.net", []string{"Fastly error: unknown domain"}, false},
	{"Ghost", "ghost.io", []string{"The thing you were looking for is no longer here"}, true},
	{"Surge.sh", "surge.sh", []string{"project not found"}, true},
	{"Bitbucket", "bitbucket.io", []string{"Repository not found"}, true},
	{"Cargo Collective", "cargocollective.com", []string{"If you're moving your domain away from Cargo"}, true},
	{"Tumblr", "domains.tumblr.com", []string{"Whatever you were looking for doesn't currently exist at this address"}, true},
	{"Wordpress", "wordpress.com", []string{"Do you want to register"}, true},
	{"Tilda", "tilda.ws", []string{"Please renew your subscription"}, true},
	{"Unbounce", "unbouncepages.com", []string{"The requested URL was not found on this server"}, true},
	{"Helpjuice", "helpjuice.com", []string{"We could not find what you're looking for"}, true},
	{"Helpscout", "helpscoutdocs.com", []string{"No settings were found for this company"}, true},
	{"Pantheon", "pantheonsite.io", []string{"The gods are wise", "404 error unknown site"}, true},
	{"Netlify", "netlify.app", []string{"Not Found - Request ID"}, true},
	{"Zendesk", "zendesk.com", []string{"Help Center Closed"}, true},
	{"Readme.io", "readme.io", []string{"Project doesnt exist... yet!"}, true},
	{"Airee", "airee.ru", []string{"Ошибка 402"}, true},
	{"Vercel", "vercel.app", []string{"The deployment could not be found", "DEPLOYMENT_NOT_FOUND"}, true},
	{"Agile CRM", "agilecrm.com", []string{"Sorry, this page is no longer available"}, true},
	{"Anima", "animaapp.io", []string{"If this is your website and you've just created it"}, true},
	{"Kinsta", "kinsta.cloud", []string{"No Site For Domain"}, true},
	{"LaunchRock", "launchrock.com", []string{"It looks like you may have taken a wrong turn somewhere"}, true},
	{"Uptimerobot", "stats.uptimerobot.com", []string{"page not found"}, true},
	{"Wix", "wixsite.com", []string{"Looks Like This Domain Isn't Connected To A Website Yet"}, true},
}

// genericBodyService lists services whose takeover marker is a generic error
// string shared with ordinary web servers; for these we also require a small
// response body to avoid flagging real sites that happen to 404 on "/".
var genericBodyService = map[string]bool{
	"Unbounce":    true,
	"Uptimerobot": true,
}

func RunTakeover(cfg *core.Config, report *core.ReconReport, log *core.Logger) {
	log.Module("TAKEOVER // Subdomain Takeover Detection")

	if cfg.Passive {
		log.Info("Skipping takeover check in passive mode")
		return
	}

	// Gather subdomains from shared context
	cfg.SharedMu.Lock()
	subs := make([]string, len(cfg.SharedSubdomains))
	copy(subs, cfg.SharedSubdomains)
	cfg.SharedMu.Unlock()

	if len(subs) == 0 {
		log.Info("No subdomains to check (run 'passivesrc' or 'dns' first)")
		return
	}

	client := core.NewHTTPClient(cfg)
	result := TakeoverResult{Checked: len(subs)}
	log.Info("Checking %d subdomains for takeover...", len(subs))

	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, cfg.Concurrency)
	)

	for _, sub := range subs {
		wg.Add(1)
		sem <- struct{}{}
		go func(sub string) {
			defer core.RecoverWorker(log, "takeover")
			defer wg.Done()
			defer func() { <-sem }()

			// Get the CNAME to help identify the service
			cname := ""
			if c, err := cfg.Resolver.LookupCNAME(context.Background(), sub); err == nil {
				cname = strings.TrimSuffix(c, ".")
			}

			// Fetch the HTTP body
			var body string
			for _, scheme := range []string{"https", "http"} {
				b, status, err := core.FetchBodyRL(client, scheme+"://"+sub, cfg.UserAgent, cfg.RL)
				if err == nil && status > 0 {
					body = b
					break
				}
			}
			if body == "" {
				return
			}

			// Check each signature
			for _, sig := range takeoverSigs {
				cnameMatches := cname != "" && strings.Contains(cname, sig.CNAMEHint)

				// High-precision signatures require the CNAME to match the service.
				// This prevents generic error strings from matching unrelated CDNs.
				if sig.RequireCNAME && !cnameMatches {
					continue
				}

				for _, bodySig := range sig.BodySigs {
					if strings.Contains(body, bodySig) {
						// Some services (Unbounce, Uptimerobot) are only
						// identifiable by a GENERIC error string (e.g. Apache's
						// "The requested URL was not found on this server").
						// A real, claimed site that merely 404s on "/" would also
						// contain it — so for these, additionally require a SMALL
						// body: genuine unclaimed error pages are tiny, full sites
						// are not. This kills the generic-string false positives.
						if genericBodyService[sig.Service] && len(body) > 2048 {
							continue
						}
						confidence := "medium"
						if cnameMatches {
							confidence = "high"
						}
						tf := TakeoverFinding{
							Subdomain:  sub,
							Service:    sig.Service,
							CNAME:      cname,
							Evidence:   bodySig,
							Confidence: confidence,
						}
						mu.Lock()
						result.Vulnerable = append(result.Vulnerable, tf)
						mu.Unlock()
						log.Warn("TAKEOVER [%s conf]: %s → %s (%s)", confidence, sub, sig.Service, truncate(bodySig, 40))
						return
					}
				}
			}
		}(sub)
	}
	wg.Wait()

	sort.Slice(result.Vulnerable, func(i, j int) bool {
		return result.Vulnerable[i].Subdomain < result.Vulnerable[j].Subdomain
	})

	if len(result.Vulnerable) > 0 {
		report.Add(core.Finding{
			Module:      "takeover",
			WSTG:        "WSTG-CONF-10",
			Title:       fmt.Sprintf("Subdomain takeover: %d vulnerable subdomains", len(result.Vulnerable)),
			Severity:    core.SevHigh,
			Description: "Subdomains serving unclaimed third-party service error pages (detected via HTTP body fingerprint; may overlap with the DNS/CNAME takeover finding).",
			Data:        result,
		})
	} else {
		log.Info("No takeover vulnerabilities detected")
	}
}

// ══════════════════════════════════════════════
//  SUBDOMAIN PERMUTATION GENERATION
//  Generates variations of known subdomains and
//  resolves them. (Checklist Fase 12)
// ══════════════════════════════════════════════

var permWords = []string{
	"dev", "development", "staging", "stage", "stg", "test", "testing", "qa", "uat",
	"prod", "production", "internal", "int", "corp", "admin", "api", "app",
	"beta", "alpha", "demo", "sandbox", "preview", "preprod", "pre",
	"new", "old", "legacy", "v1", "v2", "v3", "backup", "bak",
	"1", "2", "3", "eu", "us", "asia", "east", "west",
}

func RunPermute(cfg *core.Config, report *core.ReconReport, log *core.Logger) {
	log.Module("PERMUTE // Subdomain Permutation & Resolution")

	if cfg.Passive {
		log.Info("Skipping permutation in passive mode")
		return
	}

	cfg.SharedMu.Lock()
	baseSubs := make([]string, len(cfg.SharedSubdomains))
	copy(baseSubs, cfg.SharedSubdomains)
	cfg.SharedMu.Unlock()

	if len(baseSubs) == 0 {
		log.Info("No base subdomains for permutation (run 'passivesrc' first)")
		return
	}

	domain := cfg.Domain
	// Generate permutations from the base list
	candidates := make(map[string]bool)
	for _, sub := range baseSubs {
		// Extract the label prefix (e.g. "api" from "api.target.com")
		prefix := strings.TrimSuffix(sub, "."+domain)
		if prefix == "" || prefix == sub {
			continue
		}
		firstLabel := strings.Split(prefix, ".")[0]

		for _, word := range permWords {
			// word-prefix, prefix-word, word.prefix
			candidates[word+"-"+firstLabel+"."+domain] = true
			candidates[firstLabel+"-"+word+"."+domain] = true
			candidates[word+"."+firstLabel+"."+domain] = true
		}
	}

	log.Info("Generated %d permutation candidates, resolving...", len(candidates))

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		sem      = make(chan struct{}, cfg.Concurrency)
		resolved []string
	)

	// Get wildcard IPs to filter
	var wildcardIPs map[string]bool
	if detectWildcard(cfg.Resolver, domain) {
		wildcardIPs = getWildcardIPs(cfg.Resolver, domain)
	}

	for cand := range candidates {
		wg.Add(1)
		sem <- struct{}{}
		go func(cand string) {
			defer core.RecoverWorker(log, "permute")
			defer wg.Done()
			defer func() { <-sem }()

			ips, err := cfg.Resolver.LookupHost(context.Background(), cand)
			if err != nil || len(ips) == 0 {
				return
			}
			if wildcardIPs != nil && allIPsMatch(ips, wildcardIPs) {
				return
			}
			mu.Lock()
			resolved = append(resolved, cand)
			mu.Unlock()
			log.Info("Permutation resolved: %-40s %s", cand, strings.Join(ips, ", "))
		}(cand)
	}
	wg.Wait()

	sort.Strings(resolved)
	if len(resolved) > 0 {
		cfg.AddSharedSubdomains(resolved)
		log.Info("Permutation found %d new subdomains", len(resolved))
		report.Add(core.Finding{
			Module:      "permute",
			WSTG:        "WSTG-INFO-04",
			Title:       fmt.Sprintf("Permutation discovery: %d new subdomains", len(resolved)),
			Severity:    core.SevInfo,
			Description: "Subdomains found by permuting known subdomain names.",
			Data:        resolved,
		})
	} else {
		log.Info("No new subdomains from permutation")
	}
}
