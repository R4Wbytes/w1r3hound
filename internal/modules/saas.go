package modules

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

// ══════════════════════════════════════════════
//  SAAS ENUMERATION
//  Third-party platforms (Zendesk, JIRA, Okta,
//  Salesforce, ServiceNow...) sit outside the
//  normal security review cycle.
//  (Checklist Fase 10: SaaS de terceros)
// ══════════════════════════════════════════════

type SaaSResult struct {
	Platforms []SaaSPlatform `json:"platforms_found"`
}

type SaaSPlatform struct {
	Platform   string `json:"platform"`
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Note       string `json:"note,omitempty"`
}

// SaaS platform templates. Each has a "not found" marker: if the response
// body contains it, the instance does NOT exist (avoids false positives from
// platforms that return 200 for any name). If notFound is empty, existence is
// inferred from a non-404 status alone (used for platforms with reliable 404s).
var saasTemplates = []struct {
	Platform string
	Template string
	NotFound string // body marker meaning "does not exist"
	Note     string
}{
	{"Zendesk", "https://%s.zendesk.com", "", "Help Centre search may leak private tickets"},
	{"Freshdesk", "https://%s.freshdesk.com", "", ""},
	{"Freshservice", "https://%s.freshservice.com", "", ""},
	{"Atlassian", "https://%s.atlassian.net", "", "Check public JIRA projects & Confluence spaces"},
	{"ServiceNow", "https://%s.service-now.com", "instance not found", "Check public portal & REST API"},
	{"Okta", "https://%s.okta.com", "", "Username enum via /api/v1/authn"},
	{"OktaPreview", "https://%s.oktapreview.com", "", ""},
	{"Salesforce", "https://%s.my.salesforce.com", "", "Community guest access → sobjects"},
	{"SharePoint", "https://%s.sharepoint.com", "", ""},
	{"Statuspage", "https://%s.statuspage.io", "Could not resolve", ""},
	{"BambooHR", "https://%s.bamboohr.com", "", ""},
	{"Workday", "https://%s.workday.com", "", ""},
	{"Zoom", "https://%s.zoom.us", "", ""},
	{"Jamf", "https://%s.jamfcloud.com", "", "MDM console"},
	{"Pipedrive", "https://%s.pipedrive.com", "", ""},
}

// Path-style SaaS: the org appears in the path. These platforms return 200 for
// ANY path with a generic page, so we require a specific "found" marker instead.
var saasPathTemplates = []struct {
	Platform string
	Template string
	Found    string // body marker confirming the org exists
	Note     string
}{
	{"GitHub", "https://github.com/%s", "", "Org repos, commits, secrets"},
	{"GitLab", "https://gitlab.com/%s", "", "Public repos & CI configs"},
	{"Bitbucket", "https://bitbucket.org/%s", "", "Public repos may leak code"},
	{"Trello", "https://trello.com/%s", "", "Public boards may leak internal data"},
}

func RunSaaS(cfg *core.Config, report *core.ReconReport, log *core.Logger) {
	log.Module("SAASENUM // Third-Party Platform Discovery")

	if cfg.Passive {
		log.Info("Skipping SaaS enum in passive mode")
		return
	}

	client := core.NewHTTPClient(cfg)
	// Use the apex domain (eTLD+1) so scanning "docs.anthropic.com"
	// checks "anthropic.zendesk.com", not "docs.zendesk.com".
	// IP targets have no org name to enumerate — deriving one from
	// "127.0.0.1" yields org "0" and probes 0.okta.com, gitlab.com/0,
	// etc: pure false positives (verified vs a Juice Shop instance on
	// 127.0.0.1:3000 reporting 10 phantom "SaaS platforms").
	if net.ParseIP(cfg.Domain) != nil {
		log.Info("Target is an IP literal — SaaS org enumeration not applicable, skipping")
		return
	}
	if isNonRoutableDomain(cfg.Domain) {
		log.Info("Target is a non-routable hostname — SaaS org enumeration not applicable, skipping")
		return
	}
	apex := extractApexDomain(cfg.Domain)
	orgName := strings.Split(apex, ".")[0]
	log.Info("Checking SaaS platforms for org '%s'...", orgName)

	result := SaaSResult{}
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, cfg.Concurrency)
	)

	// ── Subdomain-style platforms: verify the subdomain actually resolves ──
	// A vanity subdomain like org.zendesk.com only exists if it resolves in DNS.
	// This eliminates the false positives from platforms returning 200 for any name.
	for _, tmpl := range saasTemplates {
		wg.Add(1)
		sem <- struct{}{}
		go func(platform, template, notFound, note string) {
			defer core.RecoverWorker(log, "saasenum")
			defer wg.Done()
			defer func() { <-sem }()

			url := fmt.Sprintf(template, orgName)
			// Extract host for DNS check
			host := strings.TrimPrefix(url, "https://")
			host = strings.SplitN(host, "/", 2)[0]

			// Primary signal: does the vanity subdomain resolve?
			lookupCtx, lookupCancel := cfg.Context(cfg.Timeout)
			_, err := cfg.Resolver.LookupHost(lookupCtx, host)
			lookupCancel()
			if err != nil {
				return // doesn't resolve → instance doesn't exist
			}

			body, status, err := core.FetchBodyRL(client, url, cfg.UserAgent, cfg.RL)
			if err != nil {
				return
			}

			// Status gate: many SaaS use wildcard DNS, so "the host resolves" is
			// NOT proof the tenant exists. A 404/410 means the vanity instance is
			// unclaimed — don't report it. 401/403 mean it exists but is
			// protected (still a valid finding).
			if status == 404 || status == 410 || status >= 500 {
				return
			}

			// Secondary: reject if body says "not found"
			if notFound != "" && strings.Contains(strings.ToLower(body), strings.ToLower(notFound)) {
				return
			}

			sp := SaaSPlatform{Platform: platform, URL: url, StatusCode: status, Note: note}
			mu.Lock()
			result.Platforms = append(result.Platforms, sp)
			mu.Unlock()
			log.Warn("SaaS found [%s]: %s [%d] %s", platform, url, status, note)
		}(tmpl.Platform, tmpl.Template, tmpl.NotFound, tmpl.Note)
	}

	// ── Path-style platforms: require a "found" marker ──
	// github.com/org returns 200 for any path, so DNS won't help. Instead we
	// check whether the org page contains org-specific content vs a 404 page.
	for _, tmpl := range saasPathTemplates {
		wg.Add(1)
		sem <- struct{}{}
		go func(platform, template, found, note string) {
			defer core.RecoverWorker(log, "saasenum")
			defer wg.Done()
			defer func() { <-sem }()

			url := fmt.Sprintf(template, orgName)
			body, status, err := core.FetchBodyRL(client, url, cfg.UserAgent, cfg.RL)
			if err != nil || status != 200 {
				return
			}

			// Reject known "not found" pages from these platforms
			lb := strings.ToLower(body)
			pageNotFound := []string{
				"page not found", "404", "doesn't exist", "couldn't find",
				"this is not the web page you are looking for",
			}
			isNotFound := false
			for _, nf := range pageNotFound {
				if strings.Contains(lb, nf) {
					isNotFound = true
					break
				}
			}
			// The org name should appear in a real org page
			if isNotFound || !strings.Contains(lb, strings.ToLower(orgName)) {
				return
			}

			sp := SaaSPlatform{Platform: platform, URL: url, StatusCode: status, Note: note}
			mu.Lock()
			result.Platforms = append(result.Platforms, sp)
			mu.Unlock()
			log.Warn("SaaS found [%s]: %s [%d] %s", platform, url, status, note)
		}(tmpl.Platform, tmpl.Template, tmpl.Found, tmpl.Note)
	}

	wg.Wait()

	if len(result.Platforms) > 0 {
		report.Add(core.Finding{
			Module:      "saasenum",
			WSTG:        "WSTG-INFO-10",
			Title:       fmt.Sprintf("SaaS platforms discovered: %d", len(result.Platforms)),
			Severity:    core.SevLow,
			Description: "Third-party platforms outside the normal security review cycle.",
			Data:        result,
		})
	} else {
		log.Info("No SaaS platforms found for org name")
	}
}
