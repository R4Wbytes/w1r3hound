package modules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/w1r3hound/w1r3hound/internal/core"
)

// ──────────────────────────────────────────────
//  WSTG-INFO-03 — Review Webserver Metafiles
//  robots.txt, sitemap.xml, security.txt,
//  humans.txt, .well-known resources
// ──────────────────────────────────────────────

type MetafilesResult struct {
	RobotsTxt    *RobotsData `json:"robots_txt,omitempty"`
	Sitemaps     []string    `json:"sitemaps,omitempty"`
	SecurityTxt  string      `json:"security_txt,omitempty"`
	HumansTxt    string      `json:"humans_txt,omitempty"`
	WellKnown    []string    `json:"well_known_found,omitempty"`
	CrossDomain  string      `json:"crossdomain_xml,omitempty"`
	ClientAccess string      `json:"clientaccesspolicy,omitempty"`
}

type RobotsData struct {
	Found       bool     `json:"found"`
	Disallowed  []string `json:"disallowed_paths"`
	Allowed     []string `json:"allowed_paths"`
	SitemapURLs []string `json:"sitemap_urls,omitempty"`
	RawContent  string   `json:"raw_content,omitempty"`
}

func RunMetafiles(cfg *core.Config, report *core.ReconReport, log *core.Logger) {
	log.Module("METADATA // Metafile & Policy Extraction")

	client := core.NewHTTPClient(cfg)
	target := normalizeTarget(cfg.Target)
	result := MetafilesResult{}

	// ── 1. robots.txt ──
	log.Info("Fetching robots.txt...")
	body, status, err := core.FetchBodyRL(client, target+"/robots.txt", cfg.UserAgent, cfg.RL)
	if err == nil && status == 200 && len(body) > 0 {
		rd := parseRobots(body)
		rd.Found = true
		result.RobotsTxt = &rd
		log.Info("robots.txt found — %d disallowed paths", len(rd.Disallowed))
		for _, p := range rd.Disallowed {
			log.Debug("  Disallow: %s", p)
		}
		if len(rd.Disallowed) > 0 {
			report.Add(core.Finding{
				Module:      "metafiles",
				WSTG:        "WSTG-INFO-03",
				Title:       fmt.Sprintf("robots.txt exposes %d hidden paths", len(rd.Disallowed)),
				Severity:    core.SevLow,
				Description: "Disallowed paths may reveal sensitive directories.",
				Data:        rd.Disallowed,
			})
		}
	} else {
		log.Debug("robots.txt not found or empty")
	}

	// ── 2. sitemap.xml ──
	log.Info("Fetching sitemap.xml...")
	sitemapURLs := []string{
		target + "/sitemap.xml",
		target + "/sitemap_index.xml",
		target + "/sitemap.xml.gz",
		target + "/sitemaps.xml",
	}
	// Also from robots.txt
	if result.RobotsTxt != nil {
		sitemapURLs = append(sitemapURLs, result.RobotsTxt.SitemapURLs...)
	}

	for _, surl := range sitemapURLs {
		body, status, err := core.FetchBodyRL(client, surl, cfg.UserAgent, cfg.RL)
		if err == nil && status == 200 && strings.Contains(body, "<") {
			result.Sitemaps = append(result.Sitemaps, surl)
			// Extract URLs from sitemap
			urls := extractSitemapURLs(body)
			log.Info("Sitemap %s — %d URLs", surl, len(urls))
		}
	}

	// ── 3. security.txt ──
	log.Info("Fetching security.txt...")
	secPaths := []string{
		target + "/.well-known/security.txt",
		target + "/security.txt",
	}
	for _, sp := range secPaths {
		body, status, err := core.FetchBodyRL(client, sp, cfg.UserAgent, cfg.RL)
		if err == nil && status == 200 && len(body) > 10 {
			result.SecurityTxt = body
			log.Info("security.txt found at %s", sp)
			// Extract bug bounty / contact info
			if strings.Contains(strings.ToLower(body), "bounty") ||
				strings.Contains(strings.ToLower(body), "hackerone") ||
				strings.Contains(strings.ToLower(body), "bugcrowd") {
				log.Info("Bug bounty program detected in security.txt!")
				report.Add(core.Finding{
					Module:   "metafiles",
					WSTG:     "WSTG-INFO-03",
					Title:    "Bug bounty program referenced in security.txt",
					Severity: core.SevInfo,
					Data:     body,
				})
			}
			break
		}
	}

	// ── 4. humans.txt ──
	body, status, err = core.FetchBodyRL(client, target+"/humans.txt", cfg.UserAgent, cfg.RL)
	if err == nil && status == 200 && len(body) > 5 {
		result.HumansTxt = body
		log.Info("humans.txt found — may reveal team/tech info")
	}

	// ── 5. .well-known resources ──
	log.Info("Probing .well-known paths...")
	wellKnownPaths := []string{
		"/.well-known/openid-configuration",
		"/.well-known/jwks.json",
		"/.well-known/oauth-authorization-server",
		"/.well-known/assetlinks.json",
		"/.well-known/apple-app-site-association",
		"/.well-known/change-password",
		"/.well-known/host-meta",
		"/.well-known/host-meta.json",
		"/.well-known/nodeinfo",
		"/.well-known/webfinger",
		"/.well-known/dnt-policy.txt",
		"/.well-known/gpc.json",
		"/.well-known/mta-sts.txt",
	}
	for _, p := range wellKnownPaths {
		_, status, err := core.FetchBodyRL(client, target+p, cfg.UserAgent, cfg.RL)
		if err == nil && status == 200 {
			result.WellKnown = append(result.WellKnown, p)
			log.Info("Found: %s", p)
		}
	}

	// ── OIDC/OAuth metadata analysis ──
	for _, oidcPath := range []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"} {
		oidcBody, oidcStatus, _ := core.FetchBodyRL(client, target+oidcPath, cfg.UserAgent, cfg.RL)
		if oidcStatus == 200 && strings.Contains(oidcBody, "grant_types") {
			lowerBody := strings.ToLower(oidcBody)
			var dangerousGrants []string
			if strings.Contains(lowerBody, `"password"`) || strings.Contains(lowerBody, `"password"`) {
				dangerousGrants = append(dangerousGrants, "password (resource owner)")
			}
			if strings.Contains(lowerBody, `"implicit"`) {
				dangerousGrants = append(dangerousGrants, "implicit (deprecated)")
			}
			if len(dangerousGrants) > 0 {
				log.Warn("OIDC metadata at %s exposes dangerous grants: %v", oidcPath, dangerousGrants)
				report.Add(core.Finding{
					Module:      "metafiles",
					WSTG:        "WSTG-CONF-07",
					Title:       fmt.Sprintf("OAuth/OIDC dangerous grant types enabled: %s", strings.Join(dangerousGrants, ", ")),
					Severity:    core.SevMedium,
					Description: "The password grant enables brute-force if client_id is discovered. The implicit grant is deprecated and vulnerable to token leakage.",
				})
			}
			break
		}
	}

	// ── Fingerprint-aware path probing ──
	// Calibrate catch-all / SPA behaviour first: if the server returns 200
	// for arbitrary paths we must not trust bare 200s as proof that a
	// technology-specific endpoint exists.
	catchAll := calibrateCatchAll(client, target, cfg)
	if catchAll.isCatchAll {
		log.Warn("Catch-all/SPA detected (~%d bytes) — filtering sensitive-path false positives", catchAll.bodyLen)
	}

	techPaths := []struct {
		Path   string
		Desc   string
		Marker string // body substring that confirms a genuine response
	}{
		{"/pf/heartbeat.ping", "PingFederate heartbeat", "OK"},
		{"/pf-ws/rest/sessionMgmt/", "PingFederate session management API", ""},
		{"/wp-json/", "WordPress REST API namespace", "wp-json"},
		{"/wp-json/wp/v2/users", "WordPress user enumeration", "\"id\""},
		{"/wp-signup.php", "WordPress signup page", "wp-signup"},
		{"/xmlrpc.php", "WordPress XML-RPC", "XML-RPC"},
		{"/wp-admin/maint/repair.php", "WordPress database repair", "repair"},
		{"/.auth/me", "Azure App Service auth", ""},
		{"/.auth/login/aad", "Azure AAD login", ""},
	}
	for _, tp := range techPaths {
		body, status, err := core.FetchBodyRL(client, target+tp.Path, cfg.UserAgent, cfg.RL)
		if err != nil || (status != 200 && status != 401 && status != 403) {
			continue
		}
		if status == 200 && len(body) > 0 {
			if isCloudflareChallenge(body) {
				log.Debug("Sensitive path %s returned CF challenge, skipping", tp.Path)
				continue
			}
			if catchAll.matches(status, len(body)) {
				log.Debug("Sensitive path %s matches catch-all signature, skipping", tp.Path)
				continue
			}
			if tp.Marker != "" && !strings.Contains(strings.ToLower(body), strings.ToLower(tp.Marker)) {
				log.Debug("Sensitive path %s lacks expected marker %q, skipping", tp.Path, tp.Marker)
				continue
			}
			log.Warn("Sensitive path accessible: %s (%s)", tp.Path, tp.Desc)
			sev := core.SevLow
			if strings.Contains(tp.Path, "heartbeat") || strings.Contains(tp.Path, "sessionMgmt") || strings.Contains(tp.Path, "users") {
				sev = core.SevMedium
			}
			report.Add(core.Finding{
				Module:      "metafiles",
				WSTG:        "WSTG-INFO-03",
				Title:       fmt.Sprintf("Sensitive endpoint accessible: %s (%s)", tp.Path, tp.Desc),
				Severity:    sev,
				Description: fmt.Sprintf("The %s endpoint returned status %d.", tp.Desc, status),
			})
		} else if status == 401 || status == 403 {
			log.Info("Protected endpoint exists: %s (%s) → %d", tp.Path, tp.Desc, status)
		}
	}

	// ── 6. Cross-domain policy files (WSTG-CONF-08) ──
	body, status, _ = core.FetchBodyRL(client, target+"/crossdomain.xml", cfg.UserAgent, cfg.RL)
	if status == 200 && strings.Contains(body, "cross-domain-policy") {
		result.CrossDomain = body
		if strings.Contains(body, `domain="*"`) {
			log.Warn("crossdomain.xml allows all domains (wildcard)!")
			report.Add(core.Finding{
				Module:      "metafiles",
				WSTG:        "WSTG-CONF-08",
				Title:       "Overly permissive crossdomain.xml (wildcard)",
				Severity:    core.SevMedium,
				Description: "Flash/Silverlight cross-domain policy allows any origin.",
			})
		} else {
			log.Info("crossdomain.xml found")
		}
	}

	body, status, _ = core.FetchBodyRL(client, target+"/clientaccesspolicy.xml", cfg.UserAgent, cfg.RL)
	if status == 200 && strings.Contains(body, "access-policy") {
		result.ClientAccess = body
		log.Info("clientaccesspolicy.xml found")
	}

	report.Add(core.Finding{
		Module:   "metafiles",
		WSTG:     "WSTG-INFO-03",
		Title:    "Metafiles analysis complete",
		Severity: core.SevInfo,
		Data:     result,
	})
}

// ── helpers ──

func parseRobots(content string) RobotsData {
	rd := RobotsData{RawContent: content}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "disallow:") {
			path := strings.TrimSpace(line[len("disallow:"):])
			if path != "" {
				rd.Disallowed = append(rd.Disallowed, path)
			}
		} else if strings.HasPrefix(lower, "allow:") {
			path := strings.TrimSpace(line[len("allow:"):])
			if path != "" {
				rd.Allowed = append(rd.Allowed, path)
			}
		} else if strings.HasPrefix(lower, "sitemap:") {
			url := strings.TrimSpace(line[len("sitemap:"):])
			if url != "" {
				rd.SitemapURLs = append(rd.SitemapURLs, url)
			}
		}
	}
	return rd
}

var sitemapLocRe = regexp.MustCompile(`<loc>\s*(.*?)\s*</loc>`)

func extractSitemapURLs(body string) []string {
	matches := sitemapLocRe.FindAllStringSubmatch(body, -1)
	var urls []string
	for _, m := range matches {
		if len(m) > 1 {
			urls = append(urls, m[1])
		}
	}
	return urls
}
