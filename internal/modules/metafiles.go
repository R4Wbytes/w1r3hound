package modules

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

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

	// Calibrate SPA/catch-all up front so every section below can
	// filter responses that are just the SPA shell served for any URL.
	catchAll := calibrateCatchAll(client, target, cfg)
	if catchAll.isCatchAll {
		log.Warn("Catch-all/SPA detected (~%d bytes) — filtering false positives across all probes", catchAll.bodyLen)
	}

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
			// A robots.txt Disallow list is the site owner's own inventory of
			// paths worth hiding — the highest-signal recon leads on the target.
			// Verify each one instead of merely reporting the hint: a reachable
			// auto-indexed directory behind a Disallow is a real disclosure. (On
			// Juice Shop this turns the bare "/ftp is disallowed" note into the
			// actual finding — /ftp is a live listing exposing *.bak backups and
			// a KeePass DB.)
			probeRobotsDisallowed(client, cfg, target, rd.Disallowed, report, log)
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
		if err != nil || status != 200 {
			continue
		}
		if catchAll.matches(status, len(body)) {
			log.Debug("Sitemap %s matches catch-all signature, skipping", surl)
			continue
		}
		if strings.Contains(body, "<") {
			result.Sitemaps = append(result.Sitemaps, surl)
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
		if err == nil && status == 200 && len(body) > 10 && !catchAll.matches(status, len(body)) {
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
			analyzeSecurityTxt(body, target, cfg, report, log)
			break
		}
	}

	// ── 4. humans.txt ──
	body, status, err = core.FetchBodyRL(client, target+"/humans.txt", cfg.UserAgent, cfg.RL)
	if err == nil && status == 200 && len(body) > 5 && !catchAll.matches(status, len(body)) {
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
		"/.well-known/csaf/provider-metadata.json",
	}
	for _, p := range wellKnownPaths {
		wkBody, wkStatus, wkErr := core.FetchBodyRL(client, target+p, cfg.UserAgent, cfg.RL)
		if wkErr != nil || wkStatus != 200 {
			continue
		}
		if catchAll.matches(wkStatus, len(wkBody)) {
			log.Debug("Well-known %s matches catch-all signature, skipping", p)
			continue
		}
		result.WellKnown = append(result.WellKnown, p)
		log.Info("Found: %s", p)
	}

	// ── OIDC/OAuth metadata analysis ──
	for _, oidcPath := range []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"} {
		oidcBody, oidcStatus, _ := core.FetchBodyRL(client, target+oidcPath, cfg.UserAgent, cfg.RL)
		if oidcStatus == 200 && !catchAll.matches(oidcStatus, len(oidcBody)) && strings.Contains(oidcBody, "grant_types") {
			lowerBody := strings.ToLower(oidcBody)
			var dangerousGrants []string
			if strings.Contains(lowerBody, `"password"`) ||
				strings.Contains(lowerBody, `urn:ietf:params:oauth:grant-type:password`) {
				dangerousGrants = append(dangerousGrants, "password (resource owner)")
			}
			if strings.Contains(lowerBody, `"client_credentials"`) {
				dangerousGrants = append(dangerousGrants, "client_credentials (machine-to-machine)")
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

// ── security.txt field analysis (RFC 9116) ──

// secTxtFieldRe matches RFC 9116 field lines: "FieldName: value".
var secTxtFieldRe = regexp.MustCompile(`(?m)^([A-Za-z-]+):\s*(.+)$`)

func analyzeSecurityTxt(body, target string, cfg *core.Config, report *core.ReconReport, log *core.Logger) {
	fields := make(map[string][]string)
	for _, m := range secTxtFieldRe.FindAllStringSubmatch(body, -1) {
		key := strings.ToLower(strings.TrimSpace(m[1]))
		val := strings.TrimSpace(m[2])
		fields[key] = append(fields[key], val)
	}

	// RFC 9116 §2.5.5: Expires is REQUIRED. Check whether the date
	// has passed — an expired security.txt means the contact/policy
	// information may be stale and should not be relied upon.
	if expires, ok := fields["expires"]; ok && len(expires) > 0 {
		if t, err := time.Parse(time.RFC1123, expires[0]); err == nil {
			if time.Now().After(t) {
				log.Warn("security.txt Expires date has passed: %s", expires[0])
				report.Add(core.Finding{
					Module:      "metafiles",
					WSTG:        "WSTG-INFO-03",
					Title:       "security.txt has expired",
					Severity:    core.SevLow,
					Description: fmt.Sprintf("The Expires field is set to %s, which is in the past. Per RFC 9116 the file content should no longer be trusted.", expires[0]),
				})
			} else {
				log.Info("security.txt Expires: %s (valid)", expires[0])
			}
		}
	}

	// Feed Contact URLs and Hiring/Acknowledgements paths into shared
	// context so downstream modules can discover them. These are the
	// site operator's own pointers to interesting pages.
	var extraURLs []string
	for _, key := range []string{"contact", "acknowledgements", "hiring"} {
		for _, val := range fields[key] {
			if strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") {
				extraURLs = append(extraURLs, val)
			} else if strings.HasPrefix(val, "/") || strings.HasPrefix(val, "#") {
				extraURLs = append(extraURLs, resolveURL(target, val))
			}
		}
	}
	if len(extraURLs) > 0 {
		cfg.AddSharedURLs(extraURLs)
	}
}

// ── robots.txt Disallow verification (WSTG-CONF-04) ──

// dirListingHrefRe pulls entry names out of an HTML directory listing. It skips
// Apache/serve-index sort links (href="?C=N;O=D") via the leading [^"?].
var dirListingHrefRe = regexp.MustCompile(`(?i)<a\s+[^>]*href="([^"?][^"]*)"`)

// sensitiveListingExts are suffixes whose presence in a public directory listing
// is a genuine information-disclosure problem: backups, archives, secret stores,
// VCS artefacts, byte-compiled code.
var sensitiveListingExts = []string{
	".bak", ".old", ".swp", ".orig", ".save", ".backup",
	".sql", ".db", ".sqlite", ".kdbx",
	".zip", ".tar", ".tgz", ".gz", ".rar", ".7z",
	".key", ".pem", ".p12", ".pfx", ".env", ".pyc", ".git",
	".tf", ".tfvars", ".tfstate",
}

// sensitiveListingNames are exact filenames (case-insensitive) whose presence
// in a directory listing is always a disclosure — infrastructure-as-code files
// that expose internal architecture, build processes, and often credentials.
var sensitiveListingNames = map[string]bool{
	"dockerfile":         true,
	"docker-compose.yml": true,
	"docker-compose.yaml": true,
	".dockerenv":         true,
	"makefile":           true,
	"vagrantfile":        true,
	"jenkinsfile":        true,
	".gitlab-ci.yml":     true,
	".travis.yml":        true,
	".env.example":       true,
	"wp-config.php":      true,
	"web.config":         true,
	"config.php":         true,
	"database.yml":       true,
	".htpasswd":          true,
	".htaccess":          true,
	".npmrc":             true,
	".pypirc":            true,
}

// logFileRe matches log files including rotated ones, where ".log" is not the
// final suffix: access.log, error.log, access.log.2026-08-11, app.log.1.gz.
// Access/error logs exposed via a listing leak request paths, IPs and often
// session tokens (e.g. Juice Shop /support/logs, the accessLogDisclosureChallenge).
var logFileRe = regexp.MustCompile(`(?i)\.log(\.[0-9a-z_.-]+)?$`)

// isDirectoryListing reports whether an HTML body is an auto-generated directory
// index — Apache/nginx autoindex or the Node serve-index used by Express apps
// like Juice Shop. A listing hands an attacker every filename in the directory,
// which is the whole point of verifying robots.txt Disallow entries.
func isDirectoryListing(body string) bool {
	lower := strings.ToLower(body)
	if strings.Contains(lower, "<title>index of /") || strings.Contains(lower, "<h1>index of /") {
		return true // Apache / nginx autoindex
	}
	if strings.Contains(lower, "listing directory") {
		return true // Node serve-index <title>listing directory /ftp/</title>
	}
	if strings.Contains(lower, `id="files"`) && strings.Contains(lower, "icon-directory") {
		return true // serve-index tile/detail view markup
	}
	return false
}

// extractListingEntries returns the de-duplicated entry names from a directory
// listing, dropping the parent-directory link, breadcrumb links and sort links.
func extractListingEntries(body string) []string {
	var entries []string
	seen := map[string]bool{}
	for _, m := range dirListingHrefRe.FindAllStringSubmatch(body, -1) {
		e := strings.TrimSpace(m[1])
		e = strings.TrimPrefix(e, "./")
		e = strings.TrimSuffix(e, "/")
		// Relative leaf names only: breadcrumb/parent links are absolute ("/ftp")
		// or "." / "..", external links start with a scheme.
		if e == "" || e == "." || e == ".." || strings.HasPrefix(e, "/") ||
			strings.HasPrefix(e, "http://") || strings.HasPrefix(e, "https://") {
			continue
		}
		if seen[e] {
			continue
		}
		seen[e] = true
		entries = append(entries, e)
	}
	return entries
}

// sensitiveListingFiles returns the subset of listing entries that look like
// backups, archives, secret stores or VCS artefacts.
func sensitiveListingFiles(entries []string) []string {
	var out []string
	for _, e := range entries {
		lower := strings.ToLower(e)
		hit := logFileRe.MatchString(lower)
		if !hit {
			hit = sensitiveListingNames[lower]
		}
		if !hit {
			for _, ext := range sensitiveListingExts {
				if strings.HasSuffix(lower, ext) {
					hit = true
					break
				}
			}
		}
		if hit {
			out = append(out, e)
		}
	}
	return out
}

// probeRobotsDisallowed fetches each path a robots.txt Disallow-lists and reports
// the reachable directory listings among them. It deliberately reports only
// listings (content-verified, so the SPA app-shell served for any path can never
// be mistaken for one) rather than every accessible path, since robots.txt is
// advisory and a plain 200 behind a Disallow is expected, not a finding.
func probeRobotsDisallowed(client *http.Client, cfg *core.Config, target string, disallowed []string, report *core.ReconReport, log *core.Logger) {
	const maxProbe = 25
	seen := map[string]bool{}
	probed := 0
	for _, raw := range disallowed {
		if probed >= maxProbe {
			break
		}
		p := strings.TrimSpace(raw)
		// Pattern Disallow entries ("/*.json$", "/search?q=") aren't concrete
		// fetchable paths.
		if p == "" || p == "/" || strings.ContainsAny(p, "*$?") {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		probed++

		// Probe the directory form (trailing slash). serve-index/autoindex emit
		// clean relative entry names ("package.json.bak") for "/ftp/" but base
		// them on the parent ("ftp/package.json.bak", plus a "." self-link) when
		// the slash is missing. Redirect-following makes this a no-op on servers
		// that 301 "/ftp" → "/ftp/".
		probeURL := target + p
		if !strings.HasSuffix(probeURL, "/") {
			probeURL += "/"
		}
		body, status, err := core.FetchBodyRL(client, probeURL, cfg.UserAgent, cfg.RL)
		if err != nil || status != 200 || len(body) == 0 || !isDirectoryListing(body) {
			continue
		}
		entries := extractListingEntries(body)
		log.Warn("Directory listing enabled at %s — %d entries (%d sensitive)", p, len(entries), len(sensitiveListingFiles(entries)))
		report.Add(buildDirectoryListingFinding("metafiles", p, " (disclosed via robots.txt Disallow)", entries))
	}
}

// buildDirectoryListingFinding constructs the WSTG-CONF-04 finding for a
// discovered auto-indexed directory. It is rated HIGH when the listing exposes
// backups/secrets/keys/logs and MEDIUM otherwise. sourceNote is an optional
// parenthetical describing how the path was found (e.g. via robots.txt). Shared
// by the metafiles (robots.txt-driven) and dirbrute (wordlist-driven) discovery
// paths so both rate and phrase directory listings identically.
func buildDirectoryListingFinding(module, path, sourceNote string, entries []string) core.Finding {
	sensitive := sensitiveListingFiles(entries)
	sev := core.SevMedium
	desc := fmt.Sprintf("Directory listing at %s%s exposes %d entries.", path, sourceNote, len(entries))
	if len(sensitive) > 0 {
		sev = core.SevHigh
		desc = fmt.Sprintf("Directory listing at %s%s exposes %d entries, including %d sensitive file(s): %s.",
			path, sourceNote, len(entries), len(sensitive), strings.Join(sensitive, ", "))
	}
	if strings.HasPrefix(path, "/.well-known") && len(sensitive) == 0 {
		sev = core.SevInfo
	}
	return core.Finding{
		Module:      module,
		WSTG:        "WSTG-CONF-04",
		Title:       fmt.Sprintf("Directory listing enabled at %s", path),
		Severity:    sev,
		Description: desc,
		Data:        entries,
	}
}
