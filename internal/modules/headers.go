package modules

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

// ──────────────────────────────────────────────
//  WSTG-INFO-08 — Framework Fingerprinting
//  WSTG-CONF-07 — Security Headers (HSTS, CSP…)
//  Technology detection via headers + cookies.
// ──────────────────────────────────────────────

type HeadersResult struct {
	SecurityHeaders map[string]SecurityHeader `json:"security_headers"`
	Technologies    []TechDetection           `json:"technologies_detected"`
	Cookies         []CookieInfo              `json:"cookies"`
}

type SecurityHeader struct {
	Present bool   `json:"present"`
	Value   string `json:"value,omitempty"`
	Grade   string `json:"grade"` // GOOD, WARN, MISSING
}

type TechDetection struct {
	Source string `json:"source"` // header, cookie, html
	Name   string `json:"name"`
	Value  string `json:"value,omitempty"`
}

type CookieInfo struct {
	Name     string `json:"name"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"httponly"`
	SameSite string `json:"samesite"`
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
}

// Cookie → framework mapping
var cookieFingerprints = map[string]string{
	"PHPSESSID":           "PHP",
	"JSESSIONID":          "Java (Servlet/JSP)",
	"ASP.NET_SessionId":   "ASP.NET",
	"CFID":                "ColdFusion",
	"CFTOKEN":             "ColdFusion",
	"connect.sid":         "Node.js (Express)",
	"rack.session":        "Ruby (Rack)",
	"_session_id":         "Ruby on Rails",
	"laravel_session":     "Laravel",
	"cakephp":             "CakePHP",
	"ci_session":          "CodeIgniter",
	"django":              "Django",
	"csrftoken":           "Django",
	"wp-settings":         "WordPress",
	"wordpress_logged_in": "WordPress",
	"joomla":              "Joomla",
	"drupal":              "Drupal",
	"BITRIX_SM":           "1C-Bitrix",
	"kohanasession":       "Kohana",
	"phpbb3_":             "phpBB",
	"fe_typo_user":        "TYPO3",
	"DotNetNukeAnonymous": "DotNetNuke",
	"EPiServer":           "EPiServer",
	"BIGipServer":         "F5 BIG-IP (Load Balancer)",
	"AWSALB":              "AWS ALB",
	"AWSALBCORS":          "AWS ALB (CORS)",
	"__cf_bm":             "Cloudflare",
	"cf_clearance":        "Cloudflare",
	"incap_ses":           "Imperva/Incapsula WAF",
	"visid_incap":         "Imperva/Incapsula WAF",
	"SERVERID":            "HAProxy",
	"ROUTEID":             "Apache mod_proxy",
	"citrix_ns_id":        "Citrix NetScaler",
}

// f5ASMCookieRe matches F5 BIG-IP/ASM persistence cookies, which are named
// "TS" followed by a hex-encoded pool/timestamp value (e.g. "TS019b9d84").
// A bare "ts" HasPrefix check (the previous approach) matched any unrelated
// cookie starting with those two letters — e.g. Postgres's "tsvector_pref",
// a demonstrated false "F5 ASM" fingerprint. Requiring a hex-only suffix
// keeps the signal while rejecting dictionary-word cookie names.
var f5ASMCookieRe = regexp.MustCompile(`(?i)^ts[0-9a-f]{6,}$`)

func RunHeaders(cfg *core.Config, report *core.ReconReport, log *core.Logger) {
	log.Module("SENTRY // Security Headers & Tech Fingerprint")

	client := core.NewHTTPClient(cfg)
	target := normalizeTarget(cfg.Target)
	result := HeadersResult{
		SecurityHeaders: make(map[string]SecurityHeader),
	}

	resp, err := core.DoRequestRL(client, "GET", target, cfg.UserAgent, cfg.RL)
	if err != nil {
		log.Error("Could not connect: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if location != "" {
			log.Info("Target returned redirect %d to %s — header findings skipped", resp.StatusCode, location)
		} else {
			log.Info("Target returned redirect %d — header findings skipped", resp.StatusCode)
		}
		return
	}
	if resp.StatusCode >= 400 {
		log.Info("Target returned status %d — header findings skipped", resp.StatusCode)
		return
	}
	var responseBody string
	if isHTMLContentType(resp.Header.Get("Content-Type")) {
		responseBody = core.ReadBodyLimit(resp, 512*1024)
		if isGenericErrorPage(responseBody) {
			log.Info("Target returned a generic error document — header findings skipped")
			return
		}
	}

	// ── 1. Security Headers Check ──
	isHTTPS := strings.HasPrefix(target, "https://")
	secHeaders := []struct {
		Name      string
		Required  bool
		HTTPSOnly bool
		Desc      string
	}{
		{"Strict-Transport-Security", true, true, "HSTS prevents protocol downgrade attacks"},
		{"Content-Security-Policy", true, false, "CSP mitigates XSS and injection attacks"},
		{"X-Content-Type-Options", true, false, "Prevents MIME-type sniffing"},
		{"X-Frame-Options", true, false, "Prevents clickjacking"},
		{"X-XSS-Protection", false, false, "Legacy XSS filter (deprecated in modern browsers)"},
		{"Referrer-Policy", true, false, "Controls referrer information leakage"},
		{"Permissions-Policy", true, false, "Controls browser feature access"},
		{"Cross-Origin-Embedder-Policy", false, false, "COEP for cross-origin isolation"},
		{"Cross-Origin-Opener-Policy", false, false, "COOP prevents cross-origin attacks"},
		{"Cross-Origin-Resource-Policy", false, false, "CORP controls resource sharing"},
		{"Cache-Control", false, false, "Cache directives for sensitive data"},
	}

	var missing []string
	for _, sh := range secHeaders {
		val := resp.Header.Get(sh.Name)
		entry := SecurityHeader{Present: val != "", Value: val}

		// HSTS is only meaningful over HTTPS — RFC 6797 §7.2 says
		// browsers MUST ignore it over plain HTTP. Reporting it as
		// MISSING on an HTTP target inflates the count and can push
		// severity from LOW to MEDIUM without cause.
		if sh.HTTPSOnly && !isHTTPS {
			if val == "" {
				entry.Grade = "WARN"
				log.Debug("  ~ %-35s not applicable (HTTP target)", sh.Name)
			} else {
				entry.Grade = "GOOD"
				log.Info("  ✓ %-35s = %s", sh.Name, truncate(val, 80))
			}
			result.SecurityHeaders[sh.Name] = entry
			continue
		}

		if val != "" {
			entry.Grade = "GOOD"
			log.Info("  ✓ %-35s = %s", sh.Name, truncate(val, 80))
		} else if sh.Required {
			entry.Grade = "MISSING"
			missing = append(missing, sh.Name)
			log.Warn("  ✗ %-35s MISSING", sh.Name)
		} else {
			entry.Grade = "WARN"
			log.Debug("  ~ %-35s not set (optional)", sh.Name)
		}
		result.SecurityHeaders[sh.Name] = entry
	}

	// Feature-Policy is the deprecated predecessor of Permissions-Policy.
	// When Permissions-Policy is missing but Feature-Policy is present,
	// flag the deprecated header use rather than leaving a silent gap.
	if resp.Header.Get("Permissions-Policy") == "" {
		if fp := resp.Header.Get("Feature-Policy"); fp != "" {
			log.Warn("Feature-Policy header present (deprecated — use Permissions-Policy)")
			report.Add(core.Finding{
				Module:      "headers",
				WSTG:        "WSTG-CONF-07",
				Title:       "Deprecated Feature-Policy header in use",
				Severity:    core.SevLow,
				Description: fmt.Sprintf("Server sends Feature-Policy (%s) instead of the modern Permissions-Policy header. Feature-Policy is deprecated and not supported in all browsers.", truncate(fp, 120)),
			})
			result.Technologies = append(result.Technologies, TechDetection{
				Source: "header",
				Name:   "Feature-Policy (deprecated)",
				Value:  fp,
			})
		}
	}

	if len(missing) > 0 {
		report.Add(core.Finding{
			Module:      "headers",
			WSTG:        "WSTG-CONF-07",
			Title:       fmt.Sprintf("%d security headers missing", len(missing)),
			Severity:    core.SevInfo,
			Description: "Defense-in-depth headers absent (absence alone is not proof of exploitability): " + strings.Join(missing, ", "),
			Data:        result.SecurityHeaders,
		})
	}

	// CSP content analysis — flag dangerous directives even when the header is present
	cspVal := resp.Header.Get("Content-Security-Policy")
	if cspVal != "" {
		directives := make(map[string]string)
		for _, part := range strings.Split(cspVal, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			fields := strings.SplitN(part, " ", 2)
			key := strings.ToLower(fields[0])
			val := ""
			if len(fields) > 1 {
				val = fields[1]
			}
			directives[key] = val
		}

		// Check for unsafe-inline in script-src or default-src
		for _, dir := range []string{"script-src", "default-src"} {
			if v, ok := directives[dir]; ok && strings.Contains(v, "'unsafe-inline'") {
				log.Warn("CSP %s contains 'unsafe-inline'", dir)
				report.Add(core.Finding{
					Module:      "headers",
					WSTG:        "WSTG-CONF-07",
					Title:       fmt.Sprintf("CSP %s contains 'unsafe-inline'", dir),
					Severity:    core.SevLow,
					Description: "'unsafe-inline' weakens CSP as a defense-in-depth control; practical impact requires a separate script-injection primitive.",
				})
			}
		}

		// Check for unsafe-eval in script-src or default-src
		for _, dir := range []string{"script-src", "default-src"} {
			if v, ok := directives[dir]; ok && strings.Contains(v, "'unsafe-eval'") {
				log.Warn("CSP %s contains 'unsafe-eval'", dir)
				report.Add(core.Finding{
					Module:      "headers",
					WSTG:        "WSTG-CONF-07",
					Title:       fmt.Sprintf("CSP %s contains 'unsafe-eval'", dir),
					Severity:    core.SevLow,
					Description: "'unsafe-eval' permits eval()-style execution and weakens CSP, but is not independently exploitable without attacker-controlled script input.",
				})
			}
		}

		// Check for wildcard * in default-src, script-src, or object-src
		for _, dir := range []string{"default-src", "script-src", "object-src"} {
			if v, ok := directives[dir]; ok {
				for _, token := range strings.Fields(v) {
					if token == "*" {
						log.Warn("CSP %s contains wildcard '*'", dir)
						report.Add(core.Finding{
							Module:      "headers",
							WSTG:        "WSTG-CONF-07",
							Title:       fmt.Sprintf("CSP %s contains wildcard '*'", dir),
							Severity:    core.SevLow,
							Description: "Wildcard '*' in CSP allows loading resources from any origin.",
						})
						break
					}
				}
			}
		}

		// Check for missing default-src
		if _, ok := directives["default-src"]; !ok {
			log.Warn("CSP missing default-src directive")
			report.Add(core.Finding{
				Module:      "headers",
				WSTG:        "WSTG-CONF-07",
				Title:       "CSP missing default-src directive",
				Severity:    core.SevLow,
				Description: "Without default-src, unlisted fetch directives have no fallback policy.",
			})
		}

		// Check for data: in script-src
		if v, ok := directives["script-src"]; ok && strings.Contains(v, "data:") {
			log.Warn("CSP script-src contains 'data:' URI scheme")
			report.Add(core.Finding{
				Module:      "headers",
				WSTG:        "WSTG-CONF-07",
				Title:       "CSP script-src contains 'data:' URI scheme",
				Severity:    core.SevLow,
				Description: "Allowing data: URIs in script-src can be used to bypass CSP via encoded scripts.",
			})
		}
	}

	// HSTS specifics
	hsts := resp.Header.Get("Strict-Transport-Security")
	if hsts != "" {
		if !strings.Contains(hsts, "includeSubDomains") {
			log.Warn("HSTS does not include subdomains")
		}
		if !strings.Contains(hsts, "preload") {
			log.Debug("HSTS preload not set")
		}
		// Check max-age value
		for _, part := range strings.Split(hsts, ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(strings.ToLower(part), "max-age") {
				kv := strings.SplitN(part, "=", 2)
				if len(kv) == 2 {
					if maxAge, err := strconv.Atoi(strings.TrimSpace(kv[1])); err == nil && maxAge < 31536000 {
						log.Warn("HSTS max-age=%d is below recommended minimum of 31536000", maxAge)
						report.Add(core.Finding{
							Module:      "headers",
							WSTG:        "WSTG-CONF-07",
							Title:       fmt.Sprintf("HSTS max-age=%d below recommended minimum", maxAge),
							Severity:    core.SevLow,
							Description: "HSTS max-age is below the recommended minimum of 1 year (31536000 seconds) required for HSTS preload.",
						})
					}
				}
				break
			}
		}
	}

	// ── 2. Technology Detection via Headers ──
	techHeaders := map[string]string{
		"X-Powered-By":                   "",
		"X-Generator":                    "",
		"X-AspNet-Version":               "ASP.NET",
		"X-AspNetMvc-Version":            "ASP.NET MVC",
		"X-Drupal-Cache":                 "Drupal",
		"X-Drupal-Dynamic-Cache":         "Drupal",
		"X-Varnish":                      "Varnish Cache",
		"X-Pingback":                     "WordPress (XML-RPC)",
		"X-Litespeed-Cache":              "LiteSpeed",
		"X-Turbo-Charged-By":             "LiteSpeed",
		"X-Mod-Pagespeed":                "Google mod_pagespeed",
		"X-Page-Speed":                   "Google PageSpeed",
		"Via":                            "",
		"X-Cache":                        "",
		"X-Cache-Status":                 "",
		"X-Served-By":                    "",
		"X-Backend-Server":               "",
		"X-CDN":                          "",
		"X-Envoy-Upstream-Service-Time":  "Envoy Proxy",
		"X-Envoy-Decorator-Operation":    "Envoy Proxy",
		"X-Kubernetes-Pf-Flowschema-Uid": "Kubernetes",
	}
	for h, defaultName := range techHeaders {
		val := resp.Header.Get(h)
		if val == "" {
			continue
		}
		name := defaultName
		if name == "" {
			name = val
		}
		result.Technologies = append(result.Technologies, TechDetection{
			Source: "header",
			Name:   h + ": " + name,
			Value:  val,
		})
		log.Info("Tech detected [header]: %s = %s", h, val)
	}

	// Server header analysis
	server := resp.Header.Get("Server")
	if server != "" {
		result.Technologies = append(result.Technologies, TechDetection{
			Source: "header",
			Name:   "Server: " + server,
			Value:  server,
		})
		// Check for version in server header
		if containsVersion(server) {
			report.Add(core.Finding{
				Module:      "headers",
				WSTG:        "WSTG-INFO-02",
				Title:       fmt.Sprintf("Server header exposes version: %s", server),
				Severity:    core.SevLow,
				Description: "Exposed version information aids attackers in finding known vulnerabilities.",
			})
		}
	}

	// ── 3. Cookie Analysis ──
	// Fix #7 (2026-08-07): Cookies are now deduplicated by
	// (name, host) before being added to the result and the finding list. The
	// original code appended a new Finding for every Set-Cookie header on every
	// URL the crawler visited, which produced duplicate MEDIUM findings
	// (e.g. "wordpress_xxx" appeared 3x in the same report) and inflated severity
	// counts without adding information.
	//
	// We also skip framework cookies (`wordpress_*`, `wp-*`, `PHPSESSID`, etc.)
	// from being reported as "missing Secure" — these are managed by the
	// framework via `wp-config.php` constants (COOKIE_DOMAIN, FORCE_SSL_ADMIN)
	// and are typically Secure when the site is HTTPS-only, even when the
	// Set-Cookie header doesn't carry the flag explicitly.
	var frameworkCookiePrefixes = []string{
		"wordpress_", "wp-", "PHPSESSID", "JSESSIONID", "ASP.NET_SessionId",
		"__Secure-", "__Host-", "_ga", "_gid", "_gat", // Google Analytics — managed by GA itself
	}
	var seenCookies = make(map[string]bool) // dedup across multiple resp.Cookies() iterations

	for _, cookie := range resp.Cookies() {
		dedupKey := cookie.Name + "@" + target
		if seenCookies[dedupKey] {
			continue
		}
		seenCookies[dedupKey] = true

		ci := CookieInfo{
			Name:     cookie.Name,
			Secure:   cookie.Secure,
			HTTPOnly: cookie.HttpOnly,
			SameSite: sameSiteName(cookie.SameSite),
			Domain:   cookie.Domain,
			Path:     cookie.Path,
		}
		result.Cookies = append(result.Cookies, ci)

		// Check for framework fingerprint
		for prefix, fw := range cookieFingerprints {
			if strings.HasPrefix(cookie.Name, prefix) || strings.EqualFold(cookie.Name, prefix) {
				result.Technologies = append(result.Technologies, TechDetection{
					Source: "cookie",
					Name:   fw,
					Value:  cookie.Name,
				})
				log.Info("Tech detected [cookie]: %s → %s", cookie.Name, fw)
				break
			}
		}
		if f5ASMCookieRe.MatchString(cookie.Name) {
			result.Technologies = append(result.Technologies, TechDetection{
				Source: "cookie",
				Name:   "F5 ASM",
				Value:  cookie.Name,
			})
			log.Info("Tech detected [cookie]: %s → F5 ASM", cookie.Name)
		}

		// Cookie security flags
		// Fix #7: skip framework cookies — they're managed by the framework
		// itself, often via Secure-by-default on HTTPS, and reporting them as
		// MEDIUM findings is almost always a false positive (e.g. WordPress VIP
		// sites with 17 wordpress_* cookies → 17 noise findings).
		isFrameworkCookie := false
		lowerName := strings.ToLower(cookie.Name)
		for _, pfx := range frameworkCookiePrefixes {
			if strings.HasPrefix(lowerName, strings.ToLower(pfx)) {
				isFrameworkCookie = true
				break
			}
		}
		if !cookie.Secure && strings.HasPrefix(target, "https://") && !isFrameworkCookie {
			log.Warn("Cookie '%s' missing Secure flag on HTTPS", cookie.Name)
			report.Add(core.Finding{
				Module:      "headers",
				WSTG:        "WSTG-SESS-02",
				Title:       fmt.Sprintf("Cookie '%s' missing Secure flag on HTTPS", cookie.Name),
				Severity:    core.SevMedium,
				Description: "Cookies without Secure flag can be sent over unencrypted HTTP connections.",
			})
		}
		if !cookie.HttpOnly && isSessionCookie(cookie.Name) {
			log.Warn("Session cookie '%s' missing HttpOnly flag", cookie.Name)
			report.Add(core.Finding{
				Module:      "headers",
				WSTG:        "WSTG-SESS-02",
				Title:       fmt.Sprintf("Session cookie '%s' missing HttpOnly", cookie.Name),
				Severity:    core.SevMedium,
				Description: "Session cookies without HttpOnly are vulnerable to XSS-based session hijacking.",
			})
		}
		if cookie.SameSite == http.SameSiteNoneMode && !cookie.Secure {
			log.Warn("Cookie '%s' has SameSite=None without Secure flag", cookie.Name)
			report.Add(core.Finding{
				Module:      "headers",
				WSTG:        "WSTG-SESS-02",
				Title:       fmt.Sprintf("Cookie '%s' SameSite=None without Secure flag", cookie.Name),
				Severity:    core.SevMedium,
				Description: "SameSite=None without Secure flag is rejected by modern browsers and may indicate misconfiguration.",
			})
		}
	}

	// ── 4. Framework fingerprint via HTML body (WSTG-INFO-08) ──
	// Header/cookie detection is blind to modern single-page apps, which
	// announce themselves only in the markup (Angular's <app-root>, Next.js's
	// __NEXT_DATA__, …). Read the HTML body once and match a high-signal set so
	// an SPA target isn't mislabelled as "1 technology".
	if responseBody != "" {
		for _, td := range detectBodyTech(responseBody) {
			result.Technologies = append(result.Technologies, td)
			log.Info("Tech detected [body]: %s (%s)", td.Name, td.Value)
		}
	}

	report.Add(core.Finding{
		Module:   "headers",
		WSTG:     "WSTG-INFO-08",
		Title:    fmt.Sprintf("Technology stack: %d technologies, %d cookies detected", len(result.Technologies), len(result.Cookies)),
		Severity: core.SevInfo,
		Data:     result,
	})
}

// bodyTechSignatures fingerprints web frameworks from static HTML markup. Each
// framework lists high-signal substrings; a single match identifies it. Kept
// deliberately specific (Angular's "<app-root", Next.js's "__NEXT_DATA__") to
// avoid false positives from generic words.
var bodyTechSignatures = []struct {
	Name     string
	Patterns []string
}{
	{"Angular", []string{"<app-root", "ng-version=", "_nghost", "_ngcontent"}},
	{"React", []string{"data-reactroot", "__REACT_DEVTOOLS_GLOBAL_HOOK__"}},
	{"Next.js", []string{"__NEXT_DATA__", "/_next/static"}},
	{"Nuxt.js", []string{"__NUXT__", "/_nuxt/"}},
	{"Vue.js", []string{"data-v-app", "data-server-rendered", "__vue__"}},
	{"Gatsby", []string{"___gatsby", "/page-data/app-data.json"}},
	{"SvelteKit", []string{"__sveltekit", "sveltekit:"}},
	{"jQuery", []string{"/jquery-", "/jquery.min.js"}},
	{"Modernizr", []string{"/modernizr-", "/modernizr.min.js"}},
	{"WordPress", []string{"/wp-content/", "/wp-includes/"}},
	{"Drupal", []string{"Drupal.settings", "/sites/all/"}},
	{"Bootstrap", []string{"/bootstrap.min.css", "/bootstrap.min.js"}},
}

// ngVersionRe extracts the Angular version from ng-version="X.Y.Z" when present.
var ngVersionRe = regexp.MustCompile(`ng-version="([^"]+)"`)
var jqueryVersionRe = regexp.MustCompile(`(?i)/jquery-([0-9]+(?:\.[0-9]+){1,3})(?:\.min)?\.js`)
var modernizrVersionRe = regexp.MustCompile(`(?i)/modernizr-([0-9]+(?:\.[0-9]+){1,3})(?:\.min)?\.js`)

// detectBodyTech returns the frameworks whose signature appears in the HTML body.
func detectBodyTech(body string) []TechDetection {
	var techs []TechDetection
	for _, sig := range bodyTechSignatures {
		for _, p := range sig.Patterns {
			if !strings.Contains(body, p) {
				continue
			}
			value := p
			switch sig.Name {
			case "Angular":
				if m := ngVersionRe.FindStringSubmatch(body); len(m) > 1 {
					value = "version " + m[1]
				}
			case "jQuery":
				if m := jqueryVersionRe.FindStringSubmatch(body); len(m) > 1 {
					value = "version " + m[1]
				}
			case "Modernizr":
				if m := modernizrVersionRe.FindStringSubmatch(body); len(m) > 1 {
					value = "version " + m[1]
				}
			}
			techs = append(techs, TechDetection{Source: "body", Name: sig.Name, Value: value})
			break // one match per framework is enough
		}
	}
	return techs
}

func sameSiteName(s http.SameSite) string {
	switch s {
	case http.SameSiteDefaultMode:
		return "Default"
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return "Unknown"
	}
}

var versionPattern = regexp.MustCompile(`\d+\.\d+`)

func containsVersion(s string) bool {
	return versionPattern.MatchString(s)
}

// knownSessionCookieNames are exact (case-insensitive) cookie names known to
// carry an authentication/session identifier.
var knownSessionCookieNames = map[string]bool{
	"phpsessid":         true,
	"jsessionid":        true,
	"asp.net_sessionid": true,
	"connect.sid":       true,
	"session":           true,
	"sessionid":         true,
	"session_id":        true,
	"sid":               true,
	"auth_token":        true,
	"authtoken":         true,
	"access_token":      true,
	"refresh_token":     true,
	"id_token":          true,
}

// isSessionCookie reports whether name looks like a session/auth identifier
// that should carry HttpOnly. The previous implementation matched by bare
// substring ("sid", "token", "auth", …), which flagged CSRF/anti-forgery
// tokens — csrf_token, authenticity_token — as missing-HttpOnly findings even
// though those cookies are deliberately JS-readable (double-submit pattern),
// and matched unrelated cookies like "consid" (contains "sid"). This checks
// a whitelist of known exact names first, explicitly excludes CSRF-style
// tokens, then falls back to a word-boundary match (split on common cookie
// separators) against a narrow, low-ambiguity term set.
func isSessionCookie(name string) bool {
	lower := strings.ToLower(name)
	if knownSessionCookieNames[lower] {
		return true
	}
	if strings.Contains(lower, "csrf") || strings.Contains(lower, "xsrf") || strings.Contains(lower, "authenticity") {
		return false
	}
	words := strings.FieldsFunc(lower, func(r rune) bool {
		return r == '_' || r == '-' || r == '.'
	})
	for _, w := range words {
		switch w {
		case "session", "sess", "sid", "jwt":
			return true
		}
	}
	return false
}
