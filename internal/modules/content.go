package modules

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/w1r3hound/w1r3hound/internal/core"
)

// ──────────────────────────────────────────────
//  WSTG-INFO-05 — Review Webpage Content for
//  Information Leakage: HTML comments, meta tags,
//  JavaScript secrets, source maps, API keys.
// ──────────────────────────────────────────────

type ContentResult struct {
	HTMLComments  []string          `json:"html_comments,omitempty"`
	MetaTags      map[string]string `json:"meta_tags,omitempty"`
	JSFiles       []string          `json:"js_files,omitempty"`
	SecretsFound  []SecretMatch     `json:"secrets_found,omitempty"`
	SourceMaps    []string          `json:"source_maps_found,omitempty"`
	InternalPaths []string          `json:"internal_paths,omitempty"`
	Emails        []string          `json:"emails_found,omitempty"`
	InternalIPs   []string          `json:"internal_ips,omitempty"`
}

type SecretMatch struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	Source  string `json:"source"`
	Context string `json:"context,omitempty"`
}

// Regex patterns for secret detection
var secretPatterns = []struct {
	Name    string
	Pattern *regexp.Regexp
}{
	{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"AWS Secret Key", regexp.MustCompile(`(?i)aws_secret_access_key\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})`)},
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)},
	{"Google OAuth ID", regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`)},
	{"GitHub Token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,255}`)},
	{"GitHub Classic Token", regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`)},
	{"Slack Token", regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}`)},
	{"Slack Webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`)},
	{"Stripe Secret Key", regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,99}`)},
	{"Stripe Publishable Key", regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,99}`)},
	{"Square Access Token", regexp.MustCompile(`sq0atp-[0-9A-Za-z_-]{22}`)},
	{"Twilio API Key", regexp.MustCompile(`(?i)(?:twilio|account_?sid|api_?key|api_?secret)\s*[:=]\s*['"]?SK[0-9a-fA-F]{32}`)},
	{"Mailgun API Key", regexp.MustCompile(`(?i)(?:mailgun|mg_?api)\s*[:=]\s*['"]?key-[0-9a-zA-Z]{32}`)},
	{"SendGrid API Key", regexp.MustCompile(`SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}`)},
	{"Heroku API Key", regexp.MustCompile(`(?i)heroku[a-z0-9_ .,:]+[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`)},
	{"Firebase URL", regexp.MustCompile(`https://[a-z0-9-]+\.firebaseio\.com`)},
	{"Firebase API Key", regexp.MustCompile(`(?i)firebase[a-z0-9_ .,:]*['"][A-Za-z0-9_-]{39}['"]`)},
	{"JWT Token", regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)},
	{"Private Key", regexp.MustCompile(`-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`)},
	{"Basic Auth", regexp.MustCompile(`(?i)(?:authorization|auth)\s*[:=]\s*['"]?basic\s+[A-Za-z0-9+/=]{20,}`)},
	{"Bearer Token", regexp.MustCompile(`(?i)(?:authorization|auth|token)\s*[:=]\s*['"]?bearer\s+[A-Za-z0-9_\-.~+/]{20,}=*`)},
	{"Password in URL", regexp.MustCompile(`(?i)(?:https?|ftp|ssh|mongodb\+srv)://[a-zA-Z0-9._-]{1,40}:([^@\s'"<>]{3,40})@[a-zA-Z0-9.-]+`)},
	{"DB Connection String", regexp.MustCompile(`(?i)(mongodb|postgres|mysql|redis|mssql|jdbc)://[^\s'"<>]{10,200}`)},
	{"Generic API Key", regexp.MustCompile(`(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"]?([A-Za-z0-9_-]{16,64})['"]?`)},
	{"Generic Secret", regexp.MustCompile(`(?i)(secret[_-]?key|client[_-]?secret|app[_-]?secret)\s*[:=]\s*['"]?([A-Za-z0-9_-]{16,64})['"]?`)},
	// Fix #6 (bbp-abercrombie-2026-08-07): The original regex
	//   (?i)(password|passwd|pwd)\s*[:=]\s*['"]([^'"]{4,40})['"]
	// matched translation keys in minified JavaScript (e.g. "FORGOT_PASSWORD"
	// is often split into "FORGOT_PASS" + "WORD" by minifiers, or appears as
	// "INVALID_EMAIL_OR_PASS" + "WORD" via string concatenation). With JS
	// minification concatenating adjacent string literals, the original regex
	// matched any fragment containing the word "pass" followed by a quoted
	// string. In one scan, this produced 10/10 false positives — every match
	// was an i18n key, not an actual hardcoded password.
	//
	// The new regex requires:
	//   - The keyword to be a *standalone* word at the START of a string
	//     (not a suffix of a CamelCase identifier like "FORGOT_PASS" or
	//     "INVALID_EMAIL_OR_PASS")
	//   - The value to NOT be a translation-key pattern (no underscores at
	//     the start, no all-uppercase with underscores in the middle)
	//   - A reasonable minimum length of 6 chars (4 was too short — it caught
	//     "|.*'" from a regex pattern)
	//   - A "secret-like" value: must contain at least one digit OR be
	//     unambiguously a password format (e.g. "MyP@ssw0rd123")
	//
	// We also add a post-filter via isLikelyI18nKey() to drop obvious i18n
	// keys that slip through the regex.
	{"Hardcoded Password", regexp.MustCompile(`(?i)(?:^|[\s;,{(\[])(password|passwd|pwd)\s*[:=]\s*['"]([^\s'"]{6,40})['"]`)},
}

// Internal IP patterns
var internalIPPattern = regexp.MustCompile(`(?:^|[^0-9])((?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})|(?:192\.168\.\d{1,3}\.\d{1,3}))(?:[^0-9]|$)`)

// Email pattern
var emailPattern = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)

// HTML comment pattern
var htmlCommentPattern = regexp.MustCompile(`<!--([\s\S]*?)-->`)

// Meta tag pattern
var metaTagPattern = regexp.MustCompile(`<meta\s+([^>]+)>`)
var metaAttrPattern = regexp.MustCompile(`(?i)(name|property|http-equiv)\s*=\s*["']([^"']+)["']`)
var metaContentPattern = regexp.MustCompile(`(?i)content\s*=\s*["']([^"']+)["']`)

// JS file patterns
var jsFilePattern = regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']([^"']*\.js(?:\?[^"']*)?)["']`)

// Source map reference
var sourceMapPattern = regexp.MustCompile(`//[#@]\s*sourceMappingURL\s*=\s*(\S+)`)

func RunContent(cfg *core.Config, report *core.ReconReport, log *core.Logger) {
	log.Module("DEEPDIVE // Content Analysis & Secret Scan")

	client := core.NewHTTPClient(cfg)
	target := normalizeTarget(cfg.Target)
	result := ContentResult{
		MetaTags: make(map[string]string),
	}
	emailSeen := make(map[string]bool)

	// Fetch main page
	body, status, err := core.FetchBodyRL(client, target, cfg.UserAgent, cfg.RL)
	if err != nil || status != 200 {
		log.Error("Could not fetch main page: %v (status %d)", err, status)
		return
	}

	// ── 1. HTML Comments ──
	comments := htmlCommentPattern.FindAllStringSubmatch(body, -1)
	for _, m := range comments {
		comment := strings.TrimSpace(m[1])
		if len(comment) < 3 || isBoringComment(comment) {
			continue
		}
		result.HTMLComments = append(result.HTMLComments, comment)
	}
	if len(result.HTMLComments) > 0 {
		log.Info("Found %d HTML comments with potential information", len(result.HTMLComments))
		for _, c := range result.HTMLComments {
			log.Debug("  Comment: %s", truncate(c, 100))
		}
	}

	// ── 2. Meta Tags ──
	metas := metaTagPattern.FindAllStringSubmatch(body, -1)
	for _, m := range metas {
		attrs := m[1]
		nameMatch := metaAttrPattern.FindStringSubmatch(attrs)
		contentMatch := metaContentPattern.FindStringSubmatch(attrs)
		if len(nameMatch) > 2 && len(contentMatch) > 1 {
			key := nameMatch[2]
			val := contentMatch[1]
			result.MetaTags[key] = val
			// Generator tag reveals CMS
			if strings.EqualFold(key, "generator") {
				log.Info("META generator: %s", val)
				report.Add(core.Finding{
					Module:   "content",
					WSTG:     "WSTG-INFO-08",
					Title:    fmt.Sprintf("CMS/Framework detected via meta tag: %s", val),
					Severity: core.SevInfo,
				})
			}
		}
	}

	// ── 3. JavaScript files ──
	jsFiles := jsFilePattern.FindAllStringSubmatch(body, -1)
	seen := make(map[string]bool)
	for _, m := range jsFiles {
		jsURL := m[1]
		if seen[jsURL] {
			continue
		}
		seen[jsURL] = true
		fullURL := resolveURL(target, jsURL)
		result.JSFiles = append(result.JSFiles, fullURL)
	}
	log.Info("Found %d JavaScript files referenced", len(result.JSFiles))

	// Feed JS files into shared context so the jsdeep module can analyze them
	cfg.SharedMu.Lock()
	cfg.SharedJSFiles = append(cfg.SharedJSFiles, result.JSFiles...)
	cfg.SharedMu.Unlock()

	// ── 4. Scan for secrets in HTML ──
	scanForSecrets(&result, body, "main_page", log)

	// ── 5. Scan JS files for secrets ──
	jsLimit := cfg.MaxJSFiles
	if jsLimit <= 0 {
		jsLimit = 30
	}
	if len(result.JSFiles) < jsLimit {
		jsLimit = len(result.JSFiles)
	}
	for i := 0; i < jsLimit; i++ {
		jsURL := result.JSFiles[i]
		jsBody, jsStatus, err := core.FetchBodyRL(client, jsURL, cfg.UserAgent, cfg.RL)
		if err != nil || jsStatus != 200 {
			continue
		}
		scanForSecrets(&result, jsBody, jsURL, log)

		// Extract emails from JS files (FN-11)
		jsEmails := emailPattern.FindAllString(jsBody, -1)
		for _, e := range jsEmails {
			lower := strings.ToLower(e)
			if !emailSeen[lower] && !strings.HasSuffix(lower, ".png") && !strings.HasSuffix(lower, ".jpg") {
				emailSeen[lower] = true
				result.Emails = append(result.Emails, lower)
			}
		}

		// Check for source map references (FIX #2: verify HTTP 200 + body shape
		// before adding, to avoid reporting source maps that are referenced in
		// a JS file but actually return 404 — a known source of false positives
		// on catch-all / SPA servers and CMS themes that include sourceMappingURL
		// comments for debugging even though the .map file is not deployed.)
		smMatches := sourceMapPattern.FindAllStringSubmatch(jsBody, -1)
		for _, sm := range smMatches {
			smURL := resolveURL(jsURL, cleanSourceMapURL(sm[1]))
			if !issameDomain(smURL, cfg.Domain) {
				log.Debug("Third-party source map (ignored): %s", smURL)
				continue
			}
			smBody, smStatus, _ := core.FetchBodyRL(client, smURL, cfg.UserAgent, cfg.RL)
			if smStatus == 200 && looksLikeSourceMap(smBody) {
				result.SourceMaps = append(result.SourceMaps, smURL)
				log.Warn("Source map accessible: %s", smURL)
			} else {
				log.Debug("Source map referenced but not accessible (status %d): %s", smStatus, smURL)
			}
		}
	}

	// ── 6. Try common source map paths (same-domain JS only) ──
	smSeen := make(map[string]bool)
	for _, sm := range result.SourceMaps {
		smSeen[sm] = true
	}
	for _, jsURL := range result.JSFiles {
		if len(result.SourceMaps) > 10 {
			break
		}
		if !issameDomain(jsURL, cfg.Domain) {
			continue // skip third-party JS
		}
		// The source map lives next to the FILE, not after the query string:
		// foo.min.js?ver=3.7.1 → foo.min.js.map  (not foo.min.js?ver=3.7.1.map)
		base := jsURL
		if i := strings.IndexByte(base, '?'); i != -1 {
			base = base[:i]
		}
		smURL := base + ".map"
		if smSeen[smURL] {
			continue
		}
		smSeen[smURL] = true
		smBody, smStatus, _ := core.FetchBodyRL(client, smURL, cfg.UserAgent, cfg.RL)
		// A 200 alone is meaningless on catch-all/SPA servers — validate that the
		// body is actually a Source Map v3 document before flagging it.
		if smStatus == 200 && looksLikeSourceMap(smBody) {
			result.SourceMaps = append(result.SourceMaps, smURL)
			log.Warn("Source map accessible: %s", smURL)
		}
	}

	if len(result.SourceMaps) > 0 {
		report.Add(core.Finding{
			Module:      "content",
			WSTG:        "WSTG-INFO-05",
			Title:       fmt.Sprintf("%d source map files exposed (same domain)", len(result.SourceMaps)),
			Severity:    core.SevMedium,
			Description: "Source maps expose original source code, aiding reverse engineering.",
			Data:        result.SourceMaps,
		})
	}

	// ── 7. Internal IPs ──
	ipMatches := internalIPPattern.FindAllStringSubmatch(body, -1)
	ipSeen := make(map[string]bool)
	for _, m := range ipMatches {
		ip := m[1]
		if !ipSeen[ip] {
			ipSeen[ip] = true
			result.InternalIPs = append(result.InternalIPs, ip)
		}
	}
	if len(result.InternalIPs) > 0 {
		log.Warn("Internal IPs leaked: %v", result.InternalIPs)
		report.Add(core.Finding{
			Module:   "content",
			WSTG:     "WSTG-INFO-05",
			Title:    fmt.Sprintf("Internal IP addresses leaked: %d found", len(result.InternalIPs)),
			Severity: core.SevLow,
			Data:     result.InternalIPs,
		})
	}

	// ── 8. Emails ──
	emailMatches := emailPattern.FindAllString(body, -1)
	for _, e := range emailMatches {
		lower := strings.ToLower(e)
		if !emailSeen[lower] && !strings.HasSuffix(lower, ".png") && !strings.HasSuffix(lower, ".jpg") {
			emailSeen[lower] = true
			result.Emails = append(result.Emails, lower)
		}
	}
	if len(result.Emails) > 0 {
		log.Info("Emails found: %v", result.Emails)
	}

	// Report secrets
	if len(result.SecretsFound) > 0 {
		sev := core.SevHigh
		if allGeneric(result.SecretsFound) {
			sev = core.SevMedium
		}
		report.Add(core.Finding{
			Module:      "content",
			WSTG:        "WSTG-INFO-05",
			Title:       fmt.Sprintf("Potential secrets/API keys found: %d matches", len(result.SecretsFound)),
			Severity:    sev,
			Description: "Sensitive data exposed in client-side code.",
			Data:        result.SecretsFound,
		})
	}

	report.Add(core.Finding{
		Module:   "content",
		WSTG:     "WSTG-INFO-05",
		Title:    "Content analysis complete",
		Severity: core.SevInfo,
		Data:     result,
	})
}

func scanForSecrets(result *ContentResult, text, source string, log *core.Logger) {
	for _, sp := range secretPatterns {
		matches := sp.Pattern.FindAllStringIndex(text, 10) // find indices
		for _, loc := range matches {
			matchStr := text[loc[0]:loc[1]]

			// Skip absurdly long matches (data URIs, inline SVGs, CSS)
			if len(matchStr) > 500 {
				continue
			}

			// Skip known safe patterns
			if isSafeMatch(matchStr) {
				continue
			}

			// Fix #6 (bbp-abercrombie-2026-08-07): drop false-positive
			// translation keys / framework constants that the regex matched.
			// Minified JS frequently concatenates i18n keys like
			// "FORGOT_PASSWORD" into "FORGOT_PASS" + "WORD" via
			// string-literal merging, and the original Hardcoded Password
			// regex happily matched the "FORGOT_PASS" side. Filter these.
			if sp.Name == "Hardcoded Password" && isLikelyI18nKey(matchStr) {
				log.Debug("Dropping i18n key false positive: %s", maskSecret(matchStr))
				continue
			}

			// Extract a short context window
			ctxStart := loc[0] - 30
			if ctxStart < 0 {
				ctxStart = 0
			}
			ctxEnd := loc[1] + 30
			if ctxEnd > len(text) {
				ctxEnd = len(text)
			}
			ctx := strings.ReplaceAll(text[ctxStart:ctxEnd], "\n", " ")
			ctx = strings.ReplaceAll(ctx, matchStr, maskSecret(matchStr)) // mask in context too

			sm := SecretMatch{
				Type:    sp.Name,
				Value:   maskSecret(matchStr),
				Source:  source,
				Context: truncate(ctx, 120),
			}
			result.SecretsFound = append(result.SecretsFound, sm)
			log.Warn("Secret [%s] in %s: %s", sp.Name, source, maskSecret(matchStr))
		}
	}
}

// isSafeMatch filters out known false-positive patterns.
func isSafeMatch(s string) bool {
	lower := strings.ToLower(s)
	safePrefixes := []string{
		"http://www.w3.org",
		"https://www.w3.org",
		"http://ns.adobe.com",
		"http://purl.org",
		"http://schemas.",
		"https://schemas.",
		"http://xml.",
		"http://xmlns.",
		"data:image/",
		"data:font/",
		"data:application/",
		"data:text/",
	}
	for _, p := range safePrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	// Skip if it looks like a MIME type or content-type, not a credential
	if strings.Contains(lower, "content-type") || strings.Contains(lower, "text/html") ||
		strings.Contains(lower, "text/plain") || strings.Contains(lower, "text/css") ||
		strings.Contains(lower, "application/json") || strings.Contains(lower, "image/svg") {
		return true
	}
	return false
}

// isLikelyI18nKey returns true when a "Hardcoded Password" match looks more
// like a translation key / framework constant than a real credential. Used by
// the secret scanner to suppress noisy false positives flagged during BBP
// recon (e.g. "INVALID_EMAIL_OR_PASS***ord\"").
// Fix #6 (bbp-abercrombie-2026-08-07).
func isLikelyI18nKey(s string) bool {
	lower := strings.ToLower(s)

	// Suffixes typical of i18n keys (after JS minification or string concat):
	//   - "word\"" (closing of a CamelCase key like "FORGOT_PASSWORD")
	//   - "ord\"" (similar)
	//   - "assword\"" (closing of a concatenated key)
	//   - ":.*'" (regex pattern tail, not a credential)
	i18nSuffixes := []string{`word"`, `ord"`, `assword"`, `ord"`, `ass"`, `wd"`, `:.*'`, `|.*'`, `passord"`}
	for _, suf := range i18nSuffixes {
		if strings.HasSuffix(lower, suf) {
			return true
		}
	}

	// CamelCase / ALL_CAPS_SNAKE prefixes typical of i18n keys:
	//   - INVALID_..., FORGOT_..., CREATE_..., RESET_..., PASSWORD_REQUIREMENTS
	//   - ...OR_PASS (mid-key, suggesting concatenation)
	//   - ..._PASSWORD mid-key
	i18nPrefixes := []string{
		"invalid_", "forgot_", "create_", "reset_", "update_", "change_",
		"set_", "enter_", "confirm_", "new_", "old_", "current_",
		"email_or_", "user_or_", "user_pass", "your_pass", "my_pass",
		"required_pass", "pass_requirements", "password_requirements",
		"password_hint", "password_strength", "password_validation",
		"username_or_", "username_pass", "userpassword",
	}
	for _, pfx := range i18nPrefixes {
		if strings.HasPrefix(lower, pfx) {
			return true
		}
	}

	// Mid-key "OR_PASS" / "AND_PASS" / "_PASS_" suggests concatenation
	// of a CamelCase identifier with the word "password".
	concatIndicators := []string{"_or_pass", "_and_pass", "_pass_", "_password_", "_passord_"}
	for _, ci := range concatIndicators {
		if strings.Contains(lower, ci) {
			return true
		}
	}

	// If the value contains no digits AND is short (< 12 chars), it's
	// overwhelmingly likely to be a key/identifier, not a password.
	if !hasDigit(lower) && len(lower) < 12 {
		return true
	}

	return false
}

// hasDigit returns true if s contains at least one ASCII digit. Cheap
// helper for isLikelyI18nKey.
func hasDigit(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

// cleanSourceMapURL trims trailing delimiters (`;`, `,`, `"`, `'`, `)`, `}`)
// that the sourceMapPattern regex captures when a JS file ends with
// `//# sourceMappingURL=...;` or has a trailing comma/quote after the URL.
// Fix #8 (bbp-abercrombie-2026-08-07).
func cleanSourceMapURL(s string) string {
	for {
		trimmed := false
		for _, c := range []string{";", ",", `"`, "'", ")", "}", "]", " "} {
			if strings.HasSuffix(s, c) {
				s = strings.TrimSuffix(s, c)
				trimmed = true
			}
		}
		if !trimmed {
			return s
		}
	}
}

// maskSecret masks a secret, revealing only a small prefix (runes, so a
// multi-byte character is never split into invalid UTF-8 in the report).
func maskSecret(s string) string {
	runes := []rune(s)
	n := len(runes)
	switch {
	case n < 6:
		// Too short to reveal anything without exposing most of it.
		return strings.Repeat("*", n)
	case n <= 12:
		// Reveal only a 2-char prefix (previously first-4+last-4 exposed up to
		// 8 of a 9-char secret).
		return string(runes[:2]) + strings.Repeat("*", n-2)
	default:
		return string(runes[:4]) + strings.Repeat("*", n-8) + string(runes[n-4:])
	}
}

func isBoringComment(c string) bool {
	boring := []string{
		"[if", "endif", "google", "facebook", "analytics", "gtm",
		"schema.org", "viewport", "doctype",
	}
	lower := strings.ToLower(c)
	for _, b := range boring {
		if strings.Contains(lower, b) {
			return true
		}
	}
	return len(c) > 500 // skip very long minified chunks
}

func allGeneric(secrets []SecretMatch) bool {
	for _, s := range secrets {
		if !strings.HasPrefix(s.Type, "Generic") && !strings.HasPrefix(s.Type, "Hardcoded") {
			return false
		}
	}
	return true
}

// looksLikeSourceMap reports whether a body is a genuine Source Map v3 document
// rather than an HTML soft-404 / app shell returned with status 200.
func looksLikeSourceMap(body string) bool {
	head := body
	if len(head) > 4096 {
		head = head[:4096]
	}
	if strings.Contains(head, "<html") || strings.Contains(head, "<!DOCTYPE") ||
		strings.Contains(head, "<!doctype") {
		return false
	}
	// Require the JSON shape of a source map.
	return strings.Contains(head, "\"version\"") &&
		strings.Contains(head, "\"mappings\"") &&
		(strings.Contains(head, "\"sources\"") || strings.Contains(head, "\"names\""))
}

func resolveURL(base, ref string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ref
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return b.ResolveReference(r).String()
}

// issameDomain checks if a URL belongs to the target domain (including subdomains).
func issameDomain(rawURL, domain string) bool {
	u := strings.TrimPrefix(rawURL, "https://")
	u = strings.TrimPrefix(u, "http://")
	host := strings.SplitN(u, "/", 2)[0]
	host = strings.Split(host, ":")[0]
	return host == domain || strings.HasSuffix(host, "."+domain)
}
