package modules

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/w1r3hound/w1r3hound/internal/core"
)

// ══════════════════════════════════════════════
//  WAYBACK MACHINE  (WSTG-INFO-01)
//  Fetches known URLs from the Internet Archive
//  to find hidden endpoints, old files, params.
// ══════════════════════════════════════════════

type WaybackResult struct {
	URLs       []string `json:"urls"`
	Parameters []string `json:"interesting_params,omitempty"`
	OldPaths   []string `json:"old_paths,omitempty"`
}

func RunWayback(cfg *core.Config, report *core.ReconReport, log *core.Logger) {
	log.Module("ARCHAEOLOGY // Wayback Machine Archive Mining")

	client := core.NewHTTPClient(cfg)
	domain := cfg.Domain

	var allRows [][]string
	resumeKey := ""
	page := 0
	maxPages := 20 // safety limit

	// FIX #4: if the wildcard subdomain query returns zero rows, fall back
	// to a domain-scope query. Targets hosted behind CDNs (Wix, Cloudflare,
	// Azure) often have no historical "www." subdomain in Wayback but DO
	// have apex-domain captures. Without this fallback, the tool reports
	// "Wayback Machine: 0 URLs" even when the CDX API has thousands of
	// snapshots from years ago.
	queryTemplates := []string{
		"https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey&limit=%d",
		"https://web.archive.org/cdx/search/cdx?url=%s/*&matchType=domain&output=json&fl=original&collapse=urlkey&limit=%d",
	}
	queryIdx := 0

	for queryIdx < len(queryTemplates) {
		for page < maxPages {
			apiURL := fmt.Sprintf(queryTemplates[queryIdx], domain, cfg.WaybackLimit)
			if resumeKey != "" {
				apiURL += "&resumeKey=" + url.QueryEscape(resumeKey)
			}
			apiURL += "&showResumeKey=true"

			body, status, err := core.FetchBodyRL(client, apiURL, cfg.UserAgent, cfg.RL)
			if err != nil || status != 200 {
				if page == 0 && queryIdx == 0 {
					log.Error("Wayback API request failed (status %d): %v", status, err)
				}
				break
			}

			var rows [][]string
			if err := json.Unmarshal([]byte(body), &rows); err != nil {
				break
			}

			// Check for resumeKey in last row
			gotMore := false
			if len(rows) > 0 {
				lastRow := rows[len(rows)-1]
				if len(lastRow) == 1 && !strings.Contains(lastRow[0], "://") {
					resumeKey = lastRow[0]
					rows = rows[:len(rows)-1] // remove resumeKey row
					gotMore = true
				}
			}

			allRows = append(allRows, rows...)
			page++

			if !gotMore {
				break
			}
			log.Debug("Wayback page %d (query %d): %d rows (resuming...)", page, queryIdx, len(rows))
		}

		// FIX #4: if the first query template returned nothing and we have
		// more templates to try, switch to the next one before giving up.
		if len(allRows) == 0 && queryIdx+1 < len(queryTemplates) {
			log.Info("Wayback subdomain query returned 0 results, falling back to matchType=domain")
			resumeKey = ""
			page = 0
			queryIdx++
			continue
		}
		break
	}

	rows := allRows

	result := WaybackResult{}
	seen := make(map[string]bool)
	paramSeen := make(map[string]bool)

	interestingExts := []string{
		".php", ".asp", ".aspx", ".jsp", ".json", ".xml", ".yml", ".yaml",
		".env", ".config", ".conf", ".cfg", ".ini", ".sql", ".bak", ".backup",
		".old", ".orig", ".log", ".txt", ".csv", ".xls", ".xlsx", ".doc",
		".docx", ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z", ".swp",
		".git", ".svn", ".htaccess", ".htpasswd", ".DS_Store",
	}

	for i, row := range rows {
		if i == 0 || len(row) == 0 { // skip header
			continue
		}
		url := row[0]
		if seen[url] {
			continue
		}
		seen[url] = true
		result.URLs = append(result.URLs, url)

		// Extract interesting parameters
		if idx := strings.Index(url, "?"); idx != -1 {
			params := url[idx+1:]
			for _, p := range strings.Split(params, "&") {
				kv := strings.SplitN(p, "=", 2)
				if len(kv) > 0 && !paramSeen[kv[0]] {
					paramSeen[kv[0]] = true
					result.Parameters = append(result.Parameters, kv[0])
				}
			}
		}

		// Flag interesting old paths
		lower := strings.ToLower(url)
		for _, ext := range interestingExts {
			if strings.HasSuffix(lower, ext) || strings.Contains(lower, ext+"?") {
				result.OldPaths = append(result.OldPaths, url)
				break
			}
		}
	}

	log.Info("Wayback URLs: %d total, %d with interesting extensions", len(result.URLs), len(result.OldPaths))
	if len(result.Parameters) > 0 {
		log.Info("Parameters discovered: %d unique", len(result.Parameters))
	}

	// Feed discovered subdomains and URLs into shared context (data feedback).
	// Wayback URLs often reference subdomains not in DNS or CT logs.
	waybackSubs := make(map[string]bool)
	for _, u := range result.URLs {
		host := u
		host = strings.TrimPrefix(host, "https://")
		host = strings.TrimPrefix(host, "http://")
		host = strings.SplitN(host, "/", 2)[0]
		host = strings.SplitN(host, ":", 2)[0]
		if strings.HasSuffix(host, "."+domain) || host == domain {
			waybackSubs[host] = true
		}
	}
	var subList []string
	for s := range waybackSubs {
		subList = append(subList, s)
	}
	if len(subList) > 0 {
		cfg.AddSharedSubdomains(subList)
		log.Debug("Fed %d subdomains from Wayback into shared context", len(subList))
	}
	cfg.AddSharedURLs(result.URLs)

	sev := core.SevInfo
	if len(result.OldPaths) > 10 {
		sev = core.SevLow
	}

	report.Add(core.Finding{
		Module:      "wayback",
		WSTG:        "WSTG-INFO-01",
		Title:       fmt.Sprintf("Wayback Machine: %d URLs, %d params, %d interesting paths", len(result.URLs), len(result.Parameters), len(result.OldPaths)),
		Severity:    sev,
		Description: "Historical URLs may expose forgotten endpoints, backup files, and parameters.",
		Data:        result,
	})
}

// ══════════════════════════════════════════════
//  CORS MISCONFIGURATION CHECK
//  Tests for overly permissive CORS origins.
// ══════════════════════════════════════════════

type CORSResult struct {
	Vulnerable bool             `json:"vulnerable"`
	Tests      []CORSTestResult `json:"tests"`
}

type CORSTestResult struct {
	Origin string `json:"origin_sent"`
	ACAO   string `json:"access_control_allow_origin"`
	ACAC   string `json:"access_control_allow_credentials"`
	Issue  string `json:"issue,omitempty"`
}

func RunCORS(cfg *core.Config, report *core.ReconReport, log *core.Logger) {
	log.Module("CORSTRACE // Cross-Origin Policy Scan")

	if cfg.Passive {
		log.Info("Skipping CORS check in passive mode")
		return
	}

	client := core.NewHTTPClient(cfg)
	target := normalizeTarget(cfg.Target)
	result := CORSResult{}

	origins := []struct {
		Origin string
		Desc   string
	}{
		{"https://evil.com", "arbitrary origin"},
		{target, "self-origin (baseline)"},
		{"null", "null origin"},
		{"https://" + cfg.Domain + ".evil.com", "subdomain prefix attack"},
		{"https://evil" + cfg.Domain, "suffix match bypass"},
		{"https://sub." + cfg.Domain, "subdomain"},
	}

	for _, o := range origins {
		req, err := http.NewRequest("GET", target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Origin", o.Origin)
		req.Header.Set("User-Agent", cfg.UserAgent)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")

		tr := CORSTestResult{
			Origin: o.Origin,
			ACAO:   acao,
			ACAC:   acac,
		}

		if acao == "*" && acac == "true" {
			tr.Issue = "Wildcard with credentials — critical misconfiguration"
			result.Vulnerable = true
		} else if acao == "null" && o.Origin == "null" {
			tr.Issue = "Accepts null origin"
			result.Vulnerable = true
		} else if acao != "" && acao == o.Origin && o.Origin != target {
			// The server reflected an untrusted origin
			if acac == "true" {
				tr.Issue = fmt.Sprintf("Reflects untrusted origin with credentials (%s)", o.Desc)
				result.Vulnerable = true
			} else {
				tr.Issue = fmt.Sprintf("Reflects untrusted origin without credentials (%s)", o.Desc)
			}
		}

		result.Tests = append(result.Tests, tr)
		if tr.Issue != "" {
			log.Warn("CORS: Origin=%s → ACAO=%s, ACAC=%s — %s", o.Origin, acao, acac, tr.Issue)
		}
	}

	if result.Vulnerable {
		report.Add(core.Finding{
			Module:      "cors",
			WSTG:        "WSTG-CLNT-07",
			Title:       "CORS misconfiguration detected",
			Severity:    core.SevHigh,
			Description: "The application reflects untrusted origins, potentially allowing cross-origin data theft.",
			Data:        result,
		})
	} else {
		log.Info("No CORS misconfiguration detected")
	}
}

// ══════════════════════════════════════════════
//  CLOUD STORAGE DETECTION  (WSTG-CONF-11)
//  Probes for open S3 buckets, Azure blobs, GCS.
// ══════════════════════════════════════════════

type CloudResult struct {
	Buckets []CloudBucket `json:"buckets"`
}

type CloudBucket struct {
	Provider string `json:"provider"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Public   bool   `json:"public"`
	Status   int    `json:"status_code"`
	// Generic marks buckets whose name is so generic (e.g. "www", "images",
	// "static", "cdn", "www-staging") that the status-200 heuristic cannot
	// distinguish a target-owned bucket from a publicly-listed generic bucket
	// owned by another party (e.g. storage.googleapis.com/www-staging is owned
	// by Google project 868530998679, not by the scan target). These buckets
	// are still reported for awareness but are excluded from the HIGH-severity
	// "Public cloud storage buckets found" finding.
	Generic bool `json:"generic,omitempty"`
}

// genericBucketNames is the set of bucket names that are so common that a
// 200 response from a public cloud provider almost certainly belongs to a
// third party, not the scan target. If a target's buckets fall in this set,
// they must be validated via body content (owner/project) before being
// reported as a HIGH-severity finding.
var genericBucketNames = map[string]bool{
	"www": true, "www-staging": true, "www-test": true, "www-dev": true,
	"www-cdn": true, "www-web": true, "www-assets": true, "www-images": true,
	"www-public": true, "www-prod": true, "www-static": true, "www-media": true,
	"www-uploads": true, "www-files": true, "www-data": true, "www-backup": true,
	"www-app": true, "www-api": true, "www-db": true, "www-docs": true,
	"images": true, "static": true, "cdn": true, "media": true, "uploads": true,
	"assets": true, "files": true, "public": true, "data": true, "backup": true,
	"web": true, "api": true, "app": true, "docs": true, "console": true,
	"staging": true, "test": true, "dev": true, "prod": true,
}

// publicBucketLooksUnrelated checks the body of a public (listable) bucket
// for signs that it belongs to the scan target. We extract a sample of object
// keys from the XML listing; if none of them reference the target domain or
// apex organisation, the bucket is almost certainly owned by an unrelated
// party (e.g. "claude" as a common first name, not Anthropic's "claude.ai").
func publicBucketLooksUnrelated(body, domain, baseName string) bool {
	if len(body) == 0 {
		return false
	}
	lower := strings.ToLower(body)
	if !strings.Contains(lower, "<key>") {
		return false
	}
	keys := extractXMLKeys(lower)
	if len(keys) == 0 {
		return false
	}
	apex := strings.ToLower(extractApexDomain(domain))
	apexOrg := strings.Split(apex, ".")[0]
	refs := []string{strings.ToLower(domain), apex}
	if apexOrg != strings.ToLower(baseName) {
		refs = append(refs, apexOrg)
	}
	for _, key := range keys {
		for _, ref := range refs {
			if strings.Contains(key, ref) {
				return false
			}
		}
	}
	return true
}

func extractXMLKeys(lower string) []string {
	var keys []string
	s := lower
	for i := 0; i < 20; i++ {
		start := strings.Index(s, "<key>")
		if start < 0 {
			break
		}
		s = s[start+5:]
		end := strings.Index(s, "</key>")
		if end < 0 {
			break
		}
		keys = append(keys, s[:end])
		s = s[end+6:]
	}
	return keys
}

func looksGenericBucketName(name string) bool {
	if genericBucketNames[name] {
		return true
	}
	// If the stem (before the first "-") is itself generic, the whole
	// permutation is generic too: "docs-dev", "api-staging", "data-backup"
	// are just as unrelated to the target as the bare "docs"/"api"/"data".
	if i := strings.Index(name, "-"); i > 0 {
		return genericBucketNames[name[:i]]
	}
	return false
}

func RunCloudStorage(cfg *core.Config, report *core.ReconReport, log *core.Logger) {
	log.Module("CLOUDSNIFF // Cloud Storage Enumeration")

	client := core.NewHTTPClient(cfg)
	domain := cfg.Domain
	baseName := strings.Split(domain, ".")[0]

	result := CloudResult{}

	// Generate bucket name permutations
	names := []string{
		baseName, domain, baseName + "-dev", baseName + "-staging",
		baseName + "-prod", baseName + "-backup", baseName + "-assets",
		baseName + "-static", baseName + "-media", baseName + "-uploads",
		baseName + "-public", baseName + "-private", baseName + "-data",
		baseName + "-logs", baseName + "-internal", baseName + "-test",
		baseName + "-cdn", baseName + "-web", baseName + "-api",
		baseName + "-app", baseName + "-db", baseName + "-files",
		baseName + "-images", baseName + "-docs", baseName + "-config",
	}

	// Cloud providers to check
	type cloudCheck struct {
		provider string
		template string // %s will be replaced by bucket name
	}

	checks := []cloudCheck{
		{"AWS S3", "https://%s.s3.amazonaws.com"},
		{"AWS S3 (path)", "https://s3.amazonaws.com/%s"},
		// Azure root returns 400 (InvalidUri); the ?comp=list endpoint is correct.
		{"Azure Blob", "https://%s.blob.core.windows.net/?comp=list"},
		{"GCS", "https://storage.googleapis.com/%s"},
		{"GCS (vhost)", "https://%s.storage.googleapis.com"},
		{"DigitalOcean", "https://%s.nyc3.digitaloceanspaces.com"},
		{"DigitalOcean SFO", "https://%s.sfo3.digitaloceanspaces.com"},
		{"Firebase RTDB", "https://%s.firebaseio.com/.json"},
		{"Firebase (default)", "https://%s-default-rtdb.firebaseio.com/.json"},
	}

	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, cfg.Concurrency)
	)

	for _, name := range names {
		for _, chk := range checks {
			wg.Add(1)
			sem <- struct{}{}
			go func(n string, c cloudCheck) {
				defer core.RecoverWorker(log, "cloud")
				defer wg.Done()
				defer func() { <-sem }()

				url := fmt.Sprintf(c.template, n)
				body, status, err := core.FetchBodyRL(client, url, cfg.UserAgent, cfg.RL)
				if err != nil {
					return
				}

				// Classify: distinguish "exists+public" vs "exists+private" vs "not found"
				public := false
				exists := false
				switch {
				case status == 200:
					// Verify it's not an error body (Azure/Firebase return 200 with error XML/JSON)
					lb := strings.ToLower(body)
					if strings.Contains(lb, "authenticationfailed") ||
						strings.Contains(lb, "resourcenotfound") ||
						strings.Contains(lb, "permission_denied") ||
						strings.Contains(lb, "\"error\"") && strings.Contains(lb, "firebase") {
						exists = true // exists but locked
					} else if strings.Contains(lb, "publicaccessnotpermitted") {
						exists = true
					} else {
						public = true
						exists = true
					}
				case status == 403:
					exists = true // AccessDenied — bucket exists
				case status == 401:
					exists = true
				}

				if exists {
					lb := strings.ToLower(body)
					if strings.Contains(lb, "nosuchbucket") {
						return // doesn't actually exist
					}
					generic := public && looksGenericBucketName(n)
					if public && !generic {
						generic = publicBucketLooksUnrelated(body, domain, baseName)
					}
					bucket := CloudBucket{
						Provider: c.provider,
						Name:     n,
						URL:      url,
						Public:   public,
						Status:   status,
						Generic:  generic,
					}
					mu.Lock()
					result.Buckets = append(result.Buckets, bucket)
					mu.Unlock()

					if public {
						if bucket.Generic {
							log.Info("Public bucket (content unrelated to target): %s (%s)", url, c.provider)
						} else {
							log.Warn("PUBLIC bucket: %s (%s)", url, c.provider)
						}
					} else {
						log.Info("Bucket exists (%d): %s (%s)", status, url, c.provider)
					}
				}
			}(name, chk)
		}
	}
	wg.Wait()

	publicCount := 0
	for _, b := range result.Buckets {
		if b.Public && !b.Generic {
			publicCount++
		}
	}

	if publicCount > 0 {
		report.Add(core.Finding{
			Module:      "cloud",
			WSTG:        "WSTG-CONF-11",
			Title:       fmt.Sprintf("Public cloud storage buckets found: %d", publicCount),
			Severity:    core.SevHigh,
			Description: "Publicly accessible cloud storage may expose sensitive data.",
			Data:        result,
		})
	}

	if len(result.Buckets) > 0 {
		log.Info("Total buckets found: %d (%d public)", len(result.Buckets), publicCount)
		report.Add(core.Finding{
			Module:   "cloud",
			WSTG:     "WSTG-CONF-11",
			Title:    fmt.Sprintf("Cloud storage scan: %d buckets found", len(result.Buckets)),
			Severity: core.SevInfo,
			Data:     result,
		})
	} else {
		log.Info("No cloud storage buckets found")
	}
}

// ══════════════════════════════════════════════
//  DIRECTORY / FILE DISCOVERY (WSTG-CONF-03/04)
//  Brute-force common paths, backup files,
//  admin interfaces.
// ══════════════════════════════════════════════

type DirBruteResult struct {
	Found []DirEntry `json:"found"`
}

type DirEntry struct {
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
	Size       int64  `json:"size"`
	Redirect   string `json:"redirect,omitempty"`

	// bodyHash is the FNV hash of the response body with the requested path
	// stripped out. It lets the post-scan cluster filter tell a genuine file
	// (different body) from the catch-all shell (identical body) even when the
	// sizes match. Unexported → never serialised into the JSON report.
	bodyHash uint32
}

// stripPathHash hashes a body after removing the requested path from it, so
// pages that merely echo the path back still hash identically to the shell.
// Only the full requested path is stripped. We deliberately do NOT also strip
// path[1:] (the path without its leading "/"): for a short/generic path like
// /api or /v1 that ReplaceAll would delete every occurrence of that word
// anywhere in the body, hashing unrelated real pages identically to the shell
// and silently filtering them as soft-404s (false negatives).
func stripPathHash(body, path string) uint32 {
	stripped := strings.ReplaceAll(body, path, "")
	return simpleHash([]byte(stripped))
}

// Embedded wordlist for common paths — admin panels, backup files, configs
var defaultDirPaths = []string{
	// Admin interfaces (WSTG-CONF-05)
	"/admin", "/admin/", "/administrator", "/administrator/",
	"/wp-admin", "/wp-admin/", "/wp-login.php",
	"/phpmyadmin", "/phpmyadmin/", "/pma", "/pma/",
	"/adminer.php", "/adminer",
	"/cpanel", "/webmail", "/whm",
	"/manager/html", "/manager/", "/admin/config",
	"/console", "/console/", "/dashboard", "/dashboard/",
	"/panel", "/panel/", "/control", "/controlpanel",
	"/_admin", "/__admin", "/admin.php", "/login", "/login/",
	"/signin", "/auth", "/auth/login",

	// Configuration files (WSTG-CONF-03)
	"/.env", "/.env.local", "/.env.production", "/.env.staging",
	"/.env.development", "/.env.backup", "/.env.old",
	"/config.php", "/config.yml", "/config.yaml", "/config.json",
	"/configuration.php", "/settings.php", "/settings.py",
	"/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
	"/web.config", "/Web.config", "/appsettings.json",
	"/application.yml", "/application.properties",
	"/database.yml", "/db.conf",

	// Backup files (WSTG-CONF-04)
	"/backup", "/backup/", "/backups", "/backups/",
	"/backup.sql", "/backup.zip", "/backup.tar.gz",
	"/db.sql", "/database.sql", "/dump.sql",
	"/site.zip", "/www.zip", "/public.zip",
	"/backup.sql.gz", "/data.sql",

	// Version control (information leakage)
	"/.git/config", "/.git/HEAD", "/.git/index",
	"/.svn/entries", "/.svn/wc.db",
	"/.hg/store", "/.bzr/branch-format",
	"/CVS/Root", "/CVS/Entries",

	// Info/debug files
	"/info.php", "/phpinfo.php", "/test.php", "/debug.php",
	"/server-status", "/server-info",
	"/.htaccess", "/.htpasswd",
	"/elmah.axd", "/trace.axd",
	"/web-console", "/jmx-console",

	// API documentation
	"/swagger", "/swagger/", "/swagger-ui.html", "/swagger-ui/",
	"/api-docs", "/api/docs", "/api/swagger.json",
	"/api/v1", "/api/v2", "/api/v3",
	"/graphql", "/graphiql", "/altair",
	"/openapi.json", "/openapi.yaml",
	"/redoc", "/api-explorer",

	// CI/CD & deployment artifacts
	"/Dockerfile", "/docker-compose.yml",
	"/Jenkinsfile", "/.travis.yml", "/.circleci/config.yml",
	"/Makefile", "/Rakefile", "/Gemfile",
	"/package.json", "/composer.json", "/requirements.txt",
	"/Pipfile", "/go.mod", "/Cargo.toml",

	// CMS-specific
	"/wp-includes/", "/wp-content/",
	"/wp-content/debug.log", "/wp-json/wp/v2/users",
	"/xmlrpc.php", "/readme.html",
	"/sites/default/files/", "/misc/drupal.js",
	"/user/login", "/node",
	"/administrator/manifests/files/joomla.xml",

	// Common framework paths
	"/debug/vars", "/debug/pprof",
	"/metrics", "/health", "/healthz", "/ready", "/readyz",
	"/actuator", "/actuator/health", "/actuator/env",
	"/actuator/beans", "/actuator/mappings",
	"/__debug__", "/_debug_toolbar",

	// DS_Store, IDE files
	"/.DS_Store", "/Thumbs.db",
	"/.idea/workspace.xml", "/.vscode/settings.json",

	// Error pages / info
	"/404", "/500",
	"/error", "/errors/", "/error_log",
	"/cgi-bin/", "/cgi-bin/test",
}

// loadDirPaths returns the wordlist to use for directory bruteforce: the
// operator's -dir-wordlist when set and readable, otherwise the embedded
// defaultDirPaths. Reuses core.ReadLines — same one-entry-per-line format as
// the subdomain wordlist, just normalised into leading-slash paths here
// instead of FQDNs.
func loadDirPaths(cfg *core.Config, log *core.Logger) []string {
	if cfg.DirWordlist == "" {
		return defaultDirPaths
	}
	words := core.ReadLines(cfg.DirWordlist)
	if len(words) == 0 {
		log.Warn("Could not read -dir-wordlist %q (or it's empty) — falling back to the embedded path list", cfg.DirWordlist)
		return defaultDirPaths
	}
	paths := make([]string, 0, len(words))
	for _, w := range words {
		if p := normalizeDirPath(w); p != "" {
			paths = append(paths, p)
		}
	}
	return paths
}

// normalizeDirPath ensures a wordlist entry becomes a proper request path.
// Most public wordlists (SecLists, raft-*, etc.) list bare words like "admin"
// or "backup.zip" with no leading slash; ours (and the target URL join) expect
// one.
func normalizeDirPath(entry string) string {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return ""
	}
	if !strings.HasPrefix(entry, "/") {
		entry = "/" + entry
	}
	return entry
}

// expandDirExtensions appends each extension to every non-directory path
// (paths ending in "/" are left alone — appending ".bak" to "/backup/" isn't
// meaningful), in addition to keeping the original path. Mirrors ffuf/
// feroxbuster's -e behaviour.
func expandDirExtensions(paths []string, extList string) []string {
	var exts []string
	for _, e := range strings.Split(extList, ",") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if e != "~" && !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		exts = append(exts, e)
	}
	if len(exts) == 0 {
		return paths
	}

	seen := make(map[string]bool, len(paths)*(len(exts)+1))
	out := make([]string, 0, len(paths)*(len(exts)+1))
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, p := range paths {
		add(p)
		if strings.HasSuffix(p, "/") {
			continue
		}
		for _, e := range exts {
			add(p + e)
		}
	}
	return out
}

func RunDirBrute(cfg *core.Config, report *core.ReconReport, log *core.Logger) {
	log.Module("BRUTEFORCE // Hidden Path & File Discovery")

	if cfg.Passive {
		log.Info("Skipping dir brute in passive mode")
		return
	}

	client := core.NewHTTPClient(cfg)
	target := normalizeTarget(cfg.Target)
	paths := loadDirPaths(cfg, log)
	if cfg.DirExtensions != "" {
		before := len(paths)
		paths = expandDirExtensions(paths, cfg.DirExtensions)
		log.Info("Extension fuzzing (%s): %d → %d paths", cfg.DirExtensions, before, len(paths))
	}

	// ── Soft-404 baseline detection ──
	// Request a path that certainly doesn't exist and record the response
	// signature (status, body length, title) to filter false positives.
	log.Info("Calibrating soft-404 baseline...")
	baseline404 := detectSoft404Baseline(client, target, cfg.UserAgent, cfg.RL)
	if baseline404.status == 200 {
		log.Warn("Soft-404 detected: server returns 200 for non-existent pages (body size ~%d)", baseline404.bodyLen)
	}

	result := DirBruteResult{}
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, cfg.Concurrency)
	)

	log.Info("Probing %d paths...", len(paths))

	for _, path := range paths {
		wg.Add(1)
		sem <- struct{}{}
		go func(p string) {
			defer core.RecoverWorker(log, "dirbrute")
			defer wg.Done()
			defer func() { <-sem }()

			url := target + p
			resp, err := core.DoRequestRL(client, "GET", url, cfg.UserAgent, cfg.RL)
			if err != nil {
				return
			}

			// Read body for soft-404 comparison
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
			resp.Body.Close()
			bodyLen := len(bodyBytes)
			bodyStr := string(bodyBytes)

			// Skip if this looks like the soft-404 baseline
			if resp.StatusCode == 200 && baseline404.status == 200 {
				if isSoft404(baseline404, bodyLen, bodyStr, p) {
					return // soft 404, skip
				}
			}

			// Interesting: 200 (real), 301/302 (redirect), 403 (forbidden)
			if resp.StatusCode == 200 || resp.StatusCode == 403 ||
				resp.StatusCode == 301 || resp.StatusCode == 302 {

				entry := DirEntry{
					Path:       p,
					StatusCode: resp.StatusCode,
					Size:       int64(bodyLen),
				}
				if resp.StatusCode == 200 {
					entry.bodyHash = stripPathHash(bodyStr, p)
				}
				if resp.StatusCode == 301 || resp.StatusCode == 302 {
					entry.Redirect = resp.Header.Get("Location")
				}

				mu.Lock()
				result.Found = append(result.Found, entry)
				mu.Unlock()

				// The status label is plain text: the logger sanitises string
				// arguments (control-byte stripping for untrusted data such as the
				// redirect target), so embedding raw ANSI here would be rendered
				// literally. Colour is applied by the logger's own format string.
				var label string
				if resp.StatusCode == 301 || resp.StatusCode == 302 {
					label = fmt.Sprintf("%d → %s", resp.StatusCode, entry.Redirect)
				} else {
					label = fmt.Sprintf("%d", resp.StatusCode)
				}
				log.Info("  [%s] %s (%d bytes)", label, p, bodyLen)
			}
		}(path)
	}
	wg.Wait()

	// ── Post-scan cluster analysis ──
	// If a large fraction of 200 responses cluster in the same size range,
	// they're all soft-404s (the same "not found" page with the path embedded).
	// This catches cases where per-request strategies fail due to dynamic content.
	beforeCluster := len(result.Found)
	result.Found = clusterFilterSoft404s(result.Found, baseline404, log)
	// A WAF/CDN edge often returns the SAME fixed 403 block page for every path.
	// That is one blanket block, not N sensitive-path findings — drop the uniform
	// 403 cluster (keeping outlier sizes, which may be real access-denied pages).
	result.Found = filterCatchAll403s(result.Found, log)
	if diff := beforeCluster - len(result.Found); diff > 0 {
		log.Info("Cluster analysis removed %d additional soft-404/403 responses", diff)
	}

	// Categorize findings
	var critical, high []string
	for _, e := range result.Found {
		if e.StatusCode == 200 {
			lower := strings.ToLower(e.Path)
			if strings.Contains(lower, ".env") || strings.Contains(lower, ".git") ||
				strings.Contains(lower, "config") && (strings.HasSuffix(lower, ".php") ||
					strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".json")) {
				critical = append(critical, e.Path)
			} else if strings.Contains(lower, "admin") || strings.Contains(lower, "backup") ||
				strings.Contains(lower, "phpinfo") || strings.Contains(lower, "swagger") ||
				strings.Contains(lower, "actuator") || strings.Contains(lower, "debug") {
				high = append(high, e.Path)
			}
		}
	}

	if len(critical) > 0 {
		report.Add(core.Finding{
			Module:      "dirbrute",
			WSTG:        "WSTG-CONF-04",
			Title:       fmt.Sprintf("Critical files exposed: %d", len(critical)),
			Severity:    core.SevCritical,
			Description: "Configuration or version control files accessible: " + strings.Join(critical, ", "),
			Data:        critical,
		})
	}
	if len(high) > 0 {
		report.Add(core.Finding{
			Module:      "dirbrute",
			WSTG:        "WSTG-CONF-05",
			Title:       fmt.Sprintf("Sensitive paths accessible: %d", len(high)),
			Severity:    core.SevMedium,
			Description: strings.Join(high, ", "),
			Data:        high,
		})
	}

	log.Info("Total paths found: %d (after soft-404 filtering)", len(result.Found))
	report.Add(core.Finding{
		Module:   "dirbrute",
		WSTG:     "WSTG-CONF-03",
		Title:    fmt.Sprintf("Directory discovery: %d paths found", len(result.Found)),
		Severity: core.SevInfo,
		Data:     result,
	})
}

// ── Soft-404 detection ──
// Strategy: multiple baselines with different path lengths, title matching,
// body similarity after stripping dynamic content, and "not found" keyword
// detection in 200-status responses.

type soft404Baseline struct {
	status    int
	bodyLen   int
	titleTag  string // <title> content
	bodyHash  uint32 // hash after stripping the path from the body
	bodyLines int    // line count as secondary size metric
}

func detectSoft404Baseline(client *http.Client, target, ua string, rl *core.RateLimiter) soft404Baseline {
	// Use paths of DIFFERENT lengths to detect path-length-dependent body sizes
	randomPaths := []string{
		"/W1r3hound-chk",            // short
		"/W1r3hound-calibrate-xk9m", // medium
		"/W1r3hound-this-route-does-not-exist-calibration-z4w8", // long
	}

	var baselines []soft404Baseline
	for _, p := range randomPaths {
		resp, err := core.DoRequestRL(client, "GET", target+p, ua, rl)
		if err != nil {
			continue
		}
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()

		// Strip the path name from the body before hashing —
		// this way pages that embed the requested path still match.
		// Only the full path is stripped: stripping path[1:] (no leading "/")
		// would delete every occurrence of a generic word (e.g. "api" for /api)
		// from the whole body, making unrelated pages hash like the shell.
		stripped := strings.ReplaceAll(string(bodyBytes), p, "")

		b := soft404Baseline{
			status:    resp.StatusCode,
			bodyLen:   len(bodyBytes),
			bodyHash:  simpleHash([]byte(stripped)),
			bodyLines: strings.Count(string(bodyBytes), "\n"),
		}

		if m := dirTitlePattern.FindSubmatch(bodyBytes); len(m) > 1 {
			b.titleTag = strings.TrimSpace(string(m[1]))
		}
		baselines = append(baselines, b)
	}

	if len(baselines) == 0 {
		return soft404Baseline{status: 404}
	}

	// Verify baselines are consistent (all same title = confirmed soft-404 pattern)
	if len(baselines) >= 2 && baselines[0].titleTag != "" &&
		baselines[0].titleTag == baselines[1].titleTag {
		// Title is stable across different paths — strong soft-404 signal
	}

	return baselines[0]
}

var dirTitlePattern = regexp.MustCompile(`(?is)<title>(.*?)</title>`)

// "Not found" keywords in body — catches custom error pages returning 200
var notFoundKeywords = []string{
	"page not found",
	"not found",
	"404",
	"doesn't exist",
	"does not exist",
	"no longer available",
	"couldn't find",
	"could not find",
	"nothing here",
	"the page you",
	"requested page",
	"pagina no encontrada",
	"seite nicht gefunden",
}

func isSoft404(baseline soft404Baseline, bodyLen int, body, path string) bool {
	// ── Pre-check: raw files are never soft-404s ──
	// If the response has no HTML structure at all, it's likely a raw file
	// (.env, .git/HEAD, config files) — never treat as soft-404.
	if !strings.Contains(body, "<html") && !strings.Contains(body, "<HTML") &&
		!strings.Contains(body, "<!DOCTYPE") && !strings.Contains(body, "<!doctype") {
		return false
	}

	// ── Strategy 1: Title comparison (most reliable) ──
	// If the title matches the baseline 404 page, it's a soft-404
	// regardless of body size differences.
	if baseline.titleTag != "" {
		if m := dirTitlePattern.FindStringSubmatch(body); len(m) > 1 {
			pageTitle := strings.TrimSpace(m[1])
			if pageTitle == baseline.titleTag {
				return true
			}
		}
	}

	// ── Strategy 2: Body similarity after stripping the path ──
	// Strip the requested path from both bodies, then compare hashes.
	// This handles pages that embed the path in the response. Only the full
	// path is stripped (see stripPathHash for why not stripping path[1:]).
	stripped := strings.ReplaceAll(body, path, "")
	if simpleHash([]byte(stripped)) == baseline.bodyHash {
		return true
	}

	// ── Strategy 3: Size-based comparison (wider tolerance) ──
	// Use ±40% tolerance since path embedding causes variable sizes.
	// BUT: only if the page title is either absent, empty, or matches the baseline.
	// A genuinely different title means a different page, even if similarly sized.
	lenDiff := abs(bodyLen - baseline.bodyLen)
	threshold := baseline.bodyLen * 4 / 10 // 40%
	if threshold < 100 {
		threshold = 100
	}
	if lenDiff <= threshold {
		bodyLines := strings.Count(body, "\n")
		lineDiff := abs(bodyLines - baseline.bodyLines)
		if lineDiff <= baseline.bodyLines/4+5 {
			// Check that the title isn't distinctly different
			pageTitle := ""
			if m := dirTitlePattern.FindStringSubmatch(body); len(m) > 1 {
				pageTitle = strings.TrimSpace(m[1])
			}
			// If no title extracted, or title matches baseline, or title is
			// very generic → treat as soft-404
			if pageTitle == "" || pageTitle == baseline.titleTag ||
				isGenericTitle(pageTitle) {
				return true
			}
		}
	}

	// ── Strategy 4: "Not found" keyword detection in 200-status responses ──
	// Some sites return 200 with "page not found" text.
	lowerBody := strings.ToLower(body)
	for _, kw := range notFoundKeywords {
		if strings.Contains(lowerBody, kw) {
			// Verify it's in a meaningful context (title, heading, or prominent text)
			// not just a random mention in navigation or footer
			lowerTitle := ""
			if m := dirTitlePattern.FindStringSubmatch(body); len(m) > 1 {
				lowerTitle = strings.ToLower(m[1])
			}
			if strings.Contains(lowerTitle, kw) {
				return true
			}
			// Check in <h1> tags
			if h1Match := h1Pattern.FindStringSubmatch(body); len(h1Match) > 1 {
				if strings.Contains(strings.ToLower(h1Match[1]), kw) {
					return true
				}
			}
		}
	}

	return false
}

var h1Pattern = regexp.MustCompile(`(?is)<h1[^>]*>(.*?)</h1>`)

// isGenericTitle returns true for titles that don't indicate unique page content.
func isGenericTitle(title string) bool {
	lower := strings.ToLower(title)
	generic := []string{
		"not found", "404", "error", "page not found",
		"welcome", "home", "index", "default",
		"untitled", "document", "loading",
	}
	for _, g := range generic {
		if strings.Contains(lower, g) || lower == g {
			return true
		}
	}
	// Very short titles are often generic
	return len(title) <= 3
}

func simpleHash(data []byte) uint32 {
	var h uint32 = 2166136261
	for _, b := range data {
		h ^= uint32(b)
		h *= 16777619
	}
	return h
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// filterCatchAll403s removes the "everything is 403" noise produced by a WAF or
// CDN edge that serves the same fixed block page for every path. When a large
// group of 403 responses share one body size they are a single blanket block,
// not N individual findings, so they are dropped — keeping only 403s whose size
// is an outlier (a path-specific access-denied page that may be genuine). This
// mirrors clusterFilterSoft404s but for 403 (e.g. bugcrowd/Fastly returning a
// uniform 149-byte 403 for /.env, /.git/config, /wp-config.php, …).
func filterCatchAll403s(entries []DirEntry, log *core.Logger) []DirEntry {
	var forbidden, rest []DirEntry
	for _, e := range entries {
		if e.StatusCode == 403 {
			forbidden = append(forbidden, e)
		} else {
			rest = append(rest, e)
		}
	}
	if len(forbidden) < 5 {
		return entries // too few to be a systematic block
	}

	sizes := make([]int, len(forbidden))
	for i, e := range forbidden {
		sizes[i] = int(e.Size)
	}
	sort.Ints(sizes)
	median := sizes[len(sizes)/2]
	tolerance := median * 15 / 100
	if tolerance < 64 {
		tolerance = 64
	}
	inCluster := 0
	for _, s := range sizes {
		if abs(s-median) <= tolerance {
			inCluster++
		}
	}
	if float64(inCluster)/float64(len(forbidden)) < 0.70 {
		return entries // no dominant 403 size → the 403s may be meaningful, keep
	}

	log.Warn("Uniform 403 block detected (%d paths at ~%d bytes) — likely WAF/CDN edge, filtering as catch-all", inCluster, median)
	kept := rest
	for _, e := range forbidden {
		if abs(int(e.Size)-median) > tolerance {
			kept = append(kept, e) // outlier size → likely path-specific, keep
		}
	}
	return kept
}

// clusterFilterSoft404s performs post-scan cluster analysis.
// If a large majority of 200-responses have similar body sizes, they are all
// soft-404s — the server returns its "not found" page for every unknown path,
// with minor size variations from embedding the path name.
//
// Algorithm:
//  1. Collect all 200-status results
//  2. Find the dominant size cluster (±20% of median)
//  3. If the cluster contains ≥60% of results AND the baseline also falls in
//     this range, remove all cluster members
//  4. Keep 403s, 301/302s, and 200s that are significantly different from the cluster
//
// clusterFilterSoft404s performs post-scan cluster analysis to catch
// SPA/catch-all servers. A server that returns the same app shell for most
// paths produces a dominant size cluster among the 200 responses. When ≥70%
// of 200s cluster within ±15% of the median, they are the catch-all page —
// regardless of what the calibration baseline returned. This handles SPAs
// (like HackerOne) where random paths return a real 404 but dictionary words
// return 200 + the app shell.
func clusterFilterSoft404s(entries []DirEntry, baseline soft404Baseline, log *core.Logger) []DirEntry {
	// Separate by status code
	var status200 []DirEntry
	var others []DirEntry
	for _, e := range entries {
		if e.StatusCode == 200 {
			status200 = append(status200, e)
		} else {
			others = append(others, e)
		}
	}

	if len(status200) < 8 {
		// Too few to cluster reliably; keep as-is
		return entries
	}

	// Find median size
	sizes := make([]int, len(status200))
	for i, e := range status200 {
		sizes[i] = int(e.Size)
	}
	sort.Ints(sizes)
	median := sizes[len(sizes)/2]

	// Count how many fall within ±15% of median (tighter than before)
	tolerance := median * 15 / 100
	if tolerance < 150 {
		tolerance = 150
	}
	clusterCount := 0
	for _, s := range sizes {
		if abs(s-median) <= tolerance {
			clusterCount++
		}
	}
	clusterRatio := float64(clusterCount) / float64(len(status200))

	// A dominant cluster (≥70%) IS the catch-all signal on its own.
	// We no longer require the calibration baseline to be 200 — SPAs return
	// 404 for random paths but 200+shell for dictionary words, so the baseline
	// check produced false negatives.
	baselineInCluster := baseline.status == 200 && abs(baseline.bodyLen-median) <= tolerance
	dominant := clusterRatio >= 0.70

	if !dominant && !(clusterRatio >= 0.60 && baselineInCluster) {
		// No dominant cluster and baseline doesn't confirm — keep results
		return entries
	}

	reason := "dominant cluster"
	if baselineInCluster {
		reason = "cluster + baseline match"
	}
	log.Warn("Catch-all/soft-404 cluster detected (%s): %d/%d responses (%.0f%%) at ~%d±%d bytes",
		reason, clusterCount, len(status200), clusterRatio*100, median, tolerance)

	// Identify the shell's body fingerprint: the modal bodyHash among cluster
	// members. A sensitive path is only worth keeping if its body differs from
	// this shell — otherwise it IS the shell and flagging it CRITICAL would be a
	// false positive (the /config.php + /backup.sql bug against catch-all CDNs).
	shellHash := modalBodyHash(status200, median, tolerance)

	var kept []DirEntry
	for _, e := range status200 {
		outsideCluster := abs(int(e.Size)-median) > tolerance
		// Keep an always-keep path unless we can POSITIVELY identify it as the
		// shell: we have a shell fingerprint, we captured this response's body,
		// its size is in the cluster, AND its body matches the shell. Any missing
		// signal → keep conservatively (better a false positive than dropping a
		// real .env whose body we couldn't compare).
		provablyShell := shellHash != 0 && e.bodyHash != 0 && !outsideCluster && e.bodyHash == shellHash
		sensitiveKeep := isAlwaysKeepPath(e.Path) && !provablyShell
		if outsideCluster || sensitiveKeep {
			kept = append(kept, e)
		} else if isAlwaysKeepPath(e.Path) {
			log.Debug("Dropping shell-identical sensitive path (catch-all false positive): %s", e.Path)
		}
	}

	// Add back non-200 results (403s, redirects) — these are meaningful signals
	kept = append(kept, others...)
	return kept
}

// modalBodyHash returns the most common bodyHash among the in-cluster entries,
// i.e. the fingerprint of the catch-all shell page.
func modalBodyHash(entries []DirEntry, median, tolerance int) uint32 {
	counts := make(map[uint32]int)
	for _, e := range entries {
		if e.bodyHash == 0 {
			continue
		}
		if abs(int(e.Size)-median) <= tolerance {
			counts[e.bodyHash]++
		}
	}
	var best uint32
	bestN := 0
	for h, n := range counts {
		if n > bestN {
			bestN, best = n, h
		}
	}
	return best
}

// isAlwaysKeepPath returns true for paths so sensitive we never filter them,
// even if they match the catch-all cluster size (a real hit here is critical).
func isAlwaysKeepPath(path string) bool {
	p := strings.ToLower(path)
	critical := []string{
		".env", ".git", ".svn", ".htpasswd", "id_rsa", ".aws/credentials",
		"wp-config", "config.php", ".ssh", "backup.sql", "dump.sql",
		".DS_Store", "web.config", ".npmrc", ".dockercfg",
	}
	for _, c := range critical {
		if strings.Contains(p, c) {
			return true
		}
	}
	return false
}
