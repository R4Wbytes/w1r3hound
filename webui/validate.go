package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ModuleInfo describes one w1r3hound recon module for the UI catalog.
type ModuleInfo struct {
	Alias    string `json:"alias"`
	Internal string `json:"internal"`
	Category string `json:"category"`
	Desc     string `json:"desc"`
	Active   bool   `json:"active"` // skipped by the CLI in -passive mode
}

// moduleCatalog mirrors the knownModules / mapProtocol tables in main.go.
// endprobe is exposed under its own name (its alias equals its internal name);
// the CLI reaches it the same way via `-m endprobe`.
var moduleCatalog = []ModuleInfo{
	{Alias: "recon", Internal: "whois", Category: "Passive OSINT", Desc: "WHOIS/RDAP domain intelligence", Active: false},
	{Alias: "traceroute", Internal: "asnmap", Category: "Passive OSINT", Desc: "ASN → CIDR range discovery via BGP", Active: false},
	{Alias: "passivewatch", Internal: "passivesrc", Category: "Passive OSINT", Desc: "Passive subdomains (CT logs, 6 sources)", Active: false},

	{Alias: "fingerprinter", Internal: "dns", Category: "DNS & Subdomains", Desc: "DNS enum, AXFR, SRV, SPF/DMARC, takeover", Active: false},
	{Alias: "archaeology", Internal: "wayback", Category: "DNS & Subdomains", Desc: "Wayback Machine URL & parameter harvesting", Active: false},
	{Alias: "diversify", Internal: "permute", Category: "DNS & Subdomains", Desc: "Subdomain permutation & resolution", Active: true},

	{Alias: "heartbeat", Internal: "httprobe", Category: "Live Detection & Fingerprinting", Desc: "HTTP probe + favicon hash (Shodan pivoting)", Active: true},
	{Alias: "probescan", Internal: "webserver", Category: "Live Detection & Fingerprinting", Desc: "Server fingerprint, TLS cert, HTTP methods", Active: true},
	{Alias: "metadata", Internal: "metafiles", Category: "Live Detection & Fingerprinting", Desc: "robots.txt, sitemap, security.txt, .well-known", Active: true},
	{Alias: "sentry", Internal: "headers", Category: "Live Detection & Fingerprinting", Desc: "Security headers audit, tech fingerprinting", Active: true},
	{Alias: "deepdive", Internal: "content", Category: "Live Detection & Fingerprinting", Desc: "HTML comments, JS secrets, source maps, leaks", Active: true},

	{Alias: "portscan", Internal: "portscan", Category: "Attack Surface", Desc: "TCP port scan with service ID & banner grab", Active: true},
	{Alias: "corstrace", Internal: "cors", Category: "Attack Surface", Desc: "CORS misconfiguration testing", Active: true},
	{Alias: "cloudsniff", Internal: "cloud", Category: "Attack Surface", Desc: "S3/Azure/GCS/Firebase/DigitalOcean buckets", Active: true},
	{Alias: "bruteforce", Internal: "dirbrute", Category: "Attack Surface", Desc: "Hidden paths, admin panels, backups, configs", Active: true},
	{Alias: "apiscan", Internal: "apiscan", Category: "Attack Surface", Desc: "GraphQL introspection, Swagger/OpenAPI, REST, WS", Active: true},
	{Alias: "saasenum", Internal: "saasenum", Category: "Attack Surface", Desc: "SaaS enum (Zendesk/JIRA/Okta/Salesforce +15 more)", Active: true},
	{Alias: "crawler", Internal: "crawler", Category: "Attack Surface", Desc: "Web crawl for forms, params, entry points", Active: true},

	{Alias: "jsdeep", Internal: "jsdeep", Category: "Deep Analysis", Desc: "JS endpoint extraction (LinkFinder style)", Active: true},
	{Alias: "endprobe", Internal: "endprobe", Category: "Deep Analysis", Desc: "Unauthenticated access on JS-discovered endpoints", Active: true},
	{Alias: "takeover", Internal: "takeover", Category: "Deep Analysis", Desc: "Subdomain takeover via HTTP fingerprints (37 services)", Active: true},
}

// aliasToInternal accepts both themed aliases and internal names, exactly
// like mapProtocol in main.go, and normalizes to the internal name.
var aliasToInternal = func() map[string]string {
	m := make(map[string]string, len(moduleCatalog)*2)
	for _, mi := range moduleCatalog {
		m[mi.Alias] = mi.Internal
		m[mi.Internal] = mi.Internal
	}
	return m
}()

// ScanRequest is the JSON body accepted by POST /api/scan.
type ScanRequest struct {
	Target      string   `json:"target"`
	Modules     []string `json:"modules"` // empty means "all"
	Concurrency int      `json:"concurrency"`
	Ports       string   `json:"ports"`
	Wordlist    string   `json:"wordlist"`
	Passive     bool     `json:"passive"`
	Rate        int      `json:"rate"`
	TimeoutSec  int      `json:"timeout_sec"`
	UserAgent   string   `json:"user_agent"`
	Output      string   `json:"output"`
	Verbose     bool     `json:"verbose"`
	Authorized  bool     `json:"authorized"`

	// ── CLI-parity advanced options (see docs/CLI_PARITY.md) ──
	DirWordlist        string   `json:"dir_wordlist"`         // -dir-wordlist, confined to wordlistsDir
	DirExt             string   `json:"dir_ext"`              // -dir-ext, charset-restricted csv
	Headers            []string `json:"headers"`              // -H, each "Name: value", CRLF-rejected
	SkipTLSVerify      *bool    `json:"skip_tls_verify"`      // nil = CLI default (skip); false = verification ON
	BlockPrivateEgress bool     `json:"block_private_egress"` // -block-private-egress, opt-in SSRF egress guard
	Resolver           string   `json:"resolver"`             // -resolver, bare IP or ip:port
	Resolvers          string   `json:"resolvers"`            // -resolvers, confined to wordlistsDir
	WaybackLimit       int      `json:"wayback_limit"`        // -wayback-limit, 0 = engine default
	CrawlPages         int      `json:"crawl_pages"`          // -crawl-pages, 0 = engine default
	JSFiles            int      `json:"js_files"`             // -js-files, 0 = engine default
}

var (
	hostnameLabel = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	outputNameRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	// dirExtRe restricts -dir-ext to a conservative csv of extension tokens.
	dirExtRe = regexp.MustCompile(`^[A-Za-z0-9.,~_-]{1,256}$`)
	// headerNameRe is the RFC-token charset accepted for a header field-name.
	headerNameRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,128}$`)
)

func validHostname(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	h = strings.TrimSuffix(h, ".")
	for _, label := range strings.Split(h, ".") {
		if !hostnameLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func validHostPort(hostport string) bool {
	host := hostport
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		if n, err := net.LookupPort("tcp", p); err != nil || n < 1 || n > 65535 {
			return false
		}
		host = h
	} else if strings.Count(hostport, ":") == 1 {
		// single colon but unparseable host:port
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	return validHostname(host)
}

// validateTarget accepts a bare hostname, IPv4/IPv6 literal, CIDR range, or
// an http(s) URL. Anything else is rejected outright.
func validateTarget(raw string) error {
	if raw == "" {
		return fmt.Errorf("the target is required")
	}
	if len(raw) > 2048 {
		return fmt.Errorf("target too long")
	}
	if strings.ContainsAny(raw, " \t\r\n\x00") {
		return fmt.Errorf("the target cannot contain spaces or control characters")
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return fmt.Errorf("invalid target URL")
		}
		if u.User != nil {
			return fmt.Errorf("userinfo (user:password@) is not allowed in the URL")
		}
		if !validHostPort(u.Host) {
			return fmt.Errorf("invalid URL host: %q", u.Host)
		}
		return nil
	}
	if strings.Contains(raw, "://") {
		return fmt.Errorf("unsupported scheme (only http/https or hostname/IP/CIDR)")
	}
	if _, _, err := net.ParseCIDR(raw); err == nil {
		return nil
	}
	if ip := net.ParseIP(raw); ip != nil {
		return nil
	}
	// host[:port] without scheme
	if validHostPort(raw) {
		return nil
	}
	return fmt.Errorf("invalid target: must be a hostname, IP, CIDR or http(s) URL")
}

// normalizeModules validates the requested list against the catalog and
// returns internal names, deduplicated, in catalog order.
func normalizeModules(mods []string) ([]string, error) {
	if len(mods) == 0 {
		return nil, nil // "all"
	}
	if len(mods) > len(moduleCatalog) {
		return nil, fmt.Errorf("too many modules")
	}
	want := map[string]bool{}
	for _, m := range mods {
		internal, ok := aliasToInternal[strings.ToLower(strings.TrimSpace(m))]
		if !ok {
			return nil, fmt.Errorf("unknown module: %q", m)
		}
		want[internal] = true
	}
	out := make([]string, 0, len(want))
	for _, mi := range moduleCatalog {
		if want[mi.Internal] {
			out = append(out, mi.Internal)
		}
	}
	return out, nil
}

// resolveWordlist confines the requested wordlist to wordlistsDir. The path
// must resolve (after cleaning and symlink evaluation) to a regular file
// inside that directory; anything else is rejected.
func resolveWordlist(wordlistsDir, raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	if strings.ContainsRune(raw, 0) {
		return "", fmt.Errorf("invalid wordlist path")
	}
	base, err := filepath.EvalSymlinks(wordlistsDir)
	if err != nil {
		return "", fmt.Errorf("wordlists directory unavailable")
	}
	clean := filepath.Clean(raw)
	var candidate string
	if filepath.IsAbs(clean) {
		candidate = clean
	} else {
		candidate = filepath.Join(base, clean)
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", fmt.Errorf("wordlist not found: %q", raw)
	}
	if resolved != base && !strings.HasPrefix(resolved, base+string(os.PathSeparator)) {
		return "", fmt.Errorf("the wordlist must be inside the wordlists directory")
	}
	fi, err := os.Stat(resolved)
	if err != nil || !fi.Mode().IsRegular() {
		return "", fmt.Errorf("the wordlist is not a regular file")
	}
	return resolved, nil
}

// validateHeaders enforces the -H injection allow-list: each entry is
// "Name: value" with an RFC-token name (<=128 chars), no CR/LF/NUL anywhere,
// a non-empty value (<=1024 chars), and at most 32 entries. Empty/whitespace
// entries are dropped. It returns the canonicalised list or an error. This is
// a header-injection sink (the value lands in the subprocess argv and on the
// wire), so anything off the allow-list is rejected rather than sanitised.
func validateHeaders(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, raw := range in {
		h := strings.TrimSpace(raw)
		if h == "" {
			continue
		}
		if strings.ContainsAny(h, "\r\n\x00") {
			return nil, fmt.Errorf("invalid header (CR/LF/NUL not allowed)")
		}
		i := strings.IndexByte(h, ':')
		if i <= 0 {
			return nil, fmt.Errorf("invalid header %q (want 'Name: value')", raw)
		}
		name := h[:i]
		if !headerNameRe.MatchString(name) {
			return nil, fmt.Errorf("invalid header name %q", name)
		}
		val := strings.TrimPrefix(h[i+1:], " ")
		if len(val) == 0 || len(val) > 1024 {
			return nil, fmt.Errorf("invalid header value length for %q", name)
		}
		out = append(out, name+": "+val)
	}
	if len(out) > 32 {
		return nil, fmt.Errorf("too many headers (max 32)")
	}
	return out, nil
}

// validResolver accepts a bare IP (v4/v6) or an ip:port. Hostnames are
// rejected on purpose so the engine never performs a DNS lookup just to find
// the resolver it should use.
func validResolver(s string) bool {
	if s == "" || strings.ContainsAny(s, " \t\r\n\x00") {
		return false
	}
	if ip := net.ParseIP(s); ip != nil {
		return true // bare IPv4 or IPv6 literal (incl. ::1, 2001:db8::1)
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}
	if n, err := net.LookupPort("tcp", port); err != nil || n < 1 || n > 65535 {
		return false
	}
	return net.ParseIP(host) != nil
}

// sanitizeForFilename replicates the CLI's sanitize(): dots, slashes and
// colons become underscores.
func sanitizeForFilename(s string) string {
	s = strings.ReplaceAll(s, ".", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, ":", "_")
	return s
}

// domainOfTarget extracts the host part the same way the CLI's
// extractDomain does, for building the default output base name.
func domainOfTarget(target string) string {
	t := strings.TrimPrefix(target, "https://")
	t = strings.TrimPrefix(t, "http://")
	t = strings.Split(t, "/")[0]
	if strings.HasPrefix(t, "[") {
		if i := strings.Index(t, "]"); i != -1 {
			return t[1:i]
		}
		return t
	}
	if i := strings.LastIndex(t, ":"); i != -1 && !strings.Contains(t[:i], ":") {
		t = t[:i]
	}
	return t
}

// buildArgs validates the request and returns the argv slice for the
// w1r3hound binary plus the absolute output base path (without extension).
// Validation rejects unknown values instead of trying to sanitize them.
func buildArgs(req *ScanRequest, wordlistsDir, resultsDir string) ([]string, string, error) {
	if !req.Authorized {
		return nil, "", fmt.Errorf("you must confirm you are authorized to scan the target")
	}
	if err := validateTarget(req.Target); err != nil {
		return nil, "", err
	}
	mods, err := normalizeModules(req.Modules)
	if err != nil {
		return nil, "", err
	}
	if req.Concurrency < 0 || req.Concurrency > 500 {
		return nil, "", fmt.Errorf("concurrency out of range (1-500)")
	}
	if req.Rate < 0 || req.Rate > 10000 {
		return nil, "", fmt.Errorf("rate out of range (0-10000)")
	}
	if req.TimeoutSec < 0 || req.TimeoutSec > 300 {
		return nil, "", fmt.Errorf("timeout out of range (1-300 s)")
	}
	switch req.Ports {
	case "", "top100", "1-1024", "full":
	default:
		return nil, "", fmt.Errorf("ports must be top100, 1-1024 or full")
	}
	if len(req.UserAgent) > 256 || strings.ContainsAny(req.UserAgent, "\r\n") {
		return nil, "", fmt.Errorf("invalid user-agent")
	}
	wordlist, err := resolveWordlist(wordlistsDir, req.Wordlist)
	if err != nil {
		return nil, "", err
	}

	// ── CLI-parity advanced options (validation) ──
	dirWordlist, err := resolveWordlist(wordlistsDir, req.DirWordlist)
	if err != nil {
		return nil, "", err
	}
	if req.DirExt != "" && !dirExtRe.MatchString(req.DirExt) {
		return nil, "", fmt.Errorf("invalid dir-ext (letters, numbers, dot, comma, tilde, underscore, hyphen; max 256)")
	}
	headers, err := validateHeaders(req.Headers)
	if err != nil {
		return nil, "", err
	}
	if req.Resolver != "" && !validResolver(req.Resolver) {
		return nil, "", fmt.Errorf("invalid resolver (want a bare IP or ip:port, not a hostname)")
	}
	resolvers, err := resolveWordlist(wordlistsDir, req.Resolvers)
	if err != nil {
		return nil, "", err
	}
	if req.WaybackLimit < 0 || req.WaybackLimit > 100000 {
		return nil, "", fmt.Errorf("wayback-limit out of range (0-100000)")
	}
	if req.CrawlPages < 0 || req.CrawlPages > 5000 {
		return nil, "", fmt.Errorf("crawl-pages out of range (0-5000)")
	}
	if req.JSFiles < 0 || req.JSFiles > 2000 {
		return nil, "", fmt.Errorf("js-files out of range (0-2000)")
	}

	base := req.Output
	if base != "" {
		if !outputNameRe.MatchString(base) || strings.Contains(base, "..") {
			return nil, "", fmt.Errorf("invalid output name (letters, numbers, dot, hyphen and underscore; no '..')")
		}
	} else {
		base = fmt.Sprintf("w1r3hound_%s_%s", sanitizeForFilename(domainOfTarget(req.Target)),
			time.Now().UTC().Format("20060102_150405"))
		if _, err := os.Stat(filepath.Join(resultsDir, base+".json")); err == nil {
			suffix := make([]byte, 2)
			if _, err := rand.Read(suffix); err == nil {
				base += "_" + hex.EncodeToString(suffix)
			}
		}
	}

	args := []string{"-t", req.Target}
	if len(mods) > 0 {
		args = append(args, "-m", strings.Join(mods, ","))
	}
	if req.Concurrency > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", req.Concurrency))
	}
	if req.Ports != "" {
		args = append(args, "-p", req.Ports)
	}
	if wordlist != "" {
		args = append(args, "-w", wordlist)
	}
	if req.Passive {
		args = append(args, "-passive")
	}
	if req.Rate > 0 {
		args = append(args, "-rate", fmt.Sprintf("%d", req.Rate))
	}
	if req.TimeoutSec > 0 {
		args = append(args, "-timeout", fmt.Sprintf("%ds", req.TimeoutSec))
	}
	if req.UserAgent != "" {
		args = append(args, "-ua", req.UserAgent)
	}
	if req.Verbose {
		args = append(args, "-v")
	}
	// ── CLI-parity advanced options (emission, stable order) ──
	if dirWordlist != "" {
		args = append(args, "-dir-wordlist", dirWordlist)
	}
	if req.DirExt != "" {
		args = append(args, "-dir-ext", req.DirExt)
	}
	for _, h := range headers {
		args = append(args, "-H", h)
	}
	// CLI default is skip-verify=true; only emit when the user opts into
	// verification (skip_tls_verify=false), matching docs/CLI_PARITY.md §2.4.
	if req.SkipTLSVerify != nil && !*req.SkipTLSVerify {
		args = append(args, "-skip-tls-verify=false")
	}
	if req.BlockPrivateEgress {
		args = append(args, "-block-private-egress")
	}
	if req.Resolver != "" {
		args = append(args, "-resolver", req.Resolver)
	}
	if resolvers != "" {
		args = append(args, "-resolvers", resolvers)
	}
	if req.WaybackLimit > 0 {
		args = append(args, "-wayback-limit", fmt.Sprintf("%d", req.WaybackLimit))
	}
	if req.CrawlPages > 0 {
		args = append(args, "-crawl-pages", fmt.Sprintf("%d", req.CrawlPages))
	}
	if req.JSFiles > 0 {
		args = append(args, "-js-files", fmt.Sprintf("%d", req.JSFiles))
	}
	args = append(args, "-o", filepath.Join(resultsDir, base))
	return args, base, nil
}
