// Package core provides shared types, HTTP client, configuration, and output
// utilities used by all reconnaissance modules.
package core

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ──────────────────────────────────────────────
//  Configuration
// ──────────────────────────────────────────────

type Config struct {
	Target        string
	Domain        string        // extracted root domain
	Concurrency   int           // max goroutines per module
	Timeout       time.Duration // per-request timeout
	UserAgent     string
	OutputFile    string // path for JSON report
	Verbose       bool
	Modules       []string // which modules to run ("all" = everything)
	Wordlist      string   // path to a wordlist for subdomain bruteforce
	DirWordlist   string   // path to a wordlist for directory/file bruteforce (falls back to the embedded list when empty)
	DirExtensions string   // comma-separated extensions appended to each dirbrute word (e.g. ".bak,.php,.zip,~")
	Resolvers     []string // ip[:port] pool for the raw-UDP DNS brute-force engine; empty = use Resolver (stdlib) as today
	Ports         string   // port spec for scanner (e.g. "top100", "1-1024", "full")
	RateLimit     int      // requests per second (0 = unlimited)
	SkipSSLCheck  bool
	// BlockPrivateEgress (opt-in, -block-private-egress) makes the shared dialer
	// refuse connections whose RESOLVED IP is loopback/private/link-local/
	// unspecified — a dial-time SSRF guard that catches an in-scope hostname, or
	// a target-supplied URL, pointing at an internal/metadata address. Off by
	// default so intended internal/CTF scans keep working.
	BlockPrivateEgress bool
	Passive            bool              // passive-only mode (no active probing)
	RL                 *RateLimiter      // rate limiter shared across modules
	RequestHeaders     map[string]string // headers added to every HTTP request

	// Cancel is the root context cancellation function. Modules that perform
	// raw net.Dial/tls.Dial (outside the shared HTTP client) should derive a
	// context from this so SIGINT can interrupt an in-flight dial rather than
	// blocking for the full OS timeout. Lazy-initialised; the Cancel func is
	// safe to call multiple times (idempotent).
	Cancel    context.CancelFunc
	cancelCtx context.Context

	Resolver      *net.Resolver // DNS resolver (system default, or custom via -resolver)
	WaybackLimit  int           // max URLs from the Wayback CDX API
	CrawlMaxPages int           // max pages for the crawler
	MaxJSFiles    int           // max JS files to analyse

	// RootDomains lists the apex/root domains covered by the scan. Used by
	// helpers like isSubdomain() to suppress duplicate findings on subdomains
	// that inherit behaviour from the apex (e.g. DMARC, SPF, MX). When empty,
	// helpers fall back to label-count heuristics.
	// Fix #3 (2026-08-07).
	RootDomains []string

	// ── Shared context (data feedback between modules) ──
	// Modules populate these so downstream modules can consume them.
	// (Checklist Phase 8.1: data feedback between phases)
	SharedMu         sync.Mutex
	SharedSubdomains []string // discovered subdomains (passive + active)
	SharedURLs       []string // discovered URLs (wayback, crawler)
	SharedParams     []string // discovered parameters
	SharedJSFiles    []string // discovered JS file URLs
	SharedIPs        []string // resolved IPs / CIDR ranges
	SharedEndpoints  []string // endpoints/routes found in JS

	sharedSubdomainsSeen map[string]bool
	sharedURLsSeen       map[string]bool
	sharedParamsSeen     map[string]bool
}

// APIKeyStore removed: the fields were never populated (no env/flag/config
// loading) and the only sources in use (crt.sh, HackerTarget, …) are keyless.

// AddSharedSubdomains merges subdomains into the shared context (thread-safe).
func (c *Config) AddSharedSubdomains(subs []string) {
	c.SharedMu.Lock()
	defer c.SharedMu.Unlock()
	if c.sharedSubdomainsSeen == nil {
		c.sharedSubdomainsSeen = make(map[string]bool)
		for _, s := range c.SharedSubdomains {
			c.sharedSubdomainsSeen[s] = true
		}
	}
	for _, s := range subs {
		if s != "" && !c.sharedSubdomainsSeen[s] {
			c.sharedSubdomainsSeen[s] = true
			c.SharedSubdomains = append(c.SharedSubdomains, s)
		}
	}
}

// AddSharedURLs merges URLs into the shared context (thread-safe).
func (c *Config) AddSharedURLs(urls []string) {
	c.SharedMu.Lock()
	defer c.SharedMu.Unlock()
	if c.sharedURLsSeen == nil {
		c.sharedURLsSeen = make(map[string]bool)
		for _, u := range c.SharedURLs {
			c.sharedURLsSeen[u] = true
		}
	}
	for _, u := range urls {
		if u != "" && !c.sharedURLsSeen[u] {
			c.sharedURLsSeen[u] = true
			c.SharedURLs = append(c.SharedURLs, u)
		}
	}
}

// AddSharedParams merges discovered parameter names into the shared context.
func (c *Config) AddSharedParams(params []string) {
	c.SharedMu.Lock()
	defer c.SharedMu.Unlock()
	if c.sharedParamsSeen == nil {
		c.sharedParamsSeen = make(map[string]bool)
		for _, p := range c.SharedParams {
			c.sharedParamsSeen[p] = true
		}
	}
	for _, p := range params {
		if p != "" && !c.sharedParamsSeen[p] {
			c.sharedParamsSeen[p] = true
			c.SharedParams = append(c.SharedParams, p)
		}
	}
}

func DefaultConfig() *Config {
	ctx, cancel := context.WithCancel(context.Background())
	return &Config{
		Concurrency:   20,
		Timeout:       10 * time.Second,
		UserAgent:     "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
		Verbose:       false,
		Modules:       []string{"all"},
		Ports:         "top100",
		RateLimit:     0,
		SkipSSLCheck:  true,
		Passive:       false,
		Resolver:      net.DefaultResolver,
		WaybackLimit:  5000,
		CrawlMaxPages: 100,
		MaxJSFiles:    50,
		cancelCtx:     ctx,
		Cancel:        cancel,
	}
}

// Context returns a child context derived from the root cancel context, with
// the per-request timeout layered on top. Modules should pass this to
// DialContext-style APIs so SIGINT (which triggers cfg.Cancel()) tears down
// in-flight dials immediately instead of waiting for the OS-level timeout.
// Safe to call before DefaultConfig has run — falls back to context.Background()
// with the per-request timeout so tests don't have to wire the full config.
func (c *Config) Context(timeout time.Duration) (context.Context, context.CancelFunc) {
	if c == nil || c.cancelCtx == nil {
		return context.WithTimeout(context.Background(), timeout)
	}
	return context.WithTimeout(c.cancelCtx, timeout)
}

// NewResolver returns a *net.Resolver. When server is non-empty (e.g. "1.1.1.1"
// or "8.8.8.8:53") every lookup is sent to that DNS server through a custom
// dialer, which makes results reproducible behind a VPN / split-horizon DNS;
// otherwise the system resolver is used.
func NewResolver(server string, timeout time.Duration) *net.Resolver {
	if server == "" {
		return net.DefaultResolver
	}
	// SplitHostPort fails when there's no port, whether the host is a plain
	// IPv4/hostname or a bare IPv6 literal — JoinHostPort then adds ":53" and
	// correctly brackets IPv6 in the process. A strings.Contains(server, ":")
	// check would misfire on bare IPv6 literals (they contain ":" but have no
	// port), silently breaking every lookup through that resolver.
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	d := &net.Dialer{Timeout: timeout}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, server)
		},
	}
}

// ReadLines reads a plain-text list file: one entry per line, blank lines
// and "#"-prefixed comments skipped. Single source of truth for the several
// wordlist-shaped inputs the CLI accepts (subdomain wordlist, dirbrute
// wordlist, DNS resolver list) — previously each had its own copy of this
// same ~15-line loader.
func ReadLines(path string) []string {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines
}

// ──────────────────────────────────────────────
//  Shared HTTP Client
// ──────────────────────────────────────────────

// NewHTTPClient returns the shared client for traffic to the scan target. It
// honours cfg.SkipSSLCheck (default true) so recon can still fingerprint
// broken/self-signed TLS on the target itself.
func NewHTTPClient(cfg *Config) *http.Client {
	return newHTTPClient(cfg, cfg.SkipSSLCheck)
}

// NewVerifiedHTTPClient returns a client that ALWAYS verifies the server
// certificate and requires TLS 1.2+, regardless of cfg.SkipSSLCheck. Use it for
// calls to trusted, fixed third-party intel APIs (crt.sh, HackerTarget,
// AlienVault, RapidDNS, jldc/Anubis, CertSpotter, BGPView, RDAP, the Wayback
// Machine): their responses steer active scanning and populate the report, so a
// MITM must not be able to tamper with them even when the operator disabled TLS
// verification for the target.
func NewVerifiedHTTPClient(cfg *Config) *http.Client {
	return newHTTPClient(cfg, false)
}

func newHTTPClient(cfg *Config, insecureSkipVerify bool) *http.Client {
	tlsConf := &tls.Config{InsecureSkipVerify: insecureSkipVerify}
	if !insecureSkipVerify {
		tlsConf.MinVersion = tls.VersionTLS12
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConf,
		// A hand-built Transport doesn't inherit http.DefaultTransport's h2
		// auto-negotiation, so without this Go silently stays on HTTP/1.1 even
		// against servers that support HTTP/2.
		ForceAttemptHTTP2: true,
		DialContext: (&net.Dialer{
			Timeout:   cfg.Timeout,
			KeepAlive: 30 * time.Second,
			Control:   egressControl(cfg),
		}).DialContext,
		MaxIdleConns:        cfg.Concurrency,
		MaxIdleConnsPerHost: cfg.Concurrency,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
	}
	var roundTripper http.RoundTripper = transport
	if len(cfg.RequestHeaders) > 0 {
		headers := make(map[string]string, len(cfg.RequestHeaders))
		for name, value := range cfg.RequestHeaders {
			headers[name] = value
		}
		roundTripper = &requestHeaderTransport{base: transport, headers: headers}
	}
	targetHost, targetPath := configuredTargetScope(cfg.Target)
	return &http.Client{
		Transport: roundTripper,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			if len(via) > 0 {
				initialHost := via[0].URL.Hostname()
				if targetHost != "" && strings.EqualFold(initialHost, targetHost) {
					if !strings.EqualFold(req.URL.Hostname(), targetHost) {
						return http.ErrUseLastResponse
					}
					if targetPath != "" && !pathWithinTarget(req.URL.Path, targetPath) {
						return http.ErrUseLastResponse
					}
					return nil
				}
				if isTargetHost(initialHost, cfg.Domain) && !strings.EqualFold(req.URL.Hostname(), initialHost) {
					return http.ErrUseLastResponse
				}
			}
			return nil
		},
	}
}

// egressControl returns a net.Dialer Control hook that blocks dials to
// non-public IPs when cfg.BlockPrivateEgress is set (opt-in). The hook runs
// AFTER DNS resolution with the concrete IP:port, so it catches an in-scope
// hostname (the target controls its own DNS) or a target-supplied URL that
// resolves to loopback/RFC1918/link-local/metadata — a dial-time SSRF guard.
// Returns nil (a no-op hook) when the guard is off, preserving the default
// behaviour for intended internal/CTF targets.
func egressControl(cfg *Config) func(network, address string, c syscall.RawConn) error {
	if cfg == nil || !cfg.BlockPrivateEgress {
		return nil
	}
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address
		}
		ip := net.ParseIP(host)
		if ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified()) {
			return fmt.Errorf("egress to non-public address %s blocked (-block-private-egress)", host)
		}
		return nil
	}
}

// configuredTargetScope returns the exact host and optional path prefix supplied
// by the operator. A non-root path is an active-scan boundary: following a
// same-host redirect from /programs to /engagements would otherwise scan and
// attribute a route that was never authorized or requested.
func configuredTargetScope(rawTarget string) (string, string) {
	u, err := url.Parse(rawTarget)
	if err != nil || u.Hostname() == "" {
		return "", ""
	}
	return strings.ToLower(u.Hostname()), cleanTargetPath(u.Path)
}

func cleanTargetPath(rawPath string) string {
	if rawPath == "" || rawPath == "/" {
		return ""
	}
	cleaned := path.Clean("/" + strings.TrimPrefix(rawPath, "/"))
	if cleaned == "/" || cleaned == "." {
		return ""
	}
	return cleaned
}

func pathWithinTarget(candidatePath, targetPath string) bool {
	if targetPath == "" {
		return true
	}
	candidatePath = cleanTargetPath(candidatePath)
	return candidatePath == targetPath || strings.HasPrefix(candidatePath, targetPath+"/")
}

func isTargetHost(host, domain string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	return host == domain || strings.HasSuffix(host, "."+domain)
}

type requestHeaderTransport struct {
	base    http.RoundTripper
	headers map[string]string
}

func (t *requestHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	cloned.Header = req.Header.Clone()
	for name, value := range t.headers {
		cloned.Header.Set(name, value)
	}
	return t.base.RoundTrip(cloned)
}

// DoRequest is a convenience wrapper that adds the configured User-Agent
// and respects the rate limiter if one is set.
func DoRequest(client *http.Client, method, url, ua string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)
	return client.Do(req)
}

// DoRequestRL is DoRequest with rate limiting.
func DoRequestRL(client *http.Client, method, url, ua string, rl *RateLimiter) (*http.Response, error) {
	if rl != nil {
		rl.Wait()
	}
	return DoRequest(client, method, url, ua)
}

// FetchBody performs a GET and returns the response body as string + status code.
func FetchBody(client *http.Client, url, ua string) (string, int, error) {
	resp, err := DoRequest(client, "GET", url, ua)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10 MB cap
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(body), resp.StatusCode, nil
}

// FetchBodyRL is FetchBody with rate limiting.
func FetchBodyRL(client *http.Client, url, ua string, rl *RateLimiter) (string, int, error) {
	if rl != nil {
		rl.Wait()
	}
	return FetchBody(client, url, ua)
}

// FetchBodyCT is FetchBody that additionally returns the response Content-Type.
// The crawler needs it to avoid running HTML link/form extraction over non-HTML
// bodies (JS/CSS/JSON): framework bundles embed template literals like
// href="{{...}}" that would otherwise be mistaken for real links.
func FetchBodyCT(client *http.Client, url, ua string) (string, int, string, error) {
	resp, err := DoRequest(client, "GET", url, ua)
	if err != nil {
		return "", 0, "", err
	}
	defer resp.Body.Close()
	ct := resp.Header.Get("Content-Type")
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10 MB cap
	if err != nil {
		return "", resp.StatusCode, ct, err
	}
	return string(body), resp.StatusCode, ct, nil
}

// FetchBodyCTRL is FetchBodyCT with rate limiting.
func FetchBodyCTRL(client *http.Client, url, ua string, rl *RateLimiter) (string, int, string, error) {
	if rl != nil {
		rl.Wait()
	}
	return FetchBodyCT(client, url, ua)
}

// NewPostRequest builds a POST request with a body and content type.
func NewPostRequest(url, contentType, body, ua string) (*http.Request, error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", ua)
	return req, nil
}

// ReadBodyLimit reads up to limit bytes from a response body and returns a string.
func ReadBodyLimit(resp *http.Response, limit int64) string {
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return ""
	}
	return string(data)
}

// ──────────────────────────────────────────────
//  Rate Limiter
// ──────────────────────────────────────────────

type RateLimiter struct {
	ch   chan struct{}
	done chan struct{}
	once sync.Once
}

func NewRateLimiter(rps int) *RateLimiter {
	if rps <= 0 {
		return nil
	}
	rl := &RateLimiter{
		ch:   make(chan struct{}),
		done: make(chan struct{}),
	}
	// Guard against an interval of 0: for rps > 1e9 the integer division
	// time.Second/rps truncates to 0, and time.NewTicker(0) panics. Clamp to a
	// minimum 1ns tick (effectively "unlimited" at that rate) instead of crashing.
	interval := time.Second / time.Duration(rps)
	if interval <= 0 {
		interval = time.Nanosecond
	}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-rl.done:
				return
			case <-ticker.C:
				select {
				case rl.ch <- struct{}{}:
				case <-rl.done:
					return
				}
			}
		}
	}()
	return rl
}

func (rl *RateLimiter) Wait() {
	if rl == nil {
		return
	}
	select {
	case <-rl.ch:
	case <-rl.done:
	}
}

func (rl *RateLimiter) Stop() {
	if rl == nil {
		return
	}
	rl.once.Do(func() { close(rl.done) })
}

// ──────────────────────────────────────────────
//  Findings / Report Model
// ──────────────────────────────────────────────

type Severity string

const (
	SevInfo     Severity = "INFO"
	SevLow      Severity = "LOW"
	SevMedium   Severity = "MEDIUM"
	SevHigh     Severity = "HIGH"
	SevCritical Severity = "CRITICAL"
)

type Finding struct {
	Module      string   `json:"module"`
	WSTG        string   `json:"wstg_id,omitempty"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Severity    Severity `json:"severity"`
	Data        any      `json:"data,omitempty"`
}

type ReconReport struct {
	Target    string    `json:"target"`
	StartedAt string    `json:"started_at"`
	EndedAt   string    `json:"ended_at"`
	Findings  []Finding `json:"findings"`
	mu        sync.Mutex
}

func NewReport(target string) *ReconReport {
	return &ReconReport{
		Target:    target,
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		Findings:  []Finding{},
	}
}

func (r *ReconReport) Add(f Finding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Findings = append(r.Findings, f)
}

func (r *ReconReport) Finalize() {
	r.EndedAt = time.Now().UTC().Format(time.RFC3339)
}

func (r *ReconReport) SaveJSON(path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// ──────────────────────────────────────────────
//  Logger // w1r3hound Terminal Output
// ──────────────────────────────────────────────

type Logger struct {
	verbose bool
	mu      sync.Mutex
}

func NewLogger(verbose bool) *Logger {
	return &Logger{verbose: verbose}
}

// stripControl neutralises ANSI escape sequences and other C0/C1 control bytes
// that originate from untrusted network input (port banners, Server/Location
// headers, TLS certificate CN/SAN/issuer, page titles, cookie names…). Left
// unfiltered, such a value can rewrite the analyst's terminal (screen clears,
// cursor moves, title-bar/clipboard escapes) or forge extra log lines. Our own
// colour codes live in the fixed format strings, never in these arguments, so
// they are unaffected. Control bytes become a single space to keep output on
// one line.
func stripControl(s string) string {
	needsWork := false
	for i := 0; i < len(s); i++ {
		if b := s[i]; b == 0x1b || b < 0x20 && b != '\t' || b == 0x7f {
			needsWork = true
			break
		}
	}
	if !needsWork && !strings.ContainsRune(s, 0x9b) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == 0x1b || (r < 0x20 && r != '\t') || (r >= 0x7f && r <= 0x9f) {
			b.WriteByte(' ')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// scrubArgs sanitises the string arguments passed to the logger. The variadic
// slice is freshly allocated at each call site, so mutating it in place is safe.
func scrubArgs(args []any) []any {
	for i, a := range args {
		switch v := a.(type) {
		case string:
			args[i] = stripControl(v)
		case []string:
			// C-4: a []string logged with %v (e.g. discovered subdomains, port
			// banners, allowed HTTP methods) was previously passed through raw,
			// so a hostile entry could inject terminal-control sequences. Scrub
			// each element into a fresh slice (never mutate the caller's).
			cleaned := make([]string, len(v))
			for j, s := range v {
				cleaned[j] = stripControl(s)
			}
			args[i] = cleaned
		}
	}
	return args
}

// Module header — styled as w1r3hound protocol activation
func (l *Logger) Module(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(os.Stderr, "\n\033[1;36m  ┌──────────────────────────────────────────────────┐\033[0m\n")
	fmt.Fprintf(os.Stderr, "\033[1;36m  │ ◉ %s\033[0m\n", stripControl(strings.ToUpper(name)))
	fmt.Fprintf(os.Stderr, "\033[1;36m  └──────────────────────────────────────────────────┘\033[0m\n")
}

func (l *Logger) Info(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(os.Stderr, "\033[32m  ▸\033[0m "+format+"\n", scrubArgs(args)...)
}

func (l *Logger) Warn(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(os.Stderr, "\033[33m  ⚠\033[0m "+format+"\n", scrubArgs(args)...)
}

func (l *Logger) Error(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(os.Stderr, "\033[31m  ✖\033[0m "+format+"\n", scrubArgs(args)...)
}

func (l *Logger) Debug(format string, args ...any) {
	if !l.verbose {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(os.Stderr, "\033[90m  ─ %s\033[0m\n", stripControl(fmt.Sprintf(format, args...)))
}

// RecoverWorker should be `defer`-ed as the first statement inside a worker
// goroutine (right after `go func(...) {`). Modules process hostile,
// unpredictable third-party input (HTTP bodies, port banners, DNS/AXFR wire
// data, TLS certificates) across dozens of concurrent goroutines; a single
// panic in one of them (bad index, nil map, malformed data) would otherwise
// crash the whole process before the report is written. This contains the
// panic to the one goroutine that raised it and logs it instead.
func RecoverWorker(log *Logger, module string) {
	if r := recover(); r != nil {
		log.Warn("[%s] worker panic recovered: %v", module, r)
	}
}

func (l *Logger) Finding(sev Severity, title string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var color string
	switch sev {
	case SevCritical:
		color = "\033[1;31m"
	case SevHigh:
		color = "\033[31m"
	case SevMedium:
		color = "\033[33m"
	case SevLow:
		color = "\033[34m"
	default:
		color = "\033[37m"
	}
	fmt.Fprintf(os.Stderr, "    %s■ [%s]\033[0m %s\n", color, sev, stripControl(title))
}
