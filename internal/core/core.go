// Package core provides shared types, HTTP client, configuration, and output
// utilities used by all reconnaissance modules.
package core

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ──────────────────────────────────────────────
//  Configuration
// ──────────────────────────────────────────────

type Config struct {
	Target       string
	Domain       string        // extracted root domain
	Concurrency  int           // max goroutines per module
	Timeout      time.Duration // per-request timeout
	UserAgent    string
	OutputFile   string // path for JSON report
	Verbose      bool
	Modules      []string // which modules to run ("all" = everything)
	Wordlist     string   // path to a wordlist for dir bruteforce
	Ports        string   // port spec for scanner (e.g. "top100", "1-1024", "full")
	RateLimit    int      // requests per second (0 = unlimited)
	SkipSSLCheck bool
	Passive      bool         // passive-only mode (no active probing)
	RL           *RateLimiter // rate limiter shared across modules

	Resolver      *net.Resolver // DNS resolver (system default, or custom via -resolver)
	WaybackLimit  int           // max URLs from the Wayback CDX API
	CrawlMaxPages int           // max pages for the crawler
	MaxJSFiles    int           // max JS files to analyse

	// RootDomains lists the apex/root domains covered by the scan. Used by
	// helpers like isSubdomain() to suppress duplicate findings on subdomains
	// that inherit behaviour from the apex (e.g. DMARC, SPF, MX). When empty,
	// helpers fall back to label-count heuristics.
	// Fix #3 (bbp-abercrombie-2026-08-07).
	RootDomains []string

	// ── Shared context (data feedback between modules) ──
	// Modules populate these so downstream modules can consume them.
	// (Checklist Fase 8.1: realimentación de datos entre fases)
	SharedMu         sync.Mutex
	SharedSubdomains []string // discovered subdomains (passive + active)
	SharedURLs       []string // discovered URLs (wayback, crawler)
	SharedParams     []string // discovered parameters
	SharedJSFiles    []string // discovered JS file URLs
	SharedIPs        []string // resolved IPs / CIDR ranges
	SharedEndpoints  []string // API endpoints found in JS
}

// APIKeyStore removed: the fields were never populated (no env/flag/config
// loading) and the only sources in use (crt.sh, HackerTarget, …) are keyless.

// AddSharedSubdomains merges subdomains into the shared context (thread-safe).
func (c *Config) AddSharedSubdomains(subs []string) {
	c.SharedMu.Lock()
	defer c.SharedMu.Unlock()
	seen := make(map[string]bool)
	for _, s := range c.SharedSubdomains {
		seen[s] = true
	}
	for _, s := range subs {
		if s != "" && !seen[s] {
			seen[s] = true
			c.SharedSubdomains = append(c.SharedSubdomains, s)
		}
	}
}

// AddSharedURLs merges URLs into the shared context (thread-safe).
func (c *Config) AddSharedURLs(urls []string) {
	c.SharedMu.Lock()
	defer c.SharedMu.Unlock()
	seen := make(map[string]bool)
	for _, u := range c.SharedURLs {
		seen[u] = true
	}
	for _, u := range urls {
		if u != "" && !seen[u] {
			seen[u] = true
			c.SharedURLs = append(c.SharedURLs, u)
		}
	}
}

// AddSharedParams merges discovered parameter names into the shared context.
func (c *Config) AddSharedParams(params []string) {
	c.SharedMu.Lock()
	defer c.SharedMu.Unlock()
	seen := make(map[string]bool)
	for _, p := range c.SharedParams {
		seen[p] = true
	}
	for _, p := range params {
		if p != "" && !seen[p] {
			seen[p] = true
			c.SharedParams = append(c.SharedParams, p)
		}
	}
}

func DefaultConfig() *Config {
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
	}
}

// NewResolver returns a *net.Resolver. When server is non-empty (e.g. "1.1.1.1"
// or "8.8.8.8:53") every lookup is sent to that DNS server through a custom
// dialer, which makes results reproducible behind a VPN / split-horizon DNS;
// otherwise the system resolver is used.
func NewResolver(server string, timeout time.Duration) *net.Resolver {
	if server == "" {
		return net.DefaultResolver
	}
	if !strings.Contains(server, ":") {
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

// ──────────────────────────────────────────────
//  Shared HTTP Client
// ──────────────────────────────────────────────

func NewHTTPClient(cfg *Config) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.SkipSSLCheck},
		DialContext: (&net.Dialer{
			Timeout:   cfg.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        cfg.Concurrency,
		MaxIdleConnsPerHost: cfg.Concurrency,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
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
//  Logger // W1r3hound Terminal Output
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
		if s, ok := a.(string); ok {
			args[i] = stripControl(s)
		}
	}
	return args
}

// Module header — styled as W1r3hound protocol activation
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
