package modules

import (
	"encoding/base64"
	"fmt"
	"html"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

// ══════════════════════════════════════════════
//  HTTP PROBE (httpx-style)
//  Takes all discovered subdomains, probes which
//  are alive on HTTP/HTTPS, grabs title, status,
//  tech, and computes favicon hash for pivoting.
//  (Checklist Fase 1.2: alive checking + Fase 9.1
//   favicon hash dorks)
// ══════════════════════════════════════════════

type ProbeResult struct {
	LiveHosts     []LiveHost        `json:"live_hosts"`
	FaviconHashes map[string]string `json:"favicon_hashes,omitempty"` // host -> mmh3 hash
	TotalProbed   int               `json:"total_probed"`
	TotalLive     int               `json:"total_live"`
}

type LiveHost struct {
	URL         string   `json:"url"`
	StatusCode  int      `json:"status_code"`
	Title       string   `json:"title,omitempty"`
	Server      string   `json:"server,omitempty"`
	Tech        []string `json:"tech,omitempty"`
	FaviconHash string   `json:"favicon_hash,omitempty"`
	Redirect    string   `json:"redirect,omitempty"`
	ContentLen  int      `json:"content_length"`
}

var probeTitleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
var faviconLinkTagRe = regexp.MustCompile(`(?is)<link\b[^>]*>`)
var htmlAttributeRe = regexp.MustCompile(`(?is)\b([a-z][a-z0-9:_-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>]+))`)

func RunHTTProbe(cfg *core.Config, report *core.ReconReport, log *core.Logger) {
	log.Module("HTTPROBE // Live Host Detection & Favicon Hashing")

	if cfg.Passive {
		log.Info("Skipping HTTP probe in passive mode")
		return
	}

	// Gather targets: shared subdomains + the main domain
	cfg.SharedMu.Lock()
	targets := make([]string, len(cfg.SharedSubdomains))
	copy(targets, cfg.SharedSubdomains)
	cfg.SharedMu.Unlock()

	// Always include the base domain
	hasBase := false
	for _, t := range targets {
		if t == cfg.Domain {
			hasBase = true
			break
		}
	}
	if !hasBase {
		targets = append(targets, cfg.Domain)
	}

	if len(targets) == 0 {
		log.Info("No subdomains to probe (run 'passivesrc' or 'dns' first)")
		return
	}

	// Probe the operator's exact target URL for the base domain. Re-probing that
	// same base host on default ports can pull an unrelated service into scope
	// when the requested app is on a non-default port (e.g. Juice Shop on
	// 127.0.0.1:3000), and made one logical target report as "1/2". Discovered
	// subdomains are still expanded to both HTTPS and HTTP below.
	targetURL := normalizeTarget(cfg.Target)

	log.Info("Probing %d hosts for HTTP/HTTPS liveness...", len(targets))

	client := core.NewHTTPClient(cfg)
	result := ProbeResult{
		FaviconHashes: make(map[string]string),
		TotalProbed:   len(targets),
	}

	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, cfg.Concurrency)
	)

	probeOne := func(url string) {
		resp, err := core.DoRequestRL(client, "GET", url, cfg.UserAgent, cfg.RL)
		if err != nil {
			return
		}
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		_ = resp.Body.Close()
		body := string(bodyBytes)
		effectiveURL := url
		if resp.Request != nil && resp.Request.URL != nil {
			effectiveURL = resp.Request.URL.String()
		}

		lh := LiveHost{
			URL:        effectiveURL,
			StatusCode: resp.StatusCode,
			Server:     resp.Header.Get("Server"),
			Redirect:   resp.Header.Get("Location"),
			ContentLen: len(bodyBytes),
		}

		if m := probeTitleRe.FindStringSubmatch(body); len(m) > 1 {
			lh.Title = strings.TrimSpace(strings.ReplaceAll(m[1], "\n", " "))
			lh.Title = truncate(lh.Title, 80)
		}

		lh.Tech = detectTechInline(resp.Header, body)

		if fh := computeFavicon(client, effectiveURL, body, cfg); fh != "" {
			lh.FaviconHash = fh
		}

		mu.Lock()
		result.LiveHosts = append(result.LiveHosts, lh)
		mu.Unlock()

		summary := lh.Title
		if summary == "" && lh.Redirect != "" {
			summary = "→ " + lh.Redirect
		}
		log.Info("  [%d] %-45s %s", resp.StatusCode, lh.URL, truncate(summary, 80))
	}

	wg.Add(1)
	sem <- struct{}{}
	go func() {
		defer core.RecoverWorker(log, "httprobe")
		defer wg.Done()
		defer func() { <-sem }()
		probeOne(targetURL)
	}()

	for _, host := range targets {
		if host == cfg.Domain {
			continue
		}
		for _, scheme := range []string{"https", "http"} {
			wg.Add(1)
			sem <- struct{}{}
			go func(host, scheme string) {
				defer core.RecoverWorker(log, "httprobe")
				defer wg.Done()
				defer func() { <-sem }()

				url := scheme + "://" + host
				resp, err := core.DoRequestRL(client, "GET", url, cfg.UserAgent, cfg.RL)
				if err != nil {
					return
				}
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
				_ = resp.Body.Close()
				body := string(bodyBytes)
				effectiveURL := url
				if resp.Request != nil && resp.Request.URL != nil {
					effectiveURL = resp.Request.URL.String()
				}

				lh := LiveHost{
					URL:        effectiveURL,
					StatusCode: resp.StatusCode,
					Server:     resp.Header.Get("Server"),
					Redirect:   resp.Header.Get("Location"),
					ContentLen: len(bodyBytes),
				}

				if m := probeTitleRe.FindStringSubmatch(body); len(m) > 1 {
					lh.Title = strings.TrimSpace(strings.ReplaceAll(m[1], "\n", " "))
					lh.Title = truncate(lh.Title, 80)
				}

				lh.Tech = detectTechInline(resp.Header, body)

				if fh := computeFavicon(client, effectiveURL, body, cfg); fh != "" {
					lh.FaviconHash = fh
				}

				mu.Lock()
				result.LiveHosts = append(result.LiveHosts, lh)
				mu.Unlock()

				summary := lh.Title
				if summary == "" && lh.Redirect != "" {
					summary = "→ " + lh.Redirect
				}
				log.Info("  [%d] %-45s %s", resp.StatusCode, lh.URL, truncate(summary, 80))
			}(host, scheme)
		}
	}
	wg.Wait()

	// Dedupe live hosts: a host may respond on both http+https. Collapse to one
	// entry per hostname, preferring the https result.
	byHost := make(map[string]LiveHost)
	for _, lh := range result.LiveHosts {
		host := probeHostKey(lh.URL)
		existing, ok := byHost[host]
		if !ok || (strings.HasPrefix(lh.URL, "https://") && !strings.HasPrefix(existing.URL, "https://")) {
			byHost[host] = lh
		}
	}
	deduped := make([]LiveHost, 0, len(byHost))
	for _, lh := range byHost {
		deduped = append(deduped, lh)
	}
	result.LiveHosts = deduped
	sort.Slice(result.LiveHosts, func(i, j int) bool {
		return result.LiveHosts[i].URL < result.LiveHosts[j].URL
	})
	result.TotalLive = len(result.LiveHosts)
	// Build the shared hash map from the selected records. HTTP and HTTPS probes
	// may finish in either order; deriving this after deduplication keeps the map
	// consistent with the preferred live-host entry.
	result.FaviconHashes = make(map[string]string)
	for _, lh := range result.LiveHosts {
		if lh.FaviconHash != "" {
			result.FaviconHashes[probeHostKey(lh.URL)] = lh.FaviconHash
		}
	}

	log.Info("Live hosts: %d/%d probed", result.TotalLive, result.TotalProbed)

	// Report interesting favicon hashes (they enable Shodan pivoting)
	if len(result.FaviconHashes) > 0 {
		log.Info("Favicon hashes computed for %d hosts (use with Shodan http.favicon.hash:)", len(result.FaviconHashes))
	}

	report.Add(core.Finding{
		Module:      "httprobe",
		WSTG:        "WSTG-INFO-04",
		Title:       fmt.Sprintf("HTTP probe: %d live hosts out of %d", result.TotalLive, result.TotalProbed),
		Severity:    core.SevInfo,
		Description: "Live web hosts with titles, tech, and favicon hashes for Shodan pivoting.",
		Data:        result,
	})
}

func probeHostKey(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		return u.Host
	}
	host := strings.TrimPrefix(rawURL, "https://")
	host = strings.TrimPrefix(host, "http://")
	return strings.SplitN(host, "/", 2)[0]
}

// computeFavicon follows the icon declared by the page (falling back to
// /favicon.ico), validates that the response is actually an image, and computes
// the mmh3 hash in Shodan's base64-then-hash format. Content validation is
// essential on SPAs: many return the HTML app shell with status 200 for a
// missing /favicon.ico, which would otherwise produce a bogus favicon hash.
func computeFavicon(client *http.Client, pageURL, pageBody string, cfg *core.Config) string {
	iconURL := discoverFaviconURL(pageURL, pageBody)
	if iconURL == "" {
		return ""
	}
	resp, err := core.DoRequestRL(client, "GET", iconURL, cfg.UserAgent, cfg.RL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil || len(data) == 0 {
		return ""
	}
	if !isImageContent(resp.Header.Get("Content-Type"), data) {
		return ""
	}
	// Shodan format: base64-encode with newlines every 76 chars, then mmh3
	encoded := base64EncodeMime(data)
	h := murmur3Hash32(encoded)
	var signed int64
	if h <= math.MaxInt32 {
		signed = int64(h)
	} else {
		signed = int64(h) - (1 << 32)
	}
	return strconv.FormatInt(signed, 10)
}

func discoverFaviconURL(pageURL, body string) string {
	for _, tag := range faviconLinkTagRe.FindAllString(body, -1) {
		attrs := make(map[string]string)
		for _, match := range htmlAttributeRe.FindAllStringSubmatch(tag, -1) {
			value := ""
			for i := 2; i < len(match); i++ {
				if match[i] != "" {
					value = match[i]
					break
				}
			}
			attrs[strings.ToLower(match[1])] = html.UnescapeString(value)
		}
		if !strings.Contains(strings.ToLower(attrs["rel"]), "icon") || attrs["href"] == "" {
			continue
		}
		candidate := resolveURL(pageURL, attrs["href"])
		if sameOrigin(pageURL, candidate) {
			return candidate
		}
	}

	u, err := url.Parse(pageURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	u.Path = "/favicon.ico"
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func sameOrigin(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	return errA == nil && errB == nil &&
		strings.EqualFold(ua.Scheme, ub.Scheme) &&
		strings.EqualFold(ua.Host, ub.Host)
}

func isImageContent(contentType string, data []byte) bool {
	prefixLen := len(data)
	if prefixLen > 256 {
		prefixLen = 256
	}
	prefix := strings.ToLower(strings.TrimSpace(string(data[:prefixLen])))
	if strings.HasPrefix(prefix, "<!doctype html") || strings.HasPrefix(prefix, "<html") {
		return false
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	if strings.HasPrefix(mediaType, "image/") {
		return true
	}
	if strings.HasPrefix(strings.ToLower(http.DetectContentType(data)), "image/") {
		return true
	}
	return strings.HasPrefix(prefix, "<svg")
}

// base64EncodeMime replicates Python base64.encodebytes (76-char lines + trailing \n).
func base64EncodeMime(data []byte) []byte {
	raw := base64.StdEncoding.EncodeToString(data)
	var sb strings.Builder
	for i := 0; i < len(raw); i += 76 {
		end := i + 76
		if end > len(raw) {
			end = len(raw)
		}
		sb.WriteString(raw[i:end])
		sb.WriteByte('\n')
	}
	return []byte(sb.String())
}

// ── MurmurHash3 x86 32-bit (matches Python mmh3.hash) ──

func murmur3Hash32(data []byte) uint32 {
	const (
		c1 = 0xcc9e2d51
		c2 = 0x1b873593
	)
	var h1 uint32 = 0 // seed 0
	length := len(data)
	nblocks := length / 4

	for i := 0; i < nblocks; i++ {
		k1 := uint32(data[i*4]) | uint32(data[i*4+1])<<8 |
			uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
		h1 = (h1 << 13) | (h1 >> 19)
		h1 = h1*5 + 0xe6546b64
	}

	var k1 uint32
	tail := data[nblocks*4:]
	switch length & 3 {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
	}

	if length < 0 || length > math.MaxUint32 {
		length = 0
	}
	h1 ^= uint32(length)
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16
	return h1
}

// detectTechInline is a lightweight tech fingerprint from headers + body.
func detectTechInline(headers map[string][]string, body string) []string {
	var tech []string
	get := func(k string) string {
		if v, ok := headers[k]; ok && len(v) > 0 {
			return v[0]
		}
		return ""
	}

	if s := get("Server"); s != "" {
		tech = append(tech, s)
	}
	if x := get("X-Powered-By"); x != "" {
		tech = append(tech, x)
	}

	// Body markers
	markers := map[string]string{
		"wp-content":           "WordPress",
		"/sites/default/files": "Drupal",
		"Joomla":               "Joomla",
		"__NEXT_DATA__":        "Next.js",
		"ng-version":           "Angular",
		"data-reactroot":       "React",
		"__NUXT__":             "Nuxt.js",
		"csrf-param":           "Ruby on Rails",
		"laravel_session":      "Laravel",
		"/jquery-":             "jQuery",
		"/jquery.min.js":       "jQuery",
		"/modernizr-":          "Modernizr",
		"/modernizr.min.js":    "Modernizr",
	}
	for marker, name := range markers {
		if strings.Contains(body, marker) && !containsStr(tech, name) {
			tech = append(tech, name)
		}
	}
	return tech
}

func containsStr(slice []string, s string) bool {
	for _, x := range slice {
		if x == s {
			return true
		}
	}
	return false
}
