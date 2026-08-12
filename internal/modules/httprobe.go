package modules

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/w1r3hound/w1r3hound/internal/core"
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
	ContentLen  int      `json:"content_length"`
}

var probeTitleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

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

	// If the operator's own target carries an explicit port or scheme
	// (http://127.0.0.1:3000, https://host:8443), probing scheme://host on
	// default ports misses it entirely — 443/80 get connection-refused while
	// the real app sits on :3000. Probe the exact target URL first, then the
	// scheme-expanded host list as before. Verified against OWASP Juice Shop
	// on 127.0.0.1:3000: previously reported "Live hosts: 0/1" on a live app.
	targetURL := normalizeTarget(cfg.Target)
	hasExplicitTarget := strings.Contains(cfg.Target, "://") &&
		(strings.Contains(strings.SplitN(strings.SplitN(cfg.Target, "://", 2)[1], "/", 2)[0], ":") ||
			strings.HasPrefix(cfg.Target, "http://"))

	log.Info("Probing %d hosts for HTTP/HTTPS liveness...", len(targets))

	client := core.NewHTTPClient(cfg)
	result := ProbeResult{
		FaviconHashes: make(map[string]string),
		TotalProbed:   len(targets),
	}
	if hasExplicitTarget {
		result.TotalProbed++
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
		resp.Body.Close()
		body := string(bodyBytes)

		lh := LiveHost{
			URL:        url,
			StatusCode: resp.StatusCode,
			Server:     resp.Header.Get("Server"),
			ContentLen: len(bodyBytes),
		}

		if m := probeTitleRe.FindStringSubmatch(body); len(m) > 1 {
			lh.Title = strings.TrimSpace(strings.ReplaceAll(m[1], "\n", " "))
			lh.Title = truncate(lh.Title, 80)
		}

		lh.Tech = detectTechInline(resp.Header, body)

		if strings.HasPrefix(url, "https://") {
			if fh := computeFavicon(client, url, cfg); fh != "" {
				lh.FaviconHash = fh
				mu.Lock()
				result.FaviconHashes[url] = fh
				mu.Unlock()
			}
		}

		mu.Lock()
		result.LiveHosts = append(result.LiveHosts, lh)
		mu.Unlock()

		log.Info("  [%d] %-45s %s", resp.StatusCode, url, truncate(lh.Title, 40))
	}

	if hasExplicitTarget {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer core.RecoverWorker(log, "httprobe")
			defer wg.Done()
			defer func() { <-sem }()
			probeOne(targetURL)
		}()
	}

	for _, host := range targets {
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
				resp.Body.Close()
				body := string(bodyBytes)

				lh := LiveHost{
					URL:        url,
					StatusCode: resp.StatusCode,
					Server:     resp.Header.Get("Server"),
					ContentLen: len(bodyBytes),
				}

				if m := probeTitleRe.FindStringSubmatch(body); len(m) > 1 {
					lh.Title = strings.TrimSpace(strings.ReplaceAll(m[1], "\n", " "))
					lh.Title = truncate(lh.Title, 80)
				}

				lh.Tech = detectTechInline(resp.Header, body)

				// Compute favicon hash on https and attach it to this host record
				// AND the shared map (both stay consistent).
				if scheme == "https" {
					fh := computeFavicon(client, scheme+"://"+host, cfg)
					if fh != "" {
						lh.FaviconHash = fh
						mu.Lock()
						result.FaviconHashes[host] = fh
						mu.Unlock()
					}
				}

				mu.Lock()
				result.LiveHosts = append(result.LiveHosts, lh)
				mu.Unlock()

				log.Info("  [%d] %-45s %s", resp.StatusCode, url, truncate(lh.Title, 40))
			}(host, scheme)
		}
	}
	wg.Wait()

	// Dedupe live hosts: a host may respond on both http+https. Collapse to one
	// entry per hostname, preferring the https result.
	byHost := make(map[string]LiveHost)
	for _, lh := range result.LiveHosts {
		host := lh.URL
		host = strings.TrimPrefix(host, "https://")
		host = strings.TrimPrefix(host, "http://")
		host = strings.SplitN(host, "/", 2)[0]
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

// computeFavicon downloads /favicon.ico and computes the mmh3 hash
// in the same base64-then-hash format Shodan uses. A matching hash on
// Shodan (http.favicon.hash:) reveals all hosts serving the same app.
func computeFavicon(client *http.Client, base string, cfg *core.Config) string {
	resp, err := core.DoRequestRL(client, "GET", base+"/favicon.ico", cfg.UserAgent, cfg.RL)
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
	// Shodan format: base64-encode with newlines every 76 chars, then mmh3
	encoded := base64EncodeMime(data)
	h := murmur3Hash32(encoded)
	return fmt.Sprintf("%d", int32(h))
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
