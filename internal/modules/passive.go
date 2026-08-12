package modules

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/w1r3hound/w1r3hound/internal/core"
)

// ══════════════════════════════════════════════
//  PASSIVE SUBDOMAIN DISCOVERY
//  Certificate Transparency logs (crt.sh, CertSpotter),\n//  HackerTarget, AlienVault OTX, RapidDNS and Anubis.
//  Pure passive — no traffic to target.
//  (Checklist Fase 1.1: CT logs, passive DNS)
// ══════════════════════════════════════════════

type PassiveResult struct {
	Subdomains  []string       `json:"subdomains"`
	BySource    map[string]int `json:"count_by_source"`
	TotalUnique int            `json:"total_unique"`
	// Fix #2 (2026-08-07): coverage metadata so users can see
	// how many sources were attempted and how many failed. The original report
	// only showed counts, hiding that 4/5 sources had silently failed.
	SourcesAttempted  []string `json:"sources_attempted"`
	SourcesFailed     []string `json:"sources_failed"`
	SourcesSuccessful []string `json:"sources_successful"`
}

var subdomainRe = regexp.MustCompile(`[a-zA-Z0-9]([a-zA-Z0-9\-\_\.]{0,120}[a-zA-Z0-9])?\.[a-zA-Z]{2,}`)

func RunPassive(cfg *core.Config, report *core.ReconReport, log *core.Logger) {
	log.Module("PASSIVESRC // CT Logs & Passive DNS Aggregation")

	domain := cfg.Domain
	client := core.NewHTTPClient(cfg)

	// Fix #5 (2026-08-11): normalise subdomain targets to the
	// apex for passive DNS sources. crt.sh, hackertarget, rapiddns, anubis and
	// OTX all accept apex domains and return subdomains OF that apex. Filtering
	// the results against a subdomain target (e.g. `www.<apex>`)
	// discards real subdomains because they don't end in `.www.<apex>` —
	// producing "1 unique subdomain" when the apex has 10+.
	if apex := extractApexDomain(domain); apex != domain {
		log.Info("Passive source target %q is a subdomain — normalising to apex %q for query and result matching", domain, apex)
		domain = apex
	}

	result := PassiveResult{BySource: make(map[string]int)}
	found := make(map[string]bool)
	var mu sync.Mutex

	// Fix #2 (2026-08-07): track attempted/successful/failed
	// sources so the report shows coverage gaps and the user can decide to
	// re-run with API keys, etc. Previously, when crt.sh + 4 other sources
	// silently failed (rate-limited), only rapiddns was visible — the rest
	// were hidden behind log.Debug() and the report showed a misleading
	// "Passive subdomain discovery: 95 unique from 1 sources".
	sourcesAttempted := []string{"crt.sh", "hackertarget", "alienvault", "rapiddns", "anubis", "certspotter"}
	sourcesFailed := make(map[string]bool)
	var sourcesMu sync.Mutex
	recordFailure := func(name string) {
		sourcesMu.Lock()
		sourcesFailed[name] = true
		sourcesMu.Unlock()
	}

	add := func(source string, subs []string) {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, s := range subs {
			s = strings.ToLower(strings.TrimSpace(s))
			s = strings.TrimPrefix(s, "*.")
			s = strings.TrimPrefix(s, ".")
			// Only keep subdomains of the target domain
			if s == "" || (!strings.HasSuffix(s, "."+domain) && s != domain) {
				continue
			}
			if !found[s] {
				found[s] = true
				n++
			}
		}
		if n > 0 {
			result.BySource[source] += n
			log.Info("%-16s +%d new subdomains", source, n)
		}
	}

	var wg sync.WaitGroup

	// ── Source 1: crt.sh (Certificate Transparency) ──
	// crt.sh is the highest-value source but frequently slow/rate-limited, so
	// give it a dedicated client with a longer timeout and one retry.
	wg.Add(1)
	go func() {
		defer core.RecoverWorker(log, "passivesrc")
		defer wg.Done()
		ctClient := core.NewHTTPClient(cfg)
		ctClient.Timeout = 30 * time.Second // crt.sh can be slow
		url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

		var body string
		var status int
		var err error
		for attempt := 0; attempt < 2; attempt++ {
			body, status, err = core.FetchBodyRL(ctClient, url, cfg.UserAgent, cfg.RL)
			if err == nil && status == 200 {
				break
			}
			if attempt == 0 {
				log.Debug("crt.sh attempt 1 failed (status %d), retrying...", status)
				time.Sleep(2 * time.Second)
			}
		}
		if err != nil || status != 200 {
			// Fix #2: surface source failure (was log.Debug only)
			log.Warn("crt.sh unavailable (status %d) — CT data missing, results may be incomplete", status)
			recordFailure("crt.sh")
			return
		}
		var entries []struct {
			NameValue string `json:"name_value"`
		}
		if err := json.Unmarshal([]byte(body), &entries); err != nil {
			log.Warn("crt.sh returned unparseable data (not JSON) — CT data missing")
			recordFailure("crt.sh")
			return
		}
		var subs []string
		for _, e := range entries {
			for _, name := range strings.Split(e.NameValue, "\n") {
				subs = append(subs, name)
			}
		}
		add("crt.sh", subs)
	}()

	// ── Source 2: HackerTarget ──
	wg.Add(1)
	go func() {
		defer core.RecoverWorker(log, "passivesrc")
		defer wg.Done()
		url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
		body, status, err := core.FetchBodyRL(client, url, cfg.UserAgent, cfg.RL)
		if err != nil || status != 200 || strings.Contains(body, "API count exceeded") {
			// Fix #2: surface source failure (was log.Debug only)
			log.Warn("hackertarget failed (status %d, err %v) — source omitted", status, err)
			recordFailure("hackertarget")
			return
		}
		var subs []string
		for _, line := range strings.Split(body, "\n") {
			parts := strings.SplitN(line, ",", 2)
			if len(parts) > 0 {
				subs = append(subs, parts[0])
			}
		}
		add("hackertarget", subs)
	}()

	// ── Source 3: AlienVault OTX ──
	wg.Add(1)
	go func() {
		defer core.RecoverWorker(log, "passivesrc")
		defer wg.Done()
		url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
		body, status, err := core.FetchBodyRL(client, url, cfg.UserAgent, cfg.RL)
		if err != nil || status != 200 {
			// Fix #2: surface source failure (was log.Debug only)
			log.Warn("alienvault failed (status %d, err %v) — source omitted", status, err)
			recordFailure("alienvault")
			return
		}
		var data struct {
			PassiveDNS []struct {
				Hostname string `json:"hostname"`
			} `json:"passive_dns"`
		}
		if err := json.Unmarshal([]byte(body), &data); err != nil {
			log.Warn("alienvault returned unparseable data — source omitted")
			recordFailure("alienvault")
			return
		}
		var subs []string
		for _, r := range data.PassiveDNS {
			subs = append(subs, r.Hostname)
		}
		add("alienvault", subs)
	}()

	// ── Source 4: RapidDNS ──
	wg.Add(1)
	go func() {
		defer core.RecoverWorker(log, "passivesrc")
		defer wg.Done()
		url := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", domain)
		body, status, err := core.FetchBodyRL(client, url, cfg.UserAgent, cfg.RL)
		if err != nil || status != 200 {
			// Fix #2: surface source failure (was log.Debug only)
			log.Warn("rapiddns failed (status %d, err %v) — source omitted", status, err)
			recordFailure("rapiddns")
			return
		}
		// Scrape subdomains from HTML table
		matches := subdomainRe.FindAllString(body, -1)
		add("rapiddns", matches)
	}()

	// ── Source 5: Anubis (jonlundy) ──
	// NOTE: ThreatCrowd was removed here — the API has been discontinued for years
	// and only ever produced a wasted request + timeout.
	wg.Add(1)
	go func() {
		defer core.RecoverWorker(log, "passivesrc")
		defer wg.Done()
		url := fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", domain)
		body, status, err := core.FetchBodyRL(client, url, cfg.UserAgent, cfg.RL)
		if err != nil || status != 200 {
			// Fix #2: surface source failure (was log.Debug only)
			log.Warn("anubis failed (status %d, err %v) — source omitted", status, err)
			recordFailure("anubis")
			return
		}
		var subs []string
		if err := json.Unmarshal([]byte(body), &subs); err != nil {
			log.Warn("anubis returned unparseable data — source omitted")
			recordFailure("anubis")
			return
		}
		add("anubis", subs)
	}()

	// ── Source 6: Certspotter (SSLMate) ──
	// Keyless CT log aggregator, separate from crt.sh's own dataset (different
	// crawl cadence/coverage) — a second CT source catches certs the first
	// misses. Unauthenticated requests are rate-limited by the API itself; a
	// 429 just lands as a normal source failure like any other.
	wg.Add(1)
	go func() {
		defer core.RecoverWorker(log, "passivesrc")
		defer wg.Done()
		url := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain)
		body, status, err := core.FetchBodyRL(client, url, cfg.UserAgent, cfg.RL)
		if err != nil || status != 200 {
			log.Warn("certspotter failed (status %d, err %v) — source omitted", status, err)
			recordFailure("certspotter")
			return
		}
		var issuances []struct {
			DNSNames []string `json:"dns_names"`
		}
		if err := json.Unmarshal([]byte(body), &issuances); err != nil {
			log.Warn("certspotter returned unparseable data — source omitted")
			recordFailure("certspotter")
			return
		}
		var subs []string
		for _, iss := range issuances {
			subs = append(subs, iss.DNSNames...)
		}
		add("certspotter", subs)
	}()

	wg.Wait()

	// Collect and sort
	for s := range found {
		result.Subdomains = append(result.Subdomains, s)
	}
	sort.Strings(result.Subdomains)
	result.TotalUnique = len(result.Subdomains)

	// Fix #2 (2026-08-07): record coverage metadata.
	result.SourcesAttempted = sourcesAttempted
	for _, name := range sourcesAttempted {
		if sourcesFailed[name] {
			result.SourcesFailed = append(result.SourcesFailed, name)
		} else {
			result.SourcesSuccessful = append(result.SourcesSuccessful, name)
		}
	}
	// Sort for stable output.
	sort.Strings(result.SourcesFailed)
	sort.Strings(result.SourcesSuccessful)

	// Surface coverage gap to the user (was only in log.Debug before).
	if len(result.SourcesFailed) > 0 {
		log.Warn("Passive source coverage: %d/%d sources succeeded, %d failed: %v",
			len(result.SourcesSuccessful), len(result.SourcesAttempted),
			len(result.SourcesFailed), result.SourcesFailed)
	}

	log.Info("Total unique subdomains from passive sources: %d", result.TotalUnique)

	// Store subdomains in shared context for downstream modules
	cfg.AddSharedSubdomains(result.Subdomains)

	report.Add(core.Finding{
		Module:   "passivesrc",
		WSTG:     "WSTG-INFO-01",
		Title:    fmt.Sprintf("Passive subdomain discovery: %d unique from %d sources", result.TotalUnique, len(result.BySource)),
		Severity: core.SevInfo,
		Data:     result,
	})
}
