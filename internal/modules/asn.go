package modules

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/w1r3hound/w1r3hound/internal/core"
)

// ══════════════════════════════════════════════
//  ASN / CIDR DISCOVERY
//  Maps organisation → ASN → IP ranges via BGP
//  data. Finds IP space DNS enumeration misses.
//  (Checklist Fase 0.1: ASN/CIDR discovery)
// ══════════════════════════════════════════════

type ASNResult struct {
	TargetIP    string      `json:"target_ip"`
	ASN         string      `json:"asn,omitempty"`
	ASNName     string      `json:"asn_name,omitempty"`
	Prefixes    []ASNPrefix `json:"prefixes,omitempty"`
	RelatedASNs []ASNInfo   `json:"related_asns,omitempty"`
}

type ASNPrefix struct {
	CIDR        string `json:"cidr"`
	Description string `json:"description,omitempty"`
}

type ASNInfo struct {
	ASN         string `json:"asn"`
	Name        string `json:"name"`
	CountryCode string `json:"country,omitempty"`
}

func RunASN(cfg *core.Config, report *core.ReconReport, log *core.Logger) {
	log.Module("ASNMAP // ASN & CIDR Range Discovery")

	client := core.NewHTTPClient(cfg)
	domain := cfg.Domain

	// 1. Resolve the target to an IP
	ctx, cancel := cfg.Context(cfg.Timeout)
	defer cancel()
	ips, err := cfg.Resolver.LookupHost(ctx, domain)
	if err != nil || len(ips) == 0 {
		log.Error("Could not resolve %s: %v", domain, err)
		return
	}

	// Pick first IPv4
	targetIP := ""
	for _, ip := range ips {
		if net.ParseIP(ip).To4() != nil {
			targetIP = ip
			break
		}
	}
	if targetIP == "" {
		targetIP = ips[0]
	}

	result := ASNResult{TargetIP: targetIP}
	log.Info("Target resolves to %s", targetIP)

	// Detect if the IP belongs to a known CDN (the ASN would be the CDN's, not
	// the org's). In that case the org-name search below is the useful path.
	if cdn := detectCDNByIP(targetIP); cdn != "" {
		log.Warn("Target IP is behind %s CDN — ASN reflects the CDN, not the origin", cdn)
		result.ASNName = cdn + " (CDN — not origin)"
	}

	// 2. Look up ASN for the IP via BGPView API
	url := fmt.Sprintf("https://api.bgpview.io/ip/%s", targetIP)
	body, status, err := core.FetchBodyRL(client, url, cfg.UserAgent, cfg.RL)
	if err != nil || status != 200 {
		log.Debug("bgpview IP lookup failed: %v (status %d)", err, status)
	} else {
		var ipData struct {
			Data struct {
				Prefixes []struct {
					Prefix string `json:"prefix"`
					ASN    struct {
						ASN         int    `json:"asn"`
						Name        string `json:"name"`
						Description string `json:"description"`
						CountryCode string `json:"country_code"`
					} `json:"asn"`
				} `json:"prefixes"`
			} `json:"data"`
		}
		if json.Unmarshal([]byte(body), &ipData) == nil && len(ipData.Data.Prefixes) > 0 {
			p := ipData.Data.Prefixes[0]
			result.ASN = fmt.Sprintf("AS%d", p.ASN.ASN)
			result.ASNName = p.ASN.Name
			log.Info("ASN: %s (%s) — %s", result.ASN, p.ASN.Name, p.ASN.CountryCode)

			// 3. Get all prefixes announced by this ASN
			asnURL := fmt.Sprintf("https://api.bgpview.io/asn/%d/prefixes", p.ASN.ASN)
			asnBody, asnStatus, asnErr := core.FetchBodyRL(client, asnURL, cfg.UserAgent, cfg.RL)
			if asnErr == nil && asnStatus == 200 {
				var prefixData struct {
					Data struct {
						IPv4Prefixes []struct {
							Prefix      string `json:"prefix"`
							Description string `json:"description"`
						} `json:"ipv4_prefixes"`
						IPv6Prefixes []struct {
							Prefix      string `json:"prefix"`
							Description string `json:"description"`
						} `json:"ipv6_prefixes"`
					} `json:"data"`
				}
				if json.Unmarshal([]byte(asnBody), &prefixData) == nil {
					for _, pf := range prefixData.Data.IPv4Prefixes {
						result.Prefixes = append(result.Prefixes, ASNPrefix{
							CIDR: pf.Prefix, Description: pf.Description,
						})
					}
					for _, pf := range prefixData.Data.IPv6Prefixes {
						result.Prefixes = append(result.Prefixes, ASNPrefix{
							CIDR: pf.Prefix, Description: pf.Description,
						})
					}
					log.Info("ASN announces %d prefixes", len(result.Prefixes))
					cfg.SharedMu.Lock()
					for _, pf := range result.Prefixes {
						log.Debug("  %s  %s", pf.CIDR, truncate(pf.Description, 40))
						cfg.SharedIPs = append(cfg.SharedIPs, pf.CIDR)
					}
					cfg.SharedMu.Unlock()
				}
			}
		}
	}

	// 4. Search for related ASNs by organisation name
	orgName := strings.Split(domain, ".")[0]
	searchURL := fmt.Sprintf("https://api.bgpview.io/search?query_term=%s", orgName)
	searchBody, searchStatus, searchErr := core.FetchBodyRL(client, searchURL, cfg.UserAgent, cfg.RL)
	if searchErr == nil && searchStatus == 200 {
		var searchData struct {
			Data struct {
				ASNs []struct {
					ASN         int    `json:"asn"`
					Name        string `json:"name"`
					Description string `json:"description"`
					CountryCode string `json:"country_code"`
				} `json:"asns"`
			} `json:"data"`
		}
		if json.Unmarshal([]byte(searchBody), &searchData) == nil {
			for _, a := range searchData.Data.ASNs {
				result.RelatedASNs = append(result.RelatedASNs, ASNInfo{
					ASN:         fmt.Sprintf("AS%d", a.ASN),
					Name:        a.Name,
					CountryCode: a.CountryCode,
				})
			}
			if len(result.RelatedASNs) > 0 {
				log.Info("Found %d ASNs matching org name '%s'", len(result.RelatedASNs), orgName)
				for _, a := range result.RelatedASNs {
					log.Debug("  %s  %s (%s)", a.ASN, a.Name, a.CountryCode)
				}
			}
		}
	}

	sev := core.SevInfo
	if len(result.Prefixes) > 5 {
		sev = core.SevLow // large IP footprint worth investigating
	}

	asnLabel := result.ASN
	if asnLabel == "" {
		if result.ASNName != "" {
			asnLabel = result.ASNName
		} else {
			asnLabel = "unknown (lookup failed for " + result.TargetIP + ")"
		}
	}

	report.Add(core.Finding{
		Module:      "asnmap",
		WSTG:        "WSTG-INFO-04",
		Title:       fmt.Sprintf("ASN mapping: %s with %d prefixes, %d related ASNs", asnLabel, len(result.Prefixes), len(result.RelatedASNs)),
		Severity:    sev,
		Description: "IP ranges owned by the organisation, discoverable beyond DNS.",
		Data:        result,
	})
}

// detectCDNByIP checks if an IP falls in well-known CDN ranges (rough prefixes).
func detectCDNByIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	cdnRanges := map[string][]string{
		"Cloudflare": {"104.16.0.0/13", "172.64.0.0/13", "173.245.48.0/20", "103.21.244.0/22", "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.24.0.0/14", "131.0.72.0/22"},
		"Fastly":     {"151.101.0.0/16", "199.232.0.0/16"},
		"Akamai":     {"23.32.0.0/11", "23.192.0.0/11", "104.64.0.0/10", "184.24.0.0/13"},
		"CloudFront": {"13.32.0.0/15", "13.224.0.0/14", "52.84.0.0/15", "54.182.0.0/16", "54.192.0.0/16", "204.246.164.0/22"},
	}
	for cdn, ranges := range cdnRanges {
		for _, r := range ranges {
			_, ipnet, err := net.ParseCIDR(r)
			if err == nil && ipnet.Contains(parsed) {
				return cdn
			}
		}
	}
	return ""
}
