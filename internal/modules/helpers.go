package modules

import "strings"

func normalizeTarget(target string) string {
	// Trim the trailing slash before branching so both the schemeless and
	// schemed inputs get the same treatment (previously only the "already has
	// a scheme" branch trimmed it, so "example.com/" kept its trailing slash
	// while "https://example.com/" didn't — inconsistent Origin/URL building
	// downstream, e.g. in the CORS check).
	target = strings.TrimRight(target, "/")
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return "https://" + target
	}
	return target
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func isNonRoutableDomain(domain string) bool {
	d := strings.ToLower(domain)
	if !strings.Contains(d, ".") {
		return true
	}
	for _, suffix := range []string{".local", ".localhost", ".test", ".invalid", ".example", ".internal", ".lan", ".home", ".arpa"} {
		if strings.HasSuffix(d, suffix) {
			return true
		}
	}
	return false
}

func isCloudflareChallenge(body string) bool {
	if len(body) > 10000 {
		return false
	}
	lower := strings.ToLower(body)
	return strings.Contains(lower, "just a moment") &&
		strings.Contains(lower, "cloudflare") &&
		strings.Contains(lower, "challenge-platform")
}
