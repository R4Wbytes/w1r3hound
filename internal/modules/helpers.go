package modules

import (
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

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

func isIPLiteral(host string) bool {
	return net.ParseIP(strings.Trim(host, "[]")) != nil
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

func writeRawHTTPRequest(w io.Writer, requestLine, host string, cfg *core.Config) {
	if cfg.RL != nil {
		cfg.RL.Wait()
	}
	clean := func(value string) string {
		value = strings.ReplaceAll(value, "\r", " ")
		return strings.ReplaceAll(value, "\n", " ")
	}
	_, _ = fmt.Fprintf(w, "%s\r\nHost: %s\r\n", clean(requestLine), clean(host))
	if cfg.UserAgent != "" {
		_, _ = fmt.Fprintf(w, "User-Agent: %s\r\n", clean(cfg.UserAgent))
	}
	names := make([]string, 0, len(cfg.RequestHeaders))
	for name := range cfg.RequestHeaders {
		if strings.ContainsAny(name, "\r\n:") ||
			strings.EqualFold(name, "Host") ||
			strings.EqualFold(name, "User-Agent") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		_, _ = fmt.Fprintf(w, "%s: %s\r\n", name, clean(cfg.RequestHeaders[name]))
	}
	_, _ = fmt.Fprint(w, "\r\n")
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

var genericErrorTitlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// isGenericErrorPage detects branded error documents that incorrectly return
// HTTP 200. Auditing their headers or content as the requested application
// creates false findings (for example api.bugcrowd.com's root error page).
// Require both a generic error title segment and an explicit body marker so
// ordinary documentation that merely discusses 404 handling is not skipped.
func isGenericErrorPage(body string) bool {
	titleMatch := genericErrorTitlePattern.FindStringSubmatch(body)
	if len(titleMatch) < 2 {
		return false
	}
	titleSignal := false
	for _, part := range strings.FieldsFunc(strings.ToLower(titleMatch[1]), func(r rune) bool {
		return r == '|' || r == '-' || r == ':'
	}) {
		switch strings.TrimSpace(part) {
		case "error", "404", "404 not found", "not found", "page not found",
			"forbidden", "access denied", "unauthorized", "bad request", "service unavailable":
			titleSignal = true
		}
	}
	if !titleSignal {
		return false
	}

	lower := strings.ToLower(body)
	for _, marker := range []string{
		"requested page was not found",
		"page was not found",
		"server returned http status 404",
		"page does not exist",
		"access denied",
		"request could not be processed",
		"service unavailable",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
