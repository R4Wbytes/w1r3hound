package modules

import (
	"testing"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

// B1: on a catch-all server (bugcrowd/Fastly), a sensitive path whose body is
// byte-identical to the shell must be DROPPED, not reported CRITICAL. A
// sensitive path with a DIFFERENT body (a real file) must survive.
func TestClusterFilter_ContentAware_DropsShellIdenticalCriticals(t *testing.T) {
	const shellHash = uint32(0xAAAA0001)
	const realHash = uint32(0xBBBB0002)

	var entries []DirEntry
	// 40 dictionary paths that all return the same 1237-byte shell body.
	for _, p := range []string{
		"/webmail", "/control", "/signin", "/auth", "/auth/login", "/config.yml",
		"/config.json", "/config.yaml", "/db.conf", "/backup", "/db.sql", "/dump.sql",
		"/www.zip", "/public.zip", "/data.sql", "/debug.php", "/test.php", "/swagger",
		"/trace.axd", "/api/v2", "/api/v1", "/api/docs", "/api/v3", "/altair",
		"/package.json", "/go.mod", "/node", "/debug/vars", "/debug/pprof", "/ready",
		"/errors/", "/error", "/wp-content/", "/backup/", "/backup.zip", "/swagger/",
		"/api/swagger.json", "/Cargo.toml", "/sites/default/files/", "/wp-content/debug.log",
	} {
		entries = append(entries, DirEntry{Path: p, StatusCode: 200, Size: 1237, bodyHash: shellHash})
	}
	// /config.php IS the shell (same body) → must be dropped (this was the false CRITICAL).
	entries = append(entries, DirEntry{Path: "/config.php", StatusCode: 200, Size: 1237, bodyHash: shellHash})
	// /backup.sql IS the shell → must be dropped (was the false MEDIUM).
	entries = append(entries, DirEntry{Path: "/backup.sql", StatusCode: 200, Size: 1237, bodyHash: shellHash})
	// /.env is a REAL file (different body, same size) → must survive.
	entries = append(entries, DirEntry{Path: "/.env", StatusCode: 200, Size: 1237, bodyHash: realHash})
	// A 403 must always survive.
	entries = append(entries, DirEntry{Path: "/server-status", StatusCode: 403, Size: 900})

	baseline := soft404Baseline{status: 404} // random paths → hard 404
	kept := clusterFilterSoft404s(entries, baseline, core.NewLogger(false))

	survived := map[string]bool{}
	for _, e := range kept {
		survived[e.Path] = true
	}
	if survived["/config.php"] {
		t.Error("/config.php is shell-identical and MUST be dropped (false CRITICAL)")
	}
	if survived["/backup.sql"] {
		t.Error("/backup.sql is shell-identical and MUST be dropped (false MEDIUM)")
	}
	if !survived["/.env"] {
		t.Error("/.env has a distinct body (real file) and MUST survive")
	}
	if !survived["/server-status"] {
		t.Error("403 responses must always survive")
	}
}

// B3: only genuine Source Map v3 documents are accepted; the HTML app shell
// returned with status 200 on a catch-all server is rejected.
func TestLooksLikeSourceMap(t *testing.T) {
	real := `{"version":3,"file":"app.js","sources":["a.ts"],"names":[],"mappings":"AAAA"}`
	if !looksLikeSourceMap(real) {
		t.Error("valid source map rejected")
	}
	shell := `<!DOCTYPE html><html><head><title>Page not found</title></head><body>404</body></html>`
	if looksLikeSourceMap(shell) {
		t.Error("HTML shell wrongly accepted as source map")
	}
	if looksLikeSourceMap(`{"version":3}`) {
		t.Error("partial JSON without mappings/sources should be rejected")
	}
}

// B2: a 200 that is the HTML shell is NOT an API; JSON / error envelopes are.
func TestLooksLikeAPIResponse(t *testing.T) {
	if !looksLikeAPIResponse(`{"error":"unauthorized"}`) {
		t.Error("JSON error envelope should look like an API")
	}
	if !looksLikeAPIResponse(`   [ {"id":1} ]`) {
		t.Error("JSON array should look like an API")
	}
	if looksLikeAPIResponse(`<!doctype html><html><body>home</body></html>`) {
		t.Error("HTML shell must not be treated as an API response")
	}
	if looksLikeAPIResponse("") {
		t.Error("empty body is not an API response")
	}
}

// B12: maskSecret must never panic on very short inputs.
func TestMaskSecret_NoPanicShort(t *testing.T) {
	for _, s := range []string{"", "a", "ab", "abc", "abcdefgh", "abcdefghijklmnop"} {
		_ = maskSecret(s) // must not panic
	}
}

// IP-literal targets have no domain namespace for CT/passive DNS discovery,
// and Wayback results for shared/reused IPs cannot be attributed to the
// application under test.
func TestIsIPLiteral(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "192.168.1.10", "::1", "[::1]", "2001:db8::1"} {
		if !isIPLiteral(host) {
			t.Errorf("isIPLiteral(%q) = false, want true", host)
		}
	}
	for _, host := range []string{"localhost", "juice-shop.local", "example.com"} {
		if isIPLiteral(host) {
			t.Errorf("isIPLiteral(%q) = true, want false", host)
		}
	}
}

func TestIsPublicASNAddress(t *testing.T) {
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !isPublicASNAddress(ip) {
			t.Errorf("isPublicASNAddress(%q) = false, want true", ip)
		}
	}
	for _, ip := range []string{
		"127.0.0.1", "10.0.0.1", "192.168.1.1", "100.64.0.1",
		"192.0.2.1", "198.51.100.1", "203.0.113.1",
		"::1", "fc00::1", "fe80::1", "2001:db8::1", "not-an-ip",
	} {
		if isPublicASNAddress(ip) {
			t.Errorf("isPublicASNAddress(%q) = true, want false", ip)
		}
	}
}

func TestIsPublicClientCredential_AlgoliaDocSearch(t *testing.T) {
	docSearch := SecretMatch{
		Type:    "Generic API Key",
		Context: "appId: '8NAIIMTFB5', apiKey: 'masked', indexName: 'docs'",
	}
	if !isPublicClientCredential(docSearch) {
		t.Error("Algolia DocSearch browser key should be classified as a public client credential")
	}
	for name, tc := range map[string]struct{ context, wantType string }{
		"amplitude": {`analytics:{config:{amplitude:{enabled:true,jsApiKey:"masked"}}}`, "Amplitude Browser API Key"},
		"stigg":     {`stigg:{clientApiKey:"client-masked"}`, "Stigg Client API Key"},
		"stripe":    {`stripe_publishable_api_key:"pk_live_masked"`, "Stripe Publishable Key"},
	} {
		match := SecretMatch{Type: "Generic API Key", Context: tc.context}
		if !isPublicClientCredential(match) {
			t.Errorf("%s browser credential should be public", name)
		}
		if got := publicClientCredentialType(match); got != tc.wantType {
			t.Errorf("%s credential type = %q, want %q", name, got, tc.wantType)
		}
	}
	adminLike := SecretMatch{
		Type:    "Generic API Key",
		Context: "apiKey: 'masked', role: 'admin'",
	}
	if isPublicClientCredential(adminLike) {
		t.Error("generic API key without DocSearch context must remain a potential secret")
	}
	if !isPublicClientCredential(SecretMatch{Type: "Google OAuth ID"}) {
		t.Error("existing public OAuth credential classification regressed")
	}
}

func TestParseHackerTargetASN(t *testing.T) {
	asn, name, prefix := parseHackerTargetASN(
		`"172.64.151.42","13335","172.64.151.0/24","CLOUDFLARENET, US"`,
	)
	if asn != "AS13335" || name != "CLOUDFLARENET, US" || prefix != "172.64.151.0/24" {
		t.Fatalf("unexpected ASN fallback parse: %q %q %q", asn, name, prefix)
	}
	if asn, _, _ := parseHackerTargetASN("error check your query"); asn != "" {
		t.Fatalf("error response parsed as ASN %q", asn)
	}
}

func TestScanForSecrets_DeduplicatesStripePublishableKey(t *testing.T) {
	var result ContentResult
	scanForSecrets(
		&result,
		`stripe_publishable_api_key:"pk_live_1234567890abcdefghijklmn"`,
		"test",
		core.NewLogger(false),
	)
	if len(result.SecretsFound) != 1 || result.SecretsFound[0].Type != "Stripe Publishable Key" {
		t.Fatalf("Stripe publishable key should have one specific match, got %+v", result.SecretsFound)
	}
}

func TestScanForSecrets_DropsPasswordSchemaDescriptor(t *testing.T) {
	var result ContentResult
	scanForSecrets(
		&result,
		`properties:{implicit:"ImplicitFlow",password:"PasswordFlow",clientCredentials:"ClientCredentials"}`,
		"redoc.js",
		core.NewLogger(false),
	)
	if len(result.SecretsFound) != 0 {
		t.Fatalf("OAuth schema descriptor was reported as a password: %+v", result.SecretsFound)
	}

	scanForSecrets(
		&result,
		`config={password:"S3cretValue!"}`,
		"app.js",
		core.NewLogger(false),
	)
	if len(result.SecretsFound) != 1 || result.SecretsFound[0].Type != "Hardcoded Password" {
		t.Fatalf("secret-like password should remain reportable, got %+v", result.SecretsFound)
	}
}
