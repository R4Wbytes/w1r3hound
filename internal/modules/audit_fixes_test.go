package modules

import (
	"testing"

	"github.com/w1r3hound/w1r3hound/internal/core"
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
