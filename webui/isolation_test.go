package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// TestPerUserScanIsolation verifies that, with the login panel active, a regular
// user may only see and act on the scans they submitted, while an administrator
// sees every scan. It covers live jobs, on-disk reports (ownership sidecar),
// legacy reports without a sidecar (admin-only), listing, log/report reads and
// cancellation.
func TestPerUserScanIsolation(t *testing.T) {
	s, adminCookie, _ := newAuthTestServer(t, "admin", "admin-strong-password")

	if _, err := s.auth.createUser("alice", "alice-strong-password", RoleUser, false); err != nil {
		t.Fatalf("create alice: %v", err)
	}
	if _, err := s.auth.createUser("bob", "bob-strong-password", RoleUser, false); err != nil {
		t.Fatalf("create bob: %v", err)
	}
	aliceRaw, aliceSess, err := s.auth.createSession("alice", RoleUser)
	if err != nil {
		t.Fatalf("alice session: %v", err)
	}
	bobRaw, bobSess, err := s.auth.createSession("bob", RoleUser)
	if err != nil {
		t.Fatalf("bob session: %v", err)
	}
	aliceCookie := &http.Cookie{Name: sessionCookieName, Value: aliceRaw}
	bobCookie := &http.Cookie{Name: sessionCookieName, Value: bobRaw}

	// A live in-memory scan owned by alice.
	s.mgr.mu.Lock()
	s.mgr.jobs["alice-scan"] = &Job{
		ID: "alice-scan", Target: "10.0.0.1", Owner: "alice", Status: StatusRunning,
		subs: make(map[chan string]struct{}), logBuf: []string{"secret log line"},
	}
	s.mgr.mu.Unlock()

	get := func(cookie *http.Cookie, path string) int {
		return serve(t, s, authReq("GET", path, "", cookie, "")).Code
	}

	// GET a scan: owner OK, other regular user 404, admin OK.
	if code := get(aliceCookie, "/api/scans/alice-scan"); code != http.StatusOK {
		t.Errorf("owner GET scan = %d, want 200", code)
	}
	if code := get(bobCookie, "/api/scans/alice-scan"); code != http.StatusNotFound {
		t.Errorf("non-owner GET scan = %d, want 404", code)
	}
	if code := get(adminCookie, "/api/scans/alice-scan"); code != http.StatusOK {
		t.Errorf("admin GET scan = %d, want 200", code)
	}

	// Log endpoint follows the same rule.
	if code := get(aliceCookie, "/api/scans/alice-scan/log"); code != http.StatusOK {
		t.Errorf("owner GET log = %d, want 200", code)
	}
	if code := get(bobCookie, "/api/scans/alice-scan/log"); code != http.StatusNotFound {
		t.Errorf("non-owner GET log = %d, want 404", code)
	}

	// Listing is filtered per user; admin sees everything.
	listIDs := func(cookie *http.Cookie) map[string]bool {
		rec := serve(t, s, authReq("GET", "/api/scans", "", cookie, ""))
		var list struct {
			Scans []ScanSummary `json:"scans"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
			t.Fatalf("decode list: %v", err)
		}
		ids := map[string]bool{}
		for _, sm := range list.Scans {
			ids[sm.ID] = true
		}
		return ids
	}
	if !listIDs(aliceCookie)["alice-scan"] {
		t.Error("alice's list should include her own scan")
	}
	if listIDs(bobCookie)["alice-scan"] {
		t.Error("bob's list must not include alice's scan")
	}
	if !listIDs(adminCookie)["alice-scan"] {
		t.Error("admin's list should include all scans")
	}

	// On-disk report owned by alice via the ownership sidecar.
	report := `{"target":"disk.example.com","findings":[]}`
	if err := os.WriteFile(filepath.Join(s.mgr.resultsDir, "alice-disk.json"), []byte(report), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeScanMeta(s.mgr.resultsDir, "alice-disk", scanMeta{Owner: "alice", Target: "disk.example.com"}); err != nil {
		t.Fatal(err)
	}
	if code := get(aliceCookie, "/api/scans/alice-disk/report.json"); code != http.StatusOK {
		t.Errorf("owner report download = %d, want 200", code)
	}
	if code := get(bobCookie, "/api/scans/alice-disk/report.json"); code != http.StatusNotFound {
		t.Errorf("non-owner report download = %d, want 404", code)
	}

	// A legacy report without a sidecar is admin-only.
	if err := os.WriteFile(filepath.Join(s.mgr.resultsDir, "legacy.json"), []byte(report), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := get(bobCookie, "/api/scans/legacy/report.json"); code != http.StatusNotFound {
		t.Errorf("legacy report to regular user = %d, want 404", code)
	}
	if code := get(adminCookie, "/api/scans/legacy/report.json"); code != http.StatusOK {
		t.Errorf("legacy report to admin = %d, want 200", code)
	}

	// Cancellation is owner/admin only (CSRF is valid for both callers here).
	cancel := func(cookie *http.Cookie, csrf string) int {
		return serve(t, s, authReq("POST", "/api/scans/alice-scan/cancel", "", cookie, csrf)).Code
	}
	if code := cancel(bobCookie, bobSess.CSRFToken); code != http.StatusNotFound {
		t.Errorf("non-owner cancel = %d, want 404", code)
	}
	if code := cancel(aliceCookie, aliceSess.CSRFToken); code != http.StatusOK {
		t.Errorf("owner cancel = %d, want 200", code)
	}
}
