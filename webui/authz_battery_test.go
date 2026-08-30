package main

import (
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// TestSessionIdleTimeout complements TestSessionExpiry (absolute timeout): it
// ages LastSeen past the idle window while CreatedAt stays fresh, so the
// session must be treated as expired and evicted (SECURITY_ASSESSMENT §4a).
func TestSessionIdleTimeout(t *testing.T) {
	withFastKDF(t)
	s := newTestServer(t, "")
	if _, err := s.auth.createUser("ida", "idas-long-password", RoleUser, false); err != nil {
		t.Fatalf("createUser: %v", err)
	}
	raw, _, err := s.auth.createSession("ida", RoleUser)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	if _, ok := s.auth.lookupSession(raw); !ok {
		t.Fatal("fresh session not found")
	}

	// Age LastSeen beyond the idle timeout while keeping CreatedAt recent.
	s.auth.mu.Lock()
	for _, sess := range s.auth.sessions {
		sess.CreatedAt = time.Now()
		sess.LastSeen = time.Now().Add(-sessionIdleTimeout - time.Minute)
	}
	s.auth.mu.Unlock()

	if _, ok := s.auth.lookupSession(raw); ok {
		t.Fatal("idle-expired session still valid")
	}
	s.auth.mu.Lock()
	n := len(s.auth.sessions)
	s.auth.mu.Unlock()
	if n != 0 {
		t.Fatalf("idle-expired session not evicted (map size %d)", n)
	}
}

// TestForcedAuthModeGatesBeforeSetup covers W1R3HOUND_AUTH=required: the API is
// refused before any admin exists (the hard form of F-3b) while the public
// auth endpoints stay reachable so the operator can bootstrap. After setup the
// session opens the gated routes.
func TestForcedAuthModeGatesBeforeSetup(t *testing.T) {
	withFastKDF(t)
	s := newTestServer(t, "")
	forced, err := NewAuthManager(filepath.Join(t.TempDir(), "auth"), true)
	if err != nil {
		t.Fatalf("forced AuthManager: %v", err)
	}
	s.auth = forced

	if !s.auth.enabled() || !s.auth.setupRequired() {
		t.Fatalf("forced+empty: enabled=%v setupRequired=%v, want true/true", s.auth.enabled(), s.auth.setupRequired())
	}

	// The public status endpoint is reachable even before setup.
	if rec := serve(t, s, loopbackReq("GET", "/api/auth/status", nil)); rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", rec.Code)
	}

	// Read/list endpoints are gated (401) before an admin exists.
	for _, path := range []string{"/api/scans", "/api/modules"} {
		if rec := serve(t, s, loopbackReq("GET", path, nil)); rec.Code != http.StatusUnauthorized {
			t.Errorf("forced-mode GET %s = %d, want 401", path, rec.Code)
		}
	}

	// Bootstrap the admin, then the session opens the gate.
	rec := serve(t, s, authReq("POST", "/api/auth/setup", `{"username":"root","password":"first-admin-passphrase"}`, nil, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("setup code = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	cookie := sessionCookieFrom(rec)
	if cookie == nil {
		t.Fatal("setup set no session cookie")
	}
	if rec := serve(t, s, authReq("GET", "/api/scans", "", cookie, "")); rec.Code != http.StatusOK {
		t.Fatalf("authenticated /api/scans after setup = %d, want 200", rec.Code)
	}
}

// TestDeletedUserSessionRejected proves that removing an account immediately
// revokes its live sessions: a regular user deleted by an admin cannot keep
// using the console with a previously issued cookie.
func TestDeletedUserSessionRejected(t *testing.T) {
	s, adminCookie, adminCSRF := newAuthTestServer(t, "boss", "bosss-long-password")
	if _, err := s.auth.createUser("temp", "temps-long-password", RoleUser, false); err != nil {
		t.Fatalf("createUser: %v", err)
	}
	raw, _, err := s.auth.createSession("temp", RoleUser)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	tempCookie := &http.Cookie{Name: sessionCookieName, Value: raw}

	if rec := serve(t, s, authReq("GET", "/api/auth/me", "", tempCookie, "")); rec.Code != http.StatusOK {
		t.Fatalf("temp session before delete = %d, want 200", rec.Code)
	}
	if rec := serve(t, s, authReq("DELETE", "/api/auth/users/temp", "", adminCookie, adminCSRF)); rec.Code != http.StatusOK {
		t.Fatalf("delete temp = %d, want 200", rec.Code)
	}
	if rec := serve(t, s, authReq("GET", "/api/auth/me", "", tempCookie, "")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("deleted user's session = %d, want 401", rec.Code)
	}
}
