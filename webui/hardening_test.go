package main

// Regression tests for the 2026-08-27 dynamic red-team hardening pass:
//   - W-02: forced password rotation is enforced server-side (authGate), not
//     just by the SPA.
//   - W-01: the pre-auth PBKDF2 path (login/setup) is throttled so an
//     unauthenticated flood cannot exhaust CPU.

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestMustChangeEnforcedServerSide covers W-02. An account that still owes a
// forced password rotation may only read /api/auth/me and change its password;
// every other API route is refused with 403 until it rotates. Rotating clears
// the confinement.
func TestMustChangeEnforcedServerSide(t *testing.T) {
	prev := pbkdf2Iterations
	pbkdf2Iterations = 4096
	t.Cleanup(func() { pbkdf2Iterations = prev })

	s := newTestServer(t, "")
	// An admin-provisioned account (mustChange=true) with a temporary password.
	if _, err := s.auth.createUser("provisioned", "temp-initial-pass-1", RoleUser, true); err != nil {
		t.Fatalf("createUser: %v", err)
	}
	raw, sess, err := s.auth.createSession("provisioned", RoleUser)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	cookie := &http.Cookie{Name: sessionCookieName, Value: raw}

	// A normal API route is refused while the rotation is owed.
	req := loopbackReq("GET", "/api/scans", nil)
	req.AddCookie(cookie)
	if rec := serve(t, s, req); rec.Code != http.StatusForbidden {
		t.Fatalf("GET /api/scans (must-change) = %d, want 403", rec.Code)
	}

	// /api/auth/me stays reachable so the SPA can learn it must prompt.
	req = loopbackReq("GET", "/api/auth/me", nil)
	req.AddCookie(cookie)
	if rec := serve(t, s, req); rec.Code != http.StatusOK {
		t.Fatalf("GET /api/auth/me (must-change) = %d, want 200", rec.Code)
	}

	// Rotating the password is allowed and lifts the confinement.
	body := `{"current_password":"temp-initial-pass-1","new_password":"a-fresh-unique-pass-9"}`
	req = loopbackReq("POST", "/api/auth/change-password", strings.NewReader(body))
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", sess.CSRFToken)
	req.Header.Set("Content-Type", "application/json")
	rec := serve(t, s, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("change-password = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	// The change re-establishes the browser with a fresh session whose
	// MustChange is now false; that session can reach the rest of the API.
	var fresh *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			fresh = c
		}
	}
	if fresh == nil {
		t.Fatal("change-password did not set a fresh session cookie")
	}
	req = loopbackReq("GET", "/api/scans", nil)
	req.AddCookie(fresh)
	if rec := serve(t, s, req); rec.Code != http.StatusOK {
		t.Fatalf("GET /api/scans after rotation = %d, want 200", rec.Code)
	}
}

// TestLoginRateLimited covers W-01. With a token bucket of burst 1 and no
// refill, the first login attempt is processed (reaching auth, 401 on bad
// creds) and the next is shed with 429 without spending a PBKDF2 hash.
func TestLoginRateLimited(t *testing.T) {
	prev := pbkdf2Iterations
	pbkdf2Iterations = 4096
	t.Cleanup(func() { pbkdf2Iterations = prev })

	s := newTestServer(t, "")
	if _, err := s.auth.createUser("admin", "correct-admin-pass-1", RoleAdmin, false); err != nil {
		t.Fatalf("createUser: %v", err)
	}
	s.loginLimiter = newLoginLimiter(1, 1, 0) // burst 1, no refill

	body := `{"username":"admin","password":"wrong-password-guess"}`
	if rec := serve(t, s, loopbackReq("POST", "/api/auth/login", strings.NewReader(body))); rec.Code != http.StatusUnauthorized {
		t.Fatalf("first login = %d, want 401 (processed)", rec.Code)
	}
	if rec := serve(t, s, loopbackReq("POST", "/api/auth/login", strings.NewReader(body))); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second login = %d, want 429 (rate-limited)", rec.Code)
	}
}

// TestLoginLimiterMechanics unit-tests the token bucket + concurrency slot and
// the nil (fail-open) behavior used by tests/open-mode.
func TestLoginLimiterMechanics(t *testing.T) {
	l := newLoginLimiter(1, 2, 0) // 1 slot, burst 2, no refill

	// Each call consumes one token; burst 2 allows exactly two, then the bucket
	// is empty (kept as separate statements so the side effect is explicit).
	if !l.allowRate() {
		t.Fatal("first attempt should pass (burst=2)")
	}
	if !l.allowRate() {
		t.Fatal("second attempt should pass (burst=2)")
	}
	if l.allowRate() {
		t.Fatal("third attempt should be rate-limited (bucket empty, no refill)")
	}

	if !l.acquire(time.Second) {
		t.Fatal("first acquire should get the only slot")
	}
	if l.acquire(20 * time.Millisecond) {
		t.Fatal("second acquire should time out (slot busy)")
	}
	l.release()
	if !l.acquire(time.Second) {
		t.Fatal("acquire should succeed after release")
	}

	var nilLimiter *loginLimiter
	if !nilLimiter.allowRate() || !nilLimiter.acquire(0) {
		t.Fatal("nil limiter must fail open")
	}
	nilLimiter.release() // must not panic
}
