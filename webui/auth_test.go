package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// withFastKDF lowers the PBKDF2 cost for the duration of a test so account
// creation and login stay quick.
func withFastKDF(t *testing.T) {
	t.Helper()
	prev := pbkdf2Iterations
	pbkdf2Iterations = 4096
	t.Cleanup(func() { pbkdf2Iterations = prev })
}

func authReq(method, target, body string, cookie *http.Cookie, csrf string) *http.Request {
	var r *http.Request
	if body != "" {
		r = loopbackReq(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = loopbackReq(method, target, nil)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	return r
}

func sessionCookieFrom(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	return nil
}

/* ── store-level behaviour ────────────────────────────────────────────── */

func TestUserStoreCRUD(t *testing.T) {
	withFastKDF(t)
	s := newTestServer(t, "")
	a := s.auth

	if a.enabled() {
		t.Fatal("empty store should be disabled")
	}
	if _, err := a.createUser("Alice", "a-strong-passphrase", RoleAdmin, false); err != nil {
		t.Fatalf("createUser: %v", err)
	}
	if !a.enabled() || a.userCount() != 1 {
		t.Fatalf("store should be enabled with 1 user, got enabled=%v n=%d", a.enabled(), a.userCount())
	}
	// Username is normalized to lowercase.
	if _, ok := a.userView("alice"); !ok {
		t.Fatal("user 'alice' not found after creating 'Alice'")
	}
	// Duplicate + invalid inputs are rejected.
	if _, err := a.createUser("alice", "another-strong-pass", RoleUser, false); err == nil {
		t.Error("duplicate username accepted")
	}
	if _, err := a.createUser("x", "another-strong-pass", RoleUser, false); err == nil {
		t.Error("too-short username accepted")
	}
	if _, err := a.createUser("bob", "short", RoleUser, false); err == nil {
		t.Error("weak password accepted")
	}
	// Persistence: a fresh manager over the same dir sees the user.
	reopened, err := NewAuthManager(a.dir, false)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, ok := reopened.userView("alice"); !ok {
		t.Fatal("user did not persist to disk")
	}
}

func TestAuthenticateAndLockout(t *testing.T) {
	withFastKDF(t)
	s := newTestServer(t, "")
	a := s.auth
	if _, err := a.createUser("carol", "carols-long-password", RoleUser, false); err != nil {
		t.Fatalf("createUser: %v", err)
	}

	if _, err := a.authenticate("carol", "carols-long-password"); err != nil {
		t.Fatalf("valid login rejected: %v", err)
	}
	if _, err := a.authenticate("nobody", "whatever-long-pass"); err != errAuthFailed {
		t.Errorf("unknown user err = %v, want errAuthFailed", err)
	}

	// Trip the lockout.
	for i := 0; i < maxFailedLogins; i++ {
		if _, err := a.authenticate("carol", "wrong-password-value"); err == nil {
			t.Fatalf("attempt %d unexpectedly succeeded", i)
		}
	}
	// Even the correct password is refused while locked.
	if _, err := a.authenticate("carol", "carols-long-password"); err != errAccountLocked {
		t.Errorf("locked account err = %v, want errAccountLocked", err)
	}
	// Admin unlock restores access.
	if err := a.unlockUser("carol"); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if _, err := a.authenticate("carol", "carols-long-password"); err != nil {
		t.Errorf("login after unlock failed: %v", err)
	}
}

func TestDeleteLastAdminGuard(t *testing.T) {
	withFastKDF(t)
	s := newTestServer(t, "")
	a := s.auth
	if _, err := a.createUser("root", "root-long-password", RoleAdmin, false); err != nil {
		t.Fatalf("createUser: %v", err)
	}
	if err := a.deleteUser("root"); err == nil {
		t.Fatal("deleting the last administrator was allowed")
	}
	if _, err := a.createUser("root2", "root2-long-password", RoleAdmin, false); err != nil {
		t.Fatalf("createUser admin2: %v", err)
	}
	if err := a.deleteUser("root"); err != nil {
		t.Fatalf("deleting one of two admins failed: %v", err)
	}
}

func TestSessionExpiry(t *testing.T) {
	withFastKDF(t)
	s := newTestServer(t, "")
	a := s.auth
	if _, err := a.createUser("dave", "daves-long-password", RoleUser, false); err != nil {
		t.Fatalf("createUser: %v", err)
	}
	raw, _, err := a.createSession("dave", RoleUser)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	if _, ok := a.lookupSession(raw); !ok {
		t.Fatal("fresh session not found")
	}
	// Force the absolute timeout by ageing the session.
	a.mu.Lock()
	for _, sess := range a.sessions {
		sess.CreatedAt = time.Now().Add(-sessionAbsTimeout - time.Minute)
	}
	a.mu.Unlock()
	if _, ok := a.lookupSession(raw); ok {
		t.Fatal("expired session still valid")
	}
	// And it was evicted.
	if _, ok := a.lookupSession(raw); ok {
		t.Fatal("expired session not evicted")
	}
}

/* ── HTTP flows through the real middleware chain ─────────────────────── */

func TestSetupFlow(t *testing.T) {
	withFastKDF(t)
	s := newTestServer(t, "") // empty store: setup available

	// status: setup required, not authenticated
	rec := serve(t, s, loopbackReq("GET", "/api/auth/status", nil))
	var st struct {
		Enabled       bool `json:"enabled"`
		SetupRequired bool `json:"setup_required"`
		Authenticated bool `json:"authenticated"`
	}
	json.Unmarshal(rec.Body.Bytes(), &st)
	if st.Enabled || !st.SetupRequired || st.Authenticated {
		t.Fatalf("status before setup = %+v", st)
	}

	// weak password rejected
	rec = serve(t, s, authReq("POST", "/api/auth/setup", `{"username":"admin","password":"short"}`, nil, ""))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("weak setup password code = %d, want 400", rec.Code)
	}

	// valid setup logs in and returns a cookie + csrf
	rec = serve(t, s, authReq("POST", "/api/auth/setup", `{"username":"admin","password":"first-admin-passphrase"}`, nil, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("setup code = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if sessionCookieFrom(rec) == nil {
		t.Fatal("setup did not set a session cookie")
	}
	var setupResp struct {
		User struct {
			Role string `json:"role"`
		} `json:"user"`
		CSRF string `json:"csrf_token"`
	}
	json.Unmarshal(rec.Body.Bytes(), &setupResp)
	if setupResp.User.Role != string(RoleAdmin) || setupResp.CSRF == "" {
		t.Fatalf("setup resp = %+v, want admin role + csrf", setupResp)
	}

	// second setup attempt is refused
	rec = serve(t, s, authReq("POST", "/api/auth/setup", `{"username":"admin2","password":"second-admin-pass"}`, nil, ""))
	if rec.Code != http.StatusConflict {
		t.Fatalf("second setup code = %d, want 409", rec.Code)
	}
}

func TestLoginAndProtectedEndpoints(t *testing.T) {
	s, cookie, csrf := newAuthTestServer(t, "operator", "operator-long-password")

	// Unauthenticated read is rejected once the panel is enabled (fixes F-3b).
	if rec := serve(t, s, loopbackReq("GET", "/api/scans", nil)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /api/scans = %d, want 401", rec.Code)
	}
	// With a valid session it succeeds.
	if rec := serve(t, s, authReq("GET", "/api/scans", "", cookie, "")); rec.Code != http.StatusOK {
		t.Fatalf("authenticated /api/scans = %d, want 200", rec.Code)
	}

	// Mutations need a CSRF token even with a valid session.
	scanBody := `{"target":"127.0.0.1","authorized":true,"passive":true}`
	if rec := serve(t, s, authReq("POST", "/api/scan", scanBody, cookie, "")); rec.Code != http.StatusForbidden {
		t.Fatalf("scan without CSRF = %d, want 403", rec.Code)
	}
	if rec := serve(t, s, authReq("POST", "/api/scan", scanBody, cookie, csrf)); rec.Code != http.StatusCreated {
		t.Fatalf("scan with session+CSRF = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}

	// Login endpoint: wrong password then right password.
	if rec := serve(t, s, authReq("POST", "/api/auth/login", `{"username":"operator","password":"nope-nope-nope"}`, nil, "")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad login = %d, want 401", rec.Code)
	}
	rec := serve(t, s, authReq("POST", "/api/auth/login", `{"username":"operator","password":"operator-long-password"}`, nil, ""))
	if rec.Code != http.StatusOK || sessionCookieFrom(rec) == nil {
		t.Fatalf("good login = %d (cookie set=%v)", rec.Code, sessionCookieFrom(rec) != nil)
	}
}

func TestChangePasswordRotatesSessions(t *testing.T) {
	s, cookie, csrf := newAuthTestServer(t, "sam", "sams-first-password")

	// wrong current password
	body := `{"current_password":"wrong-wrong-wrong","new_password":"sams-second-password"}`
	if rec := serve(t, s, authReq("POST", "/api/auth/change-password", body, cookie, csrf)); rec.Code != http.StatusBadRequest {
		t.Fatalf("change with wrong current = %d, want 400", rec.Code)
	}

	// valid change: returns a new cookie, invalidates the old session
	body = `{"current_password":"sams-first-password","new_password":"sams-second-password"}`
	rec := serve(t, s, authReq("POST", "/api/auth/change-password", body, cookie, csrf))
	if rec.Code != http.StatusOK {
		t.Fatalf("change-password = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	newCookie := sessionCookieFrom(rec)
	if newCookie == nil {
		t.Fatal("change-password did not set a fresh session cookie")
	}
	// Old session must no longer authenticate.
	if rec := serve(t, s, authReq("GET", "/api/auth/me", "", cookie, "")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old session after password change = %d, want 401", rec.Code)
	}
	// New session works, and the new password logs in.
	if rec := serve(t, s, authReq("GET", "/api/auth/me", "", newCookie, "")); rec.Code != http.StatusOK {
		t.Fatalf("new session = %d, want 200", rec.Code)
	}
	if rec := serve(t, s, authReq("POST", "/api/auth/login", `{"username":"sam","password":"sams-second-password"}`, nil, "")); rec.Code != http.StatusOK {
		t.Fatalf("login with new password = %d, want 200", rec.Code)
	}
}

func TestLogoutRequiresCSRF(t *testing.T) {
	s, cookie, csrf := newAuthTestServer(t, "erin", "erins-long-password")

	if rec := serve(t, s, authReq("POST", "/api/auth/logout", "", cookie, "")); rec.Code != http.StatusForbidden {
		t.Fatalf("logout without CSRF = %d, want 403", rec.Code)
	}
	if rec := serve(t, s, authReq("POST", "/api/auth/logout", "", cookie, csrf)); rec.Code != http.StatusOK {
		t.Fatalf("logout with CSRF = %d, want 200", rec.Code)
	}
	// Session is dead after logout.
	if rec := serve(t, s, authReq("GET", "/api/auth/me", "", cookie, "")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("session after logout = %d, want 401", rec.Code)
	}
}

func TestAdminUserManagement(t *testing.T) {
	s, adminCookie, adminCSRF := newAuthTestServer(t, "boss", "bosss-long-password")

	// Admin creates a regular user (must-change enforced).
	rec := serve(t, s, authReq("POST", "/api/auth/users", `{"username":"worker","password":"workers-long-pass","role":"user"}`, adminCookie, adminCSRF))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create user = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var created struct {
		User UserView `json:"user"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	if !created.User.MustChange || created.User.Role != RoleUser {
		t.Fatalf("created user = %+v, want must_change + role=user", created.User)
	}

	// The new user logs in, and must NOT be able to reach admin endpoints.
	rec = serve(t, s, authReq("POST", "/api/auth/login", `{"username":"worker","password":"workers-long-pass"}`, nil, ""))
	workerCookie := sessionCookieFrom(rec)
	var workerLogin struct {
		CSRF string `json:"csrf_token"`
	}
	json.Unmarshal(rec.Body.Bytes(), &workerLogin)
	if workerCookie == nil {
		t.Fatal("worker login set no cookie")
	}
	if rec := serve(t, s, authReq("GET", "/api/auth/users", "", workerCookie, "")); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin list users = %d, want 403", rec.Code)
	}
	if rec := serve(t, s, authReq("POST", "/api/auth/users", `{"username":"evil","password":"evils-long-pass"}`, workerCookie, workerLogin.CSRF)); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin create user = %d, want 403", rec.Code)
	}

	// Admin lists users (should see both).
	rec = serve(t, s, authReq("GET", "/api/auth/users", "", adminCookie, ""))
	var list struct {
		Users []UserView `json:"users"`
	}
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Users) != 2 {
		t.Fatalf("user list has %d, want 2", len(list.Users))
	}

	// Admin resets the worker's password and can delete the worker.
	if rec := serve(t, s, authReq("POST", "/api/auth/users/worker/reset", `{"new_password":"workers-reset-pass"}`, adminCookie, adminCSRF)); rec.Code != http.StatusOK {
		t.Fatalf("reset password = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if rec := serve(t, s, authReq("DELETE", "/api/auth/users/worker", "", adminCookie, adminCSRF)); rec.Code != http.StatusOK {
		t.Fatalf("delete user = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	// Admin cannot delete themselves.
	if rec := serve(t, s, authReq("DELETE", "/api/auth/users/boss", "", adminCookie, adminCSRF)); rec.Code != http.StatusBadRequest {
		t.Fatalf("self-delete = %d, want 400", rec.Code)
	}
}

func TestLegacyTokenStillWorksWhenAuthDisabled(t *testing.T) {
	// No accounts created: the server stays in open mode and the legacy
	// shared token continues to gate mutations (backwards compatibility).
	s := newTestServer(t, "s3cr3t")
	body := `{"target":"127.0.0.1","authorized":true,"passive":true}`

	if rec := serve(t, s, loopbackReq("POST", "/api/scan", strings.NewReader(body))); rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token in open mode = %d, want 401", rec.Code)
	}
	req := loopbackReq("POST", "/api/scan", strings.NewReader(body))
	req.Header.Set("X-Auth-Token", "s3cr3t")
	if rec := serve(t, s, req); rec.Code != http.StatusCreated {
		t.Fatalf("valid token in open mode = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
}
