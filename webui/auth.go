package main

// Login panel: user store, sessions, brute-force lockout and the HTTP
// handlers/middleware that protect the console.
//
// Design notes (security model):
//   - Standard library only, same as the rest of the project.
//   - Passwords are never stored in the clear; only PBKDF2-HMAC-SHA256 hashes
//     (see password.go) land in users.json, written 0600 in a 0700 dir.
//   - Session tokens are 256-bit CSPRNG values. Only their SHA-256 is held in
//     memory, so a memory disclosure does not hand out live bearer tokens.
//   - Cookies are HttpOnly + SameSite=Strict (+ Secure under TLS). CSRF is
//     defended first by the existing origin guard and, for authenticated
//     mutations, by a per-session synchroniser token (X-CSRF-Token).
//   - Login is constant-time w.r.t. account existence (a dummy hash is always
//     verified) and rate-limited by both the PBKDF2 cost and per-account
//     lockout after repeated failures.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Role is the authorization level of an account.
type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

const (
	sessionCookieName  = "w1r3hound_session"
	sessionIdleTimeout = 30 * time.Minute
	sessionAbsTimeout  = 12 * time.Hour
	maxFailedLogins    = 10
	lockoutDuration    = 15 * time.Minute
	usersFileName      = "users.json"
	maxUsers           = 256 // sanity bound on the store

	// W-01 (pre-auth CPU DoS): /api/auth/login and /api/auth/setup each run a
	// full-cost PBKDF2 hash on every attempt — even for unknown users, to keep
	// login constant-time. Without a cap, an unauthenticated flood pins every
	// core. These bound the concurrency and sustained rate of that hashing.
	// Sized generously for a single-operator loopback console.
	loginMaxConcurrent  = 2                      // parallel PBKDF2 verifications
	loginBurst          = 12                     // token-bucket burst
	loginRefillPerSec   = 6                      // tokens replenished per second
	loginAcquireTimeout = 750 * time.Millisecond // wait for a slot before 429
)

// usernameRe permits 3-32 chars: a-z, 0-9, dot, underscore, hyphen, and must
// start and end alphanumerically. Names are always normalized to lowercase.
var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{1,30}[a-z0-9]$`)

var (
	errAuthFailed    = errors.New("invalid username or password")
	errAccountLocked = errors.New("account temporarily locked")
)

// User is one account as persisted in users.json.
type User struct {
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	Role         Role      `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	LastLoginAt  time.Time `json:"last_login_at,omitempty"`
	MustChange   bool      `json:"must_change_password"`
	FailedCount  int       `json:"failed_count"`
	LockedUntil  time.Time `json:"locked_until,omitempty"`
}

// UserView is the hash-free representation returned to the browser.
type UserView struct {
	Username    string `json:"username"`
	Role        Role   `json:"role"`
	CreatedAt   string `json:"created_at,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
	LastLoginAt string `json:"last_login_at,omitempty"`
	MustChange  bool   `json:"must_change_password"`
	Locked      bool   `json:"locked"`
}

func (u *User) view() UserView {
	v := UserView{Username: u.Username, Role: u.Role, MustChange: u.MustChange}
	if !u.CreatedAt.IsZero() {
		v.CreatedAt = u.CreatedAt.UTC().Format(time.RFC3339)
	}
	if !u.UpdatedAt.IsZero() {
		v.UpdatedAt = u.UpdatedAt.UTC().Format(time.RFC3339)
	}
	if !u.LastLoginAt.IsZero() {
		v.LastLoginAt = u.LastLoginAt.UTC().Format(time.RFC3339)
	}
	v.Locked = u.lockedNow()
	return v
}

func (u *User) lockedNow() bool {
	return !u.LockedUntil.IsZero() && time.Now().Before(u.LockedUntil)
}

// Session is a live login. Only immutable fields are read outside the lock;
// LastSeen is only ever mutated while holding AuthManager.mu.
type Session struct {
	Username  string
	Role      Role
	CSRFToken string
	CreatedAt time.Time
	LastSeen  time.Time
	// MustChange mirrors the account's forced-rotation flag at the moment the
	// session was minted. authGate uses it to confine an admin-provisioned
	// account to the password-change endpoints until it rotates its initial
	// password, so the "change on first sign-in" rule is enforced server-side
	// rather than only in the UI (W-02).
	MustChange bool
}

// AuthManager owns the user store and the in-memory session table.
type AuthManager struct {
	dir       string
	usersPath string
	forced    bool   // W1R3HOUND_AUTH=required: gate access before first admin
	dummyHash string // verified on unknown users to flatten login timing

	mu       sync.RWMutex
	users    map[string]*User    // key: normalized username
	sessions map[string]*Session // key: sha256hex(raw token)
}

// NewAuthManager loads (or initializes) the user store under dir.
func NewAuthManager(dir string, forced bool) (*AuthManager, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// Tighten perms even if the directory pre-existed with a looser mode.
	if fi, err := os.Stat(dir); err == nil {
		_ = os.Chmod(dir, fi.Mode().Perm()&^0o077)
	}
	a := &AuthManager{
		dir:       dir,
		usersPath: filepath.Join(dir, usersFileName),
		forced:    forced,
		users:     map[string]*User{},
		sessions:  map[string]*Session{},
	}
	// A throwaway hash so the "unknown user" path spends PBKDF2 time too.
	seed := make([]byte, 32)
	_, _ = rand.Read(seed)
	if h, err := hashPassword(base64.RawStdEncoding.EncodeToString(seed)); err == nil {
		a.dummyHash = h
	}
	if err := a.load(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *AuthManager) load() error {
	data, err := os.ReadFile(a.usersPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var list []*User
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("could not parse %s: %w", a.usersPath, err)
	}
	m := make(map[string]*User, len(list))
	for _, u := range list {
		if u == nil || u.Username == "" {
			continue
		}
		m[normalizeUsername(u.Username)] = u
	}
	a.users = m
	return nil
}

// saveLocked persists the store atomically. The caller must hold a.mu.
func (a *AuthManager) saveLocked() error {
	list := make([]*User, 0, len(a.users))
	for _, u := range a.users {
		list = append(list, u)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.Before(list[j].CreatedAt) })
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(a.dir, "users-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, a.usersPath)
}

func normalizeUsername(u string) string { return strings.ToLower(strings.TrimSpace(u)) }

func validUsername(u string) bool { return usernameRe.MatchString(u) }

// enabled reports whether the login gate is active: either forced on, or at
// least one account exists. A nil manager (e.g. in a bare test) is disabled.
func (a *AuthManager) enabled() bool {
	if a == nil {
		return false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.forced || len(a.users) > 0
}

func (a *AuthManager) userCount() int {
	if a == nil {
		return 0
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.users)
}

// setupRequired is true when no account exists yet (first-run bootstrap).
func (a *AuthManager) setupRequired() bool {
	if a == nil {
		return false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.users) == 0
}

func (a *AuthManager) adminCountLocked() int {
	n := 0
	for _, u := range a.users {
		if u.Role == RoleAdmin {
			n++
		}
	}
	return n
}

// createUser validates and stores a new account, returning a value copy.
func (a *AuthManager) createUser(username, password string, role Role, mustChange bool) (User, error) {
	username = normalizeUsername(username)
	if !validUsername(username) {
		return User{}, errors.New("invalid username: 3-32 chars of a-z, 0-9, '.', '_', '-', starting and ending alphanumeric")
	}
	if role != RoleAdmin && role != RoleUser {
		return User{}, errors.New("invalid role: must be 'admin' or 'user'")
	}
	if err := validatePasswordPolicy(password, username); err != nil {
		return User{}, err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return User{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, exists := a.users[username]; exists {
		return User{}, fmt.Errorf("a user named %q already exists", username)
	}
	if len(a.users) >= maxUsers {
		return User{}, errors.New("user limit reached")
	}
	now := time.Now().UTC()
	u := &User{
		Username:     username,
		PasswordHash: hash,
		Role:         role,
		CreatedAt:    now,
		UpdatedAt:    now,
		MustChange:   mustChange,
	}
	a.users[username] = u
	if err := a.saveLocked(); err != nil {
		delete(a.users, username)
		return User{}, err
	}
	return *u, nil
}

// authenticate verifies credentials, applying lockout. It returns a value
// copy of the user on success. Timing is kept independent of account
// existence by always performing a PBKDF2 verification.
func (a *AuthManager) authenticate(username, password string) (User, error) {
	username = normalizeUsername(username)

	a.mu.RLock()
	u := a.users[username]
	var encoded string
	locked := false
	if u != nil {
		encoded = u.PasswordHash
		locked = u.lockedNow()
	}
	a.mu.RUnlock()

	if u == nil {
		_, _ = verifyPassword(a.dummyHash, password) // flatten timing
		return User{}, errAuthFailed
	}
	if locked {
		_, _ = verifyPassword(a.dummyHash, password)
		return User{}, errAccountLocked
	}

	ok, verr := verifyPassword(encoded, password)

	a.mu.Lock()
	defer a.mu.Unlock()
	u = a.users[username]
	if u == nil {
		return User{}, errAuthFailed
	}
	now := time.Now().UTC()
	if verr != nil || !ok {
		u.FailedCount++
		if u.FailedCount >= maxFailedLogins {
			u.LockedUntil = now.Add(lockoutDuration)
		}
		u.UpdatedAt = now
		_ = a.saveLocked()
		if u.lockedNow() {
			return User{}, errAccountLocked
		}
		return User{}, errAuthFailed
	}
	u.FailedCount = 0
	u.LockedUntil = time.Time{}
	u.LastLoginAt = now
	u.UpdatedAt = now
	_ = a.saveLocked()
	return *u, nil
}

// verifyUser checks a password for an existing account without touching the
// lockout counters (used to confirm the current password on change).
func (a *AuthManager) verifyUser(username, password string) bool {
	a.mu.RLock()
	u := a.users[normalizeUsername(username)]
	var encoded string
	if u != nil {
		encoded = u.PasswordHash
	}
	a.mu.RUnlock()
	if u == nil {
		_, _ = verifyPassword(a.dummyHash, password)
		return false
	}
	ok, err := verifyPassword(encoded, password)
	return err == nil && ok
}

// setPassword hashes and stores a new password, clearing lockout state and the
// must-change flag.
func (a *AuthManager) setPassword(username, newPassword string, mustChange bool) error {
	username = normalizeUsername(username)
	if err := validatePasswordPolicy(newPassword, username); err != nil {
		return err
	}
	hash, err := hashPassword(newPassword)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	u := a.users[username]
	if u == nil {
		return errors.New("user not found")
	}
	u.PasswordHash = hash
	u.MustChange = mustChange
	u.FailedCount = 0
	u.LockedUntil = time.Time{}
	u.UpdatedAt = time.Now().UTC()
	return a.saveLocked()
}

func (a *AuthManager) deleteUser(username string) error {
	username = normalizeUsername(username)
	a.mu.Lock()
	defer a.mu.Unlock()
	u := a.users[username]
	if u == nil {
		return errors.New("user not found")
	}
	if u.Role == RoleAdmin && a.adminCountLocked() <= 1 {
		return errors.New("cannot delete the last administrator")
	}
	delete(a.users, username)
	if err := a.saveLocked(); err != nil {
		a.users[username] = u // roll back
		return err
	}
	return nil
}

func (a *AuthManager) unlockUser(username string) error {
	username = normalizeUsername(username)
	a.mu.Lock()
	defer a.mu.Unlock()
	u := a.users[username]
	if u == nil {
		return errors.New("user not found")
	}
	u.FailedCount = 0
	u.LockedUntil = time.Time{}
	u.UpdatedAt = time.Now().UTC()
	return a.saveLocked()
}

func (a *AuthManager) userView(username string) (UserView, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	u := a.users[normalizeUsername(username)]
	if u == nil {
		return UserView{}, false
	}
	return u.view(), true
}

func (a *AuthManager) listUsers() []UserView {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]UserView, 0, len(a.users))
	for _, u := range a.users {
		out = append(out, u.view())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

/* ── Sessions ─────────────────────────────────────────────────────────── */

func randToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// createSession mints a session for (username, role) and returns the raw
// cookie token plus a copy of the session (for its CSRF token).
func (a *AuthManager) createSession(username string, role Role) (rawToken string, sess Session, err error) {
	rawToken, err = randToken()
	if err != nil {
		return "", Session{}, err
	}
	csrf, err := randToken()
	if err != nil {
		return "", Session{}, err
	}
	now := time.Now().UTC()
	s := &Session{Username: username, Role: role, CSRFToken: csrf, CreatedAt: now, LastSeen: now}
	a.mu.Lock()
	// Snapshot the account's forced-rotation flag so authGate can confine a
	// still-unrotated admin-provisioned account (W-02). Looking it up here (vs
	// taking it as a parameter) keeps every existing createSession caller intact.
	if u := a.users[normalizeUsername(username)]; u != nil {
		s.MustChange = u.MustChange
	}
	a.sessions[hashToken(rawToken)] = s
	a.mu.Unlock()
	return rawToken, *s, nil
}

// lookupSession validates and refreshes a session, returning a value copy.
func (a *AuthManager) lookupSession(rawToken string) (Session, bool) {
	if rawToken == "" {
		return Session{}, false
	}
	key := hashToken(rawToken)
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[key]
	if !ok {
		return Session{}, false
	}
	now := time.Now().UTC()
	if now.Sub(s.CreatedAt) > sessionAbsTimeout || now.Sub(s.LastSeen) > sessionIdleTimeout {
		delete(a.sessions, key)
		return Session{}, false
	}
	if _, exists := a.users[normalizeUsername(s.Username)]; !exists {
		delete(a.sessions, key)
		return Session{}, false
	}
	s.LastSeen = now
	return *s, true
}

func (a *AuthManager) destroySession(rawToken string) {
	if rawToken == "" {
		return
	}
	a.mu.Lock()
	delete(a.sessions, hashToken(rawToken))
	a.mu.Unlock()
}

func (a *AuthManager) destroyUserSessions(username string) {
	username = normalizeUsername(username)
	a.mu.Lock()
	for k, s := range a.sessions {
		if normalizeUsername(s.Username) == username {
			delete(a.sessions, k)
		}
	}
	a.mu.Unlock()
}

/* ── Pre-auth PBKDF2 throttle (W-01) ──────────────────────────────────── */

// loginLimiter bounds the CPU an unauthenticated caller can spend on the
// PBKDF2 verification behind /api/auth/login and /api/auth/setup. Each attempt
// runs a full-cost hash even for unknown users (constant-time enumeration
// defense), so without a cap a loopback flood can pin every core — a pre-auth
// CPU-exhaustion DoS. It combines a small concurrency semaphore (bounds
// parallel hashing) with a token bucket (bounds the sustained attempt rate).
// All methods are nil-safe, so a server built without a limiter (tests,
// open-mode) simply allows every attempt.
type loginLimiter struct {
	sem chan struct{}

	mu     sync.Mutex
	tokens float64
	max    float64
	refill float64 // tokens replenished per second
	last   time.Time
}

func newLoginLimiter(maxConcurrent, burst int, refillPerSec float64) *loginLimiter {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	if burst < 1 {
		burst = 1
	}
	return &loginLimiter{
		sem:    make(chan struct{}, maxConcurrent),
		tokens: float64(burst),
		max:    float64(burst),
		refill: refillPerSec,
		last:   time.Now(),
	}
}

// allowRate consumes one token, first replenishing by the elapsed time. It
// returns false when the sustained attempt rate has been exceeded.
func (l *loginLimiter) allowRate() bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.tokens += now.Sub(l.last).Seconds() * l.refill
	if l.tokens > l.max {
		l.tokens = l.max
	}
	l.last = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

// acquire takes a concurrency slot, waiting up to timeout. It returns false if
// no slot frees up in time, so the caller can shed the request cheaply (429).
func (l *loginLimiter) acquire(timeout time.Duration) bool {
	if l == nil {
		return true
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case l.sem <- struct{}{}:
		return true
	case <-timer.C:
		return false
	}
}

func (l *loginLimiter) release() {
	if l == nil {
		return
	}
	select {
	case <-l.sem:
	default:
	}
}

/* ── HTTP plumbing ────────────────────────────────────────────────────── */

type ctxKey int

const sessionCtxKey ctxKey = iota

func sessionFrom(r *http.Request) *Session {
	s, _ := r.Context().Value(sessionCtxKey).(*Session)
	return s
}

// publicAPIPaths are reachable without a session even when auth is enabled.
var publicAPIPaths = map[string]bool{
	"/api/auth/status": true,
	"/api/auth/login":  true,
	"/api/auth/setup":  true,
}

// mustChangeAllowedPaths are the only authenticated routes an account may reach
// while it still owes a forced password rotation (an admin-provisioned initial
// password). Everything else is refused until the password is changed, so the
// forced-rotation control is enforced by the server, not just the SPA (W-02).
var mustChangeAllowedPaths = map[string]bool{
	"/api/auth/me":              true,
	"/api/auth/change-password": true,
	"/api/auth/logout":          true,
}

// authGate enforces a valid session on every /api/* route (except the public
// auth endpoints) once the login panel is enabled. Static assets stay open so
// the SPA/login screen can load. It is a no-op in open (legacy) mode.
func (s *server) authGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.auth.enabled() {
			next.ServeHTTP(w, r)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/api/") || publicAPIPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		sess, ok := s.auth.currentSession(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		// W-02: an account provisioned with a temporary password must rotate it
		// before doing anything else. Confine it to the password-change flow
		// server-side (the SPA already redirects, but the API must not trust the
		// client to do so).
		if sess.MustChange && !mustChangeAllowedPaths[r.URL.Path] {
			writeError(w, http.StatusForbidden, "password change required: rotate your initial password before using the console")
			return
		}
		cp := sess
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionCtxKey, &cp)))
	})
}

func (a *AuthManager) currentSession(r *http.Request) (Session, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return Session{}, false
	}
	return a.lookupSession(c.Value)
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, raw string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    raw,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   true,
	})
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   true,
		MaxAge:   -1,
	})
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 64*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

// checkCSRF validates the per-session synchroniser token on a mutating
// request (defense-in-depth beyond the origin guard).
func (s *server) checkCSRF(w http.ResponseWriter, r *http.Request, sess *Session) bool {
	got := r.Header.Get("X-CSRF-Token")
	if sess == nil || subtle.ConstantTimeCompare([]byte(got), []byte(sess.CSRFToken)) != 1 {
		writeError(w, http.StatusForbidden, "invalid or missing CSRF token")
		return false
	}
	return true
}

func (s *server) requireAdmin(w http.ResponseWriter, r *http.Request) (*Session, bool) {
	sess := sessionFrom(r)
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	if sess.Role != RoleAdmin {
		writeError(w, http.StatusForbidden, "administrator role required")
		return nil, false
	}
	if !s.checkCSRF(w, r, sess) {
		return nil, false
	}
	return sess, true
}

// establishSession mints a session for u, sets the cookie and returns the
// user + CSRF token to the client.
func (s *server) establishSession(w http.ResponseWriter, r *http.Request, u User) {
	raw, sess, err := s.auth.createSession(u.Username, u.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	setSessionCookie(w, r, raw)
	writeJSON(w, http.StatusOK, map[string]any{"user": u.view(), "csrf_token": sess.CSRFToken})
}

// throttleAuthWork applies the pre-auth PBKDF2 DoS guard (W-01) around the
// expensive login/setup hashing. On success it returns a release func the
// caller must defer; otherwise it has already written a 429 and returns false.
func (s *server) throttleAuthWork(w http.ResponseWriter) (release func(), ok bool) {
	if !s.loginLimiter.allowRate() {
		writeError(w, http.StatusTooManyRequests, "too many authentication attempts; slow down and try again")
		return nil, false
	}
	if !s.loginLimiter.acquire(loginAcquireTimeout) {
		writeError(w, http.StatusTooManyRequests, "the server is busy verifying credentials; try again shortly")
		return nil, false
	}
	return s.loginLimiter.release, true
}

/* ── Auth handlers ────────────────────────────────────────────────────── */

func (s *server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"enabled":        s.auth.enabled(),
		"setup_required": s.auth.setupRequired(),
		"authenticated":  false,
		"user":           nil,
	}
	if sess, ok := s.auth.currentSession(r); ok {
		if v, found := s.auth.userView(sess.Username); found {
			resp["authenticated"] = true
			resp["user"] = v
			resp["csrf_token"] = sess.CSRFToken
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) handleAuthSetup(w http.ResponseWriter, r *http.Request) {
	if s.auth.userCount() != 0 {
		writeError(w, http.StatusConflict, "setup already completed; an administrator already exists")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}
	release, ok := s.throttleAuthWork(w)
	if !ok {
		return
	}
	defer release()
	u, err := s.auth.createUser(req.Username, req.Password, RoleAdmin, false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.establishSession(w, r, u)
}

func (s *server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if !s.auth.enabled() {
		writeError(w, http.StatusConflict, "login is not configured on this server")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}
	release, ok := s.throttleAuthWork(w)
	if !ok {
		return
	}
	defer release()
	u, err := s.auth.authenticate(req.Username, req.Password)
	if err != nil {
		if errors.Is(err, errAccountLocked) {
			writeError(w, http.StatusTooManyRequests, "account temporarily locked after repeated failures; try again later")
			return
		}
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	s.establishSession(w, r, u)
}

func (s *server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if !s.checkCSRF(w, r, sess) {
		return
	}
	if c, err := r.Cookie(sessionCookieName); err == nil {
		s.auth.destroySession(c.Value)
	}
	clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

func (s *server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	v, ok := s.auth.userView(sess.Username)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":          v,
		"csrf_token":    sess.CSRFToken,
		"session_start": sess.CreatedAt.UTC().Format(time.RFC3339),
	})
}

func (s *server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !s.checkCSRF(w, r, sess) {
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if !s.auth.verifyUser(sess.Username, req.CurrentPassword) {
		writeError(w, http.StatusBadRequest, "current password is incorrect")
		return
	}
	if req.NewPassword == req.CurrentPassword {
		writeError(w, http.StatusBadRequest, "the new password must differ from the current one")
		return
	}
	if err := s.auth.setPassword(sess.Username, req.NewPassword, false); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Revoke every session for this account (including this browser), then
	// re-establish the current browser with a fresh cookie + CSRF token.
	s.auth.destroyUserSessions(sess.Username)
	v, _ := s.auth.userView(sess.Username)
	s.establishSession(w, r, User{Username: v.Username, Role: v.Role, MustChange: v.MustChange})
}

func (s *server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdminReadonly(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": s.auth.listUsers()})
}

// requireAdminReadonly checks the admin role without a CSRF token (for GETs).
func (s *server) requireAdminReadonly(w http.ResponseWriter, r *http.Request) (*Session, bool) {
	sess := sessionFrom(r)
	if sess == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	if sess.Role != RoleAdmin {
		writeError(w, http.StatusForbidden, "administrator role required")
		return nil, false
	}
	return sess, true
}

func (s *server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     Role   `json:"role"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.Role == "" {
		req.Role = RoleUser
	}
	// Admin-provisioned accounts must rotate their initial password.
	u, err := s.auth.createUser(req.Username, req.Password, req.Role, true)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user": u.view()})
}

func (s *server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	target := normalizeUsername(r.PathValue("username"))
	if target == normalizeUsername(sess.Username) {
		writeError(w, http.StatusBadRequest, "you cannot delete your own account")
		return
	}
	if err := s.auth.deleteUser(target); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auth.destroyUserSessions(target)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	target := normalizeUsername(r.PathValue("username"))
	var req struct {
		NewPassword string `json:"new_password"`
	}
	if !decodeJSONBody(w, r, &req) {
		return
	}
	// Force the target to change the admin-set password on next login.
	if err := s.auth.setPassword(target, req.NewPassword, true); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auth.destroyUserSessions(target)
	writeJSON(w, http.StatusOK, map[string]string{"status": "password reset"})
}

func (s *server) handleUnlockUser(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	target := normalizeUsername(r.PathValue("username"))
	if err := s.auth.unlockUser(target); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "unlocked"})
}

// authTruthy reports whether the W1R3HOUND_AUTH env value forces the gate on.
func authTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "required", "yes", "on":
		return true
	}
	return false
}
