// Command w1r3hound-webui is a localhost-only web GUI for the w1r3hound
// recon CLI. It runs the compiled binary as a subprocess (never a shell),
// streams its output over Server-Sent Events and serves the resulting
// JSON/Markdown reports. Standard library only.
package main

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

//go:embed static
var staticFS embed.FS

// listenAddr is fixed to loopback: the GUI must never be exposed.
const listenAddr = "127.0.0.1:8737"

// sseHeartbeatInterval is how often an idle SSE stream emits a ": ping" comment
// to keep the connection alive. A var (not a const) so tests can shrink it.
var sseHeartbeatInterval = 15 * time.Second

type server struct {
	mgr   *Manager
	auth  *AuthManager
	token string // optional; legacy shared token (open mode only)
	// loginLimiter bounds pre-auth PBKDF2 work (W-01). Nil in tests/open-mode,
	// where the limiter's methods are no-ops (fail open).
	loginLimiter *loginLimiter
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[w1r3hound-webui] ")

	repoRoot, err := findRepoRoot()
	if err != nil {
		log.Fatalf("could not find the repo root: %v", err)
	}
	binPath := filepath.Join(repoRoot, "w1r3hound")
	if fi, err := os.Stat(binPath); err != nil || fi.IsDir() {
		log.Fatalf("w1r3hound binary not found at %s (build with: go build -o w1r3hound .)", binPath)
	}
	webuiDir := filepath.Join(repoRoot, "webui")
	mgr, err := NewManager(repoRoot, binPath,
		filepath.Join(webuiDir, "results"),
		filepath.Join(webuiDir, "wordlists"))
	if err != nil {
		log.Fatalf("could not initialize the manager: %v", err)
	}

	auth, err := NewAuthManager(filepath.Join(webuiDir, "auth"), authTruthy(os.Getenv("W1R3HOUND_AUTH")))
	if err != nil {
		log.Fatalf("could not initialize the login store: %v", err)
	}
	bootstrapAdminFromEnv(auth)

	s := &server{
		mgr:          mgr,
		auth:         auth,
		token:        os.Getenv("W1R3HOUND_UI_TOKEN"),
		loginLimiter: newLoginLimiter(loginMaxConcurrent, loginBurst, loginRefillPerSec),
	}

	handler, err := s.handler()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("serving on http://%s (loopback only)", listenAddr)
	log.Printf("repo root: %s", repoRoot)
	switch {
	case auth.enabled():
		log.Printf("login panel active — %d account(s); session auth required", auth.userCount())
	case s.token != "":
		log.Printf("open mode with legacy shared token (env W1R3HOUND_UI_TOKEN)")
	default:
		log.Printf("open mode — no accounts yet; create an admin in the UI or set W1R3HOUND_AUTH=required")
	}
	log.Fatal(newHTTPServer(handler).ListenAndServe())
}

// newHTTPServer builds the loopback HTTP server with conservative timeouts to
// bound slowloris / idle-socket resource exhaustion. WriteTimeout is
// intentionally omitted: the Server-Sent Events stream (/api/scans/{id}/events)
// is a long-lived response and a WriteTimeout would sever it mid-scan.
func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// bootstrapAdminFromEnv creates the first administrator non-interactively when
// the store is empty and W1R3HOUND_ADMIN_USER / W1R3HOUND_ADMIN_PASS are set.
// Handy for headless/automated deployments; the env is never persisted.
func bootstrapAdminFromEnv(auth *AuthManager) {
	if auth.userCount() != 0 {
		return
	}
	user, pass := os.Getenv("W1R3HOUND_ADMIN_USER"), os.Getenv("W1R3HOUND_ADMIN_PASS")
	if user == "" || pass == "" {
		return
	}
	if _, err := auth.createUser(user, pass, RoleAdmin, false); err != nil {
		log.Printf("admin bootstrap from environment failed: %v", err)
		return
	}
	log.Print("bootstrapped administrator account from environment variables")
}

// handler builds the full HTTP handler: the route mux wrapped in the origin
// guard and security-header middleware. Extracted from main so tests can
// drive the real middleware chain and pattern-based routing via httptest.
func (s *server) handler() (http.Handler, error) {
	mux := http.NewServeMux()
	static, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}
	mux.Handle("GET /", http.FileServer(http.FS(static)))
	mux.HandleFunc("GET /api/modules", s.handleModules)
	mux.HandleFunc("POST /api/scan", s.handleStartScan)
	mux.HandleFunc("GET /api/scans", s.handleListScans)
	mux.HandleFunc("GET /api/scans/{id}", s.handleGetScan)
	mux.HandleFunc("POST /api/scans/{id}/cancel", s.handleCancelScan)
	mux.HandleFunc("GET /api/scans/{id}/events", s.handleEvents)
	mux.HandleFunc("GET /api/scans/{id}/log", s.handleLog)
	mux.HandleFunc("GET /api/scans/{id}/report.json", s.handleReport("json"))
	mux.HandleFunc("GET /api/scans/{id}/report.md", s.handleReport("md"))

	// Login panel.
	mux.HandleFunc("GET /api/auth/status", s.handleAuthStatus)
	mux.HandleFunc("POST /api/auth/setup", s.handleAuthSetup)
	mux.HandleFunc("POST /api/auth/login", s.handleAuthLogin)
	mux.HandleFunc("POST /api/auth/logout", s.handleAuthLogout)
	mux.HandleFunc("GET /api/auth/me", s.handleAuthMe)
	mux.HandleFunc("POST /api/auth/change-password", s.handleChangePassword)
	mux.HandleFunc("GET /api/auth/users", s.handleListUsers)
	mux.HandleFunc("POST /api/auth/users", s.handleCreateUser)
	mux.HandleFunc("DELETE /api/auth/users/{username}", s.handleDeleteUser)
	mux.HandleFunc("POST /api/auth/users/{username}/reset", s.handleResetPassword)
	mux.HandleFunc("POST /api/auth/users/{username}/unlock", s.handleUnlockUser)

	return securityHeaders(originGuard(s.authGate(mux))), nil
}

// loopbackHosts / loopbackOrigins are the only Host and Origin values the GUI
// accepts. Enforcing them defeats DNS rebinding (a rebound name reaches the
// server with a foreign Host header) and cross-site CSRF (a forged POST carries
// a foreign Origin, or Sec-Fetch-Site: cross-site) — the transport-layer gaps
// the loopback bind alone did not close.
var loopbackHosts = map[string]bool{
	"127.0.0.1:8737": true, "localhost:8737": true, "[::1]:8737": true,
}
var loopbackOrigins = map[string]bool{
	"http://127.0.0.1:8737": true, "http://localhost:8737": true, "http://[::1]:8737": true,
}

// originGuard rejects any request whose Host is not loopback, or whose
// Origin / Sec-Fetch-Site marks it as a cross-site caller. It wraps the whole
// mux, so the read endpoints (events/log/report/scans) are also unreachable
// cross-origin or via rebinding, not just the mutating ones.
func originGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !loopbackHosts[r.Host] {
			writeError(w, http.StatusMisdirectedRequest, "invalid Host header: this GUI is loopback-only")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && !loopbackOrigins[origin] {
			writeError(w, http.StatusForbidden, "cross-origin request rejected")
			return
		}
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			writeError(w, http.StatusForbidden, "cross-site request rejected")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// findRepoRoot locates the cloned w1r3hound repository: the directory that
// contains main.go, go.mod and internal/.
func findRepoRoot() (string, error) {
	isRoot := func(dir string) bool {
		for _, name := range []string{"main.go", "go.mod", "internal"} {
			if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
				return false
			}
		}
		return true
	}
	var candidates []string
	if env := os.Getenv("W1R3HOUND_ROOT"); env != "" {
		candidates = append(candidates, env)
	}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, cwd, filepath.Join(cwd, ".."))
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), ".."))
	}
	for _, c := range candidates {
		abs, err := filepath.Abs(c)
		if err == nil && isRoot(abs) {
			return abs, nil
		}
	}
	return "", fmt.Errorf("neither W1R3HOUND_ROOT nor the current directory looks like the repo root")
}

// securityHeaders wraps the mux with conservative response headers.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		// Cross-origin isolation + capability lockdown. Defense-in-depth beyond
		// the loopback origin guard: the console is single-origin with no
		// cross-origin subresources, so same-origin COOP/CORP/COEP are safe and
		// close the residual scanner "missing header" flags. Permissions-Policy
		// disables powerful APIs the console never uses.
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Permissions-Policy", "geolocation=(), camera=(), microphone=(), usb=(), payment=(), interest-cohort=()")
		if !strings.HasPrefix(r.URL.Path, "/api/scans/") || !strings.HasSuffix(r.URL.Path, "/events") {
			w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; object-src 'none'; form-action 'self'; frame-ancestors 'none'")
		}
		next.ServeHTTP(w, r)
	})
}

// requireToken rejects mutating requests when W1R3HOUND_UI_TOKEN is set.
func (s *server) requireToken(w http.ResponseWriter, r *http.Request) bool {
	if s.token == "" {
		return true
	}
	got := r.Header.Get("X-Auth-Token")
	if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
		writeError(w, http.StatusUnauthorized, "invalid or missing token (X-Auth-Token header)")
		return false
	}
	return true
}

// authorizeMutation gates a state-changing request. With the login panel
// active, authGate has already proven the session, so we only need a valid
// per-session CSRF token; in open (legacy) mode we fall back to the optional
// shared token.
func (s *server) authorizeMutation(w http.ResponseWriter, r *http.Request) bool {
	if s.auth.enabled() {
		return s.checkCSRF(w, r, sessionFrom(r))
	}
	return s.requireToken(w, r)
}

// canAccessScan reports whether the caller may view or act on a scan owned by
// `owner`. In open (no-account) mode the console is shared, so every caller is
// allowed. With the login panel active, administrators see everything while
// other users are confined to the scans they submitted; a scan with an unknown
// owner (a legacy report without an ownership sidecar) is admin-only.
func (s *server) canAccessScan(r *http.Request, owner string) bool {
	if !s.auth.enabled() {
		return true
	}
	sess := sessionFrom(r)
	if sess == nil {
		return false
	}
	if sess.Role == RoleAdmin {
		return true
	}
	return owner != "" && normalizeUsername(owner) == normalizeUsername(sess.Username)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *server) handleModules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"modules": moduleCatalog})
}

func (s *server) handleStartScan(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeMutation(w, r) {
		return
	}
	var req ScanRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 64*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	args, base, err := buildArgs(&req, s.mgr.wordlistsDir, s.mgr.resultsDir)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	owner := ""
	if sess := sessionFrom(r); sess != nil {
		owner = sess.Username
	}
	job, err := s.mgr.Submit(owner, req.Target, args, base)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "queue full") {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		// Avoid leaking absolute filesystem paths from OS errors to the client.
		log.Printf("scan submit failed: %v", err)
		writeError(w, http.StatusInternalServerError, "could not start the scan")
		return
	}
	// A worker may pick up the job and mutate its Status the instant it is
	// queued; read the fields through the locked summary to stay race-free.
	sum := job.summary()
	writeJSON(w, http.StatusCreated, map[string]any{"id": sum.ID, "status": sum.Status})
}

func (s *server) handleListScans(w http.ResponseWriter, r *http.Request) {
	all := s.mgr.List()
	visible := make([]ScanSummary, 0, len(all))
	for _, sum := range all {
		if s.canAccessScan(r, sum.Owner) {
			visible = append(visible, sum)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"scans": visible})
}

func (s *server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if job, ok := s.mgr.Get(id); ok {
		sum := job.summary()
		if !s.canAccessScan(r, sum.Owner) {
			writeError(w, http.StatusNotFound, "scan not found")
			return
		}
		writeJSON(w, http.StatusOK, sum)
		return
	}
	for _, sum := range s.mgr.List() {
		if sum.ID == id {
			if !s.canAccessScan(r, sum.Owner) {
				writeError(w, http.StatusNotFound, "scan not found")
				return
			}
			writeJSON(w, http.StatusOK, sum)
			return
		}
	}
	writeError(w, http.StatusNotFound, "scan not found")
}

func (s *server) handleCancelScan(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeMutation(w, r) {
		return
	}
	id := r.PathValue("id")
	if owner, known := s.mgr.ownerOf(id); !known || !s.canAccessScan(r, owner) {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	if err := s.mgr.Cancel(id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelling"})
}

// handleEvents streams the scan log as Server-Sent Events: first a replay of
// the buffered lines, then live lines, then a final status event.
func (s *server) handleEvents(w http.ResponseWriter, r *http.Request) {
	job, ok := s.mgr.Get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "scan not found in memory")
		return
	}
	if !s.canAccessScan(r, job.owner()) {
		writeError(w, http.StatusNotFound, "scan not found in memory")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "SSE not supported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	replay, ch, final := job.subscribe()
	sendLog := func(line string) {
		payload, _ := json.Marshal(map[string]string{"line": line})
		fmt.Fprintf(w, "event: log\ndata: %s\n\n", payload)
	}
	for _, line := range replay {
		sendLog(line)
	}
	if final {
		s.sendStatus(w, job)
		flusher.Flush()
		return
	}
	defer job.unsubscribe(ch)
	flusher.Flush()

	heartbeat := time.NewTicker(sseHeartbeatInterval)
	defer heartbeat.Stop()
	for {
		select {
		case line, open := <-ch:
			if !open {
				s.sendStatus(w, job)
				flusher.Flush()
				return
			}
			sendLog(line)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (s *server) sendStatus(w http.ResponseWriter, job *Job) {
	payload, _ := json.Marshal(job.summary())
	fmt.Fprintf(w, "event: status\ndata: %s\n\n", payload)
}

// handleLog returns the full captured log as plain text (memory or .log file).
func (s *server) handleLog(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if owner, known := s.mgr.ownerOf(id); !known || !s.canAccessScan(r, owner) {
		writeError(w, http.StatusNotFound, "log not found")
		return
	}
	if job, ok := s.mgr.Get(id); ok {
		job.mu.Lock()
		lines := append([]string(nil), job.logBuf...)
		job.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		for _, line := range lines {
			fmt.Fprintln(w, line)
		}
		return
	}
	path, err := s.confinedResultFile(id, ".log")
	if err != nil {
		writeError(w, http.StatusNotFound, "log not found")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	http.ServeFile(w, r, path)
}

// handleReport serves the generated report files for download.
func (s *server) handleReport(ext string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if owner, known := s.mgr.ownerOf(id); !known || !s.canAccessScan(r, owner) {
			writeError(w, http.StatusNotFound, "report not found")
			return
		}
		path, err := s.confinedResultFile(id, "."+ext)
		if err != nil {
			writeError(w, http.StatusNotFound, "report not found")
			return
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(path)))
		http.ServeFile(w, r, path)
	}
}

// confinedResultFile resolves id+ext inside the results directory, rejecting
// anything that escapes it.
func (s *server) confinedResultFile(id, ext string) (string, error) {
	if id == "" || filepath.Base(id) != id || strings.Contains(id, "..") {
		return "", fmt.Errorf("invalid id")
	}
	candidate := filepath.Join(s.mgr.resultsDir, id+ext)
	base, err := filepath.EvalSymlinks(s.mgr.resultsDir)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", err
	}
	if resolved != base && !strings.HasPrefix(resolved, base+string(os.PathSeparator)) {
		return "", fmt.Errorf("outside the results directory")
	}
	// #nosec G703 -- resolved is confined to resultsDir just above: id is a single path component (no ".."), symlink-evaluated and prefix-checked against the results dir before this stat.
	fi, err := os.Stat(resolved)
	if err != nil || !fi.Mode().IsRegular() {
		return "", fmt.Errorf("not found")
	}
	return resolved, nil
}
