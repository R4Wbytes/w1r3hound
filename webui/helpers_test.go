package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"testing"
	"time"
)

// helperHarness is the sentinel first positional argument that tells a
// re-executed test binary to behave as a stand-in for the w1r3hound CLI
// instead of running the normal test suite.
const helperSentinel = "w1r3hound-helper"

// helperArgs builds the argv passed to the (re-executed) test binary so it
// lands in TestHelperProcess and runs the requested behavior mode. This is the
// standard os/exec test pattern: the "subprocess" is a controlled Go test that
// emits canned output and a chosen exit code, so jobs.go can be exercised with
// no real scanner and no network.
func helperArgs(mode string) []string {
	return []string{"-test.run=TestHelperProcess", "--", helperSentinel, mode}
}

// managerForTest returns a Manager whose worker pool is live and whose binPath
// points at this test binary, so Submit -> worker -> run() drives the real
// concurrency path while TestHelperProcess stands in for the CLI.
func managerForTest(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	results := filepath.Join(dir, "results")
	wordlists := filepath.Join(dir, "wordlists")
	m, err := NewManager(dir, os.Args[0], results, wordlists)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

// managerNoWorkers builds a Manager struct directly, without starting the
// worker goroutines, so tests can inspect the queue deterministically (e.g.
// the queue-full branch) without a drain race.
func managerNoWorkers(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	results := filepath.Join(dir, "results")
	wordlists := filepath.Join(dir, "wordlists")
	for _, d := range []string{results, wordlists} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	return &Manager{
		repoRoot:     dir,
		binPath:      "/bin/true",
		resultsDir:   results,
		wordlistsDir: wordlists,
		jobs:         make(map[string]*Job),
		queue:        make(chan *Job, queueCapacity),
	}
}

// newTestServer wires a server (optionally token-protected) onto a Manager
// backed by fresh temp dirs. binPath is /bin/true so any job that happens to
// run in a handler test is a harmless no-op rather than the real scanner.
func newTestServer(t *testing.T, token string) *server {
	t.Helper()
	dir := t.TempDir()
	results := filepath.Join(dir, "results")
	wordlists := filepath.Join(dir, "wordlists")
	binPath := "/bin/true"
	if _, err := os.Stat(binPath); err != nil {
		binPath = os.Args[0]
	}
	m, err := NewManager(dir, binPath, results, wordlists)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	auth, err := NewAuthManager(filepath.Join(dir, "auth"), false)
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	return &server{mgr: m, auth: auth, token: token}
}

// newAuthTestServer returns a server whose login panel is active, seeded with
// one administrator. It also lowers the PBKDF2 cost for fast tests and returns
// a logged-in session cookie + CSRF token for that admin.
func newAuthTestServer(t *testing.T, adminUser, adminPass string) (*server, *http.Cookie, string) {
	t.Helper()
	prev := pbkdf2Iterations
	pbkdf2Iterations = 4096
	t.Cleanup(func() { pbkdf2Iterations = prev })

	s := newTestServer(t, "")
	if _, err := s.auth.createUser(adminUser, adminPass, RoleAdmin, false); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	raw, sess, err := s.auth.createSession(normalizeUsername(adminUser), RoleAdmin)
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}
	return s, &http.Cookie{Name: sessionCookieName, Value: raw}, sess.CSRFToken
}

// waitClosed blocks until the job reaches a terminal (closed) state or the
// deadline elapses.
func waitClosed(t *testing.T, j *Job, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		j.mu.Lock()
		done := j.closed
		j.mu.Unlock()
		if done {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("job %q did not finish within %s", j.ID, within)
}

// waitStatus blocks until the job reaches the wanted status or the deadline
// elapses.
func waitStatus(t *testing.T, j *Job, want JobStatus, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		j.mu.Lock()
		got := j.Status
		j.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	j.mu.Lock()
	got := j.Status
	j.mu.Unlock()
	t.Fatalf("job %q status = %q, want %q within %s", j.ID, got, want, within)
}

// TestHelperProcess is not a real test. When the test binary is re-executed
// with the helper sentinel (see helperArgs), it impersonates the w1r3hound CLI
// and exits with a chosen code so jobs.go can be tested hermetically. During a
// normal `go test` run it returns immediately.
func TestHelperProcess(t *testing.T) {
	args := flag.Args()
	if len(args) == 0 || args[0] != helperSentinel {
		return
	}
	mode := ""
	if len(args) > 1 {
		mode = args[1]
	}
	switch mode {
	case "exit0":
		fmt.Fprintln(os.Stdout, "helper: recon starting")
		fmt.Fprintln(os.Stderr, "helper: a warning on stderr")
		// ANSI colour codes must be stripped before hitting the log/browser.
		fmt.Fprint(os.Stdout, "\x1b[32mhelper: coloured line\x1b[0m\r\n")
		fmt.Fprintln(os.Stdout, "helper: done")
		os.Exit(0)
	case "exitn":
		fmt.Fprintln(os.Stdout, "helper: something before failing")
		os.Exit(3)
	case "exit130":
		// Mimic the CLI handling SIGINT itself and writing a partial report.
		fmt.Fprintln(os.Stdout, "helper: interrupted, partial report written")
		os.Exit(130)
	case "sleep":
		sigc := make(chan os.Signal, 1)
		signal.Notify(sigc, os.Interrupt)
		fmt.Fprintln(os.Stdout, "helper: long scan running")
		select {
		case <-sigc:
			os.Exit(130)
		case <-time.After(30 * time.Second):
			os.Exit(0)
		}
	default:
		os.Exit(0)
	}
}
