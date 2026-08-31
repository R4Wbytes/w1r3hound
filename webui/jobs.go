package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// JobStatus is the lifecycle state of a queued scan.
type JobStatus string

const (
	StatusQueued    JobStatus = "queued"
	StatusRunning   JobStatus = "running"
	StatusDone      JobStatus = "done"
	StatusFailed    JobStatus = "failed"
	StatusCancelled JobStatus = "cancelled"
)

const (
	maxLogLines   = 5000
	queueCapacity = 32
	numWorkers    = 2
)

// ansiRe strips the CLI's own colour codes before lines hit the browser.
var ansiRe = regexp.MustCompile("\x1b\\[[0-9;]*[A-Za-z]")

// Job is one queued/running/finished w1r3hound invocation.
type Job struct {
	ID        string    `json:"id"`
	Target    string    `json:"target"`
	Owner     string    `json:"owner,omitempty"` // submitting username; empty in open mode
	Args      []string  `json:"args"`
	Status    JobStatus `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	StartedAt time.Time `json:"started_at,omitempty"`
	EndedAt   time.Time `json:"ended_at,omitempty"`
	ExitCode  int       `json:"exit_code"`
	ErrMsg    string    `json:"error,omitempty"`
	BasePath  string    `json:"-"` // absolute output base, no extension

	mu      sync.Mutex
	logBuf  []string
	subs    map[chan string]struct{}
	closed  bool
	cancel  context.CancelFunc
	logFile *os.File
	counts  map[string]int
	total   int
	hasJSON bool
	hasMD   bool
}

// appendLog records one output line, mirrors it to the on-disk .log file and
// broadcasts it to live SSE subscribers (dropping for slow consumers).
func (j *Job) appendLog(line string) {
	line = ansiRe.ReplaceAllString(line, "")
	line = strings.TrimRight(line, "\r")
	j.mu.Lock()
	if len(j.logBuf) >= maxLogLines {
		j.logBuf = j.logBuf[1:]
	}
	j.logBuf = append(j.logBuf, line)
	if j.logFile != nil {
		fmt.Fprintln(j.logFile, line)
	}
	for ch := range j.subs {
		select {
		case ch <- line:
		default:
		}
	}
	j.mu.Unlock()
}

// subscribe returns a replay snapshot and a live channel. If the job already
// finished, the channel is nil and final is true.
func (j *Job) subscribe() (replay []string, ch chan string, final bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	replay = append(replay, j.logBuf...)
	if j.closed {
		return replay, nil, true
	}
	ch = make(chan string, 256)
	j.subs[ch] = struct{}{}
	return replay, ch, false
}

func (j *Job) unsubscribe(ch chan string) {
	j.mu.Lock()
	delete(j.subs, ch)
	j.mu.Unlock()
}

// finish marks the job terminal, refreshes report metadata and closes subscribers.
func (j *Job) finish(status JobStatus, exitCode int, errMsg string) {
	j.mu.Lock()
	j.Status = status
	j.ExitCode = exitCode
	j.ErrMsg = errMsg
	j.EndedAt = time.Now()
	if j.logFile != nil {
		_ = j.logFile.Close()
		j.logFile = nil
	}
	j.closed = true
	for ch := range j.subs {
		close(ch)
	}
	j.subs = map[chan string]struct{}{}
	j.mu.Unlock()
	j.refreshReportMeta()
}

// refreshReportMeta checks which report files exist and caches severity
// counts parsed from the JSON report.
func (j *Job) refreshReportMeta() {
	j.mu.Lock()
	defer j.mu.Unlock()
	jsonPath := j.BasePath + ".json"
	mdPath := j.BasePath + ".md"
	_, jsonErr := os.Stat(jsonPath)
	_, mdErr := os.Stat(mdPath)
	j.hasJSON = jsonErr == nil
	j.hasMD = mdErr == nil
	if j.hasJSON {
		if counts, total, err := countSeverities(jsonPath); err == nil {
			j.counts = counts
			j.total = total
		}
	}
}

// ScanSummary is the list-view representation of a scan, whether still
// tracked in memory or recovered from report files on disk.
type ScanSummary struct {
	ID        string         `json:"id"`
	Target    string         `json:"target"`
	Owner     string         `json:"-"` // server-side only: used for per-user access control
	Status    JobStatus      `json:"status"`
	CreatedAt string         `json:"created_at,omitempty"`
	StartedAt string         `json:"started_at,omitempty"`
	EndedAt   string         `json:"ended_at,omitempty"`
	ExitCode  int            `json:"exit_code,omitempty"`
	ErrMsg    string         `json:"error,omitempty"`
	Total     int            `json:"total_findings"`
	Counts    map[string]int `json:"counts,omitempty"`
	HasReport bool           `json:"has_report"`
	Live      bool           `json:"live"` // in-memory: live log and cancel available
}

func (j *Job) summary() ScanSummary {
	j.mu.Lock()
	defer j.mu.Unlock()
	s := ScanSummary{
		ID:        j.ID,
		Target:    j.Target,
		Owner:     j.Owner,
		Status:    j.Status,
		ExitCode:  j.ExitCode,
		ErrMsg:    j.ErrMsg,
		Total:     j.total,
		Counts:    j.counts,
		HasReport: j.hasJSON || j.hasMD,
		Live:      true,
	}
	if !j.CreatedAt.IsZero() {
		s.CreatedAt = j.CreatedAt.UTC().Format(time.RFC3339)
	}
	if !j.StartedAt.IsZero() {
		s.StartedAt = j.StartedAt.UTC().Format(time.RFC3339)
	}
	if !j.EndedAt.IsZero() {
		s.EndedAt = j.EndedAt.UTC().Format(time.RFC3339)
	}
	return s
}

// owner returns the submitting username (empty in open mode). Safe to call
// concurrently with the job's own locking.
func (j *Job) owner() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.Owner
}

// Manager owns the job map, the queue and the worker pool.
type Manager struct {
	repoRoot     string
	binPath      string
	resultsDir   string
	wordlistsDir string

	mu    sync.RWMutex
	jobs  map[string]*Job
	queue chan *Job
}

func NewManager(repoRoot, binPath, resultsDir, wordlistsDir string) (*Manager, error) {
	for _, dir := range []string{resultsDir, wordlistsDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		// Tighten perms even if the directory pre-existed with a looser mode,
		// so other local users cannot enumerate scan names / target domains.
		if fi, err := os.Stat(dir); err == nil {
			_ = os.Chmod(dir, fi.Mode().Perm()&^0o077)
		}
	}
	m := &Manager{
		repoRoot:     repoRoot,
		binPath:      binPath,
		resultsDir:   resultsDir,
		wordlistsDir: wordlistsDir,
		jobs:         make(map[string]*Job),
		queue:        make(chan *Job, queueCapacity),
	}
	for i := 0; i < numWorkers; i++ {
		go m.worker()
	}
	return m, nil
}

// Submit registers a new job and queues it. The output base name must be
// unique both among live jobs and report files already on disk.
func (m *Manager) Submit(owner, target string, args []string, base string) (*Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.jobs[base]; exists {
		return nil, fmt.Errorf("a scan with the name %q already exists", base)
	}
	if _, err := os.Stat(filepath.Join(m.resultsDir, base+".json")); err == nil {
		return nil, errOutputExists(base)
	}
	if len(m.queue) >= queueCapacity {
		return nil, fmt.Errorf("queue full, try again when a scan finishes")
	}
	// #nosec G304 -- base is validated by outputNameRe in buildArgs (alphanumerics/._- only, no ".."), then joined under resultsDir; the path cannot escape the results directory.
	logFile, err := os.OpenFile(filepath.Join(m.resultsDir, base+".log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("could not create the log file: %w", err)
	}
	// Persist ownership next to the report so per-user access control survives a
	// server restart (the in-memory job map is lost; reports are recovered from
	// disk). Best-effort: the live job carries its owner regardless, and a
	// missing sidecar degrades to admin-only, never to a cross-user leak.
	if werr := writeScanMeta(m.resultsDir, base, scanMeta{
		Owner:     owner,
		Target:    target,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}); werr != nil {
		log.Printf("could not persist ownership metadata for scan %q: %v", base, werr)
	}
	job := &Job{
		ID:        base,
		Target:    target,
		Owner:     owner,
		Args:      args,
		Status:    StatusQueued,
		CreatedAt: time.Now(),
		BasePath:  filepath.Join(m.resultsDir, base),
		subs:      make(map[chan string]struct{}),
		logFile:   logFile,
	}
	m.jobs[base] = job
	m.queue <- job
	return job, nil
}

// scanMeta is the ownership sidecar persisted next to each report as
// "<base>.meta.json" so per-user access control survives a server restart.
type scanMeta struct {
	Owner     string `json:"owner"`
	Target    string `json:"target"`
	CreatedAt string `json:"created_at,omitempty"`
}

func metaPath(resultsDir, base string) string {
	return filepath.Join(resultsDir, base+".meta.json")
}

func writeScanMeta(resultsDir, base string, m scanMeta) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(metaPath(resultsDir, base), data, 0o600)
}

func readScanMeta(resultsDir, base string) (scanMeta, error) {
	var m scanMeta
	data, err := os.ReadFile(metaPath(resultsDir, base))
	if err != nil {
		return m, err
	}
	err = json.Unmarshal(data, &m)
	return m, err
}

// validScanID rejects ids that are not a single safe path component, so a
// crafted id can never make ownerOf read outside the results directory.
func validScanID(id string) bool {
	return id != "" && filepath.Base(id) == id && !strings.Contains(id, "..")
}

// ownerOf returns the recorded owner of a scan id, consulting the live job
// first and then the on-disk ownership sidecar. `known` is false when no such
// scan/report exists at all. A report present without a sidecar (legacy) yields
// an empty owner with known=true, which canAccessScan treats as admin-only.
func (m *Manager) ownerOf(id string) (owner string, known bool) {
	if !validScanID(id) {
		return "", false
	}
	m.mu.RLock()
	j, ok := m.jobs[id]
	m.mu.RUnlock()
	if ok {
		return j.owner(), true
	}
	if meta, err := readScanMeta(m.resultsDir, id); err == nil {
		return meta.Owner, true
	}
	for _, ext := range []string{".json", ".md", ".log"} {
		// #nosec G703 -- id is gated by validScanID at the top of ownerOf (single path component, no ".."), so the joined path stays inside resultsDir.
		if _, err := os.Stat(filepath.Join(m.resultsDir, id+ext)); err == nil {
			return "", true // legacy report without an ownership sidecar
		}
	}
	return "", false
}

func errOutputExists(base string) error {
	return fmt.Errorf("a report with the name %q already exists; choose another", base)
}

func (m *Manager) Get(id string) (*Job, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	j, ok := m.jobs[id]
	return j, ok
}

// Cancel requests termination of a queued or running job.
func (m *Manager) Cancel(id string) error {
	m.mu.RLock()
	job, ok := m.jobs[id]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("scan not found")
	}
	job.mu.Lock()
	defer job.mu.Unlock()
	switch job.Status {
	case StatusRunning:
		if job.cancel != nil {
			job.cancel()
		}
		return nil
	case StatusQueued:
		// The worker checks for pre-cancelled jobs before starting.
		if job.cancel != nil {
			job.cancel()
		}
		job.Status = StatusCancelled
		return nil
	default:
		return fmt.Errorf("the scan already finished")
	}
}

func (m *Manager) worker() {
	for job := range m.queue {
		func() {
			defer func() {
				if r := recover(); r != nil {
					job.appendLog(fmt.Sprintf("[webui] internal worker error: %v", r))
					job.finish(StatusFailed, -1, fmt.Sprintf("internal panic: %v", r))
				}
			}()
			m.run(job)
		}()
	}
}

// run executes the w1r3hound binary, streaming stdout+stderr line by line
// into the job log.
func (m *Manager) run(job *Job) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// F-7: install the cancel func and flip to Running under the SAME lock, so
	// any Cancel() that observes StatusRunning is guaranteed to see a non-nil
	// job.cancel. Previously these were two separate locked sections, leaving a
	// window where a cancellation could be silently dropped.
	job.mu.Lock()
	if job.Status == StatusCancelled {
		job.mu.Unlock()
		job.finish(StatusCancelled, -1, "cancelled before starting")
		return
	}
	job.cancel = cancel
	job.Status = StatusRunning
	job.StartedAt = time.Now()
	job.mu.Unlock()

	// #nosec G204 -- m.binPath is the fixed w1r3hound binary; job.Args is built solely by buildArgs from allow-listed flags and validated values, and exec.CommandContext runs no shell.
	cmd := exec.CommandContext(ctx, m.binPath, job.Args...)
	cmd.Dir = m.repoRoot
	// On cancel, ask politely first: the CLI writes a partial report on
	// SIGINT. WaitDelay escalates to SIGKILL if it does not exit in time.
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return cmd.Process.Signal(os.Interrupt)
	}
	cmd.WaitDelay = 10 * time.Second

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		job.finish(StatusFailed, -1, err.Error())
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		job.finish(StatusFailed, -1, err.Error())
		return
	}

	job.appendLog("[webui] $ w1r3hound " + strings.Join(job.Args, " "))
	if err := cmd.Start(); err != nil {
		job.appendLog("[webui] could not start w1r3hound: " + err.Error())
		job.finish(StatusFailed, -1, err.Error())
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	scan := func(r io.Reader) {
		defer wg.Done()
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 256*1024), 1024*1024)
		for sc.Scan() {
			job.appendLog(sc.Text())
		}
	}
	go scan(stdout)
	go scan(stderr)
	wg.Wait()

	waitErr := cmd.Wait()
	job.appendLog("[webui] process finished")
	switch {
	case ctx.Err() == context.Canceled:
		job.finish(StatusCancelled, exitCodeOf(waitErr), "cancelled by the user")
	case waitErr == nil:
		job.finish(StatusDone, 0, "")
	default:
		code := exitCodeOf(waitErr)
		if code == 130 { // SIGINT handled by the CLI (partial report written)
			job.finish(StatusCancelled, code, "interrupted")
			return
		}
		job.finish(StatusFailed, code, waitErr.Error())
	}
}

func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return -1
}

// countSeverities parses a report JSON file and returns per-severity counts.
func countSeverities(jsonPath string) (map[string]int, int, error) {
	// #nosec G304 -- jsonPath is <resultsDir>/<base>.json where base is the validated scan id (outputNameRe, no ".."); it never contains untrusted path segments.
	f, err := os.Open(jsonPath)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	var rep struct {
		Findings []struct {
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	limited := io.LimitReader(f, 64*1024*1024)
	if err := json.NewDecoder(limited).Decode(&rep); err != nil {
		return nil, 0, err
	}
	counts := map[string]int{}
	for _, finding := range rep.Findings {
		counts[finding.Severity]++
	}
	return counts, len(rep.Findings), nil
}

// List merges live jobs with report files left by previous server runs.
func (m *Manager) List() []ScanSummary {
	m.mu.RLock()
	live := make(map[string]*Job, len(m.jobs))
	for id, j := range m.jobs {
		live[id] = j
	}
	m.mu.RUnlock()

	out := make([]ScanSummary, 0, len(live))
	for _, j := range live {
		out = append(out, j.summary())
	}

	matches, _ := filepath.Glob(filepath.Join(m.resultsDir, "*.json"))
	for _, jsonPath := range matches {
		base := strings.TrimSuffix(filepath.Base(jsonPath), ".json")
		if strings.HasSuffix(base, ".meta") {
			continue // ownership sidecar, not a report
		}
		if _, ok := live[base]; ok {
			continue
		}
		rep, err := parseReportHeader(jsonPath)
		if err != nil {
			continue
		}
		owner := ""
		if meta, err := readScanMeta(m.resultsDir, base); err == nil {
			owner = meta.Owner
		}
		out = append(out, ScanSummary{
			ID:        base,
			Target:    rep.Target,
			Owner:     owner,
			Status:    StatusDone,
			StartedAt: rep.StartedAt,
			EndedAt:   rep.EndedAt,
			Total:     rep.Total,
			Counts:    rep.Counts,
			HasReport: true,
			Live:      false,
		})
	}
	sort.Slice(out, func(i, k int) bool {
		a, b := out[i].StartedAt+out[i].CreatedAt, out[k].StartedAt+out[k].CreatedAt
		return a > b
	})
	return out
}

type reportHeader struct {
	Target    string
	StartedAt string
	EndedAt   string
	Counts    map[string]int
	Total     int
}

func parseReportHeader(jsonPath string) (*reportHeader, error) {
	// #nosec G304 -- jsonPath comes from filepath.Glob over resultsDir (server-enumerated report files), never from user input.
	f, err := os.Open(jsonPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var rep struct {
		Target    string `json:"target"`
		StartedAt string `json:"started_at"`
		EndedAt   string `json:"ended_at"`
		Findings  []struct {
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if err := json.NewDecoder(io.LimitReader(f, 64*1024*1024)).Decode(&rep); err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, finding := range rep.Findings {
		counts[finding.Severity]++
	}
	return &reportHeader{
		Target:    rep.Target,
		StartedAt: rep.StartedAt,
		EndedAt:   rep.EndedAt,
		Counts:    counts,
		Total:     len(rep.Findings),
	}, nil
}
