package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func containsLine(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

func snapshotLog(j *Job) []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]string(nil), j.logBuf...)
}

func TestSubmitCreatesLogFile0600(t *testing.T) {
	m := managerNoWorkers(t)
	job, err := m.Submit("", "127.0.0.1", []string{"-t", "127.0.0.1"}, "scan-a")
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if job.Status != StatusQueued {
		t.Fatalf("status = %q, want queued", job.Status)
	}
	fi, err := os.Stat(filepath.Join(m.resultsDir, "scan-a.log"))
	if err != nil {
		t.Fatalf("stat log: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("log perm = %o, want 600", perm)
	}
}

func TestSubmitDuplicateBaseRejected(t *testing.T) {
	m := managerNoWorkers(t)
	if _, err := m.Submit("", "127.0.0.1", []string{"-t", "127.0.0.1"}, "dup"); err != nil {
		t.Fatalf("first Submit: %v", err)
	}
	_, err := m.Submit("", "127.0.0.1", []string{"-t", "127.0.0.1"}, "dup")
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate Submit err = %v, want 'already exists'", err)
	}
}

func TestSubmitExistingReportRejected(t *testing.T) {
	m := managerNoWorkers(t)
	if err := os.WriteFile(filepath.Join(m.resultsDir, "ondisk.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := m.Submit("", "127.0.0.1", []string{"-t", "127.0.0.1"}, "ondisk")
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("Submit over existing report err = %v, want 'already exists'", err)
	}
}

func TestSubmitQueueFull(t *testing.T) {
	m := managerNoWorkers(t)
	for i := 0; i < queueCapacity; i++ {
		m.queue <- &Job{}
	}
	_, err := m.Submit("", "127.0.0.1", []string{"-t", "127.0.0.1"}, "overflow")
	if err == nil || !strings.Contains(err.Error(), "queue full") {
		t.Fatalf("queue-full Submit err = %v, want 'queue full'", err)
	}
}

func TestRunSuccessCapturesAndStripsANSI(t *testing.T) {
	m := managerForTest(t)
	job, err := m.Submit("", "127.0.0.1", helperArgs("exit0"), "run-ok")
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	waitClosed(t, job, 20*time.Second)

	if job.Status != StatusDone {
		t.Fatalf("status = %q, want done", job.Status)
	}
	if job.ExitCode != 0 {
		t.Fatalf("exit = %d, want 0", job.ExitCode)
	}
	log := snapshotLog(job)
	if len(log) == 0 || !strings.HasPrefix(log[0], "[webui] $ w1r3hound ") {
		t.Fatalf("first log line = %q, want '[webui] $ w1r3hound ...'", log)
	}
	if !containsLine(log, "helper: coloured line") {
		t.Fatalf("ANSI not stripped / line missing; log = %v", log)
	}
	if !containsLine(log, "helper: recon starting") {
		t.Fatalf("stdout line missing; log = %v", log)
	}
	if !containsLine(log, "helper: a warning on stderr") {
		t.Fatalf("stderr line missing (stderr not merged); log = %v", log)
	}
	if !containsLine(log, "[webui] process finished") {
		t.Fatalf("terminal marker missing; log = %v", log)
	}
}

func TestRunNonZeroExitFails(t *testing.T) {
	m := managerForTest(t)
	job, err := m.Submit("", "127.0.0.1", helperArgs("exitn"), "run-fail")
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	waitClosed(t, job, 20*time.Second)
	if job.Status != StatusFailed {
		t.Fatalf("status = %q, want failed", job.Status)
	}
	if job.ExitCode != 3 {
		t.Fatalf("exit = %d, want 3", job.ExitCode)
	}
}

func TestRunExit130Cancelled(t *testing.T) {
	m := managerForTest(t)
	job, err := m.Submit("", "127.0.0.1", helperArgs("exit130"), "run-130")
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	waitClosed(t, job, 20*time.Second)
	if job.Status != StatusCancelled {
		t.Fatalf("status = %q, want cancelled (exit 130)", job.Status)
	}
	if job.ExitCode != 130 {
		t.Fatalf("exit = %d, want 130", job.ExitCode)
	}
}

func TestCancelRunningJob(t *testing.T) {
	m := managerForTest(t)
	job, err := m.Submit("", "127.0.0.1", helperArgs("sleep"), "run-cancel")
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	waitStatus(t, job, StatusRunning, 20*time.Second)
	// F-7 is fixed: once a job is observably Running, job.cancel is installed,
	// so a single Cancel must take effect (no retry needed). This doubles as the
	// regression guard for that fix.
	if err := m.Cancel("run-cancel"); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	waitClosed(t, job, 20*time.Second)
	if job.Status != StatusCancelled {
		t.Fatalf("status = %q, want cancelled", job.Status)
	}
}

func TestCancelQueuedJobBeforeStart(t *testing.T) {
	m := managerForTest(t)
	// Occupy both workers so the next submission stays queued.
	blockers := make([]*Job, 0, numWorkers)
	for i := 0; i < numWorkers; i++ {
		b, err := m.Submit("", "127.0.0.1", helperArgs("sleep"), fmt.Sprintf("blocker-%d", i))
		if err != nil {
			t.Fatalf("Submit blocker: %v", err)
		}
		waitStatus(t, b, StatusRunning, 20*time.Second)
		blockers = append(blockers, b)
	}
	t.Cleanup(func() {
		for _, b := range blockers {
			_ = m.Cancel(b.ID)
			waitClosed(t, b, 20*time.Second)
		}
	})

	queued, err := m.Submit("", "127.0.0.1", helperArgs("exit0"), "still-queued")
	if err != nil {
		t.Fatalf("Submit queued: %v", err)
	}
	// Give the (busy) workers a moment; it must remain queued.
	time.Sleep(100 * time.Millisecond)
	queued.mu.Lock()
	st := queued.Status
	queued.mu.Unlock()
	if st != StatusQueued {
		t.Fatalf("pre-cancel status = %q, want queued", st)
	}
	if err := m.Cancel("still-queued"); err != nil {
		t.Fatalf("Cancel queued: %v", err)
	}
	queued.mu.Lock()
	st = queued.Status
	queued.mu.Unlock()
	if st != StatusCancelled {
		t.Fatalf("post-cancel status = %q, want cancelled", st)
	}
}

func TestCancelFinishedJobRejected(t *testing.T) {
	m := managerForTest(t)
	job, err := m.Submit("", "127.0.0.1", helperArgs("exit0"), "already-done")
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	waitClosed(t, job, 20*time.Second)
	err = m.Cancel("already-done")
	if err == nil || !strings.Contains(err.Error(), "already finished") {
		t.Fatalf("cancel finished err = %v, want 'already finished'", err)
	}
}

func TestCancelUnknownJob(t *testing.T) {
	m := managerForTest(t)
	if err := m.Cancel("does-not-exist"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("cancel unknown err = %v, want 'not found'", err)
	}
}

func TestSubscribeReplayAndSlowSubscriberDropped(t *testing.T) {
	j := &Job{subs: make(map[chan string]struct{})}

	replay, ch, final := j.subscribe()
	if final || ch == nil || len(replay) != 0 {
		t.Fatalf("initial subscribe: replay=%d ch=%v final=%v", len(replay), ch, final)
	}

	const n = 300 // > channel capacity (256), < maxLogLines
	done := make(chan struct{})
	go func() {
		for i := 0; i < n; i++ {
			j.appendLog(fmt.Sprintf("line-%d", i))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("appendLog blocked on a slow subscriber (backpressure not dropped)")
	}

	// The buffered channel must have capped at 256; extra lines are dropped.
	count := 0
drain:
	for {
		select {
		case <-ch:
			count++
		default:
			break drain
		}
	}
	if count != 256 {
		t.Fatalf("buffered lines = %d, want 256 (drop-on-full)", count)
	}

	// The full log is retained in the ring buffer regardless of subscriber speed.
	if got := len(snapshotLog(j)); got != n {
		t.Fatalf("logBuf len = %d, want %d", got, n)
	}

	// After finish, subscribe replays everything and reports final with no channel.
	j.finish(StatusDone, 0, "")
	replay2, ch2, final2 := j.subscribe()
	if !final2 || ch2 != nil {
		t.Fatalf("post-finish subscribe: ch=%v final=%v, want nil/true", ch2, final2)
	}
	if len(replay2) != n {
		t.Fatalf("replay after finish = %d, want %d", len(replay2), n)
	}
}

func TestLogRingBufferEviction(t *testing.T) {
	j := &Job{subs: make(map[chan string]struct{})}
	total := maxLogLines + 25
	for i := 0; i < total; i++ {
		j.appendLog(fmt.Sprintf("l-%d", i))
	}
	log := snapshotLog(j)
	if len(log) != maxLogLines {
		t.Fatalf("ring buffer len = %d, want %d", len(log), maxLogLines)
	}
	// Oldest lines evicted; newest retained.
	if !containsLine(log, fmt.Sprintf("l-%d", total-1)) {
		t.Fatalf("newest line missing after eviction")
	}
	if containsLine(log, "l-0") {
		t.Fatalf("oldest line should have been evicted")
	}
}
