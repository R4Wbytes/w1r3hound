package core

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestReconReport_ConcurrentAddAndRender reproduces the SIGINT data race: the
// signal handler calls GenerateReport (Finalize + Snapshot + SaveJSON) in a
// separate goroutine while worker goroutines are still calling Add(). Before the
// fix, Finalize/SaveJSON read r.Findings / wrote r.EndedAt with no lock, so this
// tripped the race detector and could serialise a torn slice. Run under -race,
// it must be clean now that all three paths go through r.mu.
func TestReconReport_ConcurrentAddAndRender(t *testing.T) {
	r := NewReport("example.com")
	dir := t.TempDir()
	out := filepath.Join(dir, "out.json")

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writers: several goroutines appending findings, as modules do mid-scan.
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				select {
				case <-stop:
					return
				default:
				}
				r.Add(Finding{Module: "m", Title: "f", Severity: SevInfo})
			}
		}()
	}

	// Two concurrent renderers, mirroring the real hazard: the SIGINT handler
	// and main()'s final GenerateReport can both run Finalize()+Snapshot()+
	// SaveJSON() at the same time, while modules are still calling Add(). This
	// races both fields — Findings (append vs. Snapshot copy) and EndedAt
	// (Finalize write vs. Snapshot read) — so every path must go through r.mu.
	var rwg sync.WaitGroup
	for rdr := 0; rdr < 2; rdr++ {
		rwg.Add(1)
		go func() {
			defer rwg.Done()
			for i := 0; i < 300; i++ {
				r.Finalize()
				_ = r.Snapshot()
				if err := r.SaveJSON(out); err != nil {
					t.Errorf("SaveJSON: %v", err)
					return
				}
			}
		}()
	}
	rwg.Wait()
	close(stop)

	wg.Wait()

	if _, err := os.Stat(out); err != nil {
		t.Fatalf("expected a report file to be written: %v", err)
	}
}

// TestReconReport_SnapshotIsIndependent verifies a snapshot is frozen at capture
// time: appends to the live report after Snapshot() must not mutate the copy the
// renderers hold, which is what makes single-snapshot rendering consistent.
func TestReconReport_SnapshotIsIndependent(t *testing.T) {
	r := NewReport("t")
	r.Add(Finding{Title: "a", Severity: SevInfo})

	snap := r.Snapshot()
	r.Add(Finding{Title: "b", Severity: SevInfo}) // must not reach snap

	if len(snap.Findings) != 1 {
		t.Fatalf("snapshot should stay frozen at 1 finding, got %d", len(snap.Findings))
	}
	if snap.Findings[0].Title != "a" {
		t.Fatalf("snapshot content changed after a later Add: %q", snap.Findings[0].Title)
	}
	// The live report kept growing.
	if got := r.Snapshot(); len(got.Findings) != 2 {
		t.Fatalf("live report should have 2 findings, got %d", len(got.Findings))
	}
}
