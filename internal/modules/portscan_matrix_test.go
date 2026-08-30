package modules

import (
	"net"
	"testing"
	"time"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

// selectPorts edge cases (inverted/huge/clamped ranges) are covered in
// audit_new_test.go; this fills the TEST_PLAN §1.2 gap for the named specs.
func TestSelectPortsNamedSpecs(t *testing.T) {
	if got := selectPorts("top100"); len(got) != len(top100Ports) {
		t.Errorf("top100 -> %d ports, want %d", len(got), len(top100Ports))
	}
	if got := selectPorts("TOP100"); len(got) != len(top100Ports) {
		t.Errorf("case-insensitive TOP100 -> %d ports, want %d", len(got), len(top100Ports))
	}

	r := selectPorts("1-1024")
	if len(r) != 1024 || r[0] != 1 || r[len(r)-1] != 1024 {
		t.Errorf("1-1024 -> len=%d first=%d last=%d, want 1024/1/1024", len(r), r[0], r[len(r)-1])
	}

	full := selectPorts("full")
	if len(full) != 65535 || full[0] != 1 || full[len(full)-1] != 65535 {
		t.Errorf("full -> len=%d first=%d last=%d, want 65535/1/65535", len(full), full[0], full[len(full)-1])
	}
	if len(selectPorts("FULL")) != 65535 {
		t.Errorf("case-insensitive FULL should expand to 65535 ports")
	}
}

// TestScanOneIPOpenVsClosed is a hermetic FP/FN check for the port scanner: an
// actually-listening loopback port must be reported open, and a closed port
// must not be (no false positive). No traffic leaves the host.
func TestScanOneIPOpenVsClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	openPort := ln.Addr().(*net.TCPAddr).Port
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	// A port that is bound then released is very likely closed for the test's
	// duration; the scanner must not report it open.
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen2: %v", err)
	}
	closedPort := ln2.Addr().(*net.TCPAddr).Port
	_ = ln2.Close()

	cfg := core.DefaultConfig()
	cfg.Concurrency = 4
	log := core.NewLogger(false)

	res := scanOneIP(cfg, log, "127.0.0.1", "127.0.0.1",
		[]int{openPort, closedPort}, 500*time.Millisecond, 150*time.Millisecond)

	open := map[int]bool{}
	for _, p := range res.OpenPorts {
		open[p.Port] = true
	}
	if !open[openPort] {
		t.Errorf("false negative: listening port %d not detected as open", openPort)
	}
	if open[closedPort] {
		t.Errorf("false positive: closed port %d reported open", closedPort)
	}
}
