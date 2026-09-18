package modules

import (
	"bytes"
	"testing"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

func TestRunTakeoverSkipsPassiveMode(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Passive = true
	report := core.NewReport("example.com")
	var buf bytes.Buffer
	log := core.NewLoggerWriter(true, true, &buf)

	RunTakeover(cfg, report, log)

	if !bytes.Contains(buf.Bytes(), []byte("passive mode")) {
		t.Fatalf("expected passive mode skip, got: %s", buf.String())
	}
	if len(report.Snapshot().Findings) != 0 {
		t.Fatal("expected no findings in passive mode")
	}
}

func TestRunTakeoverSkipsNoSubdomains(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Passive = false
	report := core.NewReport("example.com")
	var buf bytes.Buffer
	log := core.NewLoggerWriter(true, true, &buf)

	RunTakeover(cfg, report, log)

	if !bytes.Contains(buf.Bytes(), []byte("No subdomains")) {
		t.Fatalf("expected no-subdomains message, got: %s", buf.String())
	}
}

func TestRunPermuteSkipsPassiveMode(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Passive = true
	report := core.NewReport("example.com")
	var buf bytes.Buffer
	log := core.NewLoggerWriter(true, true, &buf)

	RunPermute(cfg, report, log)

	if !bytes.Contains(buf.Bytes(), []byte("passive mode")) {
		t.Fatalf("expected passive mode skip, got: %s", buf.String())
	}
}

func TestRunPermuteSkipsNoSubdomains(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Passive = false
	report := core.NewReport("example.com")
	var buf bytes.Buffer
	log := core.NewLoggerWriter(true, true, &buf)

	RunPermute(cfg, report, log)

	if !bytes.Contains(buf.Bytes(), []byte("No base subdomains")) {
		t.Fatalf("expected no-subdomains message, got: %s", buf.String())
	}
}
