package modules

import (
	"bytes"
	"testing"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

func TestRunPassiveSkipsIPLiteral(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Domain = "192.168.1.1"
	report := core.NewReport("192.168.1.1")
	var buf bytes.Buffer
	log := core.NewLoggerWriter(true, true, &buf)

	RunPassive(cfg, report, log)

	if !bytes.Contains(buf.Bytes(), []byte("IP literal")) {
		t.Fatalf("expected IP literal skip message, got: %s", buf.String())
	}
	if len(report.Snapshot().Findings) != 0 {
		t.Fatal("expected no findings for IP literal target")
	}
}

func TestRunPassiveSkipsNonRoutable(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Domain = "localhost"
	report := core.NewReport("localhost")
	var buf bytes.Buffer
	log := core.NewLoggerWriter(true, true, &buf)

	RunPassive(cfg, report, log)

	if !bytes.Contains(buf.Bytes(), []byte("non-routable")) {
		t.Fatalf("expected non-routable skip message, got: %s", buf.String())
	}
}
