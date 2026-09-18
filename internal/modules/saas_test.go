package modules

import (
	"bytes"
	"testing"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

func TestRunSaaSSkipsPassiveMode(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Passive = true
	report := core.NewReport("example.com")
	var buf bytes.Buffer
	log := core.NewLoggerWriter(true, true, &buf)

	RunSaaS(cfg, report, log)

	if !bytes.Contains(buf.Bytes(), []byte("passive mode")) {
		t.Fatalf("expected passive mode skip, got: %s", buf.String())
	}
}

func TestRunSaaSSkipsIPLiteral(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Domain = "10.0.0.1"
	report := core.NewReport("10.0.0.1")
	var buf bytes.Buffer
	log := core.NewLoggerWriter(true, true, &buf)

	RunSaaS(cfg, report, log)

	if !bytes.Contains(buf.Bytes(), []byte("IP literal")) {
		t.Fatalf("expected IP literal skip, got: %s", buf.String())
	}
}

func TestRunSaaSSkipsNonRoutable(t *testing.T) {
	cfg := core.DefaultConfig()
	cfg.Domain = "localhost"
	report := core.NewReport("localhost")
	var buf bytes.Buffer
	log := core.NewLoggerWriter(true, true, &buf)

	RunSaaS(cfg, report, log)

	if !bytes.Contains(buf.Bytes(), []byte("non-routable")) {
		t.Fatalf("expected non-routable skip, got: %s", buf.String())
	}
}
