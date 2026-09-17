package main

import (
	"encoding/json"
	"testing"
)

func TestEnrichWorkflows(t *testing.T) {
	raw := json.RawMessage(`[
		{"name":"passive_recon","description":"passive"},
		{"name":"bug_bounty_recon","description":"bb"},
		{"name":"exhaustive_recon","description":"exhaustive"},
		{"name":"unknown_prompt","description":"should be skipped"}
	]`)
	wf := enrichWorkflows(raw)
	if len(wf) != 3 {
		t.Fatalf("expected 3 workflows, got %d", len(wf))
	}
	names := map[string]bool{}
	for _, w := range wf {
		names[w.Name] = true
		if w.Title == "" {
			t.Errorf("workflow %q has empty title", w.Name)
		}
		if w.Icon == "" {
			t.Errorf("workflow %q has empty icon", w.Name)
		}
		if w.Defaults == nil {
			t.Errorf("workflow %q has nil defaults", w.Name)
		}
		if w.Defaults["source"] != "mcp" {
			t.Errorf("workflow %q defaults missing source=mcp", w.Name)
		}
	}
	if !names["passive_recon"] {
		t.Error("missing passive_recon")
	}
	if !names["bug_bounty_recon"] {
		t.Error("missing bug_bounty_recon")
	}
	if names["unknown_prompt"] {
		t.Error("unknown_prompt should have been filtered out")
	}
}

func TestEnrichWorkflowsExhaustiveDefaults(t *testing.T) {
	raw := json.RawMessage(`[{"name":"exhaustive_recon","description":"x"}]`)
	wf := enrichWorkflows(raw)
	if len(wf) != 1 {
		t.Fatalf("expected 1, got %d", len(wf))
	}
	d := wf[0].Defaults
	if d["ports"] != "full" {
		t.Errorf("expected ports=full, got %v", d["ports"])
	}
	if d["concurrency"] != 5 {
		t.Errorf("expected concurrency=5, got %v", d["concurrency"])
	}
	if wf[0].Icon != "microscope" {
		t.Errorf("expected icon=microscope, got %q", wf[0].Icon)
	}
}

func TestEnrichWorkflowsInvalidJSON(t *testing.T) {
	wf := enrichWorkflows(json.RawMessage(`not json`))
	if wf != nil {
		t.Errorf("expected nil on bad JSON, got %v", wf)
	}
}

func TestEnrichWorkflowsEmpty(t *testing.T) {
	wf := enrichWorkflows(json.RawMessage(`[]`))
	if len(wf) != 0 {
		t.Errorf("expected 0, got %d", len(wf))
	}
}
