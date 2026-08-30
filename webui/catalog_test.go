package main

import "testing"

// TestModuleCatalogActiveFlagsMatchCLI guards that the GUI's notion of which
// modules are "active" (skipped by -passive) stays in lockstep with the CLI's
// activeModules table in main.go. PROJECT_STATE.md calls out that these must
// mirror each other; drift would make the GUI mislabel passive/active modules.
func TestModuleCatalogActiveFlagsMatchCLI(t *testing.T) {
	// Mirror of activeModules in ../main.go (the -passive source of truth).
	cliActive := map[string]bool{
		"webserver": true, "metafiles": true, "headers": true, "content": true,
		"portscan": true, "cors": true, "cloud": true, "dirbrute": true, "crawler": true,
		"httprobe": true, "apiscan": true, "saasenum": true, "jsdeep": true,
		"endprobe": true, "takeover": true, "permute": true,
	}
	for _, m := range moduleCatalog {
		if want := cliActive[m.Internal]; m.Active != want {
			t.Errorf("catalog %q (alias %q): Active=%v, CLI activeModules=%v", m.Internal, m.Alias, m.Active, want)
		}
	}
}

// TestAliasToInternalMatchesCatalog verifies the resolution map accepts both
// the themed alias and the internal name for every module, and that the
// catalog size matches the advertised count.
func TestAliasToInternalMatchesCatalog(t *testing.T) {
	if len(moduleCatalog) != 21 {
		t.Errorf("module catalog has %d entries, want 21", len(moduleCatalog))
	}
	for _, m := range moduleCatalog {
		if got := aliasToInternal[m.Alias]; got != m.Internal {
			t.Errorf("aliasToInternal[%q] = %q, want %q", m.Alias, got, m.Internal)
		}
		if got := aliasToInternal[m.Internal]; got != m.Internal {
			t.Errorf("aliasToInternal[%q] (internal) = %q, want self", m.Internal, got)
		}
	}
}
