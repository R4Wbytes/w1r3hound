package report

import (
	"fmt"
	"strings"
	"testing"

	"github.com/R4Wbytes/w1r3hound/internal/core"
)

// N2: a server-controlled finding title (Server header, cert CN, cookie name,
// redirect target, meta tag…) must not be able to inject Markdown structure —
// no new headings, no remote images/links, no raw control bytes, no line breaks.
func TestMarkdown_InjectionNeutralised(t *testing.T) {
	r := core.NewReport("example.com")
	evil := "nginx\x1b[2J\x1b[31mX\x1b[0m](https://attacker.tld/leak) " +
		"![pixel](https://attacker.tld/x.png)\n\n## Fake Critical Section\n- line"
	r.Add(core.Finding{
		Module:      "webserver",
		WSTG:        "WSTG-INFO-02",
		Title:       "Web server fingerprint: " + evil,
		Severity:    core.SevInfo,
		Description: evil,
	})
	r.Finalize()
	md := generateMarkdown(r)

	if strings.Contains(md, "\n## Fake Critical Section") {
		t.Error("attacker injected a heading into the report")
	}
	if strings.Contains(md, "![pixel](https://attacker.tld/x.png)") {
		t.Error("attacker injected a remote image (SSRF/tracking pixel on report open)")
	}
	if strings.Contains(md, "](https://attacker.tld/leak)") {
		t.Error("attacker injected a clickable link out of the inline context")
	}
	if strings.ContainsRune(md, 0x1b) {
		t.Error("raw ANSI escape survived into the Markdown")
	}
}

// mdInline unit checks.
func TestMdInline(t *testing.T) {
	if got := mdInline("a\nb"); strings.ContainsRune(got, '\n') {
		t.Errorf("newline not folded: %q", got)
	}
	if got := mdInline("[x](y)"); strings.Contains(got, "](") {
		t.Errorf("link syntax not escaped: %q", got)
	}
	// Plain text is preserved (modulo escaping of metacharacters).
	if got := mdInline("Apache 2.4"); got != "Apache 2.4" {
		t.Errorf("plain text altered: %q", got)
	}
}

// BenchmarkGenerateMarkdown measures the human-report builder over a large
// findings set (OPTIMIZATIONS.md §7). It exercises the per-finding inline
// escaping and severity grouping — the string-heavy hot path of report gen.
func BenchmarkGenerateMarkdown(b *testing.B) {
	r := core.NewReport("bench.example.com")
	sevs := []core.Severity{core.SevInfo, core.SevLow, core.SevMedium, core.SevHigh, core.SevCritical}
	for i := 0; i < 1000; i++ {
		r.Add(core.Finding{
			Module:      "headers",
			WSTG:        "WSTG-CONF-07",
			Title:       fmt.Sprintf("Finding %d on host-%d", i, i),
			Severity:    sevs[i%len(sevs)],
			Description: "A representative description with enough length to exercise the markdown inline escaper and the severity-grouped builder.",
			Data:        map[string]any{"index": i, "url": fmt.Sprintf("https://host-%d.example.com/path", i)},
		})
	}
	r.Finalize()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = generateMarkdown(r)
	}
}
