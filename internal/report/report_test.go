package report

import (
	"strings"
	"testing"

	"github.com/w1r3hound/w1r3hound/internal/core"
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
