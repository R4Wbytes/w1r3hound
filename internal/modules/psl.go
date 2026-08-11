package modules

import (
	_ "embed"
	"strings"
	"sync"
)

// The official Mozilla Public Suffix List (MPL 2.0 — license header preserved
// in the file itself). Pulled from https://publicsuffix.org/list/public_suffix_list.dat.
// Replaces the previous curated ~50-entry compoundTLDs map, which missed any
// compound TLD an operator's target happened to use (.edu.co, .gov.br, .ac.nz,
// .gov.cn, …) and silently mis-normalised the apex for those.
//
//go:embed data/public_suffix_list.dat
var pslRaw string

type publicSuffixList struct {
	normal    map[string]bool // exact rule, e.g. "co.uk", "com"
	wildcard  map[string]bool // fixed part of a "*.base" rule, e.g. "ck" for "*.ck"
	exception map[string]bool // rule after stripping "!", e.g. "www.ck" for "!www.ck"
}

var (
	pslOnce sync.Once
	psl     *publicSuffixList
)

func loadPSL() *publicSuffixList {
	pslOnce.Do(func() {
		p := &publicSuffixList{
			normal:    make(map[string]bool),
			wildcard:  make(map[string]bool),
			exception: make(map[string]bool),
		}
		for _, line := range strings.Split(pslRaw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "//") {
				continue
			}
			switch {
			case strings.HasPrefix(line, "!"):
				p.exception[strings.ToLower(line[1:])] = true
			case strings.HasPrefix(line, "*."):
				p.wildcard[strings.ToLower(line[2:])] = true
			default:
				p.normal[strings.ToLower(line)] = true
			}
		}
		psl = p
	})
	return psl
}

// publicSuffixLabelCount returns how many trailing labels of a domain (given
// as its dot-split labels) form its public suffix (eTLD), per the matching
// algorithm at https://publicsuffix.org/list/:
//  1. An exception rule ("!www.ck") wins outright over any other match; the
//     suffix is the exception rule's labels minus its leftmost label.
//  2. Otherwise the longest matching normal ("co.uk") or wildcard ("*.ck",
//     which matches exactly one extra label plus its fixed part) rule wins.
//  3. An unmatched domain falls back to the implicit "*" rule: the bare TLD
//     label (count 1) — e.g. an unlisted TLD still gets a sane apex split.
func publicSuffixLabelCount(labels []string) int {
	p := loadPSL()
	n := len(labels)

	for k := 1; k <= n; k++ {
		candidate := strings.Join(labels[n-k:], ".")
		if p.exception[candidate] {
			return k - 1
		}
	}

	best := 1
	for k := 1; k <= n; k++ {
		candidate := strings.Join(labels[n-k:], ".")
		if p.normal[candidate] && k > best {
			best = k
		}
	}
	for k := 1; k < n; k++ {
		base := strings.Join(labels[n-k:], ".")
		if p.wildcard[base] && k+1 > best {
			best = k + 1
		}
	}
	return best
}
