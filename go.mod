module github.com/R4Wbytes/w1r3hound

go 1.22

// Pinned to clear the go1.26.5 stdlib advisories flagged by govulncheck
// (C-11/F-13). go 1.22 remains the minimum language version.
toolchain go1.26.6
