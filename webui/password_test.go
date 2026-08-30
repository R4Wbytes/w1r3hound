package main

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestPBKDF2SHA256Vectors pins the KDF against authoritative
// PBKDF2-HMAC-SHA256 test vectors (generated with Python's
// hashlib.pbkdf2_hmac). A regression in the hand-rolled construction would
// change these outputs and fail the build.
func TestPBKDF2SHA256Vectors(t *testing.T) {
	cases := []struct {
		password, salt string
		iter, keyLen   int
		want           string
	}{
		{"password", "salt", 1, 32, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
		{"password", "salt", 2, 32, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
		{"password", "salt", 4096, 32, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
		// Multi-block output (dkLen 64 > hLen 32) exercises the block loop.
		{"passwd", "salt", 1, 64, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"},
	}
	for _, c := range cases {
		got := hex.EncodeToString(pbkdf2SHA256([]byte(c.password), []byte(c.salt), c.iter, c.keyLen))
		if got != c.want {
			t.Errorf("pbkdf2(%q,%q,%d,%d) = %s, want %s", c.password, c.salt, c.iter, c.keyLen, got, c.want)
		}
	}
}

func TestHashAndVerifyPassword(t *testing.T) {
	prev := pbkdf2Iterations
	pbkdf2Iterations = 4096
	defer func() { pbkdf2Iterations = prev }()

	enc, err := hashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if !strings.HasPrefix(enc, pbkdf2Algo+"$") {
		t.Fatalf("encoded hash has wrong prefix: %q", enc)
	}
	if strings.Contains(enc, "correct horse") {
		t.Fatalf("plaintext leaked into the hash: %q", enc)
	}
	// Two hashes of the same password must differ (unique salt).
	enc2, _ := hashPassword("correct horse battery staple")
	if enc == enc2 {
		t.Fatalf("identical hashes for the same password — salt not random")
	}

	ok, err := verifyPassword(enc, "correct horse battery staple")
	if err != nil || !ok {
		t.Fatalf("verify correct password: ok=%v err=%v", ok, err)
	}
	ok, err = verifyPassword(enc, "wrong password entirely")
	if err != nil {
		t.Fatalf("verify wrong password errored: %v", err)
	}
	if ok {
		t.Fatalf("verify accepted a wrong password")
	}
}

func TestVerifyPasswordMalformed(t *testing.T) {
	bad := []string{
		"",
		"notahash",
		"pbkdf2-sha256$abc$c2FsdA$aGFzaA", // non-numeric iterations
		"pbkdf2-sha256$1000$$aGFzaA",      // empty salt
		"md5$1$c2FsdA$aGFzaA",             // unsupported algo
	}
	for _, enc := range bad {
		if ok, err := verifyPassword(enc, "whatever"); ok || err == nil {
			t.Errorf("verifyPassword(%q) = (%v,%v), want (false, error)", enc, ok, err)
		}
	}
}

func TestValidatePasswordPolicy(t *testing.T) {
	good := []string{"a-very-long-passphrase", "Tr0ub4dour&3xtra", "twelvechars!"}
	for _, p := range good {
		if err := validatePasswordPolicy(p, "alice"); err != nil {
			t.Errorf("policy rejected good password %q: %v", p, err)
		}
	}
	bad := []struct {
		password, username, why string
	}{
		{"tooshort", "bob", "shorter than the minimum"},
		{"password123", "bob", "on the common deny-list"},
		{"administrator", "administrator", "equal to the username"},
		{"              ", "bob", "whitespace only"},
		{strings.Repeat("x", maxPasswordLen+1), "bob", "over the maximum length"},
	}
	for _, c := range bad {
		if err := validatePasswordPolicy(c.password, c.username); err == nil {
			t.Errorf("policy accepted a password that is %s", c.why)
		}
	}
}
