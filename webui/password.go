package main

// Password hashing for the login panel.
//
// The whole project is deliberately dependency-free (standard library only)
// and pins the go.mod language floor at go1.22. That rules out
// golang.org/x/crypto (bcrypt/scrypt/argon2) and the stdlib crypto/pbkdf2
// package (added in go1.24). We therefore implement PBKDF2-HMAC-SHA256
// (RFC 8018 / RFC 2898 §5.2) on top of crypto/hmac + crypto/sha256, which is
// a simple, well-specified construction verified against published test
// vectors in password_test.go.
//
// PBKDF2-HMAC-SHA256 with a per-password random salt and a high iteration
// count is an OWASP-accepted password KDF. Hashes are stored in a
// self-describing PHC-style string so the iteration count can be raised over
// time without invalidating existing hashes.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	// pbkdf2SaltLen is the per-password salt size (128 bits).
	pbkdf2SaltLen = 16
	// pbkdf2KeyLen is the derived-key length; matches SHA-256's 32-byte block.
	pbkdf2KeyLen = 32
	// pbkdf2Algo is the identifier stored in the encoded hash.
	pbkdf2Algo = "pbkdf2-sha256"

	// minPasswordLen follows NIST SP 800-63B / OWASP ASVS: favour length over
	// composition rules. maxPasswordLen bounds the HMAC input to keep a single
	// login from turning into a CPU-DoS with a multi-megabyte "password".
	minPasswordLen = 12
	maxPasswordLen = 128
)

// pbkdf2Iterations is the work factor applied to *new* hashes. It is a var
// (not a const) purely so tests can lower it; verification always uses the
// iteration count embedded in the stored hash. 600k is the OWASP 2023
// recommendation for PBKDF2-HMAC-SHA256.
var pbkdf2Iterations = 600_000

// commonPasswords is a tiny embedded deny-list of the most abused passwords.
// It is not a substitute for a breach-corpus check, but it cheaply blocks the
// worst choices without a network call or third-party dependency.
var commonPasswords = map[string]struct{}{
	"password":      {},
	"password1":     {},
	"password123":   {},
	"passw0rd":      {},
	"123456":        {},
	"12345678":      {},
	"123456789":     {},
	"1234567890":    {},
	"qwerty":        {},
	"qwertyuiop":    {},
	"letmein":       {},
	"welcome":       {},
	"admin":         {},
	"administrator": {},
	"changeme":      {},
	"iloveyou":      {},
	"monkey":        {},
	"dragon":        {},
	"abc123":        {},
	"111111":        {},
	"000000":        {},
	"w1r3hound":     {},
}

var errWeakPassword = errors.New("weak password")

// pbkdf2SHA256 implements PBKDF2 (RFC 8018 §5.2) with HMAC-SHA256 as the PRF.
// It reuses a single HMAC instance across iterations for speed.
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hLen := prf.Size()
	numBlocks := (keyLen + hLen - 1) / hLen

	out := make([]byte, 0, numBlocks*hLen)
	u := make([]byte, hLen)
	t := make([]byte, hLen)
	var blockIdx [4]byte

	for block := 1; block <= numBlocks; block++ {
		// U_1 = PRF(password, salt || INT_32_BE(block))
		blockIdx[0] = byte(block >> 24)
		blockIdx[1] = byte(block >> 16)
		blockIdx[2] = byte(block >> 8)
		blockIdx[3] = byte(block)

		prf.Reset()
		prf.Write(salt)
		prf.Write(blockIdx[:])
		u = prf.Sum(u[:0])
		copy(t, u)

		// U_j = PRF(password, U_{j-1}); T = U_1 ^ U_2 ^ ... ^ U_iter
		for j := 1; j < iter; j++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for k := range t {
				t[k] ^= u[k]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

// hashPassword derives a salted PBKDF2 hash and returns it in the encoded
// PHC-style form: "pbkdf2-sha256$<iterations>$<salt-b64>$<hash-b64>".
func hashPassword(plain string) (string, error) {
	salt := make([]byte, pbkdf2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("could not generate salt: %w", err)
	}
	iter := pbkdf2Iterations
	dk := pbkdf2SHA256([]byte(plain), salt, iter, pbkdf2KeyLen)
	enc := base64.RawStdEncoding.EncodeToString
	return fmt.Sprintf("%s$%d$%s$%s", pbkdf2Algo, iter, enc(salt), enc(dk)), nil
}

// verifyPassword reports whether plain matches the encoded hash. The
// comparison is constant-time. A malformed encoded hash returns (false, err).
func verifyPassword(encoded, plain string) (bool, error) {
	algo, iter, salt, want, err := decodeHash(encoded)
	if err != nil {
		return false, err
	}
	if algo != pbkdf2Algo {
		return false, fmt.Errorf("unsupported hash algorithm %q", algo)
	}
	got := pbkdf2SHA256([]byte(plain), salt, iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func decodeHash(encoded string) (algo string, iter int, salt, hash []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 {
		return "", 0, nil, nil, errors.New("malformed password hash")
	}
	algo = parts[0]
	iter, err = strconv.Atoi(parts[1])
	if err != nil || iter < 1 {
		return "", 0, nil, nil, errors.New("invalid iteration count in password hash")
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) == 0 {
		return "", 0, nil, nil, errors.New("invalid salt in password hash")
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(hash) == 0 {
		return "", 0, nil, nil, errors.New("invalid hash in password hash")
	}
	return algo, iter, salt, hash, nil
}

// validatePasswordPolicy enforces the sign-up / change-password rules. It
// favours length over composition (NIST SP 800-63B) but blocks a few obvious
// footguns: over-long inputs, the username itself, and common passwords.
func validatePasswordPolicy(password, username string) error {
	if !utf8.ValidString(password) {
		return fmt.Errorf("%w: password must be valid UTF-8", errWeakPassword)
	}
	n := utf8.RuneCountInString(password)
	if n < minPasswordLen {
		return fmt.Errorf("%w: use at least %d characters", errWeakPassword, minPasswordLen)
	}
	if n > maxPasswordLen {
		return fmt.Errorf("%w: keep it under %d characters", errWeakPassword, maxPasswordLen)
	}
	if strings.TrimSpace(password) == "" {
		return fmt.Errorf("%w: password cannot be only whitespace", errWeakPassword)
	}
	lower := strings.ToLower(strings.TrimSpace(password))
	if _, bad := commonPasswords[lower]; bad {
		return fmt.Errorf("%w: that password is too common", errWeakPassword)
	}
	if username != "" && lower == strings.ToLower(strings.TrimSpace(username)) {
		return fmt.Errorf("%w: password must not equal the username", errWeakPassword)
	}
	return nil
}
