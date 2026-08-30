package core

import (
	"reflect"
	"strings"
	"testing"
)

// TestScrubArgsSlices pins the C-4 fix: []string log args (discovered
// subdomains, port banners, allowed HTTP methods) are scrubbed element-wise,
// non-string/slice args pass through, and the caller's slice is never mutated.
func TestScrubArgsSlices(t *testing.T) {
	orig := []string{"good.example.com", "evil\x1b[2Jname", "c1\u009bbanner"}
	before := append([]string(nil), orig...)

	args := []any{"plain\x1bstring", orig, 42}
	out := scrubArgs(args)

	if s, _ := out[0].(string); strings.ContainsRune(s, 0x1b) {
		t.Errorf("string arg not scrubbed: %q", s)
	}
	cleaned, ok := out[1].([]string)
	if !ok {
		t.Fatalf("slice arg type changed: %T", out[1])
	}
	for _, s := range cleaned {
		if strings.ContainsRune(s, 0x1b) || strings.ContainsRune(s, 0x9b) {
			t.Errorf("slice element not scrubbed: %q", s)
		}
	}
	if out[2] != 42 {
		t.Errorf("non-string arg altered: %v", out[2])
	}
	if !reflect.DeepEqual(orig, before) {
		t.Errorf("scrubArgs mutated the caller's slice: %v (was %v)", orig, before)
	}
}
