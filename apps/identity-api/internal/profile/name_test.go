package profile

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestNormalizeName(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
		invalid           bool
	}{
		{"empty", "", "", false},
		{"outer whitespace", " \u00a0\u2002Ada Lovelace\u3000 ", "Ada Lovelace", false},
		{"clear", " \u00a0\u2002\u3000 ", "", false},
		{"non Latin", "\u0647\u0627\u062a\u0641", "\u0647\u0627\u062a\u0641", false},
		{"multi byte boundary", strings.Repeat("\U0001f600", 80), strings.Repeat("\U0001f600", 80), false},
		{"trim before length", " " + strings.Repeat("a", 80) + " ", strings.Repeat("a", 80), false},
		{"no grapheme folding", "e\u0301", "e\u0301", false},
		{"preserve internal space", "a  b", "a  b", false},
		{"long", strings.Repeat("a", 81), "", true},
		{"multi byte long", strings.Repeat("\U0001f600", 81), "", true},
		{"invalid UTF8", "private\xffname", "", true},
		{"line separator", "a\u2028b", "", true},
		{"paragraph separator", "\u2029name", "", true},
		{"newline at edge", "name\n", "", true},
		{"tab at edge", "\tname", "", true},
		{"NUL", "a\x00b", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeName(tc.input)
			if got != tc.want || errors.Is(err, ErrInvalidName) != tc.invalid {
				t.Fatalf("normalization mismatch: error=%v", err)
			}
			if err != nil && strings.Contains(err.Error(), "private") {
				t.Fatal("error exposed name")
			}
		})
	}
	for r := rune(0); r <= 0x9f; r++ {
		if r > 0x1f && r < 0x7f {
			continue
		}
		if _, err := NormalizeName("name" + string(r)); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("control U+%04X accepted", r)
		}
	}
}

func TestRevisionExactDecimalStrings(t *testing.T) {
	for _, value := range []int64{0, 1, 1<<53 + 1, 9223372036854775807} {
		raw := strconv.FormatInt(value, 10)
		if got, err := parseRevision(raw); err != nil || got != value {
			t.Fatalf("revision %s changed: %v", raw, err)
		}
	}
	for _, raw := range []string{"", "00", "01", "+1", "-0", "-1", " 1", "1 ", "1.0", "1e1", "0x1", "9223372036854775808", strings.Repeat("1", 500)} {
		if _, err := parseRevision(raw); !errors.Is(err, ErrInvalidRevision) {
			t.Fatalf("invalid revision %q accepted", raw)
		}
	}
}
