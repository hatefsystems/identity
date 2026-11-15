package profile

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
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

func TestNormalizePersonalName(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
		invalid           bool
	}{
		{"missing", "", "", true},
		{"spaces only", "   ", "", true},
		{"given name", "\u0639\u0644\u06cc", "\u0639\u0644\u06cc", false},
		{"compound", "\u0645\u062d\u0645\u062f \u0631\u0636\u0627", "\u0645\u062d\u0645\u062f \u0631\u0636\u0627", false},
		{"ZWNJ compound", "\u0646\u06cc\u06a9\u200c\u0646\u0627\u0645", "\u0646\u06cc\u06a9\u200c\u0646\u0627\u0645", false},
		{"keyboard aliases", "\u0643\u064a\u0648\u0627\u0646", "\u06a9\u06cc\u0648\u0627\u0646", false},
		{"ASCII spaces", "  \u0639\u0644\u06cc   \u0631\u0636\u0627  ", "\u0639\u0644\u06cc \u0631\u0636\u0627", false},
		{"madda composition", "\u0627\u0653", "\u0622", false},
		{"Waw Hamza composition", "\u0648\u0654", "\u0624", false},
		{"Yeh Hamza composition", "\u064a\u0654", "\u0626", false},
		{"Persian Yeh Hamza unsupported", "\u06cc\u0654", "", true},
		{"Hamza distinctions", "\u0621\u0622\u0627\u0624\u0648\u0626\u06cc", "\u0621\u0622\u0627\u0624\u0648\u0626\u06cc", false},
		{"80 code points", strings.Repeat("\u0628", 80), strings.Repeat("\u0628", 80), false},
		{"81 code points", strings.Repeat("\u0628", 81), "", true},
		{"separators count at 80", strings.Repeat("\u0628\u200c", 39) + "\u0628\u0628", strings.Repeat("\u0628\u200c", 39) + "\u0628\u0628", false},
		{"separators count at 81", strings.Repeat("\u0628 ", 40) + "\u0628", "", true},
		{"collapse before count", "\u0628" + strings.Repeat(" ", 100) + "\u0628", "\u0628 \u0628", false},
		{"raw 1024 bytes", strings.Repeat(" ", 1022) + "\u0628", "\u0628", false},
		{"raw 1025 bytes", strings.Repeat(" ", 1023) + "\u0628", "", true},
		{"invalid UTF8", "private\xffname", "", true},
		{"Latin", "Ada", "", true},
		{"mixed script", "\u0628a", "", true},
		{"emoji", "\U0001f600", "", true},
		{"punctuation", "\u0628.\u0628", "", true},
		{"underscore", "\u0628_\u0628", "", true},
		{"Arabic punctuation", "\u0628\u060c\u0628", "", true},
		{"vowel mark", "\u0628\u064e", "", true},
		{"combining mark", "\u0628\u0301", "", true},
		{"Alef Hamza unsupported", "\u0627\u0654", "", true},
		{"Alef below unsupported", "\u0625", "", true},
		{"Alef wasla unsupported", "\u0671", "", true},
		{"Alef maksura unsupported", "\u0649", "", true},
		{"Arabic U0629 unsupported", "\u0629", "", true},
		{"tatweel", "\u0628\u0640\u0628", "", true},
		{"presentation form", "\ufb8e", "", true},
		{"presentation ligature", "\ufefb", "", true},
		{"outer ZWNJ left", "\u200c\u0628", "", true},
		{"outer ZWNJ right", "\u0628\u200c", "", true},
		{"repeated ZWNJ", "\u0628\u200c\u200c\u0628", "", true},
		{"space then ZWNJ", "\u0628 \u200c\u0628", "", true},
		{"ZWNJ then space", "\u0628\u200c \u0628", "", true},
		{"trim cannot repair ZWNJ", "  \u200c\u0628  ", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizePersonalName(tc.input)
			if got != tc.want || (err != nil) != tc.invalid || (err != nil && err != ErrInvalidPersonalName) {
				t.Fatal("private-name normalization mismatch")
			}
			assertPersonalNameInvariant(t, got, err)
		})
	}
}

func TestPersonalNameRepertoireAndSeparatorProperties(t *testing.T) {
	const admitted = "\u0621\u0622\u0624\u0626\u0627\u0628\u062a\u062b\u062c\u062d\u062e\u062f\u0630\u0631\u0632\u0633\u0634\u0635\u0636\u0637\u0638\u0639\u063a\u0641\u0642\u0643\u0644\u0645\u0646\u0647\u0648\u064a\u067e\u0686\u0698\u06a9\u06af\u06cc"
	for _, left := range admitted {
		for _, right := range admitted {
			for _, separator := range []string{"", " ", "   ", "\u200c"} {
				got, err := NormalizePersonalName(string(left) + separator + string(right))
				if err != nil {
					t.Fatal("permitted letter pair or structural separator rejected")
				}
				assertPersonalNameInvariant(t, got, err)
			}
		}
	}
	for _, separator := range []string{"\u200c", "\u200c\u200c", " \u200c", "\u200c ", " \u200c "} {
		for _, input := range []string{separator, separator + "\u0628", "\u0628" + separator} {
			if got, err := NormalizePersonalName(input); err != ErrInvalidPersonalName || got != "" {
				t.Fatal("invalid edge separator accepted")
			}
		}
		if separator != "\u200c" {
			if got, err := NormalizePersonalName("\u0628" + separator + "\u0628"); err != ErrInvalidPersonalName || got != "" {
				t.Fatal("adjacent separators accepted")
			}
		}
	}
	for _, attack := range "0123456789\u0660\u0661\u0662\u0663\u0664\u0665\u0666\u0667\u0668\u0669\u06f0\u06f1\u06f2\u06f3\u06f4\u06f5\u06f6\u06f7\u06f8\u06f9\u0966\u0967\uff10\uff11\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\u200b\u200d\u200e\u200f\u061c\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\ufeff" {
		for _, input := range []string{string(attack) + "\u0628", "\u0628" + string(attack), "\u0628" + string(attack) + "\u0628"} {
			if got, err := NormalizePersonalName(input); err != ErrInvalidPersonalName || got != "" {
				t.Fatalf("unsupported scalar U+%04X accepted", attack)
			}
		}
	}
	for r := rune(0); r <= 0x9f; r++ {
		if r > 0x1f && r < 0x7f {
			continue
		}
		for _, input := range []string{string(r) + "\u0628", "\u0628" + string(r), "\u0628" + string(r) + "\u0628"} {
			if got, err := NormalizePersonalName(input); err != ErrInvalidPersonalName || got != "" {
				t.Fatalf("control U+%04X accepted", r)
			}
		}
	}
}

func FuzzNormalizePersonalName(f *testing.F) {
	for _, input := range []string{"", "   ", "\u0639\u0644\u06cc", " \u0643\u064a  \u0628 ", "\u0627\u0653", "\u0648\u0654", "\u064a\u0654", "\u0628\u200c\u0628", "\u0628 \u200c\u0628", "\u0628\u202e", "\u0628\u06f1", "private\xffname", strings.Repeat("\u0628", 80), strings.Repeat("\u0628", 81), strings.Repeat(" ", 1022) + "\u0628", strings.Repeat(" ", 1023) + "\u0628"} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		got, err := NormalizePersonalName(input)
		assertPersonalNameInvariant(t, got, err)
		if err == nil {
			if !utf8.ValidString(input) || len(input) > MaxPersonalNameBytes {
				t.Fatal("raw input bound bypassed")
			}
			equivalent, err := NormalizePersonalName(norm.NFC.String(input))
			if err != nil || equivalent != got {
				t.Fatal("NFC equivalence changed")
			}
		}
	})
}

func assertPersonalNameInvariant(t *testing.T, got string, err error) {
	t.Helper()
	if err != nil {
		if err != ErrInvalidPersonalName || got != "" || err.Error() != "profile: invalid personal name" {
			t.Fatal("private-name error is not static and redacted")
		}
		return
	}
	if !utf8.ValidString(got) || !norm.NFC.IsNormalString(got) || len(got) > MaxPersonalNameBytes || utf8.RuneCountInString(got) < 1 || utf8.RuneCountInString(got) > MaxPersonalNameLength {
		t.Fatal("normalized private-name bounds violated")
	}
	const letters = "\u0621\u0622\u0624\u0626\u0627\u0628\u062a\u062b\u062c\u062d\u062e\u062f\u0630\u0631\u0632\u0633\u0634\u0635\u0636\u0637\u0638\u0639\u063a\u0641\u0642\u0644\u0645\u0646\u0647\u0648\u067e\u0686\u0698\u06a9\u06af\u06cc"
	runes := []rune(got)
	for i, r := range runes {
		if r == ' ' || r == '\u200c' {
			if i == 0 || i == len(runes)-1 || !strings.ContainsRune(letters, runes[i-1]) || !strings.ContainsRune(letters, runes[i+1]) {
				t.Fatal("normalized separator lacks letter context")
			}
		} else if !strings.ContainsRune(letters, r) {
			t.Fatal("normalized repertoire violated")
		}
	}
	if again, err := NormalizePersonalName(got); err != nil || again != got {
		t.Fatal("private-name normalization is not idempotent")
	}
}
