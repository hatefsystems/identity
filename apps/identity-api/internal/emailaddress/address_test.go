package emailaddress

import (
	"errors"
	"strings"
	"testing"
)

func TestValidMailbox(t *testing.T) {
	for _, address := range []string{
		"user@example.test", "UPPER+tag@EXAMPLE.Test", "o'hara@example.test", "a!#$%&'*+-/=?^_`{|}~b@example.test",
		"user@xn--bcher-kva.example", strings.Repeat("a", 64) + "@example.test",
		"us\u00e9r@example.test", "\u0639\u0644\u06cc@xn--mgbh0fb.xn--mgba3a4f16a",
		strings.Repeat("a", 64) + "@" + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61),
	} {
		t.Run(address, func(t *testing.T) {
			if !ValidMailbox(address) {
				t.Fatal("supported mailbox rejected")
			}
		})
	}
}

func TestInvalidMailbox(t *testing.T) {
	for _, address := range []string{
		"", "@example.test", "user@", "user@localhost", "user@127.0.0.1", "user@[127.0.0.1]", "user@[IPv6:::1]",
		"Display <user@example.test>", "<user@example.test>", "\"quoted\"@example.test", "user(comment)@example.test",
		"a@example.test,b@example.test", "a@@example.test", ".user@example.test", "user.@example.test", "u..ser@example.test",
		" user@example.test", "user@example.test ", "user\t@example.test", "user\r\nBcc:other@example.test", "user\x00@example.test",
		"use\u0301r@example.test", "user@b\xc3\xbccher.example", "user@example.test.", "user@.example.test", "user@example..test",
		"user@-example.test", "user@example-.test", "user@under_score.test", "user@example/test", "user@ex<ample.test",
		strings.Repeat("a", 65) + "@example.test", "user@" + strings.Repeat("b", 64) + ".test",
		strings.Repeat("a", 64) + "@" + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62),
	} {
		t.Run(address, func(t *testing.T) {
			if ValidMailbox(address) {
				t.Fatal("unsupported or unsafe mailbox accepted")
			}
		})
	}
}

func TestCanonicalizeVectors(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"  User+Tag@EXAMPLE.Test  ", "user+tag@example.test"},
		{"\u00a0USER@example.test\u00a0", "user@example.test"},
		{"JOSE\u0301@b\u00fccher.example", "jos\u00e9@xn--bcher-kva.example"},
		{"\u0639\u0644\u06cc@\u0645\u062b\u0627\u0644.\u0627\u06cc\u0631\u0627\u0646", "\u0639\u0644\u06cc@xn--mgbh0fb.xn--mgba3a4f16a"},
		{"Stra\u00dfe@fa\u00df.de", "stra\u00dfe@xn--fa-hia.de"},
		{"\u0130@EXAMPLE.test", "i@example.test"}, // Go simple lowercase, not full case folding.
		{"\uff35ser@EXAMPLE.test", "\uff55ser@example.test"},
		{"a\u0301\u0323@example.test", "\u1ea1\u0301@example.test"},
		{"a!#$%&'*+-/=?^_`{|}~b@example.test", "a!#$%&'*+-/=?^_`{|}~b@example.test"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got, err := Canonicalize(tc.input)
			if err != nil || got != tc.want {
				t.Fatalf("Canonicalize = %q, %v; want %q", got, err, tc.want)
			}
			if !ValidMailbox(got) || !ValidCanonicalMailbox(got) {
				t.Fatal("canonical result is not a valid stored mailbox")
			}
			again, err := Canonicalize(got)
			if err != nil || again != got {
				t.Fatal("canonicalization is not idempotent")
			}
		})
	}
}

func TestCanonicalizeDistinctIdentities(t *testing.T) {
	for _, pair := range [][2]string{
		{"\u0639\u0644\u06cc@example.test", "\u0639\u0644\u064a@example.test"},
		{"\u06a9@example.test", "\u0643@example.test"},
		{"user@example.test", "u.ser@example.test"},
		{"user@example.test", "user+tag@example.test"},
		{"user@example.test", "\uff55ser@example.test"},
		{"a@example.test", "\u00aa@example.test"},
		{"ff@example.test", "\ufb00@example.test"},
		{"strasse@example.test", "stra\u00dfe@example.test"},
		{"a@fass.de", "a@fa\u00df.de"},
	} {
		a, errA := Canonicalize(pair[0])
		b, errB := Canonicalize(pair[1])
		if errA != nil || errB != nil || a == b {
			t.Fatalf("distinct identities merged or rejected: %q, %q", pair[0], pair[1])
		}
	}
}

func TestCanonicalizeRejectsUnsafeInput(t *testing.T) {
	inputs := []string{
		"", "a@localhost", "a@127.0.0.1", "a@[IPv6:::1]", "\"a\"@example.test",
		"a@example.test,b@example.test", "a@@example.test", "A <a@example.test>",
		".a@example.test", "a.@example.test", "a..b@example.test", "a@.example.test",
		"a@example.test.", "a@example..test", "a@-example.test", "a@example-.test",
		"a@under_score.test", "a@xn--.test", "a@xn--a.test", "a@\u0627a.test",
		"a b@example.test", "a\u00a0b@example.test", "a@exa mple.test", "a@exa\u00a0mple.test",
		"a\xff@example.test", "a@exa\xffmple.test", "a\xc0\xaf@example.test",
		"a\xed\xa0\x80@example.test", "a\uFFFD@example.test", "a@\uFFFD.test",
		"a\u2603@example.test", "a\U0001f600@example.test", "\r\na@example.test",
		strings.Repeat(" ", MaxRawBytes) + "a@example.test",
		strings.Repeat("a", 65) + "@example.test", strings.Repeat("\u06cc", 33) + "@example.test",
		"a@" + strings.Repeat("b", 64) + ".test",
		strings.Repeat("a", 64) + "@" + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62),
	}
	for _, c := range []rune{0, '\t', '\r', '\n', 0x7f, 0x85, 0xad, 0x34f, 0x61c, 0x115f, 0x1160,
		0x17b4, 0x180e, 0x200b, 0x200c, 0x200d, 0x200e, 0x200f, 0x202a, 0x202e, 0x2060,
		0x2066, 0x2069, 0x3164, 0xfe0f, 0xfeff, 0xffa0, 0xfff0, 0xffff, 0xe0001, 0xe0100} {
		inputs = append(inputs, "a"+string(c)+"b@example.test", "a@ex"+string(c)+"ample.test", string(c)+"a@example.test")
	}
	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			got, err := Canonicalize(input)
			if !errors.Is(err, ErrInvalid) || got != "" {
				t.Fatalf("unsafe input accepted: %q", got)
			}
			if ValidMailbox(input) || ValidCanonicalMailbox(input) {
				t.Fatal("unsafe stored input accepted")
			}
		})
	}
}

func TestCanonicalizeByteBoundsAndStoredBinding(t *testing.T) {
	for _, local := range []string{strings.Repeat("a", 64), strings.Repeat("\u06cc", 32), strings.Repeat("\U00010428", 16)} {
		if got, err := Canonicalize(local + "@example.test"); err != nil || got != local+"@example.test" {
			t.Fatal("64-byte local boundary rejected")
		}
	}
	address := strings.Repeat("a", 64) + "@" + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	if len(address) != 254 || !ValidCanonicalMailbox(address) {
		t.Fatal("254-byte canonical boundary rejected")
	}
	raw := strings.Repeat(" ", MaxRawBytes-len(address)) + address
	if got, err := Canonicalize(raw); err != nil || got != address {
		t.Fatal("1024-byte raw boundary rejected")
	}
	for _, bound := range []string{"UPPER+tag@EXAMPLE.Test", "\u00c9@example.test"} {
		if !ValidMailbox(bound) || ValidCanonicalMailbox(bound) {
			t.Fatal("stored binding validation confused with new canonical identity admission")
		}
	}
}
