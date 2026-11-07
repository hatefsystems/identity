package blindindex

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func newTestPepper(t *testing.T) []byte {
	t.Helper()
	p := make([]byte, PepperSize)
	if _, err := rand.Read(p); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return p
}

func TestComputeEmailCanonicalExactBytes(t *testing.T) {
	pepper := bytes.Repeat([]byte{0x42}, PepperSize)
	idx, err := New(pepper, 7)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ input, canonical string }{
		{" USER@EXAMPLE.COM ", "user@example.com"},
		{"JOSE\u0301@b\u00fccher.example", "jos\u00e9@xn--bcher-kva.example"},
		{"\u0639\u0644\u06cc@\u0645\u062b\u0627\u0644.\u0627\u06cc\u0631\u0627\u0646", "\u0639\u0644\u06cc@xn--mgbh0fb.xn--mgba3a4f16a"},
		{"\uff35ser@example.com", "\uff55ser@example.com"},
	} {
		mac := hmac.New(sha256.New, pepper)
		_, _ = mac.Write([]byte(tc.canonical))
		want := hex.EncodeToString(mac.Sum(nil))
		got, err := idx.ComputeEmail(tc.input)
		if err != nil || got != want || idx.Version() != 7 {
			t.Fatal("email digest differs from exact canonical bytes or generation changed")
		}
		canonicalDigest, err := idx.ComputeEmail(tc.canonical)
		if err != nil || canonicalDigest != got {
			t.Fatal("canonical equivalent digest changed")
		}
	}
	for _, input := range []string{"user@example.com", " USER@EXAMPLE.COM ", "+tag@example.test"} {
		got, err := idx.ComputeEmail(input)
		if err != nil || got != idx.Compute(input) {
			t.Fatal("canonical ASCII index bytes changed")
		}
	}
	const asciiGolden = "2bcb2417758c9b1fdfc518de094b24c710026931c3a52a996975982d8b6a223c"
	got, err := idx.ComputeEmail(" USER@EXAMPLE.COM ")
	if err != nil || got != asciiGolden || idx.Compute(" USER@EXAMPLE.COM ") != asciiGolden {
		t.Fatal("generic or canonical ASCII HMAC golden changed")
	}
	for _, pair := range [][2]string{
		{"user@example.com", "\uff55ser@example.com"},
		{"ff@example.com", "\ufb00@example.com"},
		{"\u06cc@example.com", "\u064a@example.com"},
		{"\u06a9@example.com", "\u0643@example.com"},
		{"user@example.com", "u.ser@example.com"},
		{"user@example.com", "user+tag@example.com"},
	} {
		a, errA := idx.ComputeEmail(pair[0])
		b, errB := idx.ComputeEmail(pair[1])
		if errA != nil || errB != nil || a == b {
			t.Fatal("distinct email identities merged")
		}
	}
	if idx.Compute("\uff55ser@example.com") != idx.Compute("user@example.com") {
		t.Fatal("generic NFKC semantics changed")
	}
	for _, input := range []string{"bad", "a\u200cb@example.test", "a\xff@example.test", strings.Repeat("a", 1025)} {
		if got, err := idx.ComputeEmail(input); err == nil || got != "" {
			t.Fatal("invalid email produced an index")
		}
	}
}

func TestNewInvalidPepper(t *testing.T) {
	cases := map[string]int{
		"empty":     0,
		"too-short": 16,
		"one-short": PepperSize - 1,
	}
	for name, size := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(make([]byte, size), 0); !errors.Is(err, ErrInvalidPepper) {
				t.Fatalf("New(len=%d, 0) error = %v, want ErrInvalidPepper", size, err)
			}
		})
	}
}

func TestComputeDeterministic(t *testing.T) {
	idx, err := New(newTestPepper(t), 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a := idx.Compute("+989121234567")
	b := idx.Compute("+989121234567")
	if a != b {
		t.Errorf("Compute not deterministic: %q != %q", a, b)
	}
}

func TestComputeDigestFormat(t *testing.T) {
	idx, err := New(newTestPepper(t), 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := idx.Compute("user@example.com")
	if len(got) != DigestHexLen {
		t.Errorf("digest length = %d, want %d", len(got), DigestHexLen)
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Errorf("digest is not valid hex: %v", err)
	}
}

func TestComputeDifferentInputs(t *testing.T) {
	idx, err := New(newTestPepper(t), 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a := idx.Compute("+989121234567")
	b := idx.Compute("+989127654321")
	if a == b {
		t.Error("different inputs produced identical blind index")
	}
}

// TestPepperSensitivity ensures the same PII under different peppers yields
// different indexes, so an exfiltrated database cannot be correlated without
// the in-memory pepper.
func TestPepperSensitivity(t *testing.T) {
	idx1, err := New(newTestPepper(t), 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	idx2, err := New(newTestPepper(t), 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if idx1.Compute("user@example.com") == idx2.Compute("user@example.com") {
		t.Error("same PII under different peppers produced identical index")
	}
}

// TestComputeNormalization ensures trivial representation differences map to
// the same index (case + surrounding whitespace).
func TestComputeNormalization(t *testing.T) {
	idx, err := New(newTestPepper(t), 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	base := idx.Compute("user@example.com")
	cases := []string{
		"USER@EXAMPLE.COM",
		"  user@example.com  ",
		"User@Example.Com",
	}
	for _, in := range cases {
		if got := idx.Compute(in); got != base {
			t.Errorf("Compute(%q) = %q, want %q", in, got, base)
		}
	}
}

// TestPepperDefensiveCopy ensures mutating the caller's pepper slice after
// construction does not change computed indexes.
func TestPepperDefensiveCopy(t *testing.T) {
	pepper := newTestPepper(t)
	idx, err := New(pepper, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	before := idx.Compute("value")
	for i := range pepper {
		pepper[i] ^= 0xFF
	}
	after := idx.Compute("value")
	if before != after {
		t.Error("mutating caller pepper changed index; defensive copy missing")
	}
}

func TestEqual(t *testing.T) {
	idx, err := New(newTestPepper(t), 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a := idx.Compute("value")
	b := idx.Compute("value")
	c := idx.Compute("other")

	if !Equal(a, b) {
		t.Error("Equal(a, b) = false for equal digests")
	}
	if Equal(a, c) {
		t.Error("Equal(a, c) = true for different digests")
	}
	if Equal(a, "") {
		t.Error("Equal(a, empty) = true")
	}
}

// TestVersionIsReportedAndIndependentOfTheDigest covers the pepper-rotation
// contract. The generation number travels alongside the digest and is hashed
// into the security ledger's signed body, but it must not feed the HMAC itself:
// if it did, re-stating a row's generation would change its digest and the
// lookup path for that row would break instead of being preserved.
func TestVersionIsReportedAndIndependentOfTheDigest(t *testing.T) {
	pepper := newTestPepper(t)

	v0, err := New(pepper, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v7, err := New(pepper, 7)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if v0.Version() != 0 {
		t.Errorf("Version() = %d, want 0", v0.Version())
	}
	if v7.Version() != 7 {
		t.Errorf("Version() = %d, want 7", v7.Version())
	}
	if v0.Compute("user@example.com") != v7.Compute("user@example.com") {
		t.Error("the generation number altered the digest; restating a row's generation would orphan its lookup path")
	}
}

func TestNewRejectsNegativeVersion(t *testing.T) {
	if _, err := New(newTestPepper(t), -1); !errors.Is(err, ErrInvalidVersion) {
		t.Errorf("New(pepper, -1) error = %v, want ErrInvalidVersion", err)
	}
}

// TestComputeAppliesUnicodeNormalization is the attribution-correctness case.
// An identifier captured in decomposed form (e + U+0301) and the same
// identifier in composed form (U+00E9) are one address to a human and to a mail
// server. Without NFKC they produce different indexes, so a lawful-inquiry
// lookup silently misses rows captured in the other form — a false negative
// indistinguishable from "no such subject".
func TestComputeAppliesUnicodeNormalization(t *testing.T) {
	idx, err := New(newTestPepper(t), 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	composed := "josé@example.com"         // U+00E9
	decomposed := "jose\u0301@example.com" // e + U+0301
	if composed == decomposed {
		t.Fatal("test inputs are byte-identical; the case under test is not being exercised")
	}
	if idx.Compute(composed) != idx.Compute(decomposed) {
		t.Error("composed and decomposed spellings of one identifier produced different indexes")
	}

	// Compatibility folding also has to apply, or a fullwidth homograph indexes
	// as a different subject.
	if idx.Compute("ｕser@example.com") != idx.Compute("user@example.com") {
		t.Error("a fullwidth homograph produced a different index")
	}
}
