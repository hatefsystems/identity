package blindindex

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
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
