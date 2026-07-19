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
			if _, err := New(make([]byte, size)); !errors.Is(err, ErrInvalidPepper) {
				t.Fatalf("New(len=%d) error = %v, want ErrInvalidPepper", size, err)
			}
		})
	}
}

func TestComputeDeterministic(t *testing.T) {
	idx, err := New(newTestPepper(t))
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
	idx, err := New(newTestPepper(t))
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
	idx, err := New(newTestPepper(t))
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
	idx1, err := New(newTestPepper(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	idx2, err := New(newTestPepper(t))
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
	idx, err := New(newTestPepper(t))
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
	idx, err := New(pepper)
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
	idx, err := New(newTestPepper(t))
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
