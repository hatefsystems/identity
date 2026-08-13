package smsotp

import (
	"errors"
	"strconv"
	"testing"
)

func TestNormalizePhone(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "already canonical", in: "+15551234567", want: "+15551234567"},
		{name: "strips spaces", in: "+1 555 123 4567", want: "+15551234567"},
		{name: "strips dashes", in: "+1-555-123-4567", want: "+15551234567"},
		{name: "strips parens and dots", in: "+1 (555) 123.4567", want: "+15551234567"},
		{name: "trims surrounding whitespace", in: "  +447911123456  ", want: "+447911123456"},
		{name: "shortest valid E.164", in: "+123", want: "+123"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizePhone(tc.in)
			if err != nil {
				t.Fatalf("NormalizePhone(%q) unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("NormalizePhone(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizePhoneRejectsInvalid(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{name: "empty", in: ""},
		{name: "whitespace only", in: "   "},
		{name: "no plus prefix", in: "15551234567"},
		{name: "leading zero after plus", in: "+05551234567"},
		{name: "contains letters", in: "+1555ABC4567"},
		{name: "too long (>15 digits)", in: "+1234567890123456"},
		{name: "just a plus", in: "+"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NormalizePhone(tc.in)
			if !errors.Is(err, ErrInvalidPhone) {
				t.Errorf("NormalizePhone(%q) error = %v, want ErrInvalidPhone", tc.in, err)
			}
		})
	}
}

func TestGenerateCodeShape(t *testing.T) {
	seen := make(map[string]int)
	for i := 0; i < 500; i++ {
		code, err := generateCode()
		if err != nil {
			t.Fatalf("generateCode: %v", err)
		}
		if len(code) != otpDigits {
			t.Fatalf("code %q length = %d, want %d", code, len(code), otpDigits)
		}
		if _, err := strconv.Atoi(code); err != nil {
			t.Fatalf("code %q is not all digits: %v", code, err)
		}
		seen[code]++
	}

	// A CSPRNG over 10^6 values should almost never repeat across 500 draws;
	// a heavily-biased or constant generator would collide immediately. Allow a
	// tiny amount of slack to keep the test non-flaky.
	if len(seen) < 490 {
		t.Errorf("expected near-unique codes across 500 draws, got %d distinct", len(seen))
	}
}

func TestZeroPad(t *testing.T) {
	cases := map[int64]string{
		0:      "000000",
		42:     "000042",
		999999: "999999",
		123456: "123456",
		7:      "000007",
	}
	for in, want := range cases {
		if got := zeroPad(in); got != want {
			t.Errorf("zeroPad(%d) = %q, want %q", in, got, want)
		}
	}
}
