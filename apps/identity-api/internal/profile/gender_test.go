package profile

import (
	"strings"
	"testing"
)

func TestValidateGender(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want Gender
	}{
		{"female", GenderFemale}, {"male", GenderMale},
		{"", ""}, {string(Gender("")), ""}, {" female", ""}, {"male ", ""},
		{"Female", ""}, {"MALE", ""}, {"f", ""}, {"m", ""}, {"woman", ""}, {"man", ""},
		{"\u0632\u0646", ""}, {"\u0645\u0631\u062f", ""}, {"0", ""}, {"1", ""}, {"2", ""},
		{"female\x00", ""}, {"male\n", ""}, {"male\xff", ""}, {"\u202emale", ""},
		{strings.Repeat("male", 100000), ""},
	} {
		got, err := ValidateGender(tc.raw)
		if got != tc.want || (err == nil) != (tc.want != "") {
			t.Fatal("exact gender admission mismatch")
		}
		assertGenderInvariant(t, tc.raw, got, err)
	}
	for r := rune(0); r <= 0x9f; r++ {
		if r > 0x1f && r < 0x7f {
			continue
		}
		got, err := ValidateGender("female" + string(r))
		assertGenderInvariant(t, "female"+string(r), got, err)
	}
}

func FuzzValidateGender(f *testing.F) {
	for _, raw := range []string{"", "female", "male", "Female", " male ", "f", "1", "\u0632\u0646", "male\xff", "female\x00", strings.Repeat("male", 100000)} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got, err := ValidateGender(raw)
		assertGenderInvariant(t, raw, got, err)
	})
}

func assertGenderInvariant(t *testing.T, raw string, got Gender, err error) {
	t.Helper()
	if raw == "female" || raw == "male" {
		if err != nil || string(got) != raw {
			t.Fatal("exact gender did not retain its value")
		}
		if again, err := ValidateGender(string(got)); err != nil || again != got {
			t.Fatal("gender validation is not idempotent")
		}
	} else if err != ErrInvalidGender || got != "" || err.Error() != "profile: invalid gender" {
		t.Fatal("gender error is not zero-valued, static and redacted")
	}
}
