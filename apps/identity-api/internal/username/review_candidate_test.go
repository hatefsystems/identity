package username

import (
	"bytes"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
)

func reviewCandidateNormalizer(t testing.TB) *Normalizer {
	t.Helper()
	policyJSON, err := os.ReadFile("testdata/policy-review/policy.json")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := DecodePolicy(policyJSON)
	if err != nil {
		t.Fatal(err)
	}
	regex, err := os.ReadFile("testdata/policy-review/regex.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(regex) != fixtureRegex {
		t.Fatal("review candidate differs from the verified initial assignment syntax")
	}
	n, err := New(policy, string(regex), bytes.Repeat([]byte{0x59}, 32), "username-review-test")
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestUsernameReviewCandidateSyntaxAndReservations(t *testing.T) {
	n := reviewCandidateNormalizer(t)
	policy := n.Policy()
	approved := []string{"هاتف", "هاتف.امنیت", "هاتف.حریم.خصوصی", "هاتف.سامانه", "هاتف.مدیریت", "هاتف.پشتیبانی"}
	if !slices.Equal(policy.ReservedNames, approved) {
		t.Fatal("policy differs from the six approved exact reservations")
	}
	if err := ValidateNoSplit(fixturePolicy(), policy); err != nil {
		t.Fatal("candidate did not preserve the four verified equivalence classes", err)
	}
	for _, name := range policy.ReservedNames {
		value, err := n.Normalize(name)
		if err != nil || value.Display() != name || value.SecurityName() != name || !errors.Is(n.Validate(value), ErrReserved) {
			t.Fatal("proposed reserved name is not an admitted canonical reservation", err)
		}
		alias, err := n.Normalize(strings.ReplaceAll(name, "\u06cc", "\u064a"))
		if err != nil || alias.Key() != value.Key() || !errors.Is(n.Validate(alias), ErrReserved) {
			t.Fatal("keyboard alias escaped a proposed reservation", err)
		}
		near, err := n.Normalize(name + ".\u0633")
		if err != nil || n.Validate(near) != nil || near.Key() == value.Key() {
			t.Fatal("proposed reservation affected a distinct dotted name", err)
		}
	}
	for _, input := range []string{".\u0633", "\u0633.", "\u0633..\u0633", "\u06331", "\u0633a", "\u0633\u200c\u0633"} {
		if _, err := n.Normalize(input); !errors.Is(err, ErrInvalidUsername) {
			t.Fatal("candidate admitted an unsupported spelling")
		}
	}
}

func TestUsernameApprovedLengthBoundaries(t *testing.T) {
	n := reviewCandidateNormalizer(t)
	policy := n.Policy()
	if policy.MinLetters != 4 || policy.MaxCodePoints != 40 {
		t.Fatal("policy differs from the approved length bounds")
	}
	for _, tt := range []struct {
		name, input, display string
	}{
		{"three", "سلا", ""},
		{"four", "سلام", "سلام"},
		{"three_with_dots", "س.ل.ا", ""},
		{"four_with_dots", "س.لام", "س.لام"},
		{"forty_including_dot", strings.Repeat("س", 38) + ".س", strings.Repeat("س", 38) + ".س"},
		{"forty_one_including_dot", strings.Repeat("س", 39) + ".س", ""},
		{"nfc_before_min", "و\u0654سل", ""},
		{"nfc_before_max", strings.Repeat("س", 39) + "و\u0654", strings.Repeat("س", 39) + "ؤ"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			value, err := n.Normalize(tt.input)
			if tt.display == "" {
				if !errors.Is(err, ErrInvalidUsername) {
					t.Fatal("assignment accepted input outside the approved lengths", err)
				}
				return
			}
			if err != nil || value.Display() != tt.display || n.Validate(value) != nil {
				t.Fatal("assignment rejected an admitted NFC spelling", err)
			}
		})
	}
	canonical, err := n.Normalize("کی.سل")
	alias, aliasErr := n.Normalize("كي.سل")
	if err != nil || aliasErr != nil || canonical.Key() != alias.Key() || alias.Display() != "كي.سل" {
		t.Fatal("keyboard aliases changed length, display, or ownership", err, aliasErr)
	}
	policy.MinLetters++
	policy.MaxCodePoints--
	stricter, err := New(policy, fixtureRegex, bytes.Repeat([]byte{0x59}, 32), "username-review-test")
	if err != nil {
		t.Fatal(err)
	}
	for _, oldSpelling := range []string{"كي.سل", strings.Repeat("س", 38) + ".س"} {
		old, err := n.Normalize(oldSpelling)
		lookup, lookupErr := stricter.NormalizeLookup(oldSpelling)
		_, assignmentErr := stricter.Normalize(oldSpelling)
		if err != nil || lookupErr != nil || lookup.Key() != old.Key() || !errors.Is(assignmentErr, ErrInvalidUsername) {
			t.Fatal("a length-only policy change altered the lookup domain", err, lookupErr, assignmentErr)
		}
	}
}
