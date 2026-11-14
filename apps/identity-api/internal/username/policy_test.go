package username

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestUsernameStrictPolicyJSON(t *testing.T) {
	data, _ := json.Marshal(fixturePolicy())
	if _, err := DecodePolicy(data); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		nil, []byte("null"), append(slices.Clone(data), []byte(" {}")...), bytes.Repeat([]byte{' '}, MaxArtifactBytes+1),
		[]byte(strings.Replace(string(data), `"id":`, `"ID":`, 1)),
		[]byte(strings.Replace(string(data), `"id":`, `"unknown":0,"id":`, 1)),
		[]byte(strings.Replace(string(data), `"id":`, `"id":"d0bbd127-a362-42d0-91e1-78bb8b273d79","id":`, 1)),
		[]byte(strings.Replace(string(data), `"reserved_names":[]`, `"reserved_names":null`, 1)),
		[]byte(strings.Replace(string(data), `,"reserved_names":[]`, ``, 1)),
		[]byte(strings.Replace(string(data), `"from":`, `"from":"\u064a","from":`, 1)),
		[]byte(strings.Replace(string(data), `"from":`, `"From":`, 1)),
		[]byte(strings.Replace(string(data), `"from":`, `"extra":1,"from":`, 1)),
		[]byte(strings.Replace(string(data), `"reserved_names":[]`, `"reserved_names":["\ud800"]`, 1)),
		append([]byte{0xff}, data...),
	} {
		if _, err := DecodePolicy(bad); err == nil {
			t.Fatal("malformed/ambiguous policy accepted")
		}
	}
}

func TestUsernameRejectsUnapprovedMappings(t *testing.T) {
	for _, bad := range [][]Fold{
		nil, {}, {{"\u064a", "\u06cc"}},
		{{"\u064a", ""}, {"\u0643", "\u06a9"}, {"\u0624", "\u0648"}, {"\u0626", "\u06cc"}},
		{{"\u064a", "\u06cc\u06cc"}, {"\u0643", "\u06a9"}, {"\u0624", "\u0648"}, {"\u0626", "\u06cc"}},
		{{"\u064a", "\u06cc"}, {"\u06cc", "\u064a"}, {"\u0624", "\u0648"}, {"\u0626", "\u06cc"}},
		{{"\u064a", "\u0626"}, {"\u0643", "\u06a9"}, {"\u0624", "\u0648"}, {"\u0626", "\u06cc"}},
		{{"\u064a", "\u06cc"}, {"\u064a", "\u06cc"}, {"\u0624", "\u0648"}, {"\u0626", "\u06cc"}},
		append(approvedFolds(), Fold{"\u0633", "\u0635"}),
	} {
		p := fixturePolicy()
		p.Folds = bad
		if _, err := New(p, fixtureRegex, bytes.Repeat([]byte{1}, 32), "test"); err == nil {
			t.Fatal("unapproved/invalid fold admitted")
		}
	}
}

func TestUsernameStandaloneRegexAndBounds(t *testing.T) {
	for _, source := range []string{"", "(", `x)|(?:y`, `x)|(?:\x{0633}`, ".*", `\x{0633}*`, `(?:)`, "[", strings.Repeat("x", MaxRegexBytes+1), "\xff"} {
		if _, err := New(fixturePolicy(), source, bytes.Repeat([]byte{1}, 32), "test"); err == nil {
			t.Fatal("invalid or empty-matching regex admitted")
		}
	}
	n, err := New(fixturePolicy(), `\x{0633}|\x{0635}`, bytes.Repeat([]byte{1}, 32), "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.Normalize("\u0633\u0635"); err == nil {
		t.Fatal("alternation escaped whole-string anchors")
	}
	if _, err := n.Normalize("\u0633"); err != nil {
		t.Fatal(err)
	}
}

func TestUsernameHistoricalEquivalenceCannotSplit(t *testing.T) {
	old := fixturePolicy()
	candidate := fixturePolicy()
	candidate.ID = uuid.New()
	if err := ValidateNoSplit(old, candidate); err != nil {
		t.Fatal(err)
	}
	for index := range old.Folds {
		candidate.Folds = slices.Delete(slices.Clone(old.Folds), index, index+1)
		if err := ValidateNoSplit(old, candidate); err != ErrEquivalenceSplit {
			t.Fatal("historical alias released")
		}
	}
	candidate.Folds = append(approvedFolds(), Fold{"\u0633", "\u0635"})
	if err := ValidateNoSplit(old, candidate); err != ErrInvalidPolicy {
		t.Fatal("no-split check authorized a merger")
	}
}

func TestUsernameCanonicalArtifactAndFingerprint(t *testing.T) {
	n := fixtureNormalizer(t)
	p, source, err := DecodeCanonicalArtifact(n.CanonicalArtifact())
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := New(p, source, bytes.Repeat([]byte{0x59}, 32), "username-test-1")
	if err != nil || rebuilt.Authority() != n.Authority() || !bytes.Equal(rebuilt.CanonicalArtifact(), n.CanonicalArtifact()) {
		t.Fatal("artifact reconstruction differed")
	}
	slices.Reverse(p.Folds)
	reordered, err := New(p, source, bytes.Repeat([]byte{0x59}, 32), "username-test-1")
	if err != nil || reordered.Authority() != n.Authority() {
		t.Fatal("fold order changed canonical artifact")
	}
	for _, change := range []func(*Policy){func(p *Policy) { p.ID = uuid.New() }, func(p *Policy) { p.ReservedNames = []string{"\u0633"} }} {
		p = fixturePolicy()
		change(&p)
		changed, err := New(p, source, bytes.Repeat([]byte{0x59}, 32), "username-test-1")
		if err != nil || changed.Authority().Fingerprint == n.Authority().Fingerprint {
			t.Fatal("artifact change not fingerprinted")
		}
	}
	changed, _ := New(fixturePolicy(), "(?:"+source+")", bytes.Repeat([]byte{0x59}, 32), "username-test-1")
	if changed.Authority().Fingerprint == n.Authority().Fingerprint {
		t.Fatal("exact regex source not fingerprinted")
	}
	for _, bad := range [][]byte{
		[]byte(strings.Replace(string(n.CanonicalArtifact()), ImplementationVersion, "unsupported", 1)),
		[]byte(strings.Replace(string(n.CanonicalArtifact()), `"max_username_bytes":1024`, `"max_username_bytes":1025`, 1)),
		[]byte(strings.Replace(string(n.CanonicalArtifact()), `"regex":`, `"extra":1,"regex":`, 1)),
	} {
		if _, _, err := DecodeCanonicalArtifact(bad); err == nil {
			t.Fatal("unknown artifact contract accepted")
		}
	}
}

func TestUsernameReservedSetMustBeExplicitAndCanonical(t *testing.T) {
	for _, names := range [][]string{nil, {""}, {"\u0648\u0654"}, {"\u0633\u064e"}, {"\u0643", "\u06a9"}} {
		p := fixturePolicy()
		p.ReservedNames = names
		if _, err := New(p, fixtureRegex, bytes.Repeat([]byte{1}, 32), "test"); err == nil {
			t.Fatal("invalid/ambiguous reserved list admitted")
		}
	}
	n := fixtureNormalizer(t)
	for _, spelling := range []string{"\u0633", "\u0643", "\u0624"} {
		v, _ := n.Normalize(spelling)
		if n.IsReserved(v) {
			t.Fatal("reserved name invented")
		}
	}
}
