package username

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"testing/quick"

	"github.com/google/uuid"
	"golang.org/x/text/unicode/norm"
)

// Explicit reviewed candidate, a fixture only; production has no default regex.
const fixtureRegex = `[\x{0621}\x{0622}\x{0624}\x{0626}-\x{0628}\x{062A}-\x{063A}\x{0641}-\x{0648}\x{064A}\x{067E}\x{0686}\x{0698}\x{06A9}\x{06AF}\x{06CC}]+(?:\.[\x{0621}\x{0622}\x{0624}\x{0626}-\x{0628}\x{062A}-\x{063A}\x{0641}-\x{0648}\x{064A}\x{067E}\x{0686}\x{0698}\x{06A9}\x{06AF}\x{06CC}]+)*`

func fixturePolicy() Policy {
	return Policy{ID: uuid.MustParse("d0bbd127-a362-42d0-91e1-78bb8b273d79"), Normalization: NormalizationV1, Folds: approvedFolds(), ReservedNames: []string{}}
}

func fixtureNormalizer(t testing.TB) *Normalizer {
	t.Helper()
	n, err := New(fixturePolicy(), fixtureRegex, bytes.Repeat([]byte{0x59}, 32), "username-test-1")
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestUsernameApprovedEquivalenceAndDisplay(t *testing.T) {
	n := fixtureNormalizer(t)
	groups := [][]string{
		{"\u0639\u0644\u06cc.\u0645\u0624\u0645\u0646\u06cc", "\u0639\u0644\u06cc.\u0645\u0648\u0645\u0646\u06cc", "\u0639\u0644\u064a.\u0645\u0624\u0645\u0646\u064a"},
		{"\u0643\u06cc\u0648\u0627\u0646", "\u06a9\u06cc\u0648\u0627\u0646"},
		{"\u0626", "\u06cc", "\u064a"},
		{"\u0624", "\u0648\u0654", "\u0648"},
	}
	for _, group := range groups {
		first, err := n.Normalize(group[0])
		if err != nil {
			t.Fatal(err)
		}
		for _, spelling := range group {
			v, err := n.Normalize(spelling)
			if err != nil || v.Key() != first.Key() || v.SecurityName() != first.SecurityName() || v.Display() != norm.NFC.String(spelling) {
				t.Fatal("approved equivalence or NFC-only display failed")
			}
		}
	}
}

func TestUsernameDistinctLettersAndNoBusinessLengthDefault(t *testing.T) {
	n := fixtureNormalizer(t)
	spellings := []string{"\u0627", "\u0622", "\u0621", "\u0633", "\u0635", "\u062b"}
	keys := map[[32]byte]bool{}
	for _, spelling := range spellings {
		v, err := n.Normalize(spelling)
		if err != nil || keys[v.Key()] {
			t.Fatal("unapproved letter merger or one-letter rejection")
		}
		keys[v.Key()] = true
	}
	for _, length := range []int{41, 512} {
		if _, err := n.Normalize(strings.Repeat("\u0633", length)); err != nil {
			t.Fatal("business length default added")
		}
	}
}

func TestUsernameFormatAttacks(t *testing.T) {
	n := fixtureNormalizer(t)
	for _, input := range []string{
		"", "1", "\u0661", "\u06f1", "\uff11", "\u0967", "\u0633a", "\u0633_\u0633", "\u0633 \u0633", "\u0633\t", "\n\u0633", "\u0633\n",
		".\u0633", "\u0633.", "\u0633..\u0633", "\u0633\u064e", "\u0633\u0650", "\u0633\u200c", "\u0633\u200d", "\u0633\u202e", "\u0633\u200f", "\u0633\u2066", "\u0633\ufe0f",
		"\ufef1", "\u0649", "\u0629", "\u0623", "\u0625", "\u066e", "\u0633\x00", string([]byte{0xc0, 0xaf}), strings.Repeat("\u0633", 513),
	} {
		if _, err := n.Normalize(input); err == nil {
			t.Fatal("format attack admitted")
		}
	}
	if _, err := n.Normalize("\u0633.\u0633"); err != nil {
		t.Fatal(err)
	}
}

func TestUsernameLookupDoesNotApplyCurrentAssignmentRegex(t *testing.T) {
	n, err := New(fixturePolicy(), `\x{0633}{3}`, bytes.Repeat([]byte{3}, 32), "lookup-test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.Normalize("\u0633"); err == nil {
		t.Fatal("narrow assignment regex ignored")
	}
	if _, err := n.NormalizeLookup("\u0633"); err != nil {
		t.Fatal("lookup retroactively narrowed")
	}
	for _, input := range []string{"\u0633 ", "a\u0633", "\u0633\u200c", "\u0633\u064e"} {
		if _, err := n.NormalizeLookup(input); err == nil {
			t.Fatal("lookup stripped or repaired unsupported input")
		}
	}
}

func TestUsernameNormalizerDefensiveCopies(t *testing.T) {
	p := fixturePolicy()
	p.ReservedNames = []string{"\u0643"}
	key := bytes.Repeat([]byte{3}, 32)
	n, err := New(p, fixtureRegex, key, "copy-test")
	if err != nil {
		t.Fatal(err)
	}
	v, _ := n.Normalize("\u0643")
	authority := n.Authority()
	p.Folds[0] = Fold{"\u0633", "\u0635"}
	p.ReservedNames[0] = "\u0633"
	key[0]++
	copyPolicy := n.Policy()
	copyPolicy.Folds[0] = Fold{}
	copyPolicy.ReservedNames[0] = "\u0633"
	artifact := n.CanonicalArtifact()
	artifact[0]++
	if n.Authority() != authority || !n.IsReserved(v) {
		t.Fatal("active configuration mutated")
	}
	if err := n.Validate(v); err != ErrReserved {
		t.Fatal("reserved name not enforced")
	}
	if err := n.Validate(Value{}); err != ErrPolicyMismatch {
		t.Fatal("zero value accepted")
	}
}

func TestUsernameNormalizationProperties(t *testing.T) {
	n := fixtureNormalizer(t)
	alphabet := []rune(strings.TrimSuffix(supportedScalars, "."))
	property := func(indices []uint8) bool {
		if len(indices) == 0 {
			indices = []uint8{0}
		}
		var input strings.Builder
		for _, index := range indices {
			input.WriteRune(alphabet[int(index)%len(alphabet)])
		}
		v, err := n.Normalize(input.String())
		if err != nil {
			return false
		}
		again, err := n.Normalize(v.Display())
		canonical, canonicalErr := n.Normalize(v.SecurityName())
		return err == nil && canonicalErr == nil && again == v && canonical.Key() == v.Key() && canonical.SecurityName() == v.SecurityName() && norm.NFC.IsNormalString(v.Display()) && norm.NFC.IsNormalString(v.SecurityName())
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 1000}); err != nil {
		t.Fatal(err)
	}
}

func TestUsernameNormalizerConcurrentUse(t *testing.T) {
	n := fixtureNormalizer(t)
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			for range 100 {
				v, err := n.Normalize("\u0643.\u0626")
				if err != nil || n.Validate(v) != nil {
					t.Error("concurrent normalization failed")
				}
			}
		})
	}
	workers.Wait()
}

func TestUsernameUnadmittedNormalizerFailsClosed(t *testing.T) {
	for _, n := range []*Normalizer{nil, {}} {
		if _, err := n.Normalize("\u0633"); err != ErrPolicyMismatch {
			t.Fatal("unadmitted normalizer accepted assignment")
		}
		if _, err := n.NormalizeLookup("\u0633"); err != ErrPolicyMismatch {
			t.Fatal("unadmitted normalizer derived a key")
		}
		if err := n.Validate(Value{}); err != ErrPolicyMismatch {
			t.Fatal("unadmitted normalizer accepted value")
		}
	}
}

func FuzzUsernameNormalization(f *testing.F) {
	for _, input := range []string{"\u0643", "\u0624", "\u0648\u0654", "\u0633\u200c", "", "\xff"} {
		f.Add(input)
	}
	n := fixtureNormalizer(f)
	f.Fuzz(func(t *testing.T, input string) {
		v, err := n.Normalize(input)
		if err != nil {
			return
		}
		if len(v.Display()) > MaxUsernameBytes || len(v.SecurityName()) > MaxUsernameBytes || !norm.NFC.IsNormalString(v.Display()) || !norm.NFC.IsNormalString(v.SecurityName()) {
			t.Fatal("normalization bounds/NFC invariant failed")
		}
		if again, err := n.Normalize(v.Display()); err != nil || again != v {
			t.Fatal("normalization not idempotent")
		}
	})
}
