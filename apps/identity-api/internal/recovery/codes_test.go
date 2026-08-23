package recovery

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"
)

// TestCharsForBitsRoundsUp proves the entropy budget is never silently lowered:
// a request that is not an exact multiple of bitsPerChar rounds the character
// count up, so the realized entropy meets or exceeds what was asked for.
func TestCharsForBits(t *testing.T) {
	cases := []struct {
		bits int
		want int
	}{
		{bits: 5, want: 1},
		{bits: 6, want: 2},   // 6 bits needs 2 chars (10 bits)
		{bits: 10, want: 2},  // exact multiple
		{bits: 128, want: 26}, // 128/5 = 25.6 -> 26 chars (130 bits)
		{bits: 160, want: 32}, // exact multiple -> 32 chars
	}
	for _, tc := range cases {
		if got := charsForBits(tc.bits); got != tc.want {
			t.Errorf("charsForBits(%d) = %d, want %d", tc.bits, got, tc.want)
		}
	}
}

// TestEntropyBitsMeetsFloor confirms the default and minimum policies both clear
// the 128-bit mandate once rounded to whole characters.
func TestEntropyBitsMeetsFloor(t *testing.T) {
	if got := EntropyBits(charsForBits(MinEntropyBits)); got < MinEntropyBits {
		t.Errorf("EntropyBits for the minimum policy = %d, want >= %d", got, MinEntropyBits)
	}
	if got := EntropyBits(charsForBits(DefaultEntropyBits)); got < DefaultEntropyBits {
		t.Errorf("EntropyBits for the default policy = %d, want >= %d", got, DefaultEntropyBits)
	}
	// The default is chosen to be an exact character multiple (32 * 5 = 160).
	if got := EntropyBits(charsForBits(DefaultEntropyBits)); got != 160 {
		t.Errorf("default realized entropy = %d, want exactly 160", got)
	}
}

// TestGenerateCodeLengthAndAlphabet locks in that every generated character is
// drawn from the Crockford alphabet and the code is exactly the requested
// length — the two properties the entropy accounting rests on.
func TestGenerateCodeLengthAndAlphabet(t *testing.T) {
	const chars = 32
	const draws = 200
	for i := 0; i < draws; i++ {
		code, err := generateCode(chars)
		if err != nil {
			t.Fatalf("generateCode: %v", err)
		}
		if len(code) != chars {
			t.Fatalf("len(code) = %d, want %d", len(code), chars)
		}
		for _, ch := range code {
			if !strings.ContainsRune(codeAlphabet, ch) {
				t.Fatalf("generated code %q contains out-of-alphabet rune %q", code, ch)
			}
		}
	}
}

// TestGenerateCodeRejectsNonPositive guards the length precondition so a
// misconfigured caller gets an error rather than an empty, zero-entropy code.
func TestGenerateCodeRejectsNonPositive(t *testing.T) {
	for _, n := range []int{0, -1, -32} {
		if _, err := generateCode(n); err == nil {
			t.Errorf("generateCode(%d) = nil error, want error", n)
		}
	}
}

// TestGenerateCodeIsRandom is a cheap uniqueness smoke test: 32-char codes drawn
// from a 160-bit space must never collide across a small sample.
func TestGenerateCodeIsRandom(t *testing.T) {
	const draws = 500
	seen := make(map[string]struct{}, draws)
	for i := 0; i < draws; i++ {
		code, err := generateCode(32)
		if err != nil {
			t.Fatalf("generateCode: %v", err)
		}
		if _, dup := seen[code]; dup {
			t.Fatalf("generateCode returned a duplicate %q after %d draws", code, i)
		}
		seen[code] = struct{}{}
	}
}

var formatShape = regexp.MustCompile(`^[0-9A-Z]{5}(-[0-9A-Z]{5})*$`)

// TestFormatGrouping proves the display form groups into 5-char blocks joined by
// dashes, and that stripping the dashes recovers the original code — the
// round-trip Normalize depends on.
func TestFormatGrouping(t *testing.T) {
	raw, err := generateCode(32)
	if err != nil {
		t.Fatalf("generateCode: %v", err)
	}
	formatted := format(raw)

	if !formatShape.MatchString(formatted) {
		t.Errorf("format(%q) = %q, which is not XXXXX-XXXXX-...", raw, formatted)
	}
	if got := strings.ReplaceAll(formatted, "-", ""); got != raw {
		t.Errorf("stripping dashes from %q = %q, want %q", formatted, got, raw)
	}
	// A 32-char code splits into groups of 5: 6 full groups + a 2-char tail = 6
	// separators.
	if want := strings.Count(formatted, "-"); want != 6 {
		t.Errorf("32-char code produced %d separators, want 6", want)
	}
}

// TestFormatShortCode confirms a code no longer than one group is returned
// unchanged (no leading/trailing separator).
func TestFormatShortCode(t *testing.T) {
	if got := format("ABCDE"); got != "ABCDE" {
		t.Errorf("format(short) = %q, want %q", got, "ABCDE")
	}
	if got := format("AB"); got != "AB" {
		t.Errorf("format(shorter) = %q, want %q", got, "AB")
	}
}

// TestNormalizeFolding covers every confusable substitution and separator strip,
// so a user transcribing a code by hand (lowercase, spaces, O-for-0, etc.) still
// hashes to the same value the generator stored.
func TestNormalizeFolding(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "uppercases", in: "abcde", want: "ABCDE"},
		{name: "strips dashes", in: "ABCDE-FGHJK", want: "ABCDEFGHJK"},
		{name: "strips spaces", in: "ABC DE", want: "ABCDE"},
		{name: "folds O to 0", in: "OO", want: "00"},
		{name: "folds lower o to 0", in: "oo", want: "00"},
		{name: "folds I to 1", in: "II", want: "11"},
		{name: "folds L to 1", in: "LL", want: "11"},
		{name: "folds U to V", in: "U", want: "V"},
		{name: "drops unknown punctuation", in: "A!B@C#", want: "ABC"},
		{name: "empty stays empty", in: "", want: ""},
		{name: "only separators", in: "----", want: ""},
		{name: "mixed real-world", in: "o1l-uO I", want: "011V01"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Normalize(tc.in); got != tc.want {
				t.Errorf("Normalize(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestNormalizeOutputIsInAlphabet asserts the post-condition the hash lookup
// relies on: whatever the user typed, the normalized result contains only
// alphabet characters.
func TestNormalizeOutputIsInAlphabet(t *testing.T) {
	const messy = "  aBcDe-Fg1J k!!  Ooo LLL uuu 12345 "
	for _, ch := range Normalize(messy) {
		if !strings.ContainsRune(codeAlphabet, ch) {
			t.Errorf("Normalize leaked out-of-alphabet rune %q", ch)
		}
	}
}

// TestFormatNormalizeRoundTrip is the property that makes the codes usable: a
// generated code, shown formatted, normalizes back to the exact string that was
// hashed at generation time.
func TestFormatNormalizeRoundTrip(t *testing.T) {
	for i := 0; i < 100; i++ {
		raw, err := generateCode(32)
		if err != nil {
			t.Fatalf("generateCode: %v", err)
		}
		if got := Normalize(format(raw)); got != raw {
			t.Fatalf("round trip failed: Normalize(format(%q)) = %q", raw, got)
		}
	}
}

// TestHashCodePlainSHA256 proves that without a pepper the stored hash is exactly
// SHA-256(normalized) in lowercase hex, and always 64 characters (fits
// VARCHAR(64)).
func TestHashCodePlainSHA256(t *testing.T) {
	const normalized = "ABCDE12345"
	got := hashCode(nil, normalized)

	if len(got) != 64 {
		t.Errorf("plain hash length = %d, want 64", len(got))
	}
	sum := sha256.Sum256([]byte(normalized))
	if want := hex.EncodeToString(sum[:]); got != want {
		t.Errorf("hashCode(nil, %q) = %q, want %q", normalized, got, want)
	}
	// An empty pepper slice must behave identically to nil.
	if empty := hashCode([]byte{}, normalized); empty != got {
		t.Errorf("empty pepper hash = %q, want same as nil %q", empty, got)
	}
}

// TestHashCodePepperedHMAC proves that with a pepper the stored hash is
// HMAC-SHA-256(pepper, normalized), still 64 hex characters, and distinct from
// the un-peppered hash of the same code.
func TestHashCodePepperedHMAC(t *testing.T) {
	pepper := []byte("a-service-wide-secret-pepper-value")
	const normalized = "ABCDE12345"
	got := hashCode(pepper, normalized)

	if len(got) != 64 {
		t.Errorf("peppered hash length = %d, want 64", len(got))
	}
	mac := hmac.New(sha256.New, pepper)
	_, _ = mac.Write([]byte(normalized))
	if want := hex.EncodeToString(mac.Sum(nil)); got != want {
		t.Errorf("hashCode(pepper, %q) = %q, want %q", normalized, got, want)
	}
	if plain := hashCode(nil, normalized); got == plain {
		t.Error("peppered hash equals plain hash; the pepper had no effect")
	}
}

// TestHashCodeDeterministic confirms the same input always yields the same hash
// (indexable lookup depends on this) and different inputs diverge.
func TestHashCodeDeterministic(t *testing.T) {
	if hashCode(nil, "SAME") != hashCode(nil, "SAME") {
		t.Error("plain hash is not deterministic")
	}
	if hashCode(nil, "ONE") == hashCode(nil, "TWO") {
		t.Error("distinct codes hashed to the same value")
	}
}
