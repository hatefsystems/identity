package username

import (
	"crypto/sha256"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// This is the normalization domain, not a second business-format validator.
// Lookup retains it even when new-account regex admission has been narrowed.
const supportedScalars = "\u0621\u0622\u0624\u0626\u0627\u0628\u062a\u062b\u062c\u062d\u062e\u062f\u0630\u0631\u0632\u0633\u0634\u0635\u0636\u0637\u0638\u0639\u063a\u0641\u0642\u0643\u0644\u0645\u0646\u0647\u0648\u064a\u067e\u0686\u0698\u06a9\u06af\u06cc."

// Normalizer is immutable after New; all returned tables and artifacts are copies.
type Normalizer struct {
	policy    Policy
	admission *regexp.Regexp
	folds     map[rune]rune
	key       []byte
	authority Authority
	artifact  []byte
	reserved  map[string]bool
}

type canonicalArtifact struct {
	Policy         Policy `json:"policy"`
	Regex          string `json:"regex"`
	Implementation string `json:"implementation"`
	Unicode        string `json:"unicode"`
	MaxBytes       int    `json:"max_username_bytes"`
}

// DecodeCanonicalArtifact admits only artifacts from this pinned implementation.
// It does not invent historical keys or approve a new active policy.
func DecodeCanonicalArtifact(data []byte) (Policy, string, error) {
	var artifact canonicalArtifact
	if strictJSON(data, &artifact, MaxArtifactBytes) != nil || artifact.Implementation != ImplementationVersion || artifact.Unicode != norm.Version || artifact.MaxBytes != MaxUsernameBytes {
		return Policy{}, "", ErrInvalidPolicy
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || !exactJSONFields(fields, "policy", "regex", "implementation", "unicode", "max_username_bytes") {
		return Policy{}, "", ErrInvalidPolicy
	}
	p, err := DecodePolicy(fields["policy"])
	if err != nil {
		return Policy{}, "", ErrInvalidPolicy
	}
	if _, err := compileAdmission(artifact.Regex); err != nil {
		return Policy{}, "", err
	}
	return p, artifact.Regex, nil
}

// Value can only be constructed by the admitted server-side normalizer. Its
// private authority binds frozen pending details to one exact policy and key.
type Value struct {
	display   string
	security  string
	key       [sha256.Size]byte
	authority Authority
}

// Display returns the NFC spelling without security folds.
func (v Value) Display() string { return v.display }

// SecurityName returns the folded spelling used for exact lookup.
func (v Value) SecurityName() string { return v.security }

// Key returns the domain-separated lookup HMAC.
func (v Value) Key() [sha256.Size]byte { return v.key }

// Authority returns the policy and key provenance bound to the value.
func (v Value) Authority() Authority { return v.authority }

// Authority returns the normalizer's immutable policy and key provenance.
func (n *Normalizer) Authority() Authority { return n.authority }

// CanonicalArtifact returns a copy of the fingerprinted normalization artifact.
func (n *Normalizer) CanonicalArtifact() []byte { return slices.Clone(n.artifact) }

// Policy returns a defensive copy of the admitted policy.
func (n *Normalizer) Policy() Policy {
	p := n.policy
	p.Folds = slices.Clone(p.Folds)
	p.ReservedNames = slices.Clone(p.ReservedNames)
	return p
}

// New compiles the source standalone before anchoring: malformed groups cannot
// escape the wrapper. No caller/environment default supplies policy authority.
func New(p Policy, source string, key []byte, keyID string) (*Normalizer, error) {
	if p.validate(true) != nil || len(key) < 32 || !referenceID.MatchString(keyID) {
		return nil, ErrInvalidPolicy
	}
	admission, err := compileAdmission(source)
	if err != nil {
		return nil, ErrInvalidPolicy
	}
	p.Folds = slices.Clone(p.Folds)
	p.ReservedNames = slices.Clone(p.ReservedNames)
	slices.SortFunc(p.Folds, func(a, b Fold) int { return strings.Compare(a.From, b.From) })
	slices.Sort(p.ReservedNames)
	n := &Normalizer{policy: p, admission: admission, folds: foldTable(p.Folds), key: slices.Clone(key), reserved: map[string]bool{}}
	for _, name := range p.ReservedNames {
		v, err := n.normalize(name, false)
		if err != nil || n.reserved[v.security] {
			return nil, ErrInvalidPolicy
		}
		n.reserved[v.security] = true
	}
	artifact := canonicalArtifact{p, source, ImplementationVersion, norm.Version, MaxUsernameBytes}
	n.artifact, err = json.Marshal(artifact)
	if err != nil || len(n.artifact) > MaxArtifactBytes {
		return nil, ErrInvalidPolicy
	}
	n.authority = Authority{PolicyID: p.ID, Fingerprint: sha256.Sum256(n.artifact), KeyID: keyID, KeyVerifier: exactHMAC(n.key, verifierDomain, nil)}
	return n, nil
}

func compileAdmission(source string) (*regexp.Regexp, error) {
	if len(source) == 0 || len(source) > MaxRegexBytes || !utf8.ValidString(source) {
		return nil, ErrInvalidPolicy
	}
	standalone, err := regexp.Compile(source)
	if err != nil || standalone.MatchString("") {
		return nil, ErrInvalidPolicy
	}
	admission, err := regexp.Compile(`\A(?:` + source + `)\z`)
	if err != nil {
		return nil, ErrInvalidPolicy
	}
	return admission, nil
}

// Normalize applies current assignment admission, leaving display NFC-only.
// Reservation is checked by shared storage under its policy guard, not here.
func (n *Normalizer) Normalize(input string) (Value, error) {
	return n.normalize(input, true)
}

// NormalizeLookup preserves the historical security domain without enforcing
// current assignment syntax. It never trims or strips invalid input.
func (n *Normalizer) NormalizeLookup(input string) (Value, error) {
	return n.normalize(input, false)
}

func (n *Normalizer) normalize(input string, admission bool) (Value, error) {
	if n == nil || n.admission == nil {
		return Value{}, ErrPolicyMismatch
	}
	if !boundedUTF8(input) {
		return Value{}, ErrInvalidUsername
	}
	display := norm.NFC.String(input)
	if !boundedUTF8(display) {
		return Value{}, ErrInvalidUsername
	}
	if admission && !n.admission.MatchString(display) {
		return Value{}, ErrInvalidUsername
	}
	for _, scalar := range display {
		if !strings.ContainsRune(supportedScalars, scalar) {
			return Value{}, ErrInvalidUsername
		}
	}
	security := foldString(display, n.folds)
	if !boundedUTF8(security) || !norm.NFC.IsNormalString(security) || foldString(security, n.folds) != security {
		return Value{}, ErrInvalidUsername
	}
	return Value{display, security, exactHMAC(n.key, lookupDomain, []byte(security)), n.authority}, nil
}

// IsReserved checks the folded name only for values from this authority.
func (n *Normalizer) IsReserved(v Value) bool {
	return n != nil && v.authority == n.authority && n.reserved[v.security]
}

// Validate refuses stale or zero/forged values before an initial assignment.
func (n *Normalizer) Validate(v Value) error {
	if n == nil || n.admission == nil || v.authority != n.authority {
		return ErrPolicyMismatch
	}
	expected, err := n.Normalize(v.display)
	if err != nil || expected != v {
		return ErrInvalidUsername
	}
	if n.IsReserved(v) {
		return ErrReserved
	}
	return nil
}

func boundedUTF8(s string) bool {
	return len(s) > 0 && len(s) <= MaxUsernameBytes && utf8.ValidString(s)
}

func foldTable(folds []Fold) map[rune]rune {
	table := make(map[rune]rune, len(folds))
	for _, f := range folds {
		from, _ := utf8.DecodeRuneInString(f.From)
		to, _ := utf8.DecodeRuneInString(f.To)
		table[from] = to
	}
	return table
}

func foldString(s string, table map[rune]rune) string {
	var output strings.Builder
	output.Grow(len(s))
	for _, scalar := range s {
		if to, ok := table[scalar]; ok {
			scalar = to
		}
		output.WriteRune(scalar)
	}
	return output.String()
}
