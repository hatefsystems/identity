// Package username owns the approved username normalization and exact lookup
// namespace. Admission does not install a policy or authorize a DB cutover.
package username

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/text/unicode/norm"
)

const (
	MaxUsernameBytes = 1024
	MaxRegexBytes    = 4096
	MaxArtifactBytes = 16 * 1024
	NormalizationV1  = "nfc-four-fold-v1"
	// Changes to this implementation or its pinned dependency change the artifact.
	ImplementationVersion = "hatef.username.v1;golang.org/x/text@v0.40.0"
)

var (
	ErrInvalidPolicy    = errors.New("username: invalid or unsupported policy")
	ErrInvalidUsername  = errors.New("username: invalid username")
	ErrPolicyMismatch   = errors.New("username: policy authority mismatch")
	ErrReserved         = errors.New("username: reserved name")
	ErrEquivalenceSplit = errors.New("username: historical equivalence split")
	ErrInvalidPayload   = errors.New("username: invalid protected payload")
)

// Fold is an explicit scalar-to-scalar mapping, never deletion or expansion.
type Fold struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Policy is a configuration candidate. New defensively copies and admits it;
// modifying this value cannot modify an installed Normalizer.
type Policy struct {
	ID            uuid.UUID `json:"id"`
	Normalization string    `json:"normalization"`
	Folds         []Fold    `json:"folds"`
	ReservedNames []string  `json:"reserved_names"`
}

var referenceID = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\z`)

func approvedFolds() []Fold {
	return []Fold{{"\u064a", "\u06cc"}, {"\u0643", "\u06a9"}, {"\u0624", "\u0648"}, {"\u0626", "\u06cc"}}
}

// DecodePolicy rejects unknown, omitted, duplicate (also nested) fields and
// malformed Unicode rather than relying on encoding/json's replacement behavior.
func DecodePolicy(data []byte) (Policy, error) {
	var p Policy
	if strictJSON(data, &p, MaxArtifactBytes) != nil {
		return Policy{}, ErrInvalidPolicy
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || !exactJSONFields(fields, "id", "normalization", "folds", "reserved_names") {
		return Policy{}, ErrInvalidPolicy
	}
	var folds []map[string]json.RawMessage
	if json.Unmarshal(fields["folds"], &folds) != nil {
		return Policy{}, ErrInvalidPolicy
	}
	for _, fold := range folds {
		if !exactJSONFields(fold, "from", "to") {
			return Policy{}, ErrInvalidPolicy
		}
	}
	if p.validate(true) != nil {
		return Policy{}, ErrInvalidPolicy
	}
	return p, nil
}

func (p Policy) validate(requireAll bool) error {
	if p.ID == uuid.Nil || p.Normalization != NormalizationV1 || p.Folds == nil || p.ReservedNames == nil {
		return ErrInvalidPolicy
	}
	if requireAll && len(p.Folds) != 4 {
		return ErrInvalidPolicy
	}
	seen := make(map[string]string, len(p.Folds))
	for _, f := range p.Folds {
		if !utf8.ValidString(f.From) || !utf8.ValidString(f.To) || utf8.RuneCountInString(f.From) != 1 || utf8.RuneCountInString(f.To) != 1 ||
			!norm.NFC.IsNormalString(f.From) || !norm.NFC.IsNormalString(f.To) || !slices.Contains(approvedFolds(), f) {
			return ErrInvalidPolicy
		}
		if _, exists := seen[f.From]; exists {
			return ErrInvalidPolicy
		}
		seen[f.From] = f.To
	}
	for _, to := range seen {
		if _, mapped := seen[to]; mapped {
			return ErrInvalidPolicy
		}
	}
	for _, name := range p.ReservedNames {
		if !boundedUTF8(name) || !norm.NFC.IsNormalString(name) {
			return ErrInvalidPolicy
		}
	}
	return nil
}

// ValidateNoSplit is a necessary historical alias check, not merger approval or
// a collision scan. Initial activation still requires exactly all four folds.
func ValidateNoSplit(old, candidate Policy) error {
	if old.validate(false) != nil || candidate.validate(false) != nil {
		return ErrInvalidPolicy
	}
	oldTable, newTable := foldTable(old.Folds), foldTable(candidate.Folds)
	for _, scalar := range supportedScalars {
		x := string(scalar)
		if foldString(foldString(x, oldTable), newTable) != foldString(x, newTable) {
			return ErrEquivalenceSplit
		}
	}
	return nil
}

func exactJSONFields(fields map[string]json.RawMessage, names ...string) bool {
	if len(fields) != len(names) {
		return false
	}
	for _, name := range names {
		if raw, ok := fields[name]; !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return false
		}
	}
	return true
}

func strictJSON(data []byte, target any, limit int) error {
	if len(data) == 0 || len(data) > limit || !utf8.Valid(data) {
		return ErrInvalidPolicy
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if uniqueTokens(d, 0) != nil {
		return ErrInvalidPolicy
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalidPolicy
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return ErrInvalidPolicy
	}
	return nil
}

func uniqueTokens(d *json.Decoder, depth int) error {
	if depth > 4 {
		return ErrInvalidPolicy
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	if s, ok := token.(string); ok && strings.ContainsRune(s, utf8.RuneError) {
		return ErrInvalidPolicy
	}
	delim, container := token.(json.Delim)
	if !container {
		return nil
	}
	if delim != '{' && delim != '[' {
		return ErrInvalidPolicy
	}
	seen := map[string]bool{}
	for d.More() {
		if delim == '{' {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] || strings.ContainsRune(name, utf8.RuneError) {
				return ErrInvalidPolicy
			}
			seen[name] = true
		}
		if uniqueTokens(d, depth+1) != nil {
			return ErrInvalidPolicy
		}
	}
	end, err := d.Token()
	if err != nil || (delim == '{' && end != json.Delim('}')) || (delim == '[' && end != json.Delim(']')) {
		return ErrInvalidPolicy
	}
	return nil
}
