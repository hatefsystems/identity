// Package legalpolicy validates externally approved retention artifacts. An
// approval reference is organizational evidence, never an authentication token.
package legalpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"regexp"
	"slices"
	"time"

	"github.com/google/uuid"
)

// Errors expose bounded policy rejection reasons without approval contents.
var (
	ErrInvalidPolicy     = errors.New("legalpolicy: invalid or unsupported policy")
	ErrNotApproved       = errors.New("legalpolicy: approved policy and baseline binding required")
	ErrMismatch          = errors.New("legalpolicy: configured policy differs from immutable baseline")
	ErrConflict          = errors.New("legalpolicy: policy version is immutable")
	ErrInventoryRequired = errors.New("legalpolicy: explicit legacy inventory evidence required")
	ErrOperatorRequired  = errors.New("legalpolicy: trusted operator attribution required")
	ErrUnavailable       = errors.New("legalpolicy: policy storage unavailable")
)

// Supported clocks and lifetime are explicit, exact policy values.
const (
	ClockCreatedAt   = "created_at"
	ClockReleasedAt  = "released_at"
	ClockCaseExpiry  = "created_at_max_closed_at_min"
	LifetimeNoExpiry = "no_expiry"
	MaxArtifactBytes = 16 * 1024
)

// These inventories describe retained values, not the columns that become NULL.
// Hold replay metadata is linkable pseudonymous data, not anonymous tokens.
var holdTombstoneFields = []string{
	"id", "account_ref", "applied_by", "is_active", "applied_at", "review_at",
	"released_at", "released_by", "request_kind", "idempotency_key", "details_purged_at",
}

var workflowReplayFields = []string{"operation", "scope", "idempotency_key", "result_id", "erased"}

// HoldTombstoneFields returns the exact inventory of the existing hold engine.
func HoldTombstoneFields() []string { return slices.Clone(holdTombstoneFields) }

// WorkflowReplayFields returns the minimal post-erasure workflow replay inventory.
func WorkflowReplayFields() []string { return slices.Clone(workflowReplayFields) }

// Policy is a versioned operator-installed JSON artifact. Durations are whole
// seconds, have no defaults, and are bounded by Go's duration representation.
// Workflow may be absent for a baseline-only emergency-preservation deployment.
type Policy struct {
	ID                           uuid.UUID       `json:"id"`
	ApprovalReference            string          `json:"approval_reference"`
	Fixture                      bool            `json:"fixture"`
	ContextRetentionSeconds      int64           `json:"context_retention_seconds"`
	ReleasedHoldRetentionSeconds int64           `json:"released_hold_retention_seconds"`
	ContextClock                 string          `json:"context_clock"`
	ReleasedHoldClock            string          `json:"released_hold_clock"`
	HoldTombstoneFields          []string        `json:"hold_tombstone_fields"`
	HoldTombstoneLifetime        string          `json:"hold_tombstone_lifetime"`
	LegacyInventoryReference     string          `json:"legacy_inventory_reference,omitempty"`
	Workflow                     *WorkflowPolicy `json:"workflow,omitempty"`
}

// WorkflowPolicy approves both expiry clocks and the complete replay stub.
// Expiry is fixed at intake: min(created_at + maximum, closed_at + retention).
type WorkflowPolicy struct {
	MaxCaseAgeSeconds          int64    `json:"max_case_age_seconds"`
	ClosedCaseRetentionSeconds int64    `json:"closed_case_retention_seconds"`
	CaseClock                  string   `json:"case_clock"`
	ReplayFields               []string `json:"replay_fields"`
	ReplayLifetime             string   `json:"replay_lifetime"`
}

// ContextRetention returns the validated created-relative context duration.
func (p Policy) ContextRetention() time.Duration {
	return time.Duration(p.ContextRetentionSeconds) * time.Second
}

// ReleasedHoldRetention returns the validated release-relative narrative duration.
func (p Policy) ReleasedHoldRetention() time.Duration {
	return time.Duration(p.ReleasedHoldRetentionSeconds) * time.Second
}

// MaxCaseAge returns the validated absolute maximum age fixed at intake.
func (p WorkflowPolicy) MaxCaseAge() time.Duration {
	return time.Duration(p.MaxCaseAgeSeconds) * time.Second
}

// ClosedCaseRetention returns the validated closure-relative shortening period.
func (p WorkflowPolicy) ClosedCaseRetention() time.Duration {
	return time.Duration(p.ClosedCaseRetentionSeconds) * time.Second
}

var opaqueReference = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// Validate checks all supplied approvals; an unsupported supplied extension is
// rejected even if workflow intake is currently disabled. Fixtures are accepted
// only in explicitly named development/test environments, never by a typo.
func (p Policy) Validate(environment string) error {
	if environment == "" || p.ID == uuid.Nil || !opaqueReference.MatchString(p.ApprovalReference) ||
		(p.Fixture && environment != "development" && environment != "test") ||
		!validSeconds(p.ContextRetentionSeconds) || !validSeconds(p.ReleasedHoldRetentionSeconds) ||
		p.ContextClock != ClockCreatedAt || p.ReleasedHoldClock != ClockReleasedAt ||
		p.HoldTombstoneLifetime != LifetimeNoExpiry || !exactFields(p.HoldTombstoneFields, holdTombstoneFields) ||
		(p.LegacyInventoryReference != "" && !opaqueReference.MatchString(p.LegacyInventoryReference)) {
		return ErrInvalidPolicy
	}
	if w := p.Workflow; w != nil {
		if !validSeconds(w.MaxCaseAgeSeconds) || !validSeconds(w.ClosedCaseRetentionSeconds) ||
			w.CaseClock != ClockCaseExpiry || w.ReplayLifetime != LifetimeNoExpiry || !exactFields(w.ReplayFields, workflowReplayFields) {
			return ErrInvalidPolicy
		}
	}
	return nil
}

// ValidateBaseline binds configuration to approved values without requiring the
// additional workflow approval. Call LoadBaseline first to check the DB binding.
func ValidateBaseline(p Policy, contextRetention, releasedRetention time.Duration, environment string) error {
	if err := p.Validate(environment); err != nil {
		return err
	}
	if p.ContextRetention() != contextRetention || p.ReleasedHoldRetention() != releasedRetention {
		return ErrMismatch
	}
	return nil
}

// ValidateWorkflow is required before narrative intake, including each mutation.
func ValidateWorkflow(p Policy, environment string) error {
	if err := p.Validate(environment); err != nil {
		return err
	}
	if p.Workflow == nil {
		return ErrNotApproved
	}
	return nil
}

// Decode refuses unknown/duplicate fields, omitted fixture declarations,
// trailing JSON and unbounded input. It never assigns an approval or default.
func Decode(input io.Reader) (Policy, error) {
	if input == nil {
		return Policy{}, ErrInvalidPolicy
	}
	data, err := io.ReadAll(io.LimitReader(input, MaxArtifactBytes+1))
	if err != nil || len(data) > MaxArtifactBytes {
		return Policy{}, ErrInvalidPolicy
	}
	var keys map[string]json.RawMessage
	if json.Unmarshal(data, &keys) != nil || (string(keys["fixture"]) != "true" && string(keys["fixture"]) != "false") {
		return Policy{}, ErrInvalidPolicy
	}
	if err := uniqueJSONKeys(json.NewDecoder(bytes.NewReader(data)), 0); err != nil {
		return Policy{}, ErrInvalidPolicy
	}
	var p Policy
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&p) != nil {
		return Policy{}, ErrInvalidPolicy
	}
	return p, nil
}

func uniqueJSONKeys(decoder *json.Decoder, depth int) error {
	if depth > 4 {
		return ErrInvalidPolicy
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	for decoder.More() {
		if delim == '{' {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return ErrInvalidPolicy
			}
			seen[name] = true
		}
		if err := uniqueJSONKeys(decoder, depth+1); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}

func validSeconds(seconds int64) bool {
	return seconds > 0 && seconds <= math.MaxInt64/int64(time.Second)
}

func exactFields(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	got, want = slices.Clone(got), slices.Clone(want)
	slices.Sort(got)
	slices.Sort(want)
	return slices.Equal(got, want)
}

func sameBaseline(a, b Policy) bool {
	return a.ContextRetentionSeconds == b.ContextRetentionSeconds &&
		a.ReleasedHoldRetentionSeconds == b.ReleasedHoldRetentionSeconds &&
		a.ContextClock == b.ContextClock && a.ReleasedHoldClock == b.ReleasedHoldClock &&
		a.HoldTombstoneLifetime == b.HoldTombstoneLifetime && exactFields(a.HoldTombstoneFields, b.HoldTombstoneFields)
}
