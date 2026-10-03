package legalpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/adminaction"
)

func fixturePolicy() Policy {
	return Policy{ID: uuid.New(), ApprovalReference: "fixture-approval", Fixture: true,
		ContextRetentionSeconds: 3600, ReleasedHoldRetentionSeconds: 7200,
		ContextClock: ClockCreatedAt, ReleasedHoldClock: ClockReleasedAt,
		HoldTombstoneFields: HoldTombstoneFields(), HoldTombstoneLifetime: LifetimeNoExpiry,
		Workflow: &WorkflowPolicy{MaxCaseAgeSeconds: 86400, ClosedCaseRetentionSeconds: 3600,
			CaseClock: ClockCaseExpiry, ReplayFields: WorkflowReplayFields(), ReplayLifetime: LifetimeNoExpiry}}
}

func TestPolicyValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Policy)
	}{
		{"missing version", func(p *Policy) { p.ID = uuid.Nil }},
		{"missing approval", func(p *Policy) { p.ApprovalReference = "" }},
		{"narrative approval", func(p *Policy) { p.ApprovalReference = "approved by somebody" }},
		{"URL approval", func(p *Policy) { p.ApprovalReference = "https://example.test/evidence" }},
		{"oversized approval", func(p *Policy) { p.ApprovalReference = strings.Repeat("a", 129) }},
		{"missing context duration", func(p *Policy) { p.ContextRetentionSeconds = 0 }},
		{"negative context duration", func(p *Policy) { p.ContextRetentionSeconds = -1 }},
		{"overflow context duration", func(p *Policy) { p.ContextRetentionSeconds = math.MaxInt64 }},
		{"missing released duration", func(p *Policy) { p.ReleasedHoldRetentionSeconds = 0 }},
		{"overflow released duration", func(p *Policy) { p.ReleasedHoldRetentionSeconds = math.MaxInt64 }},
		{"missing context clock", func(p *Policy) { p.ContextClock = "" }},
		{"changed context clock", func(p *Policy) { p.ContextClock = "last_access_at" }},
		{"changed release clock", func(p *Policy) { p.ReleasedHoldClock = "review_at" }},
		{"missing inventory", func(p *Policy) { p.HoldTombstoneFields = nil }},
		{"missing retained actor", func(p *Policy) { p.HoldTombstoneFields = p.HoldTombstoneFields[:10] }},
		{"additional retained narrative", func(p *Policy) { p.HoldTombstoneFields = append(p.HoldTombstoneFields, "reason") }},
		{"duplicate inventory", func(p *Policy) { p.HoldTombstoneFields[0] = p.HoldTombstoneFields[1] }},
		{"missing lifetime", func(p *Policy) { p.HoldTombstoneLifetime = "" }},
		{"finite hold lifetime", func(p *Policy) { p.HoldTombstoneLifetime = "8760h" }},
		{"nonexact lifetime", func(p *Policy) { p.HoldTombstoneLifetime = "indefinite" }},
		{"missing maximum age", func(p *Policy) { p.Workflow.MaxCaseAgeSeconds = 0 }},
		{"overflow maximum age", func(p *Policy) { p.Workflow.MaxCaseAgeSeconds = math.MaxInt64 }},
		{"missing closed retention", func(p *Policy) { p.Workflow.ClosedCaseRetentionSeconds = 0 }},
		{"negative closed retention", func(p *Policy) { p.Workflow.ClosedCaseRetentionSeconds = -1 }},
		{"unsupported case clock", func(p *Policy) { p.Workflow.CaseClock = "last_revision_at" }},
		{"missing replay inventory", func(p *Policy) { p.Workflow.ReplayFields = nil }},
		{"extra replay actor", func(p *Policy) { p.Workflow.ReplayFields = append(p.Workflow.ReplayFields, "actor_id") }},
		{"extra replay fingerprint", func(p *Policy) { p.Workflow.ReplayFields[0] = "content_digest" }},
		{"finite replay lifetime", func(p *Policy) { p.Workflow.ReplayLifetime = "24h" }},
		{"missing replay lifetime", func(p *Policy) { p.Workflow.ReplayLifetime = "" }},
		{"invalid legacy reference", func(p *Policy) { p.LegacyInventoryReference = "legacy inventory narrative" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := fixturePolicy()
			tc.edit(&p)
			if !errors.Is(p.Validate("test"), ErrInvalidPolicy) {
				t.Fatal("accepted unapproved or unsupported policy")
			}
		})
	}
}

func TestPolicyEnvironmentAndSeparateWorkflowApproval(t *testing.T) {
	p := fixturePolicy()
	for _, env := range []string{"production", "staging", "Production", "", "testing", "development "} {
		if p.Validate(env) == nil {
			t.Fatalf("fixture accepted in %q", env)
		}
	}
	for _, env := range []string{"test", "development"} {
		if err := ValidateWorkflow(p, env); err != nil {
			t.Fatal(err)
		}
	}
	p.Fixture = false
	if err := ValidateWorkflow(p, "production"); err != nil {
		t.Fatal(err)
	}
	p.Workflow = nil
	if err := ValidateBaseline(p, time.Hour, 2*time.Hour, "production"); err != nil {
		t.Fatalf("baseline required workflow extension: %v", err)
	}
	if !errors.Is(ValidateWorkflow(p, "production"), ErrNotApproved) {
		t.Fatal("baseline approval enabled workflow")
	}
	if !errors.Is(ValidateBaseline(p, time.Hour+time.Nanosecond, 2*time.Hour, "production"), ErrMismatch) ||
		!errors.Is(ValidateBaseline(p, time.Hour, 3*time.Hour, "production"), ErrMismatch) {
		t.Fatal("accepted configuration mismatch")
	}
}

func TestPolicyDurationsAndInventoryOrder(t *testing.T) {
	p := fixturePolicy()
	slices.Reverse(p.HoldTombstoneFields)
	slices.Reverse(p.Workflow.ReplayFields)
	if p.Validate("test") != nil || p.ContextRetention() != time.Hour || p.ReleasedHoldRetention() != 2*time.Hour ||
		p.Workflow.MaxCaseAge() != 24*time.Hour || p.Workflow.ClosedCaseRetention() != time.Hour {
		t.Fatal("duration conversion or set inventory validation failed")
	}
	p.ContextRetentionSeconds = math.MaxInt64 / int64(time.Second)
	if p.Validate("test") != nil || p.ContextRetention() <= 0 {
		t.Fatal("maximum representable whole-second duration rejected")
	}
	fields := HoldTombstoneFields()
	fields[0] = "modified"
	if HoldTombstoneFields()[0] == "modified" {
		t.Fatal("caller changed approved inventory")
	}
}

func TestPolicyDecode(t *testing.T) {
	p := fixturePolicy()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(bytes.NewReader(data))
	if err != nil || decoded.ID != p.ID || decoded.Validate("test") != nil {
		t.Fatalf("valid artifact rejected: %v", err)
	}
	for _, input := range []string{
		"", "null", "[]", string(data) + "{}", string(data) + "trailing",
		strings.Repeat(" ", MaxArtifactBytes+1) + string(data),
		strings.Replace(string(data), `"fixture":true,`, "", 1),
		strings.Replace(string(data), `"fixture":true`, `"fixture":null`, 1),
		strings.Replace(string(data), `"fixture":true`, `"fixture":"true"`, 1),
		strings.Replace(string(data), `"fixture":true`, `"fixture":true,"approvable":true`, 1),
		strings.Replace(string(data), `"fixture":true`, `"fixture":true,"fixture":false`, 1),
		strings.Replace(string(data), `"context_retention_seconds":3600`, `"context_retention_seconds":3600.5`, 1),
		strings.Replace(string(data), `"context_retention_seconds":3600`, `"context_retention_seconds":"1h"`, 1),
		strings.Replace(string(data), `"case_clock":`, `"extra":1,"case_clock":`, 1),
		strings.Replace(string(data), `"max_case_age_seconds":86400`, `"max_case_age_seconds":86400,"max_case_age_seconds":1`, 1),
	} {
		if _, err := Decode(strings.NewReader(input)); !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("accepted invalid JSON artifact: %s", input[:min(len(input), 80)])
		}
	}
	if _, err := Decode(nil); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("nil reader accepted")
	}
	if _, err := Decode(failingReader{}); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatal("input read failure ignored")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestPolicyUnavailableAndMissingOperation(t *testing.T) {
	ctx := context.Background()
	if _, err := Load(ctx, nil, uuid.New(), "test"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("nil database accepted")
	}
	if _, err := LoadBaseline(ctx, nil, uuid.Nil, "test"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("nil database accepted for maintenance")
	}
	if err := Install(ctx, nil, fixturePolicy(), "test"); !errors.Is(err, adminaction.ErrNoOperation) {
		t.Fatal("installation without audited transaction accepted")
	}
}
