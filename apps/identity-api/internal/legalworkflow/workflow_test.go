package legalworkflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	cryptoEnvelope "github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
)

func testEncryptor(t *testing.T) *cryptoEnvelope.Encryptor {
	t.Helper()
	p, err := kms.NewMockProvider(bytes.Repeat([]byte{0x71}, 32), 1)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := cryptoEnvelope.New(p)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}
func fixtureContent() Content {
	return Content{RequestType: "disclosure", AuthorityReference: "fixture-authority", RequestReference: "fixture-order", LegalBasis: "fixture statute",
		MinimumNecessaryScope: "one selected record", NotificationDisposition: "restricted", NotificationRestriction: "fixture sealing order", EvidenceReference: "fixture-evidence"}
}
func TestCipherBinding(t *testing.T) {
	s, _ := New(testEncryptor(t), Config{})
	ctx := context.Background()
	id, scope := uuid.New(), uuid.New()
	value := envelope{ID: id, Scope: scope, Revision: 7, Purpose: "review", Input: json.RawMessage(`{"rationale":"synthetic secret"}`), Result: MutationResult{ID: scope, Version: 7}}
	blob, err := s.seal(ctx, value)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte("synthetic secret")) {
		t.Fatal("plaintext leaked")
	}
	for _, tc := range []struct {
		name      string
		id, scope uuid.UUID
		revision  int64
		purpose   string
		ok        bool
	}{
		{"valid", id, scope, 7, "review", true}, {"record", uuid.New(), scope, 7, "review", false},
		{"case", id, uuid.New(), 7, "review", false}, {"revision", id, scope, 8, "review", false}, {"purpose", id, scope, 7, "prepare", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.open(ctx, blob, tc.id, tc.scope, tc.revision, tc.purpose)
			if (err == nil) != tc.ok {
				t.Fatalf("error=%v", err)
			}
		})
	}
	blob[len(blob)-1] ^= 1
	if _, err = s.open(ctx, blob, id, scope, 7, "review"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("tampering error=%v", err)
	}
}
func TestValidationAndCanonicalContract(t *testing.T) {
	if !content(fixtureContent()) {
		t.Fatal("fixture invalid")
	}
	for _, field := range []string{"type", "notification", "authority", "restricted"} {
		c := fixtureContent()
		switch field {
		case "type":
			c.RequestType = "unbounded narrative"
		case "notification":
			c.NotificationDisposition = "secret"
		case "authority":
			c.AuthorityReference = ""
		case "restricted":
			c.NotificationRestriction = ""
		}
		if content(c) {
			t.Fatalf("accepted invalid %s", field)
		}
	}
	a, b := uuid.New(), uuid.New()
	v, err := ids([]uuid.UUID{b, a})
	if err != nil || len(v) != 2 {
		t.Fatal(err)
	}
	if _, err = ids([]uuid.UUID{a, a}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatal("duplicate accepted")
	}
	if _, err = ids(make([]uuid.UUID, 101)); !errors.Is(err, ErrInvalidRequest) {
		t.Fatal("unbounded subjects")
	}
	if _, err = canonical(strings.Repeat("s", MaxPlaintext)); !errors.Is(err, ErrInvalidRequest) {
		t.Fatal("unbounded plaintext")
	}
	var r ReviewRequest
	if err = json.Unmarshal([]byte(`{"key":"`+a.String()+`","case_id":"`+b.String()+`","actor":"`+a.String()+`","expected_version":2}`), &r); err != nil {
		t.Fatal(err)
	}
	if r.Key != uuid.Nil || r.CaseID != uuid.Nil || r.ExpectedVersion != 2 {
		t.Fatal("server-owned identity decoded from body")
	}
	if timestamp(time.Now().In(time.FixedZone("offset", 3600))) {
		t.Fatal("non-UTC accepted")
	}
}
func fixtureResponse(id, subject uuid.UUID) ResponseRequest {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	until := from.Add(time.Hour)
	return ResponseRequest{Key: uuid.New(), CaseID: id, ExpectedVersion: 2, ContentRevision: 1, Outcome: OutcomeFullDisclosure, Rationale: "fixture minimum necessary",
		Manifest: Manifest{RecipientReference: "fixture-recipient", EvidenceReference: "fixture-evidence", LegalBasis: "fixture statute", SubjectIDs: []uuid.UUID{subject}, From: &from, Until: &until, Fields: []string{"event_type"}, Artifacts: []Artifact{{Reference: "fixture-record-1", Digest: strings.Repeat("a", 64)}}}}
}
func TestManifestDerivesDisclosureAndReviewBinding(t *testing.T) {
	id, subject := uuid.New(), uuid.New()
	valid := fixtureResponse(id, subject)
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"missing_scope", "missing_artifact", "bad_digest", "hidden_data", "bad_outcome", "duplicate_fields"} {
		r := fixtureResponse(id, subject)
		switch name {
		case "missing_scope":
			r.Manifest.SubjectIDs = nil
		case "missing_artifact":
			r.Manifest.Artifacts = nil
		case "bad_digest":
			r.Manifest.Artifacts[0].Digest = "not a digest"
		case "hidden_data":
			r.Outcome = OutcomeRefusal
		case "bad_outcome":
			r.Outcome = "other"
		case "duplicate_fields":
			r.Manifest.Fields = []string{"id", "id"}
		}
		if err := r.validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	c := state{Summary: Summary{MutationResult: MutationResult{ContentRevision: 2, Version: 9, Decision: "accepted"}}, ReviewedRevision: 2}
	if !reviewed(c, true) {
		t.Fatal("bookkeeping version invalidated content review")
	}
	c.ContentRevision = 3
	if reviewed(c, true) {
		t.Fatal("amendment retained acceptance")
	}
	c.ContentRevision = 2
	c.Decision = "needs_information"
	if reviewed(c, true) || !reviewed(c, false) {
		t.Fatal("review disclosure classification")
	}
}
func TestTransactionsAndDisabledConfiguration(t *testing.T) {
	s, err := New(testEncryptor(t), Config{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = operation(context.Background()); !errors.Is(err, ErrTransactionRequired) {
		t.Fatal(err)
	}
	if _, err = s.Create(context.Background(), Actor{}, CreateRequest{Key: uuid.New(), ReceivedAt: time.Now().UTC(), Content: fixtureContent()}); !errors.Is(err, ErrTransactionRequired) {
		t.Fatal(err)
	}
	if _, err = New(testEncryptor(t), Config{Enabled: true}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("enabled without policy")
	}
}
