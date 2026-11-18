package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/contactproof"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/envelope"
	"github.com/hatefsystems/identity/apps/identity-api/internal/crypto/kms"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

func TestProfileHTTPAbsentEmailIsRequiredNull(t *testing.T) {
	s, d, _, sess := profileHandlerFixture(t)
	d.row.Email = nil
	w := httptest.NewRecorder()
	s.handleProfileGet()(w, profileHandlerRequest(sess, http.MethodGet, ""))
	var fields map[string]json.RawMessage
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &fields) != nil || string(fields["email"]) != "null" {
		t.Fatal("absent email was omitted or fabricated")
	}
}

func TestProfileHTTPVerifiedEmailUsesProtectedOriginalTime(t *testing.T) {
	s, d, _, sess := profileHandlerFixture(t)
	provider, err := kms.NewMockProvider(bytes.Repeat([]byte{7}, 32), 1)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := envelope.New(provider)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	d.row.EmailEvidence, err = contactproof.Seal(t.Context(), cipher, d.row.ID, contactproof.Email, *d.row.Email, contactproof.EmailLink, at)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.handleProfileGet()(w, profileHandlerRequest(sess, http.MethodGet, ""))
	var response profileResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil || !response.EmailVerified || response.EmailVerifiedAt == nil || !response.EmailVerifiedAt.Equal(at) {
		t.Fatal("profile API inferred or lost original evidence")
	}
}

func TestAdminEmailRedactionAndAbsenceAreDistinct(t *testing.T) {
	for _, email := range []*string{nil, new("person@example.test")} {
		for _, authorized := range []bool{false, true} {
			response := newAdminUserResponse(db.User{ID: uuid.New(), Email: email}, authorized)
			encoded, err := json.Marshal(response)
			var fields map[string]json.RawMessage
			if err != nil || json.Unmarshal(encoded, &fields) != nil {
				t.Fatal("admin projection failed")
			}
			value, present := fields["email"]
			if present != authorized || authorized && email == nil && string(value) != "null" || authorized && email != nil && string(value) != `"person@example.test"` {
				t.Fatal("admin email absence confused with redaction")
			}
		}
	}
}
