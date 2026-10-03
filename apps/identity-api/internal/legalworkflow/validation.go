package legalworkflow

import (
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

func text(s string, maximum int) bool {
	return strings.TrimSpace(s) != "" && len(s) <= maximum && utf8.ValidString(s)
}
func timestamp(t time.Time) bool {
	_, offset := t.Zone()
	return !t.IsZero() && t.Year() >= 1 && t.Year() <= 9999 && offset == 0
}
func optionalTime(t *time.Time) bool { return t == nil || timestamp(*t) }
func decision(s string) bool         { return s == "accepted" || s == "rejected" || s == "needs_information" }

// Sorting copies prevents callers from changing a pending operation's lock set.
func ids(in []uuid.UUID) ([]uuid.UUID, error) {
	if len(in) > MaxSubjects {
		return nil, ErrInvalidRequest
	}
	out := append([]uuid.UUID{}, in...)
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	for i, id := range out {
		if id == uuid.Nil || (i > 0 && out[i-1] == id) {
			return nil, ErrInvalidRequest
		}
	}
	return out, nil
}
func content(c Content) bool {
	switch c.RequestType {
	case "disclosure", "preservation", "other":
	default:
		return false
	}
	switch c.NotificationDisposition {
	case "pending", "notify", "restricted", "not_applicable":
	default:
		return false
	}
	return text(c.AuthorityReference, 1024) && text(c.RequestReference, 1024) && text(c.LegalBasis, 4096) &&
		text(c.MinimumNecessaryScope, 8192) && text(c.EvidenceReference, 1024) && len(c.NotificationRestriction) <= 4096 &&
		(c.NotificationDisposition != "restricted" || text(c.NotificationRestriction, 4096))
}
func canonical(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	// Reserve room for the authenticated envelope and bounded result.
	if err != nil || len(b) > MaxPlaintext-2048 {
		return nil, ErrInvalidRequest
	}
	return b, nil
}
func base(key, id uuid.UUID, version int64) error {
	if key == uuid.Nil || id == uuid.Nil || version < 1 || version == 1<<63-1 {
		return ErrInvalidRequest
	}
	return nil
}
func (r *ResponseRequest) validate() error {
	if err := base(r.Key, r.CaseID, r.ExpectedVersion); err != nil {
		return err
	}
	if r.ContentRevision < 1 || !text(r.Rationale, 4096) || !text(r.Manifest.RecipientReference, 1024) ||
		!text(r.Manifest.EvidenceReference, 1024) || !text(r.Manifest.LegalBasis, 4096) {
		return ErrInvalidRequest
	}
	var err error
	r.Manifest.SubjectIDs, err = ids(r.Manifest.SubjectIDs)
	if err != nil {
		return err
	}
	disclosure := dataBearing(r.Outcome)
	switch r.Outcome {
	case OutcomeFullDisclosure, OutcomePartialDisclosure, OutcomeNoResponsiveData, OutcomeRefusal, OutcomePreservationAcknowledgement:
	default:
		return ErrInvalidRequest
	}
	if !disclosure {
		if len(r.Manifest.SubjectIDs) != 0 || len(r.Manifest.Fields) != 0 || len(r.Manifest.Artifacts) != 0 || r.Manifest.From != nil || r.Manifest.Until != nil {
			return ErrInvalidRequest
		}
		return nil
	}
	if len(r.Manifest.SubjectIDs) == 0 || len(r.Manifest.Fields) == 0 || len(r.Manifest.Fields) > 32 || len(r.Manifest.Artifacts) == 0 || len(r.Manifest.Artifacts) > 100 ||
		r.Manifest.From == nil || r.Manifest.Until == nil || !timestamp(*r.Manifest.From) || !timestamp(*r.Manifest.Until) || !r.Manifest.From.Before(*r.Manifest.Until) {
		return ErrInvalidRequest
	}
	r.Manifest.Fields = append([]string{}, r.Manifest.Fields...)
	sort.Strings(r.Manifest.Fields)
	for i, f := range r.Manifest.Fields {
		if !text(f, 64) || (i > 0 && r.Manifest.Fields[i-1] == f) {
			return ErrInvalidRequest
		}
	}
	r.Manifest.Artifacts = append([]Artifact{}, r.Manifest.Artifacts...)
	sort.Slice(r.Manifest.Artifacts, func(i, j int) bool { return r.Manifest.Artifacts[i].Reference < r.Manifest.Artifacts[j].Reference })
	for i, a := range r.Manifest.Artifacts {
		digest, err := hex.DecodeString(a.Digest)
		if !text(a.Reference, 1024) || err != nil || len(digest) != 32 || (i > 0 && r.Manifest.Artifacts[i-1].Reference == a.Reference) {
			return ErrInvalidRequest
		}
		r.Manifest.Artifacts[i].Digest = strings.ToLower(a.Digest)
	}
	return nil
}
func dataBearing(outcome string) bool {
	return outcome == OutcomeFullDisclosure || outcome == OutcomePartialDisclosure
}
