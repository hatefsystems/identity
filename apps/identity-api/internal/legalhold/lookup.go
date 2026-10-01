package legalhold

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/mail"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
)

// LookupRequest defines the legal scope, disclosure fields and pagination.
type LookupRequest struct {
	IdentifierType      string
	Identifier          string
	RequestingAuthority string
	CaseReference       string
	Purpose             string
	ActorID             uuid.UUID
	StartTime, EndTime  time.Time
	Limit               int32
	Cursor              string
	Fields              []string
}

// Coverage describes the observed indexing boundary without promising completeness.
type Coverage struct {
	ThroughSeq           int64     `json:"through_seq"`
	ObservedAt           time.Time `json:"observed_at"`
	EligibilityCheckedAt time.Time `json:"eligibility_checked_at"`
	Note                 string    `json:"note"`
}

const coverageNote = "matching indexed retained records only; ingestion may be pending; unindexed or purged history is not covered; separate account references do not establish one person"

// LookupResult holds one bounded disclosure and its authenticated continuation.
type LookupResult struct {
	Events     []db.SecurityEventLedger
	NextCursor string
	Fields     []string
	Coverage   Coverage
}

type lookupCursor struct {
	Kind     string    `json:"kind"`
	Scope    string    `json:"scope"`
	After    int64     `json:"after"`
	Through  int64     `json:"through"`
	Observed time.Time `json:"observed"`
}

var extraFields = map[string]bool{
	"client_ip": true, "ip_subnet": true, "user_agent": true,
	"device_fingerprint": true, "client_id": true, "scope": true,
}

// Lookup keeps the identifier and its index in process-local query arguments.
// Cursor scope is encrypted and randomized, never an audit correlation key.
func (s *Service) Lookup(ctx context.Context, req LookupRequest) (LookupResult, error) {
	if req.IdentifierType != IdentifierTypeEmail {
		return LookupResult{}, ErrUnsupportedIdentifierType
	}
	if req.ActorID == uuid.Nil || !bounded(req.Identifier, 320) || !bounded(req.RequestingAuthority, MaxContextBytes) ||
		!bounded(req.CaseReference, MaxContextBytes) || !bounded(req.Purpose, MaxReasonBytes) ||
		req.StartTime.IsZero() || req.EndTime.IsZero() || req.StartTime.After(req.EndTime) ||
		req.EndTime.Sub(req.StartTime) > s.maxWindow || req.StartTime.Year() < 1 || req.EndTime.Year() > 9999 ||
		req.Limit < 1 || req.Limit > 200 || len(req.Cursor) > 4096 || len(req.Fields) > len(extraFields) {
		return LookupResult{}, ErrInvalidRequest
	}
	email := strings.TrimSpace(req.Identifier)
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email {
		return LookupResult{}, ErrInvalidRequest
	}
	fields := append([]string{}, req.Fields...)
	sort.Strings(fields)
	for i, field := range fields {
		if !extraFields[field] || (i > 0 && field == fields[i-1]) {
			return LookupResult{}, ErrInvalidRequest
		}
	}
	if !s.LookupEnabled() {
		return LookupResult{}, ErrUnavailable
	}
	q, _, err := s.queries(ctx)
	if err != nil {
		return LookupResult{}, err
	}
	index := s.indexer.Compute(req.Identifier)
	// Scope is inside the authenticated ciphertext only. Never emit it in audit.
	scopeJSON, _ := json.Marshal(struct {
		Index                    string
		Actor                    uuid.UUID
		Start, End               time.Time
		Authority, Case, Purpose string
		Fields                   []string
	}{index, req.ActorID, req.StartTime.UTC(), req.EndTime.UTC(), strings.TrimSpace(req.RequestingAuthority),
		strings.TrimSpace(req.CaseReference), strings.TrimSpace(req.Purpose), fields})
	digest := sha256.Sum256(scopeJSON)
	clear(scopeJSON)
	cursor := lookupCursor{Kind: "legal-attribution-v1", Scope: hex.EncodeToString(digest[:]), Observed: s.now().UTC()}
	if req.Cursor != "" {
		blob, err := base64.RawURLEncoding.DecodeString(req.Cursor)
		if err != nil {
			return LookupResult{}, ErrInvalidRequest
		}
		plain, err := s.encryptor.Decrypt(ctx, blob)
		if err != nil {
			return LookupResult{}, ErrInvalidRequest
		}
		var previous lookupCursor
		err = json.Unmarshal(plain, &previous)
		clear(plain)
		if err != nil || previous.Kind != cursor.Kind || previous.Scope != cursor.Scope ||
			previous.After < 0 || previous.After > previous.Through || previous.Observed.IsZero() ||
			previous.Observed.After(cursor.Observed) {
			return LookupResult{}, ErrInvalidRequest
		}
		cursor = previous
	} else {
		cursor.Through, err = q.LegalAttributionHighWater(ctx)
		if err != nil {
			return LookupResult{}, ErrUnavailable
		}
	}
	asOf := s.now().UTC()
	rows, err := q.LookupLegalAttribution(ctx, db.LookupLegalAttributionParams{
		BlindIndex: index, StartTime: timestamptz(req.StartTime), EndTime: timestamptz(req.EndTime),
		AfterSeq: cursor.After, ThroughSeq: cursor.Through, AsOf: timestamptz(asOf), PageLimit: req.Limit + 1,
	})
	if err != nil {
		return LookupResult{}, ErrUnavailable
	}
	result := LookupResult{Events: rows, Fields: fields, Coverage: Coverage{ThroughSeq: cursor.Through,
		ObservedAt: cursor.Observed, EligibilityCheckedAt: asOf, Note: coverageNote}}
	if len(rows) > int(req.Limit) {
		result.Events = rows[:req.Limit]
		cursor.After = result.Events[len(result.Events)-1].Seq
		plain, _ := json.Marshal(cursor)
		blob, err := s.encryptor.Encrypt(ctx, plain)
		clear(plain)
		if err != nil {
			return LookupResult{}, ErrUnavailable
		}
		result.NextCursor = base64.RawURLEncoding.EncodeToString(blob)
	}
	return result, nil
}
