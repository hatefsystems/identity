// Package legalworkflow records reviewed authority requests. It never releases a
// hold or transfers evidence. HTTP transaction ownership stays with adminaction.
package legalworkflow

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Input bounds and canonical response outcomes are part of the public contract.
const (
	MaxSubjects                        = 100
	MaxPlaintext                       = 32 * 1024
	OutcomeFullDisclosure              = "full_disclosure"
	OutcomePartialDisclosure           = "partial_disclosure"
	OutcomeNoResponsiveData            = "no_responsive_data"
	OutcomeRefusal                     = "refusal"
	OutcomePreservationAcknowledgement = "preservation_acknowledgement"
)

// Errors deliberately omit sensitive record details.
var (
	ErrInvalidRequest      = errors.New("legalworkflow: invalid request")
	ErrNotFound            = errors.New("legalworkflow: not found")
	ErrConflict            = errors.New("legalworkflow: version or idempotency conflict")
	ErrErased              = errors.New("legalworkflow: erased")
	ErrExpired             = errors.New("legalworkflow: expired")
	ErrUnavailable         = errors.New("legalworkflow: unavailable")
	ErrTransactionRequired = errors.New("legalworkflow: admin transaction required")
)

// Actor is supplied only by the authenticated server, never decoded from JSON.
type Actor struct {
	ID          uuid.UUID
	AuthVersion int64
}

// Config enables intake only against one explicitly approved policy.
type Config struct {
	Enabled     bool
	PolicyID    uuid.UUID
	Environment string
}

// Content is restricted narrative sealed in an immutable revision.
type Content struct {
	RequestType             string `json:"request_type"`
	AuthorityReference      string `json:"authority_reference"`
	RequestReference        string `json:"request_reference"`
	LegalBasis              string `json:"legal_basis"`
	MinimumNecessaryScope   string `json:"minimum_necessary_scope"`
	NotificationDisposition string `json:"notification_disposition"`
	NotificationRestriction string `json:"notification_restriction"`
	EvidenceReference       string `json:"evidence_reference"`
}

// CreateRequest identifies one real request with an opaque retry key.
type CreateRequest struct {
	Key             uuid.UUID   `json:"-"`
	ExpectedVersion int64       `json:"expected_version"`
	ReceivedAt      time.Time   `json:"received_at"`
	NextReviewAt    *time.Time  `json:"next_review_at"`
	Content         Content     `json:"content"`
	SubjectIDs      []uuid.UUID `json:"subject_ids"`
	HoldIDs         []uuid.UUID `json:"hold_ids"`
}

// RevisionRequest replaces current content and associations, not historic subjects.
type RevisionRequest struct {
	Key             uuid.UUID   `json:"-"`
	CaseID          uuid.UUID   `json:"-"`
	ExpectedVersion int64       `json:"expected_version"`
	Content         Content     `json:"content"`
	SubjectIDs      []uuid.UUID `json:"subject_ids"`
	HoldIDs         []uuid.UUID `json:"hold_ids"`
}

// ReviewRequest records a human decision on one exact content revision.
type ReviewRequest struct {
	Key             uuid.UUID  `json:"-"`
	CaseID          uuid.UUID  `json:"-"`
	ExpectedVersion int64      `json:"expected_version"`
	ContentRevision int64      `json:"content_revision"`
	Decision        string     `json:"decision"`
	Rationale       string     `json:"rationale"`
	NextReviewAt    *time.Time `json:"next_review_at"`
}

// Manifest is the exact manually selected scope; artifact digests remain sealed.
// Disclosure outcomes require complete scope and at least one exact artifact.
type Manifest struct {
	RecipientReference string      `json:"recipient_reference"`
	EvidenceReference  string      `json:"evidence_reference"`
	LegalBasis         string      `json:"legal_basis"`
	SubjectIDs         []uuid.UUID `json:"subject_ids"`
	From               *time.Time  `json:"from"`
	Until              *time.Time  `json:"until"`
	Fields             []string    `json:"fields"`
	Artifacts          []Artifact  `json:"artifacts"`
}

// Artifact identifies one exact externally retained record or immutable bundle.
type Artifact struct {
	Reference string `json:"reference"`
	Digest    string `json:"digest"`
}

// ResponseRequest prepares or revises the single final response proposal.
type ResponseRequest struct {
	Key             uuid.UUID `json:"-"`
	CaseID          uuid.UUID `json:"-"`
	ExpectedVersion int64     `json:"expected_version"`
	ContentRevision int64     `json:"content_revision"`
	Outcome         string    `json:"outcome"`
	Manifest        Manifest  `json:"manifest"`
	Rationale       string    `json:"rationale"`
}

// ApprovalRequest binds approval to the stored immutable manifest revision.
type ApprovalRequest struct {
	Key              uuid.UUID `json:"-"`
	CaseID           uuid.UUID `json:"-"`
	ExpectedVersion  int64     `json:"expected_version"`
	ContentRevision  int64     `json:"content_revision"`
	ProposalRevision int64     `json:"proposal_revision"`
}

// DeliveryRequest attests external delivery; it never initiates a transfer.
type DeliveryRequest struct {
	Key              uuid.UUID `json:"-"`
	CaseID           uuid.UUID `json:"-"`
	ExpectedVersion  int64     `json:"expected_version"`
	ContentRevision  int64     `json:"content_revision"`
	ProposalRevision int64     `json:"proposal_revision"`
	DeliveredAt      time.Time `json:"delivered_at"`
	ReceiptReference string    `json:"receipt_reference"`
}

// CloseRequest explicitly terminates a case without counting an answer.
type CloseRequest struct {
	Key             uuid.UUID `json:"-"`
	CaseID          uuid.UUID `json:"-"`
	ExpectedVersion int64     `json:"expected_version"`
	Reason          string    `json:"reason"`
	Rationale       string    `json:"rationale"`
}

// HoldReviewRequest records advisory history without editing the original hold.
type HoldReviewRequest struct {
	Key             uuid.UUID  `json:"-"`
	HoldID          uuid.UUID  `json:"-"`
	ExpectedVersion int64      `json:"expected_version"`
	Decision        string     `json:"decision"`
	Rationale       string     `json:"rationale"`
	NextReviewAt    *time.Time `json:"next_review_at"`
}

// MutationResult is bounded replay metadata, not a copy of case narrative.
type MutationResult struct {
	ID               uuid.UUID `json:"id"`
	Version          int64     `json:"version"`
	ContentRevision  int64     `json:"content_revision"`
	ProposalRevision int64     `json:"proposal_revision"`
	Status           string    `json:"status"`
	Decision         string    `json:"decision"`
	Replayed         bool      `json:"replayed"`
}

// Summary exposes lifecycle and scheduling metadata only.
type Summary struct {
	MutationResult
	ReceivedAt   *time.Time `json:"received_at"`
	CreatedAt    *time.Time `json:"created_at"`
	ClosedAt     *time.Time `json:"closed_at"`
	NextReviewAt *time.Time `json:"next_review_at"`
	ExpiresAt    *time.Time `json:"expires_at"`
}

// Case is restricted detail, including at most 200 newest immutable events.
type Case struct {
	Summary
	Content          Content          `json:"content"`
	SubjectIDs       []uuid.UUID      `json:"subject_ids"`
	HoldIDs          []uuid.UUID      `json:"hold_ids"`
	Response         *ResponseRequest `json:"response,omitempty"`
	History          []HistoryEntry   `json:"history"`
	HistoryTruncated bool             `json:"history_truncated"`
}

// HistoryEntry is decrypted only after authorization and expiry checks.
type HistoryEntry struct {
	ID        uuid.UUID `json:"id"`
	Revision  int64     `json:"revision"`
	Purpose   string    `json:"purpose"`
	Actor     uuid.UUID `json:"actor"`
	ActionID  uuid.UUID `json:"action_id"`
	CreatedAt time.Time `json:"created_at"`
	Input     any       `json:"input"`
}

// ListRequest supports bounded pagination and lifecycle filtering, never identifiers.
type ListRequest struct {
	Status        string
	Limit, Offset int32
}

// ListResult returns the page and total from one database snapshot.
type ListResult struct {
	Cases []Summary `json:"cases"`
	Total int64     `json:"total"`
}

// QueueItem schedules work but is not legal expiry or hold release.
type QueueItem struct {
	ID           uuid.UUID `json:"id"`
	Kind         string    `json:"kind"`
	Version      int64     `json:"version"`
	NextReviewAt time.Time `json:"next_review_at"`
}

// QueueResult combines due case and hold reviews in one bounded snapshot.
type QueueResult struct {
	Items []QueueItem `json:"items"`
	Total int64       `json:"total"`
}

// CleanupResult contains counts only, suitable for controlled operator output.
type CleanupResult struct {
	Considered  int64 `json:"considered"`
	Deleted     int64 `json:"deleted"`
	Held        int64 `json:"held"`
	WouldDelete int64 `json:"would_delete"`
	DryRun      bool  `json:"dry_run"`
}
