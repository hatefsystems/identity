// Package legalreport maintains case-free request counters and reviewed,
// immutable aggregate artifacts. The adminaction boundary owns every commit.
package legalreport

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Stable errors distinguish invalid input, stale approval and unavailable storage.
var (
	ErrInvalidRequest      = errors.New("legalreport: invalid request")
	ErrNotFound            = errors.New("legalreport: report not found")
	ErrConflict            = errors.New("legalreport: version or replay conflict")
	ErrStaleSnapshot       = errors.New("legalreport: snapshot is stale")
	ErrUnavailable         = errors.New("legalreport: unavailable")
	ErrTransactionRequired = errors.New("legalreport: admin action transaction required")
)

// Reporting permissions and the export schema are explicit protocol constants.
const (
	PermissionRead    = "legal.transparency.read"
	PermissionApprove = "legal.transparency.approve"
	SchemaVersion     = 1
)

// Actor comes exclusively from the authenticated session, never request JSON.
type Actor struct {
	ID          uuid.UUID
	AuthVersion int64
}

// Config binds reporting to approved policy and deployment environment.
type Config struct {
	Enabled     bool
	PolicyID    uuid.UUID
	Environment string
}

// MonthlyRequest selects at most twelve UTC calendar months.
type MonthlyRequest struct {
	Start  time.Time
	Months int
}

// Totals counts requests and answers in their independent timestamp cohorts.
type Totals struct {
	Received                    int64 `json:"received"`
	Answered                    int64 `json:"answered"`
	FullDisclosure              int64 `json:"full_disclosure"`
	PartialDisclosure           int64 `json:"partial_disclosure"`
	NoResponsiveData            int64 `json:"no_responsive_data"`
	Refusal                     int64 `json:"refusal"`
	PreservationAcknowledgement int64 `json:"preservation_acknowledgement"`
}

// Month labels internal exact counters.
type Month struct {
	Month time.Time `json:"month"`
	Totals
}

// MonthlyResult includes the first committed collection time, not a completeness
// guarantee. A zero CoverageStart means collection has not begun.
type MonthlyResult struct {
	CoverageStart       time.Time `json:"coverage_start"`
	LateEntriesPossible bool      `json:"late_entries_possible"`
	Months              []Month   `json:"months"`
}

// PrepareRequest selects a completed year and a business replay key.
type PrepareRequest struct {
	Key             uuid.UUID `json:"-"`
	Year            int       `json:"year"`
	ExpectedVersion int64     `json:"expected_version"`
}

// ApproveRequest identifies the exact snapshot and policy being approved.
type ApproveRequest struct {
	Key             uuid.UUID `json:"-"`
	ID              uuid.UUID `json:"-"`
	ExpectedVersion int64     `json:"expected_version"`
	DataVersion     int64     `json:"data_version"`
	PolicyVersion   uuid.UUID `json:"policy_version"`
	Digest          string    `json:"digest"`
}

// DownloadRequest consumes an approved artifact without regenerating its bytes.
type DownloadRequest struct {
	Key             uuid.UUID `json:"-"`
	ID              uuid.UUID `json:"-"`
	ExpectedVersion int64     `json:"expected_version"`
}

// Report is an internal review representation, never the downloadable artifact.
type Report struct {
	ID              uuid.UUID       `json:"id"`
	Version         int64           `json:"version"`
	Year            int             `json:"year"`
	DataVersion     int64           `json:"data_version"`
	PolicyVersion   uuid.UUID       `json:"policy_version"`
	Digest          string          `json:"digest"`
	Payload         json.RawMessage `json:"payload"`
	Status          string          `json:"status"`
	PreparedBy      uuid.UUID       `json:"prepared_by"`
	ApprovedBy      *uuid.UUID      `json:"approved_by,omitempty"`
	Stale           bool            `json:"stale"`
	Replayed        bool            `json:"replayed"`
	preparedVersion int64
	approvedVersion *int64
}

// DownloadResult holds export-safe bytes and internal replay state.
type DownloadResult struct {
	Payload  json.RawMessage `json:"payload"`
	Replayed bool            `json:"replayed"`
}

// Cell distinguishes a withheld nonzero value from a measured zero.
type Cell struct {
	Count      *int64 `json:"count,omitempty"`
	Suppressed bool   `json:"suppressed"`
}

// Coverage avoids asserting complete collection of real requests.
type Coverage struct {
	Status              string `json:"status"`
	LateEntriesPossible bool   `json:"late_entries_possible"`
}

// OutcomeCounts partitions recorded answers into broad categories.
type OutcomeCounts struct {
	FullDisclosure              int64 `json:"full_disclosure"`
	PartialDisclosure           int64 `json:"partial_disclosure"`
	NoResponsiveData            int64 `json:"no_responsive_data"`
	Refusal                     int64 `json:"refusal"`
	PreservationAcknowledgement int64 `json:"preservation_acknowledgement"`
}

// OutcomeBreakdown withholds all cells together when any nonzero cell is small.
type OutcomeBreakdown struct {
	Suppressed bool           `json:"suppressed"`
	Counts     *OutcomeCounts `json:"counts,omitempty"`
}

// Artifact contains no source version, IDs, policy references or timestamps.
// In particular, a per-event source version would reconstruct suppressed totals.
type Artifact struct {
	SchemaVersion int              `json:"schema_version"`
	Year          int              `json:"year"`
	Coverage      Coverage         `json:"coverage"`
	Received      Cell             `json:"received"`
	Answered      Cell             `json:"answered"`
	Outcomes      OutcomeBreakdown `json:"outcomes"`
}
