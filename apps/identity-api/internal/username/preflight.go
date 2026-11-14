package username

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/hatefsystems/identity/apps/identity-api/internal/db"
	"github.com/hatefsystems/identity/apps/identity-api/internal/dbprivilege"
	"github.com/jackc/pgx/v5"
)

// ErrIncomplete never denotes clearance, even if the visited prefix was clean.
var ErrIncomplete = errors.New("username: preflight incomplete")

// PreflightOptions explicitly bound SQL pages, retained collision state and time.
// ReviewKey is independently provisioned for restricted account references; it
// is never included in reports or used as the username lookup key.
type PreflightOptions struct {
	PageSize  int32
	MaxRows   int64
	MaxIssues int
	Timeout   time.Duration
	ReviewKey []byte
}

// ReviewIssue contains only a category and independently keyed opaque references.
type ReviewIssue struct {
	Kind       string   `json:"kind"`
	References []string `json:"references"`
}

// PreflightReport is a read-only snapshot observation, never a cutover permit.
// Complete means every surviving account and installed artifact was visited.
// Clean additionally requires no collision, unreadable/unknown row or split.
type PreflightReport struct {
	SnapshotOnly    bool          `json:"snapshot_only"`
	Complete        bool          `json:"complete"`
	Clean           bool          `json:"clean"`
	Reason          string        `json:"reason,omitempty"`
	Scanned         int64         `json:"scanned"`
	Claimed         int64         `json:"claimed"`
	Unclaimed       int64         `json:"unclaimed"`
	ReservedNames   int64         `json:"reserved_names"`
	Collisions      int64         `json:"collisions"`
	Unreadable      int64         `json:"unreadable"`
	Inconsistent    int64         `json:"inconsistent"`
	PolicyErrors    int64         `json:"policy_errors"`
	IssuesTruncated bool          `json:"issues_truncated"`
	Issues          []ReviewIssue `json:"issues"`
}

// ProbePreflight requires an actual read-only operator login, including absence
// of application privileges, owner/DDL/role-assumption and guard bypass rights.
func ProbePreflight(ctx context.Context, q db.DBTX) error {
	guards := registryGuards()
	guards = append(guards, dbprivilege.Guard{Table: "public.users", Name: "users_username_immutable", Function: "public.username_ownership_guard()", Type: 31})
	return dbprivilege.Check(ctx, q, dbprivilege.Contract{Tables: []dbprivilege.Table{
		{Name: "public.users", Select: true},
		{Name: "public.username_policy_artifacts", Select: true},
		{Name: "public.username_lookup_keys", Select: true},
		{Name: "public.username_active_policy", Select: true},
	}, Guards: guards})
}

// Preflight never locks rows FOR SHARE: PostgreSQL forbids row-locking reads in
// READ ONLY. Its consistent snapshot is deliberately not activation evidence;
// a separately approved fenced rescan must close the scan-to-cutover race.
func Preflight(ctx context.Context, database Database, cipher Cipher, current, candidate *Normalizer, options PreflightOptions) (PreflightReport, error) {
	report := PreflightReport{SnapshotOnly: true, Issues: []ReviewIssue{}}
	if database == nil || cipher == nil || current == nil || candidate == nil || options.PageSize < 1 || options.PageSize > 1000 ||
		options.MaxRows < 1 || options.MaxRows > 1000000 || options.MaxIssues < 1 || options.MaxIssues > 1000 ||
		options.Timeout < time.Second || options.Timeout > time.Hour || len(options.ReviewKey) < 32 || len(options.ReviewKey) > 1024 {
		report.Reason = "invalid_options"
		return report, ErrIncomplete
	}
	reviewKey := slices.Clone(options.ReviewKey)
	defer clear(reviewKey)
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	tx, err := database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		report.Reason = "snapshot_unavailable"
		return report, ErrIncomplete
	}
	defer rollbackUsername(tx)
	if _, err := tx.Exec(ctx, `SELECT set_config('statement_timeout','5000',true),set_config('lock_timeout','2000',true),set_config('idle_in_transaction_session_timeout','10000',true)`); err != nil {
		report.Reason = "timeout_unavailable"
		return report, ErrIncomplete
	}
	if err := ProbePreflight(ctx, tx); err != nil {
		report.Reason = "privileges_unproven"
		return report, ErrIncomplete
	}
	if err := CheckSchema(ctx, tx); err != nil {
		report.Reason = "schema_unverified"
		return report, ErrIncomplete
	}
	if err := installedNormalizer(ctx, tx, candidate); err != nil {
		report.Reason = "candidate_uninstalled_or_mismatched"
		return report, ErrIncomplete
	}
	q := db.New(tx)
	active, err := q.GetUsernamePolicy(ctx)
	if err != nil {
		report.Reason = "authority_unavailable"
		return report, ErrIncomplete
	}
	store := &Store{database: database, cipher: cipher, normalizer: current}
	var authority GuardAuthority
	if active.AdmissionState != "uninstalled" {
		authority, err = store.checkAuthority(ctx, tx, active)
		if err != nil {
			report.Reason = "current_authority_mismatch"
			return report, ErrIncomplete
		}
	} else if !active.Guard || active.Epoch != 0 || active.PolicyID.Valid || active.KeyID != nil {
		report.Reason = "current_authority_inconsistent"
		return report, ErrIncomplete
	}
	artifacts, err := q.ListUsernameArtifacts(ctx)
	if err != nil {
		report.Reason = "artifact_scan_failed"
		return report, ErrIncomplete
	}
	if len(artifacts) > 1000 {
		report.Reason = "artifact_limit"
		return report, ErrIncomplete
	}
	known := make(map[uuid.UUID]bool, len(artifacts))
	for _, row := range artifacts {
		policy, err := decodeStoredArtifact(row)
		if err != nil || ValidateNoSplit(policy, candidate.Policy()) != nil {
			report.PolicyErrors++
			report.addIssue(options.MaxIssues, "invalid_policy_or_equivalence_split", reference(reviewKey, "policy", row.PolicyID.String()))
			continue
		}
		known[row.PolicyID] = true
	}
	// The finite reviewed model permits exactly the initial four folds. The
	// normalizer rejects extra mergers even when a scan has no affected rows.
	if ValidateNoSplit(current.Policy(), candidate.Policy()) != nil {
		report.PolicyErrors++
		report.addIssue(options.MaxIssues, "equivalence_split")
	}
	owners := make(map[[32]byte]string)
	for i, name := range candidate.Policy().ReservedNames {
		value, err := candidate.NormalizeLookup(name)
		if err != nil {
			report.PolicyErrors++
			report.addIssue(options.MaxIssues, "invalid_reserved_name")
			continue
		}
		key := value.Key()
		ref := reference(reviewKey, "reserved", strconv.Itoa(i))
		report.ReservedNames++
		if old, ok := owners[key]; ok {
			report.Collisions++
			report.addIssue(options.MaxIssues, "reserved_collision", old, ref)
		} else {
			owners[key] = ref
		}
	}
	after := uuid.Nil
	first := true
	for {
		// Fetch one row past the total ceiling to distinguish exact completion
		// from a truncated inventory without misclassifying a clean prefix.
		pageSize := options.PageSize
		remaining := options.MaxRows - report.Scanned
		if int64(pageSize) > remaining+1 {
			pageSize = int32(remaining + 1)
		}
		rows, err := q.ScanUsernameInventory(ctx, db.ScanUsernameInventoryParams{AfterID: after, PageSize: pageSize, FirstPage: first})
		if err != nil {
			report.Reason = "account_scan_failed"
			return report, ErrIncomplete
		}
		first = false
		if len(rows) == 0 {
			break
		}
		for _, inventory := range rows {
			if report.Scanned == options.MaxRows {
				report.Reason = "row_limit"
				return report, ErrIncomplete
			}
			report.Scanned++
			after = inventory.ID
			row := db.ReadUsernameRow(inventory)
			ref := reference(reviewKey, "account", row.ID.String())
			if row.UsernameKey == nil {
				if nullStorageTuple(row) && row.ID != uuid.Nil {
					report.Unclaimed++
				} else {
					report.Inconsistent++
					report.addIssue(options.MaxIssues, "inconsistent_tuple", ref)
				}
				continue
			}
			report.Claimed++
			if !row.UsernamePolicyID.Valid || !known[row.UsernamePolicyID.UUID] {
				report.PolicyErrors++
				report.addIssue(options.MaxIssues, "unknown_policy", ref)
				continue
			}
			if active.AdmissionState == "uninstalled" {
				report.Inconsistent++
				report.addIssue(options.MaxIssues, "claimed_without_authority", ref)
				continue
			}
			value, err := store.openStorage(ctx, row, authority)
			if err != nil {
				report.Unreadable++
				report.addIssue(options.MaxIssues, "unreadable_or_binding_mismatch", ref)
				continue
			}
			proposed, err := candidate.NormalizeLookup(value.Display())
			if err != nil {
				report.Inconsistent++
				report.addIssue(options.MaxIssues, "candidate_normalization_failed", ref)
				continue
			}
			key := proposed.Key()
			if old, ok := owners[key]; ok {
				report.Collisions++
				report.addIssue(options.MaxIssues, "namespace_collision", old, ref)
			} else {
				owners[key] = ref
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		report.Reason = "snapshot_finish_failed"
		return report, ErrIncomplete
	}
	report.Complete = true
	report.Clean = report.Collisions == 0 && report.Unreadable == 0 && report.Inconsistent == 0 && report.PolicyErrors == 0
	if !report.Clean {
		report.Reason = "review_required"
	}
	return report, nil
}

func reference(key []byte, kind, value string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("hatef.identity.username.review\x00" + kind + "\x00" + value))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

func (r *PreflightReport) addIssue(max int, kind string, refs ...string) {
	if len(r.Issues) >= max {
		r.IssuesTruncated = true
		return
	}
	if refs == nil {
		refs = []string{}
	}
	r.Issues = append(r.Issues, ReviewIssue{Kind: kind, References: refs})
}
