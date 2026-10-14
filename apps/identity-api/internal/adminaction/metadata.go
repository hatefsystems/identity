package adminaction

import (
	"encoding/hex"
	"encoding/json"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hatefsystems/identity/apps/identity-api/internal/audit"
)

var eventName = regexp.MustCompile(`^(admin|legal)\.[a-z_]+(\.[a-z_]+)*$`)

// IsLegalWorkflowOperation identifies the restricted routes whose response
// bodies must never become permanent content fingerprints in general audit.
func IsLegalWorkflowOperation(operation string) bool {
	switch operation {
	case "POST /api/v1/admin/legal-cases", "GET /api/v1/admin/legal-cases",
		"GET /api/v1/admin/legal-cases/{case_id}",
		"POST /api/v1/admin/legal-cases/{case_id}/revisions",
		"POST /api/v1/admin/legal-cases/{case_id}/reviews",
		"POST /api/v1/admin/legal-cases/{case_id}/close",
		"GET /api/v1/admin/legal-reviews",
		"POST /api/v1/admin/legal-holds/{hold_id}/reviews",
		"POST /api/v1/admin/legal-cases/{case_id}/response",
		"POST /api/v1/admin/legal-cases/{case_id}/response/approve",
		"POST /api/v1/admin/legal-cases/{case_id}/response/delivery",
		"GET /api/v1/admin/legal-transparency/monthly",
		"POST /api/v1/admin/legal-transparency/reports",
		"GET /api/v1/admin/legal-transparency/reports/{report_id}",
		"POST /api/v1/admin/legal-transparency/reports/{report_id}/approve",
		"POST /api/v1/admin/legal-transparency/reports/{report_id}/download":
		return true
	default:
		return false
	}
}

// IsLegalWorkflowPath also covers failures before chi resolves a route template.
// The path selects a privacy policy only; it is never copied into audit metadata.
func IsLegalWorkflowPath(path string) bool {
	for _, prefix := range []string{"/api/v1/admin/legal-cases", "/api/v1/admin/legal-reviews", "/api/v1/admin/legal-transparency"} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return strings.HasPrefix(path, "/api/v1/admin/legal-holds/") && strings.HasSuffix(path, "/reviews")
}

// Unknown keys are discarded, not passed through. Allowed keys also have typed,
// bounded values so a narrative cannot be smuggled through (say) result_count.
func sanitizedEvent(event audit.Event, actionID uuid.UUID) (audit.Event, error) {
	if len(event.EventType) > 100 || !eventName.MatchString(event.EventType) ||
		(event.ActionStatus != audit.StatusSuccess && event.ActionStatus != audit.StatusFailure) {
		return audit.Event{}, ErrInvalidEvent
	}
	payload := map[string]any{"action_id": actionID.String()}
	operation, _ := event.Payload["operation"].(string)
	restricted, _ := event.Payload["workflow_restricted"].(bool)
	workflow := IsLegalWorkflowOperation(operation) || restricted
	for key, value := range event.Payload {
		if workflow {
			switch key {
			case "operation", "http_status", "outcome", "result_count", "total", "limit", "offset", "replayed", "noop":
			default:
				continue
			}
		}
		var clean any
		var valid bool
		switch key {
		case "operation":
			if IsLegalWorkflowOperation(operation) {
				clean, valid = operation, true
				break
			}
			clean, valid = enum(value,
				"GET /api/v1/admin/users", "GET /api/v1/admin/users/{user_id}",
				"POST /api/v1/admin/users/lookup", "PATCH /api/v1/admin/users/{user_id}/status",
				"GET /api/v1/admin/audit-logs", "GET /api/v1/admin/audit-logs/verify", "GET /api/v1/admin/ledger/verify",
				"POST /api/v1/admin/legal-holds", "GET /api/v1/admin/legal-holds", "DELETE /api/v1/admin/legal-holds/{hold_id}",
				"POST /api/v1/admin/preservation-requests", "POST /api/v1/admin/legal-inquiry/lookup",
				"GET /api/v1/admin/*", "POST /api/v1/admin/*", "PATCH /api/v1/admin/*", "DELETE /api/v1/admin/*",
				"PUT /api/v1/admin/*", "HEAD /api/v1/admin/*", "OPTIONS /api/v1/admin/*",
				"TRACE /api/v1/admin/*", "CONNECT /api/v1/admin/*")
		// erased_checked replaced purged_count/purged_spans/proof_steps: canonical
		// format v2 has no erased-span bridging, so the only remaining quantity is
		// how many retained nodes had a lawfully erased payload.
		case "result_count", "total", "limit", "offset", "checked", "after_seq", "through_seq", "first_seq", "last_seq", "broken_at_seq", "next_after_seq", "before_seq", "next_before_seq", "http_status", "high_water_seq", "highwater_seq", "old_auth_version", "new_auth_version", "erased_checked":
			clean, valid = nonnegativeInteger(value)
		case "considered_count", "deleted_count", "held_count", "would_delete":
			var count int64
			count, valid = nonnegativeInteger(value)
			valid = valid && count <= 5000
			clean = count
		case "verified", "complete", "replayed", "noop", "account_present", "ledger_evidence_present", "identifier_present", "has_more", "dry_run":
			clean, valid = value.(bool)
		case "hold_id", "operation_id":
			var id uuid.UUID
			switch v := value.(type) {
			case uuid.UUID:
				id, valid = v, v != uuid.Nil
			case string:
				var err error
				id, err = uuid.Parse(v)
				valid = err == nil && id != uuid.Nil
			}
			clean = id.String()
		case "response_digest", "record_set_digest", "seed_hash", "last_hash":
			v, ok := value.(string)
			b, err := hex.DecodeString(v)
			valid = ok && err == nil && len(b) == 32
			clean = strings.ToLower(v)
		case "start_time", "end_time", "as_of", "observed_at", "cutoff":
			var t time.Time
			switch v := value.(type) {
			case time.Time:
				t, valid = v, !v.IsZero()
			case string:
				var err error
				t, err = time.Parse(time.RFC3339Nano, v)
				valid = err == nil
			}
			clean = t.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
		case "old_status", "new_status", "status_filter":
			clean, valid = enum(value, "active", "suspended", "banned", "pending_verification", "pending_deletion", "all", "released")
		case "chain":
			clean, valid = enum(value, "audit", "ledger", "security", "security_ledger")
		case "method":
			clean, valid = enum(value, "GET", "POST", "PATCH", "DELETE", "PUT", "OPTIONS", "HEAD", "TRACE", "CONNECT")
		case "request_kind":
			clean, valid = enum(value, "legal_hold", "preservation")
		case "role_id":
			clean, valid = enum(value, "super_admin", "moderator", "support", "dpo")
		// checkpoint_boundary is gone with the checkpoint table: in v2 a resumed
		// verification is always seeded from a retained chain node or an
		// operator-supplied digest.
		case "seed_source":
			clean, valid = enum(value, "genesis", "database_predecessor", "supplied_predecessor")
		// The v2 reason set. The checkpoint reasons are gone, and "hash_mismatch"
		// split into the two stages it could previously conflate: chain_mismatch is
		// a broken link, leaf_mismatch is a rewritten payload under an intact link.
		// payload_absent_without_erasure_record is new, and is the distinction v1
		// structurally could not make — an unexplained deletion rather than a
		// lawful erasure.
		case "failure_reason":
			clean, valid = enum(value, "no_stored_records", "predecessor_mismatch", "missing_head", "head_mismatch",
				"chain_mismatch", "leaf_mismatch", "invalid_leaf_hash", "invalid_chain_hash",
				"record_not_serializable", "payload_absent_without_erasure_record")
		// A short stable token, not prose: this value is for alerting and
		// correlation. The human-readable caveat about what a clean result does and
		// does not prove belongs in the HTTP response, where an operator reads it.
		case "verification_scope":
			clean, valid = enum(value, "audit_chain_database_relative", "ledger_chain_database_relative")
		case "outcome":
			clean, valid = enum(value, "success", "failure", "denied", "invalid", "not_found", "conflict", "unavailable", "noop", "replayed", "purged", "held", "ineligible")
		case "fields", "selected_fields":
			var fields []string
			switch v := value.(type) {
			case []string:
				fields = v
			case []any:
				for _, item := range v {
					field, ok := item.(string)
					if !ok {
						return audit.Event{}, ErrInvalidEvent
					}
					fields = append(fields, field)
				}
			default:
				return audit.Event{}, ErrInvalidEvent
			}
			valid = len(fields) <= 32
			for _, field := range fields {
				// "seq" replaced "chain_hash" in a disclosure: the payload row no
				// longer carries a digest, and seq is what an authority needs to
				// request an inclusion proof for a disclosed event.
				_, ok := enum(field, "id", "account_ref", "event_type", "occurred_at", "retain_until", "seq", "client_ip", "ip_subnet", "user_agent", "client_id", "scope", "device_fingerprint", "status", "email", "mfa_enabled", "created_at", "updated_at", "deleted_at", "timestamp", "is_mfa_enabled")
				valid = valid && ok
			}
			clean = append([]string{}, fields...)
		default:
			continue
		}
		if !valid {
			return audit.Event{}, ErrInvalidEvent
		}
		payload[key] = clean
	}
	event.Payload = payload
	event.Security = nil
	if workflow {
		event.ClientIP, event.UserAgent = "", ""
	}
	// The action ID is the general-audit reference; legal target attribution is
	// kept in restricted storage, not in an FK or immutable payload correlation key.
	event.SubjectID = nil
	return event, nil
}

func enum(value any, allowed ...string) (any, bool) {
	v, ok := value.(string)
	if !ok {
		return nil, false
	}
	for _, candidate := range allowed {
		if v == candidate {
			return v, true
		}
	}
	return nil, false
}

func nonnegativeInteger(value any) (int64, bool) {
	if v, ok := value.(json.Number); ok {
		n, err := strconv.ParseInt(string(v), 10, 64)
		return n, err == nil && n >= 0
	}
	v := reflect.ValueOf(value)
	if !v.IsValid() {
		return 0, false
	}
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n := v.Int()
		return n, n >= 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n := v.Uint()
		if n > 1<<63-1 {
			return 0, false
		}
		return int64(n), true
	default:
		return 0, false
	}
}
