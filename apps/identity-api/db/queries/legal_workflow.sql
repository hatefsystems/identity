-- These primitives share the caller's adminaction transaction. Account locks
-- precede workflow row locks; services revalidate the discovered lock set.

-- name: GetLegalWorkflowCase :one
SELECT * FROM legal_cases WHERE id=$1;

-- name: LockLegalWorkflowCase :one
SELECT * FROM legal_cases WHERE id=$1 FOR UPDATE;

-- name: GetLegalWorkflowReplay :one
SELECT * FROM legal_workflow_replays WHERE operation=$1 AND scope=$2 AND idempotency_key=$3;

-- name: GetLegalWorkflowEvent :one
SELECT * FROM legal_workflow_events WHERE id=$1;

-- name: ListLegalWorkflowSubjects :many
SELECT account_ref,current FROM legal_case_subjects WHERE case_id=$1 ORDER BY account_ref;

-- name: LegalWorkflowCaseHeld :one
SELECT EXISTS(SELECT 1 FROM legal_case_subjects s JOIN legal_holds h ON h.account_ref=s.account_ref
    WHERE s.case_id=$1 AND h.is_active)::boolean AS held;

-- name: ListLegalWorkflowHistory :many
SELECT * FROM legal_workflow_events WHERE scope_kind=$1 AND scope=$2
ORDER BY revision DESC LIMIT $3;
