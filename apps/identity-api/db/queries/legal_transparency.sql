-- name: LockLegalTransparencyYear :one
SELECT legal_transparency_lock_year(sqlc.arg(year)::INTEGER)::BIGINT AS data_version;

-- name: CountLegalTransparency :exec
SELECT legal_transparency_count(sqlc.arg(at)::TIMESTAMPTZ,sqlc.arg(category)::TEXT);

-- name: GetLegalTransparencyCoverage :one
SELECT started_at FROM legal_transparency_coverage WHERE singleton;

-- name: GetLegalTransparencyAnnualTotals :one
SELECT COALESCE(sum(received),0)::BIGINT AS received, COALESCE(sum(answered),0)::BIGINT AS answered,
    COALESCE(sum(full_disclosure),0)::BIGINT AS full_disclosure,
    COALESCE(sum(partial_disclosure),0)::BIGINT AS partial_disclosure,
    COALESCE(sum(no_responsive_data),0)::BIGINT AS no_responsive_data,
    COALESCE(sum(refusal),0)::BIGINT AS refusal,
    COALESCE(sum(preservation_acknowledgement),0)::BIGINT AS preservation_acknowledgement
FROM legal_transparency_months WHERE month >= sqlc.arg(start_month)::DATE AND month < sqlc.arg(end_month)::DATE;

-- name: GetLegalTransparencyReport :one
SELECT * FROM legal_transparency_reports WHERE id=$1;

-- name: GetLegalTransparencyReportForUpdate :one
SELECT * FROM legal_transparency_reports WHERE id=$1 FOR UPDATE;

-- name: ListLegalTransparencyMonths :many
SELECT * FROM legal_transparency_months
WHERE month >= sqlc.arg(start_month)::DATE AND month < sqlc.arg(end_month)::DATE ORDER BY month;

-- name: InsertLegalTransparencyReport :exec
INSERT INTO legal_transparency_reports
 (id,version,year,data_version,schema_version,policy_id,payload,digest,status,prepared_by,prepared_auth_version)
VALUES ($1,1,$2,$3,1,$4,$5,$6,'prepared',$7,$8);

-- name: ApproveLegalTransparencyReport :exec
UPDATE legal_transparency_reports SET version=version+1,status='approved',approved_by=$2,
 approved_auth_version=$3,approved_at=clock_timestamp() WHERE id=$1;

-- name: DownloadLegalTransparencyReport :exec
UPDATE legal_transparency_reports SET version=version+1,status='downloaded',downloaded_at=clock_timestamp() WHERE id=$1;

-- name: GetLegalTransparencyReplay :one
SELECT input,result FROM legal_transparency_replays WHERE operation=$1 AND scope=$2 AND idempotency_key=$3;

-- name: InsertLegalTransparencyReplay :exec
INSERT INTO legal_transparency_replays (operation,scope,idempotency_key,input,result) VALUES ($1,$2,$3,$4,$5);
