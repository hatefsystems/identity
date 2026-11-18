-- name: PutContactVerificationEvidence :exec
-- The verified destination write and this protected proof share an account-locked tx.
INSERT INTO contact_verification_evidence (user_id, channel, evidence_encrypted)
VALUES ($1, $2, $3)
ON CONFLICT (user_id, channel) DO UPDATE SET evidence_encrypted = EXCLUDED.evidence_encrypted;

-- name: GetCurrentContactEvidence :one
-- Evidence and the current contact are read from one statement snapshot.
SELECT u.id, u.email, u.phone_encrypted, e.evidence_encrypted
FROM users u
LEFT JOIN contact_verification_evidence e ON e.user_id = u.id AND e.channel = sqlc.arg('channel')::text
WHERE u.id = sqlc.arg('user_id')::uuid AND u.deleted_at IS NULL;
