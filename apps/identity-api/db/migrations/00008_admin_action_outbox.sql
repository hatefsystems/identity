-- +goose Up
-- The marker is independent of the configurable subject: deletion events must
-- never be drained by the administrative audit publisher, even after a typo.
ALTER TABLE event_outbox
    ADD COLUMN admin_action BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP;

CREATE INDEX idx_event_outbox_admin_pending
    ON event_outbox(subject, next_attempt_at, created_at, id)
    WHERE admin_action AND published_at IS NULL;

-- No users or outbox FK: lawful context can survive the account and delivery.
-- Retention is supplied by approved deployment policy, never a database default.
CREATE TABLE admin_action_contexts (
    action_id UUID PRIMARY KEY,
    account_ref UUID NULL,
    details_encrypted BYTEA NOT NULL CHECK (octet_length(details_encrypted) > 0),
    created_at TIMESTAMPTZ NOT NULL,
    retain_until TIMESTAMPTZ NOT NULL CHECK (retain_until > created_at)
);
CREATE INDEX idx_admin_action_contexts_retention
    ON admin_action_contexts(retain_until, action_id);
CREATE INDEX idx_admin_action_contexts_account
    ON admin_action_contexts(account_ref) WHERE account_ref IS NOT NULL;
REVOKE ALL ON admin_action_contexts FROM PUBLIC;

-- +goose Down
-- Deliberately refuse data-destructive rollback. Disable routes and drain/export
-- according to policy before downgrading; never erase accepted audit intent.
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM admin_action_contexts)
       OR EXISTS (SELECT 1 FROM event_outbox WHERE admin_action) THEN
        RAISE EXCEPTION 'admin action data exists; disable intake and preserve it before downgrade';
    END IF;
END $$;
-- +goose StatementEnd
DROP TABLE admin_action_contexts;
DROP INDEX idx_event_outbox_admin_pending;
ALTER TABLE event_outbox DROP COLUMN next_attempt_at, DROP COLUMN admin_action;
