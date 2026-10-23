-- +goose Up
-- Synchronization revisions are independent of credential revocation versions.
ALTER TABLE users ADD COLUMN lifecycle_revision BIGINT NOT NULL DEFAULT 0
    CHECK (lifecycle_revision >= 0);

-- No user FK: a terminal event must survive the account it describes.
ALTER TABLE event_outbox
    ADD COLUMN lifecycle_user_id UUID,
    ADD COLUMN lifecycle_revision BIGINT,
    ADD CONSTRAINT event_outbox_lifecycle_metadata CHECK (
        (lifecycle_user_id IS NULL AND lifecycle_revision IS NULL)
        OR (lifecycle_user_id IS NOT NULL AND lifecycle_revision IS NOT NULL
            AND lifecycle_user_id <> '00000000-0000-0000-0000-000000000000'::uuid
            AND lifecycle_revision > 0 AND NOT admin_action
            AND subject IN ('identity.user.created', 'identity.user.updated',
                            'identity.user.suspended', 'identity.user.deleted'))
    );

CREATE UNIQUE INDEX idx_event_outbox_lifecycle_revision
    ON event_outbox(lifecycle_user_id, lifecycle_revision)
    WHERE lifecycle_user_id IS NOT NULL;
CREATE INDEX idx_event_outbox_lifecycle_head
    ON event_outbox(lifecycle_user_id, lifecycle_revision)
    WHERE NOT admin_action AND published_at IS NULL AND lifecycle_user_id IS NOT NULL;
CREATE INDEX idx_event_outbox_lifecycle_pending
    ON event_outbox(next_attempt_at, created_at, id)
    WHERE NOT admin_action AND published_at IS NULL
      AND subject IN ('identity.user.created', 'identity.user.updated',
                      'identity.user.suspended', 'identity.user.deleted');
CREATE INDEX idx_event_outbox_lifecycle_cleanup
    ON event_outbox(published_at, id)
    WHERE NOT admin_action AND published_at IS NOT NULL
      AND subject IN ('identity.user.created', 'identity.user.updated',
                      'identity.user.suspended', 'identity.user.deleted');

-- +goose Down
-- Never erase a revision boundary, including after delivered intent was cleaned.
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION '00016 is forward-only: preserve lifecycle revisions and accepted intent';
END $$;
-- +goose StatementEnd
