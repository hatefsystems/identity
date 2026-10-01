-- Stateful credentials retain the version earned by their authentication.
-- auth_epoch orders usernameless challenges against account transitions without
-- relying on clocks shared by API instances. It is not an identity identifier.
-- +goose Up
CREATE SEQUENCE account_auth_epoch_seq AS BIGINT;
ALTER TABLE users ADD COLUMN auth_version BIGINT NOT NULL DEFAULT 0 CHECK (auth_version >= 0);
ALTER TABLE users ADD COLUMN auth_epoch BIGINT NOT NULL DEFAULT 0;

-- +goose StatementBegin
CREATE FUNCTION advance_account_auth_version() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.auth_version < OLD.auth_version THEN
        RAISE EXCEPTION 'account auth version cannot decrease';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status
       OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at
       OR NEW.auth_version IS DISTINCT FROM OLD.auth_version THEN
        IF NEW.auth_version = OLD.auth_version THEN
            NEW.auth_version := OLD.auth_version + 1;
        END IF;
        NEW.auth_epoch := nextval('account_auth_epoch_seq');
    ELSE
        NEW.auth_epoch := OLD.auth_epoch;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER users_advance_auth_version BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION advance_account_auth_version();

-- +goose Down
-- Never erase the durable revocation boundary during rollback. Disable admin
-- routes instead; older issuers must not be redeployed over invalidated state.
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION '00010 is forward-only: account auth versions must be preserved';
END $$;
-- +goose StatementEnd
