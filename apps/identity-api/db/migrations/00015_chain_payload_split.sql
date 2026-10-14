-- Canonical format v2: split tamper-evidence from payload.
--
-- Source of truth: docs/compliance-and-data-governance.md §2-3 and §7,
-- internal/audit/chain.go (the single canonical serializer).
--
-- # What changes
--
-- In v1 each record carried its own chain_hash, so erasing a row removed a chain
-- link. Recovering from that required security_ledger_checkpoints (predecessor and
-- terminal digests per erased span, GiST-excluded, compacted on every adjacent
-- erasure), a SECURITY DEFINER purge routine that re-derived bodies in SQL, and
-- therefore a second implementation of the canonical serializer in PL/pgSQL.
--
-- v2 computes the chain over leaf digests held in their own append-only tables:
--
--   leaf_hash(N)  = SHA-256( leaf_prefix  || serialize(record(N)) )
--   chain_hash(N) = SHA-256( chain_prefix || chain_hash(N-1) || leaf_hash(N) )
--
-- The chain tables are never deleted; the payload tables may be erased freely. A
-- retention purge or a GDPR erasure drops a body and leaves every digest in
-- place, so the chain stays complete and verifiable from genesis forever. All of
-- the v1 repair machinery is therefore dead and is dropped here, including the
-- PL/pgSQL serializer — leaving exactly one canonical serializer, in Go.
--
-- # Why this is safe to apply
--
-- Nothing has ever written a production digest: the ledger head has never been
-- bootstrapped (docs/admin-operations.md "Explicit Head and Subject Bootstrap"
-- requires an explicit confirmed_fresh_genesis and forbids inferring genesis from
-- an empty table), and Tasks 5.3/5.4/5.5 remain behind open deployment gates. So
-- both ledgers are empty in every environment. This is the same argument migration
-- 00006 used to add seq, and it is the last point at which the canonical format can
-- change at all: after genesis, UPDATE and DELETE are revoked on the chain tables
-- and no migration can repair a format break.
--
-- # Dedupe key
--
-- event_id moves onto the chain row. v1 could probe the payload table for an
-- already-persisted id because rows were immortal; once payloads are erasable that
-- probe would stop seeing erased ids, and a JetStream redelivery of an old message
-- would append a duplicate. The never-deleted chain row is the only correct home
-- for the idempotency key.

-- +goose Up

-- ---------------------------------------------------------------------------
-- 1. Drop the v1 repair machinery.
-- ---------------------------------------------------------------------------
-- Order matters: the purge routine and the verification helpers reference the
-- checkpoint table and the row type of the old ledger.
DROP FUNCTION IF EXISTS public.purge_security_ledger_batch(timestamptz, bigint, bigint[], text[], bytea[], uuid, text);
DROP FUNCTION IF EXISTS public.advance_security_ledger_head(bigint, uuid);
DROP FUNCTION IF EXISTS public.security_ledger_predecessor(bigint);
DROP FUNCTION IF EXISTS public.security_ledger_canonical_body(public.security_event_ledger);
DROP FUNCTION IF EXISTS public.security_ledger_chain_time(timestamptz);
DROP FUNCTION IF EXISTS public.security_ledger_account_lock_key(uuid);
DROP FUNCTION IF EXISTS public.security_ledger_require_owner();
DROP TABLE IF EXISTS public.security_ledger_checkpoints;
DROP INDEX IF EXISTS idx_security_ledger_retention_seq;

-- The old guards covered tables that are about to be replaced.
DROP TRIGGER IF EXISTS trg_security_event_ledger_no_truncate ON public.security_event_ledger;
DROP TRIGGER IF EXISTS trg_security_event_ledger_append_only ON public.security_event_ledger;
DROP TRIGGER IF EXISTS trg_mvp_audit_logs_no_truncate ON public.mvp_audit_logs;
DROP TRIGGER IF EXISTS trg_mvp_audit_logs_append_only ON public.mvp_audit_logs;

-- ---------------------------------------------------------------------------
-- 2. Chain tables: append-only, never deleted, two digests per record.
-- ---------------------------------------------------------------------------
-- seq is supplied by the signer rather than GENERATED ALWAYS AS IDENTITY. The
-- :copyfrom batch writers cannot read back generated values, so the signer could
-- not build payload rows that reference them. The signer holds the single-writer
-- advisory lock, so it allocates from these sequences itself; that also makes
-- "seq order IS chain order" an explicit property of the writer rather than an
-- emergent one. Sequence gaps remain meaningless: a rolled-back batch consumes
-- values, and a removed node is detected by the chain, never by gap analysis.
--
-- Digests are BYTEA(32), not the v1 CHAR(64) hex. These two columns are the only
-- content of the tables that must be retained forever, so halving them matters.

CREATE SEQUENCE public.audit_log_chain_seq AS BIGINT;
CREATE TABLE public.audit_log_chain (
    seq BIGINT PRIMARY KEY DEFAULT nextval('public.audit_log_chain_seq'),
    event_id UUID NOT NULL UNIQUE,
    leaf_hash BYTEA NOT NULL CHECK (octet_length(leaf_hash) = 32),
    chain_hash BYTEA NOT NULL CHECK (octet_length(chain_hash) = 32)
);
ALTER SEQUENCE public.audit_log_chain_seq OWNED BY public.audit_log_chain.seq;

CREATE SEQUENCE public.security_ledger_chain_seq AS BIGINT;
CREATE TABLE public.security_ledger_chain (
    seq BIGINT PRIMARY KEY DEFAULT nextval('public.security_ledger_chain_seq'),
    event_id UUID NOT NULL UNIQUE,
    leaf_hash BYTEA NOT NULL CHECK (octet_length(leaf_hash) = 32),
    chain_hash BYTEA NOT NULL CHECK (octet_length(chain_hash) = 32)
);
ALTER SEQUENCE public.security_ledger_chain_seq OWNED BY public.security_ledger_chain.seq;

-- ---------------------------------------------------------------------------
-- 3. Payload tables.
-- ---------------------------------------------------------------------------
-- Both are rebuilt rather than altered: every column change needed here (drop
-- chain_hash, drop the uuid primary key in favour of seq, add blind_index_version)
-- is a rewrite anyway, and the tables are empty.
--
-- ON DELETE RESTRICT on the chain reference is deliberate and load-bearing: a
-- payload may be erased, a chain node may never be. Without it a cascade from the
-- chain side would silently become the one deletion path the design forbids.

DROP TABLE public.mvp_audit_logs;
CREATE TABLE public.mvp_audit_logs (
    seq BIGINT PRIMARY KEY REFERENCES public.audit_log_chain(seq) ON DELETE RESTRICT,
    user_id UUID NULL REFERENCES public.users(id) ON DELETE SET NULL,
    actor_id UUID NOT NULL,
    actor_spiffe_id VARCHAR(255) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    action_status VARCHAR(50) NOT NULL,
    client_ip VARCHAR(50) NOT NULL,
    user_agent TEXT NOT NULL,
    payload TEXT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_mvp_audit_logs_event_type ON public.mvp_audit_logs(event_type);
CREATE INDEX idx_mvp_audit_logs_timestamp ON public.mvp_audit_logs(timestamp DESC);
CREATE INDEX idx_mvp_audit_logs_user_id ON public.mvp_audit_logs(user_id) WHERE user_id IS NOT NULL;

DROP TABLE public.security_event_ledger;
CREATE TABLE public.security_event_ledger (
    seq BIGINT PRIMARY KEY REFERENCES public.security_ledger_chain(seq) ON DELETE RESTRICT,
    -- Still no foreign key to users: the stable account_ref must outlive the
    -- account row so an action remains attributable after hard-delete, bounded by
    -- retain_until (compliance-and-data-governance.md §7).
    account_ref UUID NOT NULL,
    identity_blind_index VARCHAR(64) NULL,
    -- The pepper generation that produced identity_blind_index. Hashed into the
    -- signed body unconditionally, including when the index is NULL, so a row's
    -- generation can never be reassigned after the fact. Without this column the
    -- blind-index pepper is unrotatable: the index sits inside a signed,
    -- UPDATE-forbidden row with no way to tell which generation produced it.
    blind_index_version SMALLINT NOT NULL CHECK (blind_index_version >= 0),
    event_type VARCHAR(100) NOT NULL,
    client_ip VARCHAR(50) NULL,
    ip_subnet VARCHAR(50) NULL,
    user_agent TEXT NULL,
    device_fingerprint VARCHAR(128) NULL,
    client_id VARCHAR(100) NULL,
    scope TEXT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retain_until TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE INDEX idx_security_ledger_blind_index ON public.security_event_ledger(identity_blind_index);
CREATE INDEX idx_security_ledger_account_ref ON public.security_event_ledger(account_ref);
CREATE INDEX idx_security_ledger_event_type ON public.security_event_ledger(event_type);
-- Drives the retention worker's candidate scan, which pages by (retain_until, seq).
CREATE INDEX idx_security_ledger_retention ON public.security_event_ledger(retain_until, seq);

-- ---------------------------------------------------------------------------
-- 4. Erasure index.
-- ---------------------------------------------------------------------------
-- Records which spans have had their payloads erased, so a verifier can tell a
-- lawful erasure from a deletion. "Payload absent" alone is not proof of either.
--
-- This is an append-only index, not a chain structure: it has no predecessor or
-- terminal digests, no exclusion constraint, and no compaction, because the chain
-- it annotates is never broken. Its authority comes from the chained receipt event
-- carrying the same operation_id, which the retention worker enqueues in the same
-- transaction as the DELETE.
CREATE TABLE public.security_ledger_erasures (
    first_seq BIGINT NOT NULL CHECK (first_seq > 0),
    last_seq BIGINT NOT NULL CHECK (last_seq >= first_seq),
    operation_id UUID NOT NULL,
    erased_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (first_seq, last_seq)
);
CREATE INDEX idx_security_ledger_erasures_operation ON public.security_ledger_erasures(operation_id);

-- ---------------------------------------------------------------------------
-- 5. Append-only guards.
-- ---------------------------------------------------------------------------
-- Chain tables: nothing may ever be updated, deleted, or truncated. There is no
-- maintenance-role exemption, because v2 has no operation that removes a node.
-- +goose StatementBegin
CREATE FUNCTION public.chain_table_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'chain tables are append-only: % on % is not permitted', TG_OP, TG_TABLE_NAME
        USING ERRCODE = '42501';
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER trg_audit_log_chain_append_only
    BEFORE UPDATE OR DELETE ON public.audit_log_chain
    FOR EACH ROW EXECUTE FUNCTION public.chain_table_guard();
CREATE TRIGGER trg_audit_log_chain_no_truncate
    BEFORE TRUNCATE ON public.audit_log_chain
    FOR EACH STATEMENT EXECUTE FUNCTION public.chain_table_guard();
CREATE TRIGGER trg_security_ledger_chain_append_only
    BEFORE UPDATE OR DELETE ON public.security_ledger_chain
    FOR EACH ROW EXECUTE FUNCTION public.chain_table_guard();
CREATE TRIGGER trg_security_ledger_chain_no_truncate
    BEFORE TRUNCATE ON public.security_ledger_chain
    FOR EACH STATEMENT EXECUTE FUNCTION public.chain_table_guard();

-- Payload tables: immutable, but erasable by the dedicated retention role.
--
-- UPDATE is still rejected for everyone, with the single exception the FK
-- referential action needs (ON DELETE SET NULL nulls mvp_audit_logs.user_id when
-- the GDPR purge removes a user). DELETE is a normal, expected operation for the
-- retention role and is controlled by table privilege rather than by a trigger
-- exemption keyed on current_user — the v1 guard's role-name check inside the
-- trigger duplicated a decision that GRANT already expresses.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.mvp_audit_logs_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.user_id IS NULL
       AND OLD.user_id IS NOT NULL
       AND to_jsonb(NEW) - 'user_id' = to_jsonb(OLD) - 'user_id' THEN
        RETURN NEW; -- FK ON DELETE SET NULL from the users hard-delete purge
    END IF;
    RAISE EXCEPTION 'mvp_audit_logs is immutable: % is not permitted', TG_OP
        USING ERRCODE = '42501';
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER trg_mvp_audit_logs_immutable
    BEFORE UPDATE ON public.mvp_audit_logs
    FOR EACH ROW EXECUTE FUNCTION public.mvp_audit_logs_guard();
CREATE TRIGGER trg_mvp_audit_logs_no_truncate
    BEFORE TRUNCATE ON public.mvp_audit_logs
    FOR EACH STATEMENT EXECUTE FUNCTION public.mvp_audit_logs_guard();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.security_event_ledger_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'security_event_ledger is immutable: % is not permitted', TG_OP
        USING ERRCODE = '42501';
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER trg_security_event_ledger_immutable
    BEFORE UPDATE ON public.security_event_ledger
    FOR EACH ROW EXECUTE FUNCTION public.security_event_ledger_guard();
CREATE TRIGGER trg_security_event_ledger_no_truncate
    BEFORE TRUNCATE ON public.security_event_ledger
    FOR EACH STATEMENT EXECUTE FUNCTION public.security_event_ledger_guard();

-- Erasure index: append-only. Removing an erasure record would turn a lawful
-- erasure back into an unexplained gap.
CREATE TRIGGER trg_security_ledger_erasures_append_only
    BEFORE UPDATE OR DELETE ON public.security_ledger_erasures
    FOR EACH ROW EXECUTE FUNCTION public.chain_table_guard();
CREATE TRIGGER trg_security_ledger_erasures_no_truncate
    BEFORE TRUNCATE ON public.security_ledger_erasures
    FOR EACH STATEMENT EXECUTE FUNCTION public.chain_table_guard();

-- ---------------------------------------------------------------------------
-- 6. Privileges.
-- ---------------------------------------------------------------------------
REVOKE UPDATE, DELETE, TRUNCATE ON public.audit_log_chain FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON public.security_ledger_chain FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON public.security_ledger_erasures FROM PUBLIC;
-- The API and signer roles never erase. DELETE is granted to the dedicated
-- retention role by the operator runbook, not here: this migration must not
-- create or empower a role, only ensure nothing is erasable by default.
REVOKE UPDATE, DELETE, TRUNCATE ON public.mvp_audit_logs FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON public.security_event_ledger FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- 7. Head.
-- ---------------------------------------------------------------------------
-- security_ledger_head keeps its role as the durable, independently readable
-- logical head, but its digest is now binary and its genesis is the derived seed
-- rather than 32 zero bytes. A zeroed or default-initialized column can therefore
-- no longer be mistaken for a legitimate genesis.
--
-- The genesis literals below are duplicated verbatim from
-- internal/audit/chain_golden_test.go. internal/migrate's TestGenesisMatchesMigration
-- asserts the two agree, so a format change cannot silently diverge from the schema.
DROP TABLE IF EXISTS public.security_ledger_head;
CREATE TABLE public.security_ledger_head (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    seq bigint NOT NULL CHECK (seq >= 0),
    chain_hash BYTEA NOT NULL CHECK (octet_length(chain_hash) = 32),
    CHECK (seq <> 0 OR chain_hash = '\x6ece92219999993f2dc5b43d677c333fa6836745079b919355360170f3ea2c54'::bytea)
);
REVOKE ALL ON public.security_ledger_head FROM PUBLIC;

CREATE TABLE public.audit_log_head (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    seq bigint NOT NULL CHECK (seq >= 0),
    chain_hash BYTEA NOT NULL CHECK (octet_length(chain_hash) = 32),
    CHECK (seq <> 0 OR chain_hash = '\x5c358544585235f7ae29b4a8370d5541ddd6bd40c81321fc92bbb54b31887ebb'::bytea)
);
REVOKE ALL ON public.audit_log_head FROM PUBLIC;

-- advance_security_ledger_head verifies that every node appended since the
-- recorded head links correctly, then moves the head forward.
--
-- Two v1 checks are deliberately gone. The canonical-body recomputation is
-- impossible by design now (the body lives in a table the head routine must not
-- depend on, and re-deriving it in SQL is what required the duplicate
-- serializer); linking is verified over leaf digests instead, which is both
-- cheaper and the actual property that matters. The xmin guard is replaced by an
-- explicit expected span: comparing tuple-header xids as text broke silently if
-- the COPY was ever wrapped in a savepoint or a plpgsql EXCEPTION block, because
-- a subtransaction's xid is not the top-level one.
-- +goose StatementBegin
CREATE FUNCTION public.advance_chain_head(
    which text, expected_seq bigint, first_seq bigint, last_seq bigint, node_count bigint
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET lock_timeout = '2s' AS $$
DECLARE
    head_seq bigint;
    head_hash bytea;
    prefix bytea;
    item record;
    previous bytea;
    seen bigint := 0;
BEGIN
    IF which NOT IN ('audit', 'ledger') THEN
        RAISE EXCEPTION 'unknown chain %', which USING ERRCODE = '22023';
    END IF;
    IF expected_seq IS NULL OR first_seq IS NULL OR last_seq IS NULL OR node_count IS NULL
       OR first_seq <= expected_seq OR last_seq < first_seq OR node_count <= 0
       OR node_count > last_seq - first_seq + 1 THEN
        RAISE EXCEPTION 'invalid head advancement span' USING ERRCODE = '22023';
    END IF;

    PERFORM pg_advisory_xact_lock(CASE which WHEN 'audit' THEN 5200003 ELSE 5200002 END::bigint);

    IF which = 'audit' THEN
        SELECT h.seq, h.chain_hash INTO STRICT head_seq, head_hash
            FROM public.audit_log_head h WHERE h.singleton FOR UPDATE;
        prefix := convert_to('hatef.audit.chain.v2', 'UTF8') || '\x00'::bytea;
    ELSE
        SELECT h.seq, h.chain_hash INTO STRICT head_seq, head_hash
            FROM public.security_ledger_head h WHERE h.singleton FOR UPDATE;
        prefix := convert_to('hatef.ledger.chain.v2', 'UTF8') || '\x00'::bytea;
    END IF;

    IF head_seq <> expected_seq THEN
        RAISE EXCEPTION 'chain head expectation mismatch' USING ERRCODE = '23000';
    END IF;

    previous := head_hash;
    -- One branch is always empty because `which` is fixed, but the ordering is
    -- applied to the combined result rather than inside a branch: a per-branch
    -- ORDER BY under UNION ALL is not a guaranteed output order, and chain
    -- verification is only meaningful in seq order.
    FOR item IN
        SELECT nodes.seq, nodes.leaf_hash, nodes.chain_hash FROM (
            SELECT c.seq, c.leaf_hash, c.chain_hash FROM public.audit_log_chain c
            WHERE which = 'audit' AND c.seq > head_seq
            UNION ALL
            SELECT c.seq, c.leaf_hash, c.chain_hash FROM public.security_ledger_chain c
            WHERE which = 'ledger' AND c.seq > head_seq
        ) nodes ORDER BY nodes.seq
    LOOP
        IF item.chain_hash <> sha256(prefix || previous || item.leaf_hash) THEN
            RAISE EXCEPTION 'chain linkage mismatch at seq %', item.seq USING ERRCODE = '23000';
        END IF;
        previous := item.chain_hash;
        seen := seen + 1;
        IF seen = 1 AND item.seq <> first_seq THEN
            RAISE EXCEPTION 'chain advancement does not start at the declared first seq' USING ERRCODE = '23000';
        END IF;
        IF item.seq > last_seq THEN
            RAISE EXCEPTION 'chain advancement exceeds the declared span' USING ERRCODE = '23000';
        END IF;
    END LOOP;

    IF seen <> node_count THEN
        RAISE EXCEPTION 'chain advancement node count mismatch: saw %, declared %', seen, node_count
            USING ERRCODE = '23000';
    END IF;

    IF which = 'audit' THEN
        UPDATE public.audit_log_head SET seq = last_seq, chain_hash = previous WHERE singleton;
    ELSE
        UPDATE public.security_ledger_head SET seq = last_seq, chain_hash = previous WHERE singleton;
    END IF;
END;
$$;
-- +goose StatementEnd
-- Every function introduced or replaced here is closed to PUBLIC.
--
-- The trigger functions are included even though calling one directly only
-- raises its own exception: CREATE FUNCTION grants EXECUTE to PUBLIC by default,
-- so leaving them open contradicts the posture the rest of this schema asserts,
-- and an operator auditing the ACL surface should not have to reason about which
-- openings are harmless. internal/retentiondbintegration asserts this.
REVOKE ALL ON FUNCTION public.advance_chain_head(text, bigint, bigint, bigint, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.chain_table_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.mvp_audit_logs_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.security_event_ledger_guard() FROM PUBLIC;

-- security_ledger_retention_settings is unchanged and keeps gating which subject
-- the retention worker may write receipts to.

-- +goose Down
-- Forward-only, matching 00008 and 00011. Even an apparently empty ledger may
-- already have erased payloads, and the chain tables are the only surviving proof
-- of what was removed. Reverting would also reinstate a format whose digests
-- nothing can recompute.
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION 'canonical format v2 is forward-only; preserve the chain, head and erasure tables';
END $$;
-- +goose StatementEnd
