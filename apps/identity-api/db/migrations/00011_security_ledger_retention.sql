-- +goose Up
-- Additive and disabled until an operator has verified history, initialized the
-- head/settings, and provisioned the non-login function owner and exact grants.
-- Neither applying this migration nor an empty payload table implies genesis.
CREATE TABLE public.security_ledger_head (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    seq bigint NOT NULL CHECK (seq >= 0),
    chain_hash text NOT NULL CHECK (chain_hash ~ '^[0-9a-f]{64}$'),
    CHECK (seq <> 0 OR chain_hash = repeat('0', 64))
);

CREATE TABLE public.security_ledger_checkpoints (
    first_seq bigint PRIMARY KEY CHECK (first_seq > 0),
    last_seq bigint NOT NULL UNIQUE CHECK (last_seq >= first_seq AND last_seq < 9223372036854775807),
    predecessor_seq bigint NOT NULL UNIQUE CHECK (predecessor_seq >= 0 AND predecessor_seq < first_seq),
    predecessor_hash text NOT NULL CHECK (predecessor_hash ~ '^[0-9a-f]{64}$'),
    terminal_hash text NOT NULL CHECK (terminal_hash ~ '^[0-9a-f]{64}$'),
    erased_count bigint NOT NULL CHECK (erased_count > 0 AND erased_count <= last_seq - first_seq + 1),
    CHECK (predecessor_seq <> 0 OR predecessor_hash = repeat('0', 64)),
    EXCLUDE USING gist (int8range(first_seq, last_seq, '[]') WITH &&)
);

CREATE TABLE public.security_ledger_retention_settings (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    audit_subject text NOT NULL CHECK (
        octet_length(audit_subject) BETWEEN 1 AND 100
        AND audit_subject ~ '^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$'
        AND audit_subject <> 'identity.user.deleted'
    )
);

CREATE INDEX idx_security_ledger_retention_seq ON public.security_event_ledger(retain_until, seq);
REVOKE ALL ON public.security_ledger_head, public.security_ledger_checkpoints,
    public.security_ledger_retention_settings FROM PUBLIC;

-- Invoker context is intentional. SECURITY DEFINER here would authorize every
-- caller as the trigger owner. A caller-controlled GUC is never an exemption.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.security_event_ledger_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' AND current_user = 'identity_ledger_maintenance_owner'
       AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = current_user
                   AND NOT rolcanlogin AND NOT rolsuper AND NOT rolcreaterole
                   AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'security_event_ledger is append-only: % is not permitted', TG_OP USING ERRCODE = '42501';
END;
$$;
-- +goose StatementEnd

-- Go audit.FormatChainTime parity: UTC RFC3339Nano, persisted microseconds,
-- no trailing fractional zeroes. Non-finite/out-of-range historical values fail
-- closed rather than being silently rewritten into a different signed body.
-- +goose StatementBegin
CREATE FUNCTION public.security_ledger_chain_time(value timestamptz) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    utc timestamp := value AT TIME ZONE 'UTC';
    fraction text;
BEGIN
    IF NOT isfinite(value) OR extract(year FROM utc) NOT BETWEEN 1 AND 9999 THEN
        RAISE EXCEPTION 'unsupported ledger timestamp' USING ERRCODE = '22023';
    END IF;
    fraction := rtrim(to_char(utc, 'US'), '0');
    RETURN to_char(utc, 'YYYY-MM-DD"T"HH24:MI:SS')
        || CASE WHEN fraction = '' THEN '' ELSE '.' || fraction END || 'Z';
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.security_ledger_canonical_body(value public.security_event_ledger) RETURNS bytea
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    fields text[] := ARRAY[value.id::text, value.account_ref::text, value.identity_blind_index,
        value.event_type, value.client_ip, value.ip_subnet, value.user_agent,
        value.device_fingerprint, value.client_id, value.scope,
        public.security_ledger_chain_time(value.timestamp), public.security_ledger_chain_time(value.retain_until)];
    body bytea := convert_to('hatef.ledger.v1', 'UTF8') || decode('00', 'hex');
    field bytea;
    i integer;
BEGIN
    FOR i IN 1..12 LOOP
        IF i = 3 OR i BETWEEN 5 AND 10 THEN
            body := body || CASE WHEN fields[i] IS NULL THEN decode('00', 'hex') ELSE decode('01', 'hex') END;
        END IF;
        IF fields[i] IS NOT NULL THEN
            field := convert_to(fields[i], 'UTF8');
            body := body || int4send(octet_length(field)) || field;
        END IF;
    END LOOP;
    RETURN body;
END;
$$;
-- +goose StatementEnd

-- Exactly pglock.LockAccount's domain-separated negative int64 keyspace.
-- +goose StatementBegin
CREATE FUNCTION public.security_ledger_account_lock_key(account uuid) RETURNS bigint
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
    SELECT -(('x' || substr(encode(sha256(convert_to('identity:account-lock:v1:', 'UTF8')
        || uuid_send(account)), 'hex'), 1, 16))::bit(64)::bigint & 9223372036854775807) - 1
$$;
-- +goose StatementEnd

-- Each branch uses a boundary index. Sequence allocation holes are legitimate;
-- the preceding committed node, never numeric seq-1, defines chain adjacency.
-- +goose StatementBegin
CREATE FUNCTION public.security_ledger_predecessor(before_seq bigint)
RETURNS TABLE(seq bigint, chain_hash text)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT node.seq, node.chain_hash FROM (
        (SELECT l.seq, l.chain_hash::text FROM public.security_event_ledger l
         WHERE l.seq < before_seq ORDER BY l.seq DESC LIMIT 1)
        UNION ALL
        (SELECT c.last_seq, c.terminal_hash FROM public.security_ledger_checkpoints c
         WHERE c.last_seq < before_seq ORDER BY c.last_seq DESC LIMIT 1)
        UNION ALL SELECT 0::bigint, repeat('0', 64)
    ) node ORDER BY node.seq DESC LIMIT 1
$$;
-- +goose StatementEnd

-- Internal, invoker-context authority check. Transferring a function to a login,
-- superuser or role-admin does not accidentally enable destructive maintenance.
-- +goose StatementBegin
CREATE FUNCTION public.security_ledger_require_owner() RETURNS void
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF current_user <> 'identity_ledger_maintenance_owner'
       OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = current_user
                      AND NOT rolcanlogin AND NOT rolsuper AND NOT rolcreaterole
                      AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls) THEN
        RAISE EXCEPTION 'ledger maintenance is not provisioned' USING ERRCODE = '42501';
    END IF;
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'ledger writes require READ COMMITTED' USING ERRCODE = '25001';
    END IF;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION public.advance_security_ledger_head(expected_seq bigint, terminal_id uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET lock_timeout = '2s' AS $$
DECLARE
    head public.security_ledger_head%ROWTYPE;
    prior record;
    item record;
    previous_hash text;
    last_id uuid;
    last_seq bigint;
BEGIN
    PERFORM public.security_ledger_require_owner();
    PERFORM pg_advisory_xact_lock(5200002::bigint);
    SELECT * INTO STRICT head FROM public.security_ledger_head WHERE singleton FOR UPDATE;
    IF expected_seq IS NULL OR terminal_id IS NULL OR head.seq <> expected_seq THEN
        RAISE EXCEPTION 'ledger head expectation mismatch' USING ERRCODE = '23000';
    END IF;
    SELECT * INTO prior FROM public.security_ledger_predecessor(head.seq + 1);
    IF prior.seq <> head.seq OR prior.chain_hash <> head.chain_hash
       OR EXISTS (SELECT 1 FROM public.security_ledger_checkpoints c WHERE c.last_seq > head.seq) THEN
        RAISE EXCEPTION 'ledger prior head is inconsistent' USING ERRCODE = '23000';
    END IF;
    previous_hash := head.chain_hash;
    FOR item IN SELECT l.*, l.xmin::text AS inserting_xid FROM public.security_event_ledger l
                WHERE l.seq > head.seq ORDER BY l.seq LOOP
        IF item.inserting_xid <> (pg_current_xact_id()::text::numeric % 4294967296)::text THEN
            RAISE EXCEPTION 'ledger advancement includes a previously committed row' USING ERRCODE = '23000';
        END IF;
        IF item.chain_hash <> encode(sha256(decode(previous_hash, 'hex') ||
            public.security_ledger_canonical_body(ROW(item.id, item.account_ref, item.identity_blind_index,
                item.event_type, item.client_ip, item.ip_subnet, item.user_agent, item.device_fingerprint,
                item.client_id, item.scope, item.timestamp, item.retain_until, item.chain_hash,
                item.seq)::public.security_event_ledger)), 'hex') THEN
            RAISE EXCEPTION 'ledger advancement hash mismatch' USING ERRCODE = '23000';
        END IF;
        previous_hash := item.chain_hash;
        last_id := item.id;
        last_seq := item.seq;
    END LOOP;
    IF last_id IS NULL OR last_id <> terminal_id OR last_seq <= head.seq THEN
        RAISE EXCEPTION 'ledger terminal row mismatch' USING ERRCODE = '23000';
    END IF;
    UPDATE public.security_ledger_head SET seq = last_seq, chain_hash = previous_hash WHERE singleton;
END;
$$;
-- +goose StatementEnd

-- Bounded preflight, erasure, neighboring-span compaction and Class C intent are
-- one transaction. The caller can exercise every check by rolling it back.
-- +goose StatementBegin
CREATE FUNCTION public.purge_security_ledger_batch(
    cutoff timestamptz, highwater bigint, seqs bigint[], expected_hashes text[],
    canonical_bodies bytea[], operation_id uuid, audit_subject text
) RETURNS TABLE(deleted_count bigint, held_count bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET lock_timeout = '2s' AS $$
DECLARE
    head public.security_ledger_head%ROWTYPE;
    item public.security_event_ledger%ROWTYPE;
    neighbor public.security_event_ledger%ROWTYPE;
    left_span public.security_ledger_checkpoints%ROWTYPE;
    right_span public.security_ledger_checkpoints%ROWTYPE;
    prior record;
    span_prior record;
    subject uuid;
    position integer;
    eligible bigint[] := ARRAY[]::bigint[];
    first_erased bigint;
    last_erased bigint;
    predecessor_seq bigint;
    predecessor_hash text;
    terminal_hash text;
    erased bigint;
    affected bigint;
    event_type text;
    outcome text;
    receipt_time timestamptz;
    deadline timestamptz := clock_timestamp() + interval '15 seconds';
BEGIN
    PERFORM public.security_ledger_require_owner();
    -- SET statement_timeout inside an already-running function does not start a
    -- statement timer. Require the caller's timer instead of promising a bound
    -- that PostgreSQL cannot enforce; the worker sets it before this statement.
    IF current_setting('statement_timeout')::interval <= interval '0'
       OR current_setting('statement_timeout')::interval > interval '15 seconds' THEN
        RAISE EXCEPTION 'purge requires statement_timeout between 1ms and 15s' USING ERRCODE = '22023';
    END IF;
    IF cutoff IS NULL OR NOT isfinite(cutoff) OR cutoff > statement_timestamp()
       OR highwater IS NULL OR highwater < 0
       OR operation_id IS NULL OR operation_id = '00000000-0000-0000-0000-000000000000'::uuid
       OR cardinality(seqs) IS NULL OR cardinality(seqs) NOT BETWEEN 1 AND 5000
       OR array_ndims(seqs) <> 1 OR array_lower(seqs, 1) <> 1
       OR canonical_bodies IS NULL OR expected_hashes IS NULL
       OR array_ndims(expected_hashes) <> 1 OR array_lower(expected_hashes, 1) <> 1
       OR array_ndims(canonical_bodies) <> 1 OR array_lower(canonical_bodies, 1) <> 1
       OR cardinality(seqs) <> cardinality(expected_hashes)
       OR cardinality(seqs) <> cardinality(canonical_bodies)
       OR EXISTS (SELECT 1 FROM unnest(seqs) n WHERE n IS NULL OR n <= 0 OR n > highwater)
       OR (SELECT count(DISTINCT n) FROM unnest(seqs) n) <> cardinality(seqs)
       OR EXISTS (SELECT 1 FROM unnest(expected_hashes) h WHERE h IS NULL OR h !~ '^[0-9a-f]{64}$')
       OR EXISTS (SELECT 1 FROM unnest(canonical_bodies) b WHERE b IS NULL OR octet_length(b) > 1048576)
       OR (SELECT sum(octet_length(b)) FROM unnest(canonical_bodies) b) > 16777216 THEN
        RAISE EXCEPTION 'invalid bounded purge arguments' USING ERRCODE = '22023';
    END IF;
    IF audit_subject IS NULL OR NOT EXISTS (SELECT 1 FROM public.security_ledger_retention_settings s
                                           WHERE s.singleton AND s.audit_subject = purge_security_ledger_batch.audit_subject) THEN
        RAISE EXCEPTION 'ledger audit subject is not provisioned' USING ERRCODE = '42501';
    END IF;

    PERFORM pg_advisory_xact_lock(5200002::bigint);
    -- No deciding reads share the advisory-lock statement's pre-wait snapshot.
    -- Account locks precede all head/ledger/checkpoint row locks, including for
    -- accounts that have no users row. UUID ordering matches pglock callers.
    FOR subject IN SELECT DISTINCT l.account_ref FROM public.security_event_ledger l
                   WHERE l.seq = ANY(seqs) ORDER BY l.account_ref LOOP
        PERFORM pg_advisory_xact_lock(public.security_ledger_account_lock_key(subject));
        IF clock_timestamp() > deadline THEN
            RAISE EXCEPTION 'ledger purge deadline exceeded' USING ERRCODE = '57014';
        END IF;
    END LOOP;
    SELECT * INTO STRICT head FROM public.security_ledger_head WHERE singleton FOR UPDATE;
    SELECT * INTO prior FROM public.security_ledger_predecessor(9223372036854775807);
    IF highwater > head.seq OR prior.seq <> head.seq OR prior.chain_hash <> head.chain_hash THEN
        RAISE EXCEPTION 'ledger head is inconsistent' USING ERRCODE = '23000';
    END IF;
    PERFORM 1 FROM public.security_event_ledger l WHERE l.seq = ANY(seqs) ORDER BY l.seq FOR UPDATE;
    IF (SELECT count(*) FROM public.security_event_ledger l WHERE l.seq = ANY(seqs)) <> cardinality(seqs) THEN
        RAISE EXCEPTION 'purge candidate no longer exists' USING ERRCODE = '23000';
    END IF;

    deleted_count := 0;
    held_count := 0;
    FOR item IN SELECT * FROM public.security_event_ledger l WHERE l.seq = ANY(seqs) ORDER BY l.seq LOOP
        position := array_position(seqs, item.seq);
        SELECT * INTO prior FROM public.security_ledger_predecessor(item.seq);
        IF item.chain_hash <> expected_hashes[position]
           OR canonical_bodies[position] <> public.security_ledger_canonical_body(item)
           OR item.chain_hash <> encode(sha256(decode(prior.chain_hash, 'hex') || canonical_bodies[position]), 'hex')
           OR EXISTS (SELECT 1 FROM public.security_ledger_checkpoints c
                      WHERE int8range(c.first_seq, c.last_seq, '[]') @> item.seq) THEN
            RAISE EXCEPTION 'ledger purge proof mismatch' USING ERRCODE = '23000';
        END IF;
        -- Validate neighboring certificates before allowing their compaction.
        SELECT * INTO left_span FROM public.security_ledger_checkpoints c WHERE c.last_seq = prior.seq;
        IF FOUND THEN
            SELECT * INTO span_prior FROM public.security_ledger_predecessor(left_span.first_seq);
            IF span_prior.seq <> left_span.predecessor_seq OR span_prior.chain_hash <> left_span.predecessor_hash
               OR EXISTS (SELECT 1 FROM public.security_ledger_checkpoints c WHERE c.last_seq = span_prior.seq)
               OR EXISTS (SELECT 1 FROM public.security_event_ledger l
                          WHERE l.seq BETWEEN left_span.first_seq AND left_span.last_seq) THEN
                RAISE EXCEPTION 'ledger predecessor checkpoint mismatch' USING ERRCODE = '23000';
            END IF;
        END IF;
        SELECT * INTO neighbor FROM public.security_event_ledger l WHERE l.seq > item.seq ORDER BY l.seq LIMIT 1;
        SELECT * INTO right_span FROM public.security_ledger_checkpoints c WHERE c.first_seq > item.seq ORDER BY c.first_seq LIMIT 1;
        IF right_span.first_seq IS NOT NULL AND (neighbor.seq IS NULL OR right_span.first_seq < neighbor.seq) THEN
            IF right_span.predecessor_seq <> item.seq OR right_span.predecessor_hash <> item.chain_hash
               OR EXISTS (SELECT 1 FROM public.security_ledger_checkpoints c WHERE c.predecessor_seq = right_span.last_seq)
               OR EXISTS (SELECT 1 FROM public.security_event_ledger l
                          WHERE l.seq BETWEEN right_span.first_seq AND right_span.last_seq) THEN
                RAISE EXCEPTION 'ledger successor checkpoint mismatch' USING ERRCODE = '23000';
            END IF;
        ELSIF neighbor.seq IS NOT NULL AND neighbor.chain_hash <>
            encode(sha256(decode(item.chain_hash, 'hex') || public.security_ledger_canonical_body(neighbor)), 'hex') THEN
            RAISE EXCEPTION 'ledger successor hash mismatch' USING ERRCODE = '23000';
        END IF;
        IF EXISTS (SELECT 1 FROM public.legal_holds h WHERE h.account_ref = item.account_ref AND h.is_active) THEN
            held_count := held_count + 1;
        ELSIF item.retain_until < cutoff THEN
            eligible := array_append(eligible, item.seq);
        END IF;
    END LOOP;

    -- At most two existing spans can neighbor each removed row in maximal
    -- state. Work/storage therefore scale with this batch, not historical size.
    FOR item IN SELECT * FROM public.security_event_ledger l WHERE l.seq = ANY(eligible) ORDER BY l.seq LOOP
        SELECT * INTO prior FROM public.security_ledger_predecessor(item.seq);
        SELECT * INTO left_span FROM public.security_ledger_checkpoints c WHERE c.last_seq = prior.seq;
        SELECT * INTO right_span FROM public.security_ledger_checkpoints c
            WHERE c.predecessor_seq = item.seq AND c.first_seq > item.seq;
        first_erased := item.seq;
        last_erased := item.seq;
        predecessor_seq := prior.seq;
        predecessor_hash := prior.chain_hash;
        terminal_hash := item.chain_hash;
        erased := 1;
        IF left_span.first_seq IS NOT NULL THEN
            first_erased := left_span.first_seq;
            predecessor_seq := left_span.predecessor_seq;
            predecessor_hash := left_span.predecessor_hash;
            erased := erased + left_span.erased_count;
            DELETE FROM public.security_ledger_checkpoints c WHERE c.first_seq = left_span.first_seq;
        END IF;
        IF right_span.first_seq IS NOT NULL THEN
            last_erased := right_span.last_seq;
            terminal_hash := right_span.terminal_hash;
            erased := erased + right_span.erased_count;
            DELETE FROM public.security_ledger_checkpoints c WHERE c.first_seq = right_span.first_seq;
        END IF;
        DELETE FROM public.security_event_ledger l WHERE l.seq = item.seq AND l.retain_until < cutoff
            AND l.seq <= highwater AND NOT EXISTS (
                SELECT 1 FROM public.legal_holds h WHERE h.account_ref = l.account_ref AND h.is_active);
        GET DIAGNOSTICS affected = ROW_COUNT;
        IF affected <> 1 OR EXISTS (SELECT 1 FROM public.security_event_ledger l WHERE l.seq BETWEEN first_erased AND last_erased) THEN
            RAISE EXCEPTION 'ledger purge eligibility changed' USING ERRCODE = '23000';
        END IF;
        INSERT INTO public.security_ledger_checkpoints(first_seq, last_seq, predecessor_seq, predecessor_hash, terminal_hash, erased_count)
            VALUES (first_erased, last_erased, predecessor_seq, predecessor_hash, terminal_hash, erased);
        deleted_count := deleted_count + 1;
        IF clock_timestamp() > deadline THEN
            RAISE EXCEPTION 'ledger purge deadline exceeded' USING ERRCODE = '57014';
        END IF;
    END LOOP;

    receipt_time := clock_timestamp();
    event_type := CASE WHEN deleted_count > 0 THEN 'legal.ledger.purged' ELSE 'legal.ledger.purge_skipped' END;
    outcome := CASE WHEN deleted_count > 0 THEN 'purged' WHEN held_count > 0 THEN 'held' ELSE 'ineligible' END;
    INSERT INTO public.event_outbox(id, subject, payload, created_at, next_attempt_at, admin_action)
    VALUES (operation_id, audit_subject, jsonb_build_object(
        'event_id', operation_id, 'schema_version', 1,
        'occurred_at', public.security_ledger_chain_time(receipt_time),
        'event_type', event_type, 'action_status', 'success',
        'actor_id', '00000000-0000-0000-0000-000000000000',
        'actor_spiffe_id', 'system://identity/security-ledger-purge',
        'client_ip', '', 'user_agent', '',
        'payload', jsonb_build_object('operation_id', operation_id,
            'cutoff', public.security_ledger_chain_time(cutoff), 'considered_count', cardinality(seqs),
            'deleted_count', deleted_count, 'held_count', held_count, 'dry_run', false, 'outcome', outcome)::text
    )::text, receipt_time, receipt_time, true);
    RETURN NEXT;
END;
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION public.security_event_ledger_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.security_ledger_chain_time(timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.security_ledger_canonical_body(public.security_event_ledger) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.security_ledger_account_lock_key(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.security_ledger_predecessor(bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.security_ledger_require_owner() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.advance_security_ledger_head(bigint, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.purge_security_ledger_batch(timestamptz, bigint, bigint[], text[], bytea[], uuid, text) FROM PUBLIC;

-- +goose Down
-- Even an apparently empty ledger may already have erased payloads. Never drop
-- its only surviving proof, or enable a signer that can restart at genesis.
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION 'security ledger retention is forward-only; revoke purge EXECUTE and preserve head/checkpoints';
END $$;
-- +goose StatementEnd
