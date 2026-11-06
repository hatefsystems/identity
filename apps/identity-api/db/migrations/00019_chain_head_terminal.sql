-- Repair head advancement without rewriting any existing node or applied SQL.
-- CREATE OR REPLACE preserves the function owner and existing caller ACLs.
-- +goose Up
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.advance_chain_head(
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
    terminal_seq bigint;
BEGIN
    IF which IS NULL OR which NOT IN ('audit', 'ledger') THEN
        RAISE EXCEPTION 'unknown chain' USING ERRCODE = '22023';
    END IF;
    IF expected_seq IS NULL OR first_seq IS NULL OR last_seq IS NULL OR node_count IS NULL
       OR expected_seq < 0 OR first_seq <= expected_seq OR last_seq < first_seq OR node_count <= 0
       OR node_count > last_seq - first_seq + 1 THEN
        RAISE EXCEPTION 'invalid head advancement span' USING ERRCODE = '22023';
    END IF;

    PERFORM pg_advisory_xact_lock(CASE which WHEN 'audit' THEN 5200004 ELSE 5200002 END::bigint);
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
        terminal_seq := item.seq;
        IF seen = 1 AND item.seq <> first_seq THEN
            RAISE EXCEPTION 'chain advancement does not start at the declared first seq' USING ERRCODE = '23000';
        END IF;
        IF item.seq > last_seq THEN
            RAISE EXCEPTION 'chain advancement exceeds the declared span' USING ERRCODE = '23000';
        END IF;
    END LOOP;
    IF seen <> node_count THEN
        RAISE EXCEPTION 'chain advancement node count mismatch' USING ERRCODE = '23000';
    END IF;
    IF terminal_seq IS DISTINCT FROM last_seq THEN
        RAISE EXCEPTION 'chain advancement terminal does not equal the declared last seq' USING ERRCODE = '23000';
    END IF;
    IF which = 'audit' THEN
        UPDATE public.audit_log_head SET seq = last_seq, chain_hash = previous WHERE singleton;
    ELSE
        UPDATE public.security_ledger_head SET seq = last_seq, chain_hash = previous WHERE singleton;
    END IF;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.advance_chain_head(text, bigint, bigint, bigint, bigint) FROM PUBLIC;

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION 'chain head terminal repair is forward-only';
END $$;
-- +goose StatementEnd
