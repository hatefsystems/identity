-- Case-free counters are permanent aggregate history, not a second case archive.
-- Governance and report provenance remain restricted; no automatic publication.
-- +goose Up
CREATE TABLE legal_transparency_coverage (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    started_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE legal_transparency_years (
    year INTEGER PRIMARY KEY CHECK (year BETWEEN 1 AND 9999),
    data_version BIGINT NOT NULL DEFAULT 0 CHECK (data_version >= 0)
);

CREATE TABLE legal_transparency_months (
    month DATE PRIMARY KEY CHECK (EXTRACT(DAY FROM month) = 1),
    received BIGINT NOT NULL DEFAULT 0 CHECK (received >= 0),
    answered BIGINT NOT NULL DEFAULT 0 CHECK (answered >= 0),
    full_disclosure BIGINT NOT NULL DEFAULT 0 CHECK (full_disclosure >= 0),
    partial_disclosure BIGINT NOT NULL DEFAULT 0 CHECK (partial_disclosure >= 0),
    no_responsive_data BIGINT NOT NULL DEFAULT 0 CHECK (no_responsive_data >= 0),
    refusal BIGINT NOT NULL DEFAULT 0 CHECK (refusal >= 0),
    preservation_acknowledgement BIGINT NOT NULL DEFAULT 0 CHECK (preservation_acknowledgement >= 0),
    CHECK (answered = full_disclosure + partial_disclosure + no_responsive_data + refusal + preservation_acknowledgement)
);

-- All counter writers and snapshot readers acquire this lock BEFORE reading
-- aggregates. Separate statements after the lock use fresh READ COMMITTED views.
-- These functions run with ordinary API privileges, never migration-owner
-- authority. Deployment grants only the required aggregate writes and reads.
-- +goose StatementBegin
CREATE FUNCTION legal_transparency_lock_year(p_year INTEGER) RETURNS BIGINT
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public AS $$
DECLARE result BIGINT;
BEGIN
    IF p_year < 1 OR p_year > 9999 OR p_year IS NULL THEN
        RAISE EXCEPTION 'invalid reporting year';
    END IF;
    INSERT INTO public.legal_transparency_years (year) VALUES (p_year) ON CONFLICT DO NOTHING;
    SELECT data_version INTO STRICT result FROM public.legal_transparency_years WHERE year=p_year FOR UPDATE;
    RETURN result;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION legal_transparency_lock_year(INTEGER) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION legal_transparency_count(p_at TIMESTAMPTZ, p_category TEXT) RETURNS VOID
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public AS $$
DECLARE p_month DATE; p_year INTEGER;
BEGIN
    IF p_at IS NULL OR NOT isfinite(p_at) OR p_at > clock_timestamp() OR p_category IS NULL OR
        p_category NOT IN ('received','full_disclosure','partial_disclosure','no_responsive_data','refusal','preservation_acknowledgement') THEN
        RAISE EXCEPTION 'invalid reporting counter';
    END IF;
    p_month := date_trunc('month',p_at AT TIME ZONE 'UTC')::DATE;
    p_year := EXTRACT(YEAR FROM p_month)::INTEGER;
    PERFORM public.legal_transparency_lock_year(p_year);
    INSERT INTO public.legal_transparency_coverage (started_at) VALUES (clock_timestamp()) ON CONFLICT DO NOTHING;
    UPDATE public.legal_transparency_years SET data_version=data_version+1 WHERE year=p_year;
    INSERT INTO public.legal_transparency_months AS m
        (month,received,answered,full_disclosure,partial_disclosure,no_responsive_data,refusal,preservation_acknowledgement)
    VALUES (p_month, (p_category='received')::INTEGER, (p_category<>'received')::INTEGER,
        (p_category='full_disclosure')::INTEGER, (p_category='partial_disclosure')::INTEGER,
        (p_category='no_responsive_data')::INTEGER, (p_category='refusal')::INTEGER,
        (p_category='preservation_acknowledgement')::INTEGER)
    ON CONFLICT (month) DO UPDATE SET received=m.received+EXCLUDED.received,
        answered=m.answered+EXCLUDED.answered, full_disclosure=m.full_disclosure+EXCLUDED.full_disclosure,
        partial_disclosure=m.partial_disclosure+EXCLUDED.partial_disclosure,
        no_responsive_data=m.no_responsive_data+EXCLUDED.no_responsive_data,
        refusal=m.refusal+EXCLUDED.refusal,
        preservation_acknowledgement=m.preservation_acknowledgement+EXCLUDED.preservation_acknowledgement;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION legal_transparency_count(TIMESTAMPTZ,TEXT) FROM PUBLIC;

CREATE TABLE legal_transparency_reports (
    id UUID PRIMARY KEY,
    version BIGINT NOT NULL CHECK (version > 0),
    year INTEGER NOT NULL REFERENCES legal_transparency_years(year),
    data_version BIGINT NOT NULL CHECK (data_version >= 0),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    policy_id UUID NOT NULL REFERENCES legal_governance_policies(id),
    payload BYTEA NOT NULL CHECK (octet_length(payload) BETWEEN 2 AND 8192),
    digest TEXT NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    status TEXT NOT NULL CHECK (status IN ('prepared','approved','downloaded')),
    prepared_by UUID NOT NULL,
    prepared_auth_version BIGINT NOT NULL CHECK (prepared_auth_version >= 0),
    prepared_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    approved_by UUID,
    approved_auth_version BIGINT,
    approved_at TIMESTAMPTZ,
    downloaded_at TIMESTAMPTZ,
    CHECK (approved_by IS NULL OR approved_by <> prepared_by),
    CHECK ((status='prepared' AND approved_by IS NULL AND approved_auth_version IS NULL AND approved_at IS NULL AND downloaded_at IS NULL)
        OR (status IN ('approved','downloaded') AND approved_by IS NOT NULL AND approved_auth_version >= 0 AND approved_at IS NOT NULL
            AND ((status='approved' AND downloaded_at IS NULL) OR (status='downloaded' AND downloaded_at IS NOT NULL))))
);
CREATE INDEX legal_transparency_reports_year ON legal_transparency_reports(year,data_version);

-- Payload bytes (not JSONB reserialization), digest, policy, source version and
-- preparer cannot change even before approval. A correction needs a new report.
-- +goose StatementBegin
CREATE FUNCTION legal_transparency_report_immutable() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'report history is immutable'; END IF;
    IF ROW(NEW.id,NEW.year,NEW.data_version,NEW.schema_version,NEW.policy_id,NEW.payload,NEW.digest,
        NEW.prepared_by,NEW.prepared_auth_version,NEW.prepared_at)
        IS DISTINCT FROM ROW(OLD.id,OLD.year,OLD.data_version,OLD.schema_version,OLD.policy_id,OLD.payload,OLD.digest,
        OLD.prepared_by,OLD.prepared_auth_version,OLD.prepared_at) THEN
        RAISE EXCEPTION 'report snapshot is immutable';
    END IF;
    IF NEW.version <> OLD.version+1 OR NOT (
        (OLD.status='prepared' AND NEW.status='approved' AND NEW.downloaded_at IS NULL) OR
        (OLD.status='approved' AND NEW.status='downloaded' AND
            ROW(NEW.approved_by,NEW.approved_auth_version,NEW.approved_at) IS NOT DISTINCT FROM
            ROW(OLD.approved_by,OLD.approved_auth_version,OLD.approved_at))) THEN
        RAISE EXCEPTION 'invalid report transition';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER legal_transparency_report_immutable BEFORE UPDATE OR DELETE ON legal_transparency_reports
    FOR EACH ROW EXECUTE FUNCTION legal_transparency_report_immutable();

-- Inputs are bounded aggregate commands only, not case/subject narratives or
-- guessable personal-data hashes. API receives INSERT/SELECT, never UPDATE/DELETE.
CREATE TABLE legal_transparency_replays (
    operation TEXT NOT NULL CHECK (operation IN ('prepare','approve','download')),
    scope TEXT NOT NULL CHECK (length(scope) BETWEEN 1 AND 36),
    idempotency_key UUID NOT NULL,
    input JSONB NOT NULL CHECK (jsonb_typeof(input)='object' AND octet_length(input::TEXT) <= 2048),
    -- Preserve nested artifact bytes; JSONB would reorder/reformat approved JSON.
    result BYTEA NOT NULL CHECK (octet_length(result) BETWEEN 2 AND 16384
        AND jsonb_typeof(convert_from(result,'UTF8')::JSONB)='object'),
    PRIMARY KEY(operation,scope,idempotency_key)
);

REVOKE ALL ON legal_transparency_coverage,legal_transparency_years,legal_transparency_months,
    legal_transparency_reports,legal_transparency_replays FROM PUBLIC;

INSERT INTO permissions(id,description) VALUES
    ('legal.transparency.read','Read restricted aggregate statistics and prepare or download reviewed transparency artifacts.'),
    ('legal.transparency.approve','Approve an exact aggregate transparency artifact prepared by a different DPO.')
ON CONFLICT(id) DO NOTHING;
INSERT INTO role_permissions(role_id,permission_id) VALUES
    ('dpo','legal.transparency.read'),('dpo','legal.transparency.approve')
ON CONFLICT DO NOTHING;

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION 'transparency history is forward-only; disable routes instead';
END $$;
-- +goose StatementEnd
