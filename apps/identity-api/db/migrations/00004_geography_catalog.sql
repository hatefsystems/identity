-- +goose Up
CREATE TABLE public.geography_catalogs (
    revision BIGINT PRIMARY KEY CHECK (revision > 0),
    country TEXT NOT NULL CHECK (country = 'IR'),
    source_release TEXT NOT NULL CHECK (octet_length(source_release) BETWEEN 1 AND 256),
    cities_sha256 BYTEA NOT NULL CHECK (octet_length(cities_sha256) = 32),
    types_sha256 BYTEA NOT NULL CHECK (octet_length(types_sha256) = 32),
    cities_bytes BIGINT NOT NULL CHECK (cities_bytes BETWEEN 1 AND 67108864),
    types_bytes BIGINT NOT NULL CHECK (types_bytes BETWEEN 1 AND 65536),
    place_count INTEGER NOT NULL CHECK (place_count BETWEEN 1 AND 250000),
    type_count INTEGER NOT NULL CHECK (type_count BETWEEN 1 AND 64),
    province_count INTEGER NOT NULL CHECK (province_count BETWEEN 1 AND 250000),
    importer_version TEXT NOT NULL,
    normalization_version TEXT NOT NULL,
    imported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    writing_tx XID8 NOT NULL DEFAULT pg_current_xact_id()
);
CREATE TABLE public.geography_types (
    revision BIGINT NOT NULL REFERENCES public.geography_catalogs(revision),
    id BIGINT NOT NULL CHECK (id > 0),
    label TEXT NOT NULL CHECK (char_length(label) BETWEEN 1 AND 256 AND octet_length(label) <= 1024),
    PRIMARY KEY (revision, id)
);
CREATE TABLE public.geography_places (
    id BIGINT PRIMARY KEY CHECK (id > 0),
    first_seen_revision BIGINT NOT NULL REFERENCES public.geography_catalogs(revision),
    last_seen_revision BIGINT NOT NULL REFERENCES public.geography_catalogs(revision),
    CHECK (last_seen_revision >= first_seen_revision)
);
CREATE TABLE public.geography_place_versions (
    revision BIGINT NOT NULL REFERENCES public.geography_catalogs(revision),
    id BIGINT NOT NULL REFERENCES public.geography_places(id),
    label TEXT NOT NULL CHECK (char_length(label) BETWEEN 1 AND 256 AND octet_length(label) <= 1024),
    type_id BIGINT NOT NULL,
    parent_id BIGINT,
    province_id BIGINT NOT NULL,
    search_label TEXT COLLATE "C" NOT NULL,
    PRIMARY KEY (revision, id),
    FOREIGN KEY (revision, type_id) REFERENCES public.geography_types(revision, id),
    FOREIGN KEY (revision, parent_id) REFERENCES public.geography_place_versions(revision, id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (revision, province_id) REFERENCES public.geography_place_versions(revision, id) DEFERRABLE INITIALLY DEFERRED,
    CHECK (parent_id IS DISTINCT FROM id),
    CHECK ((type_id = 2 AND parent_id IS NULL AND province_id = id)
        OR (type_id <> 2 AND parent_id IS NOT NULL AND province_id <> id))
);
CREATE INDEX idx_geography_provinces ON public.geography_place_versions(revision, search_label COLLATE "C", id) WHERE type_id = 2;
CREATE INDEX idx_geography_localities ON public.geography_place_versions(revision, province_id, search_label COLLATE "C", id) WHERE type_id IN (5, 7);
CREATE TABLE public.geography_catalog_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    active_revision BIGINT REFERENCES public.geography_catalogs(revision)
);
INSERT INTO public.geography_catalog_state(singleton) VALUES (TRUE);

-- No roles are provisioned here. Reader gets SELECT on the five tables.
-- Importer additionally gets INSERT on catalogs (excluding writing_tx/imported_at),
-- types, places and versions; UPDATE(last_seen_revision) on places and
-- UPDATE(active_revision) on state. No DELETE, TRUNCATE, DDL or account grants.
-- Lock order: shared MigrationKey, exclusive GeographyImportKey, state row.
-- Migrators take exclusive MigrationKey before every worker exclusion.
-- +goose StatementBegin
CREATE FUNCTION public.geography_catalog_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
    catalog public.geography_catalogs%ROWTYPE;
    target BIGINT;
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'geography history is immutable' USING ERRCODE = '23514';
    END IF;
    IF TG_TABLE_NAME = 'geography_catalogs' THEN
        IF TG_OP = 'UPDATE' THEN
            RAISE EXCEPTION 'geography snapshot is immutable' USING ERRCODE = '23514';
        END IF;
        NEW.writing_tx := pg_current_xact_id();
        RETURN NEW;
    ELSIF TG_TABLE_NAME IN ('geography_types', 'geography_place_versions') THEN
        IF TG_OP = 'UPDATE' THEN
            RAISE EXCEPTION 'geography snapshot is immutable' USING ERRCODE = '23514';
        END IF;
        target := NEW.revision;
    ELSIF TG_TABLE_NAME = 'geography_places' THEN
        IF TG_OP = 'UPDATE' AND (ROW(NEW.id, NEW.first_seen_revision) IS DISTINCT FROM ROW(OLD.id, OLD.first_seen_revision)
            OR NEW.last_seen_revision <= OLD.last_seen_revision) THEN
            RAISE EXCEPTION 'geography identity is immutable' USING ERRCODE = '23514';
        END IF;
        IF TG_OP = 'INSERT' AND NEW.first_seen_revision <> NEW.last_seen_revision THEN
            RAISE EXCEPTION 'geography identity must start in one snapshot' USING ERRCODE = '23514';
        END IF;
        target := NEW.last_seen_revision;
    ELSE
        IF TG_OP <> 'UPDATE' OR NEW.singleton IS DISTINCT FROM OLD.singleton OR NEW.active_revision IS NULL THEN
            RAISE EXCEPTION 'geography state is permanent' USING ERRCODE = '23514';
        END IF;
        target := NEW.active_revision;
    END IF;
    SELECT * INTO STRICT catalog FROM public.geography_catalogs WHERE revision = target;
    IF catalog.writing_tx <> pg_current_xact_id()
        OR EXISTS(SELECT 1 FROM public.geography_catalog_state WHERE active_revision=target) THEN
        RAISE EXCEPTION 'geography snapshot is closed' USING ERRCODE = '23514';
    END IF;
    IF TG_TABLE_NAME = 'geography_catalog_state' THEN
        IF (SELECT count(*) FROM public.geography_types WHERE revision = target) <> catalog.type_count
            OR (SELECT count(*) FROM public.geography_place_versions WHERE revision = target) <> catalog.place_count
            OR (SELECT count(*) FROM public.geography_place_versions WHERE revision = target AND type_id = 2) <> catalog.province_count
            OR EXISTS (SELECT 1 FROM public.geography_place_versions v
                JOIN public.geography_place_versions p ON p.revision=v.revision AND p.id=v.province_id
                WHERE v.revision=target AND p.type_id<>2)
            OR EXISTS (SELECT 1 FROM public.geography_place_versions v
                JOIN public.geography_place_versions p ON p.revision=v.revision AND p.id=v.parent_id
                WHERE v.revision=target AND v.province_id<>p.province_id) THEN
            RAISE EXCEPTION 'geography snapshot is incomplete' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER geography_catalogs_guard BEFORE INSERT OR UPDATE OR DELETE ON public.geography_catalogs FOR EACH ROW EXECUTE FUNCTION public.geography_catalog_guard();
CREATE TRIGGER geography_types_guard BEFORE INSERT OR UPDATE OR DELETE ON public.geography_types FOR EACH ROW EXECUTE FUNCTION public.geography_catalog_guard();
CREATE TRIGGER geography_places_guard BEFORE INSERT OR UPDATE OR DELETE ON public.geography_places FOR EACH ROW EXECUTE FUNCTION public.geography_catalog_guard();
CREATE TRIGGER geography_versions_guard BEFORE INSERT OR UPDATE OR DELETE ON public.geography_place_versions FOR EACH ROW EXECUTE FUNCTION public.geography_catalog_guard();
CREATE TRIGGER geography_state_guard BEFORE INSERT OR UPDATE OR DELETE ON public.geography_catalog_state FOR EACH ROW EXECUTE FUNCTION public.geography_catalog_guard();
CREATE TRIGGER geography_catalogs_no_truncate BEFORE TRUNCATE ON public.geography_catalogs FOR EACH STATEMENT EXECUTE FUNCTION public.geography_catalog_guard();
CREATE TRIGGER geography_types_no_truncate BEFORE TRUNCATE ON public.geography_types FOR EACH STATEMENT EXECUTE FUNCTION public.geography_catalog_guard();
CREATE TRIGGER geography_places_no_truncate BEFORE TRUNCATE ON public.geography_places FOR EACH STATEMENT EXECUTE FUNCTION public.geography_catalog_guard();
CREATE TRIGGER geography_versions_no_truncate BEFORE TRUNCATE ON public.geography_place_versions FOR EACH STATEMENT EXECUTE FUNCTION public.geography_catalog_guard();
CREATE TRIGGER geography_state_no_truncate BEFORE TRUNCATE ON public.geography_catalog_state FOR EACH STATEMENT EXECUTE FUNCTION public.geography_catalog_guard();
REVOKE ALL ON public.geography_catalogs, public.geography_types, public.geography_places,
    public.geography_place_versions, public.geography_catalog_state FROM PUBLIC;
REVOKE ALL ON FUNCTION public.geography_catalog_guard() FROM PUBLIC;

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION 'geography catalog is forward-only; restore an approved backup instead';
END $$;
-- +goose StatementEnd
