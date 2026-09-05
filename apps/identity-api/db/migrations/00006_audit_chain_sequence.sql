-- Task 5.2: monotonic chain position for both cryptographic ledgers.
--
-- Both mvp_audit_logs and security_event_ledger are chained by
--   chain_hash(N) = SHA-256(chain_hash(N-1) || serialize(record(N)))
-- which is only verifiable if the reader can reconstruct the exact order in
-- which the single-threaded signing consumer assigned positions.
--
-- Before this migration that order was (timestamp, id). Neither column can
-- carry it:
--   * timestamp is the event's occurrence time, stamped by whichever API replica
--     observed it. Clock skew between replicas, JetStream redelivery, and
--     batching all make it non-monotonic in consumption order.
--   * id is a random UUID (and, from Task 5.2 on, a publisher-assigned event id
--     used for deduplication), so it cannot break a timestamp tie meaningfully.
-- A verifier walking (timestamp, id) would therefore hash the records in a
-- different order than the chain was built in and report tampering on correct
-- data.
--
-- seq fixes that: the sequence is advanced by the one process holding the
-- audit-signer advisory lock, so seq order IS chain order, permanently.
-- timestamp keeps its real meaning (when the event happened), which is what the
-- DPO time-range queries in api-design.md §1.7 need even when the pipeline is
-- running behind.
--
-- seq GAPS ARE NOT TAMPERING. An identity sequence is not transactional: a
-- rolled-back batch consumes values and leaves a hole. Detecting removed rows is
-- the chain's job -- deleting record N invalidates the stored chain_hash of
-- N+1 -- so verification must use seq strictly for ordering and must never
-- treat a gap as evidence.
--
-- Safe to apply: nothing has ever written a chain_hash (Task 5.1's LogRecorder
-- only emits slog lines), so both tables are empty in every environment. The
-- backfill performed by ADD COLUMN is a table rewrite, which does not fire the
-- append-only row triggers installed by 00001/00002.

-- +goose Up

-- GENERATED ALWAYS forbids a client from supplying seq, so the sequence remains
-- the exclusive authority on chain position even if a future caller tries to
-- insert one. Note that the :copyfrom batch writers omit the column entirely.
--
-- NOT NULL is spelled out even though GENERATED ALWAYS AS IDENTITY already
-- implies it in PostgreSQL. It is redundant to the database and load-bearing to
-- the code generator: sqlc parses these files as its schema source and does not
-- derive non-nullability from the identity clause, so without it seq is generated
-- as *int64. That would push a pointer dereference into every chain-verification
-- comparison for a column that can never be NULL.
ALTER TABLE mvp_audit_logs
    ADD COLUMN seq BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL;

-- UNIQUE gives the btree index that serves both access patterns:
--   ORDER BY seq DESC LIMIT 1   (seed the next chain hash)
--   WHERE seq > $1 ORDER BY seq (keyset scan for chain verification)
ALTER TABLE mvp_audit_logs
    ADD CONSTRAINT mvp_audit_logs_seq_key UNIQUE (seq);

ALTER TABLE security_event_ledger
    ADD COLUMN seq BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL;

ALTER TABLE security_event_ledger
    ADD CONSTRAINT security_event_ledger_seq_key UNIQUE (seq);

-- +goose Down

ALTER TABLE security_event_ledger DROP CONSTRAINT security_event_ledger_seq_key;
ALTER TABLE security_event_ledger DROP COLUMN seq;

ALTER TABLE mvp_audit_logs DROP CONSTRAINT mvp_audit_logs_seq_key;
ALTER TABLE mvp_audit_logs DROP COLUMN seq;
