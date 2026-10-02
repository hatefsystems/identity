# Admin and Ledger Retention Operations

The implementation remains opt-in. This document describes the current runtime and outstanding release gates; it is not production sign-off. The detailed acceptance matrix is in `.kilo/plans/1789692893214-task-5-3-admin-rbac-legal-holds.md`.

## Enablement

1. Apply additive migrations through `00010` using the migration identity. Inventory existing signed data before rollout; never rewrite hashes to conceal old timestamp defects. Identify an explicit verification boundary if historical segments fail.
2. Deploy account-version-aware issuers on **every** instance and restart old process-local credential stores before moderation is enabled. Ban, suspension, deletion and reactivation advance persistent versions. Old sessions, codes, refresh tokens and step-up grants cannot regain validity. Existing downstream JWTs retain their configured lifetime, at most 10 minutes.
3. Inject the envelope key/version and shared blind-index pepper through the existing secret delivery mechanism. Hold management uses envelope encryption independently of attribution. Without a pepper, SMS OTP and producer-side capture are unavailable; legal attribution stays unmounted without a verified fixture.
4. With intake disabled, run `npm exec -- nx run identity-api:admin-legal -- --operation=backfill` in bounded batches until it reports zero. Each converted row is decrypted and checked before plaintext columns are cleared in the same transaction. Retain a key recovery plan and backups. Check all legacy rows and deployed key versions; startup's crypto probe is not a full inventory of old ciphertexts.
5. Obtain approved numeric `ADMIN_CONTEXT_RETENTION` and `ADMIN_LEGAL_RELEASED_RETENTION` durations and approval for opaque replay tombstones. There are no policy defaults. Schedule `admin-audit-publisher --cleanup-contexts` and `admin-legal --operation=cleanup` with separate maintenance credentials. Both use hold-aware deletion; released holds resume original clocks. Neither command deletes ledger evidence.
6. Run the signer and `admin-audit-publisher` on the same configured audit subject. Publication requires JetStream acknowledgement; delivered metadata is never inferred from an in-memory queue. Signer event-ID deduplication covers redelivery after uncertain acknowledgements. The deletion-event outbox consumer is separate work.
7. Run `npm exec -- nx run identity-api:admin-legal -- --operation=lookup-probe` against the deployed signer. It creates a credential-free synthetic account, publishes a legacy envelope without a producer index, checks the signer's stored index, deletes only that synthetic account, and verifies attribution again. It prints `ADMIN_LOOKUP_FIXTURE_ID`. A timeout leaves the identified synthetic account for diagnosis; rerun/clean it only after resolving the signer. Never substitute a real person's identifier. Inject the printed fixture ID into the API. A missing/mismatched fixture fails startup; omission explicitly disables lookup. Repeat after signer/key deployment changes and keep the existing pepper pinned. This probe is not a chain trust anchor.
8. Configure exact HTTPS `ADMIN_ALLOWED_ORIGINS`, Redis actor/subnet limits and timeouts. Set `ADMIN_ENABLED=true` only after authenticated smoke tests and ingress logging validation. Startup requires DB, Redis, encryption, audit delivery configuration and approved retention. Readiness probes dependencies; missing step-up leaves mutations and attribution unmounted. The Admin UI is not implemented here.

## Operator role provisioning

Use `npm exec -- nx run identity-api:admin-roles -- --user-id=<uuid> --role=<role>`; add `--revoke` for revocation. Roles are `super_admin`, `moderator`, `support`, `dpo`. A grant requires an active account with an enrolled passkey or enabled MFA. Revocation works for inactive targets too. Changes serialize with moderation and commit the encrypted target reference plus durable audit intent in one transaction; retries are audited no-ops.

Run from an authenticated, MFA-protected operator environment with separately scoped `DATABASE_URL`. Its trusted launcher supplies `ADMIN_OPERATOR_ID` and `ADMIN_OPERATOR_SPIFFE_ID` from the authenticated identity. These environment values are **attribution, not authentication**; arbitrary callers must not control the launcher or database credentials. Provisioning approval remains an organizational control. No HTTP route assigns roles, no unaudited one-row bootstrap is documented, and no two-person HTTP workflow is claimed.

## Database privilege separation

Production identities must be non-owner and non-superuser. Migrations and test owners are not runtime accounts. Apply and verify deployment-specific grants before enabling ingress:

| Identity | Required scope | Must not receive |
|---|---|---|
| API | Existing authentication table access; live RBAC SELECT; legal request SELECT/INSERT/UPDATE; restricted context INSERT; admin outbox INSERT; chain/head/checkpoint SELECT for gated routes; auth epoch sequence USAGE | RBAC membership writes; ledger/audit INSERT, UPDATE, DELETE, TRUNCATE; maintenance EXECUTE; outbox delivery UPDATE; trigger bypass |
| Admin publisher | Subject-scoped marked outbox SELECT/row locks and UPDATE of `published_at`, `attempts`, `next_attempt_at` | User/role writes; narrative decryption keys; chain writes |
| Signer | Audit/ledger SELECT + INSERT and sequence usage; head/checkpoint SELECT and validated head-advance EXECUTE; narrow user-email/FK lookup with compatible locks | Evidence UPDATE/DELETE/TRUNCATE; purge EXECUTE; direct head/checkpoint mutation; role writes; legal narratives |
| Operator | Target eligibility/credential and role access, account locks, outbox/context insertion | API network exposure; unrestricted evidence editing |
| Metadata maintenance | Hold checks, subject locks and bounded context/released-narrative cleanup | Ledger DELETE or trigger bypass |
| Ledger purge worker | Dedicated `identity_ledger_purge` login, bounded evidence/hold/proof reads, approved purge EXECUTE | Direct ledger/head/checkpoint/outbox writes; owner role membership; role/trigger/schema changes; superuser or replication privileges |
| Ledger maintenance function owner | `identity_ledger_maintenance_owner` NOLOGIN; only protected routines and their required table/sequence permissions | Runtime login; membership granted to API/signer/worker; ownership of application tables/schema/database |

Repository migrations do not create deployment login roles. Database grant/RLS policy deployment and validation remain a release gate. Shared `event_outbox` currently relies on subject/marker predicates in publisher SQL; enforce the same restriction in deployment permissions/RLS. Protect backups, restricted context and all secret delivery paths.

## Audit, logging and monitoring

Every successful privileged response is buffered until audit intent commits. `503 audit_unavailable` withholds disclosure and rolls back business changes. If the store itself is down, durable recording of the rejection cannot be guaranteed. Alert on sanitized `admin audit storage unavailable` / `admin durable audit failed` diagnostics. Page on publisher backlog growth/age, increasing attempts, delivery deferrals, signer reseed failures, missing-index capture, and key/backfill failures. The publisher emits `pending`, `attempts`, and `oldest_age_seconds`; deployment must connect these signals to its monitoring system and choose operational thresholds.

Never capture admin query strings, bodies, cookies, step-up headers or referrers in proxy/APM traces. Use static route templates; this also covers rejected legacy GET lookup requests. The MVP Nginx example in the deployment guide includes an admin-specific log format and suppresses unsanitized Nginx error records on this surface. For the Traefik successor, disable access/debug/tracing capture on the dedicated admin router unless its collector demonstrably emits only allowlisted method, router/template, status and duration fields. Validate with synthetic sensitive values before enabling intake; documentation is not evidence that deployed collectors are configured.

## Automated validation

The following gates passed on 2026-10-01 against the implemented Task 5.3 code:

- `identity-api:test`, `identity-api:lint`, `identity-api:vet`, and `identity-api:sqlc-vet`.
- `identity-api:build`, all three admin command builds, the audit signer build, and the purge worker build.
- `identity-api:test-admin-integration` and `identity-api:test-security-db` against disposable PostgreSQL 16, Redis, and NATS JetStream services.
- `identity-api:test-race` in a Linux Go 1.26 container with CGO and a C compiler enabled. The Windows host had no C compiler; it was not modified.
- Integration-tagged lint for the changed database, HTTP, legal, and session tests, plus two consecutive runs of the database-query suite. Query fixtures now roll back instead of relying on soft deletion to release email reservations.

The new regressions cover hold/purge locking in both orders, independent legal requests and replay, post-deletion/retention-aware disclosure, fail-closed audit rollback, cross-instance credential cutoff, and stale step-up ceremonies. These local checks do not constitute deployment approval or verification of production proxy/DB privileges.

## Verification and rollback

Run the Nx `sqlc-vet`, `lint`, `vet`, `test`, `test-race`, `build`, worker/operator builds, `test-security-db`, and `test-admin-integration` targets. Integration runs require disposable PostgreSQL 16, Redis and NATS JetStream. Existing migration tests reset schemas. The mandatory admin target fails on missing service configuration.

Do not downgrade migrations `00008`–`00010` over durable intent, encrypted requests or auth versions. Disable admin ingress/routes first and preserve holds, ciphertext, replay tombstones, outbox intent and evidence. Migration `00007` preserves seeded/pre-existing roles on rollback and refuses downgrade with banned users. A clean up/down/up of forward-only migrations is deliberately unavailable; test downgrade refusal and forward recovery on disposable fixtures instead.

Task 5.3 stays open until its complete role/route, concurrency, migration, ingress/privacy and operational acceptance matrix is verified. Task 5.4 owns ledger maintenance with subject locks, retained-segment/checkpoint proof and signer-head coordination; external anchoring is explicitly deferred. Task 5.5 owns operational reviews/transparency and restricted-narrative retention approval; phone attribution, historical key rotation, shared credential stores and immediate downstream JWT revocation remain separately scoped.

## Security Ledger Retention (Task 5.4)

The independent `security-ledger-purge` binary removes Class B rows only. It is
not the Class A `purge-worker`, an administrative hard-delete endpoint, or a
Class C/narrative cleanup tool. These instructions define release gates, not a
claim that production provisioning, verification or deployment has passed.

### Policy and Credentials

- Keep `SECURITY_LEDGER_RETENTION=8760h` (365 days from event occurrence; validated
  range `4320h..13140h`). The worker uses persisted `retain_until < cutoff` and
  never rewrites signed timestamps. Hold release resumes the original clock.
- Any independent active hold on the original `account_ref` wins, even when the
  user row no longer exists. Review/expected dates do not expire holds. A hold
  applied after erasure cannot restore data or create an immutable snapshot.
- Inject only the dedicated `SECURITY_LEDGER_PURGE_DATABASE_URL` credential into
  this worker. There is no fallback to API `DATABASE_URL`. Use the non-owner,
  non-superuser login `identity_ledger_purge`, never a migration/database owner,
  API/signer account or the local Compose owner's example credential.
- `identity_ledger_maintenance_owner` is a distinct NOLOGIN routine owner, not a
  runtime/table/schema/database owner. No runtime login may inherit it or
  `SET ROLE` to it. `NOINHERIT` alone is not enough: remove membership paths.
- Use `AUDIT_SUBJECT` (default `identity.audit.logs`), matching protected database
  settings, the signer and `admin-audit-publisher`. `NATS_AUDIT_SUBJECT` and
  `identity.audit.events` are not this repository's current convention. The
  worker does not load NATS connection, Redis, API, pepper or encryption config.
- Default batch size is 500 (`1..5000`); max considered rows per run is 10000
  (at least batch size, at most 1000000). Whole-run timeout defaults to `2m`
  (`1s..30m`), with 2-second lock waits and 15-second batch bounds. Do not raise
  limits to work around integrity/privilege failures. Logging is structured JSON
  at the default info level; `LOG_LEVEL` is not currently loaded by this command.
- `SECURITY_LEDGER_PURGE_DRY_RUN=true` is the default until every enablement gate
  passes. It performs the same locked eligibility and proof checks but rolls
  back deletion, checkpoint changes and outbox insertion, reporting `would_delete`.

### Controlled Initial Rollout

1. Leave the host schedule absent/disabled and destructive runs off. Record an
   approved immutable image and a consistent backup. Confirm that the API,
   signer, worker and publisher come from the compatible release. No runtime
   account may alter triggers, role memberships, schema objects or replication
   settings. Do not use a custom GUC or trigger disabling as a purge exemption.
2. Perform a controlled signer drain/stop. Stop or pause producers long enough
   to drain acknowledged work and verify signer shutdown; account for queued
   envelopes rather than silently discarding them. The initial cutover is not a
   routine hourly shutdown requirement. Keep all old signer instances stopped.
3. Apply additive schema `00011` using the migration identity. Inventory and
   verify existing canonical signed history, sequence gaps and terminal record.
   Assess historical timestamp/hash defects explicitly. Unexplained deletion
   or corruption blocks destructive enablement; do not rehash rows, fabricate
   checkpoints or waive a defect by initializing a newer head.
4. Provision the separate owner/runtime roles and narrowly scoped grants, then
   explicitly initialize the durable head from the verified terminal record.
   Genesis is allowed only for a demonstrably new, never-used ledger, not an
   unexplained empty table. Normal migrations never initialize it. Missing head
   after initialization is an error, not permission to restart the chain.
5. Validate effective privileges with actual disposable runtime logins, then
   audit deployed grants/ownership. API, signer and metadata cleaners must not
   execute purge. Worker direct DELETE/UPDATE/TRUNCATE, proof/outbox mutation,
   `SET ROLE`, trigger/role alteration and search-path/GUC bypass attempts must
   fail. Test direct routine bound/hold/isolation checks as well as Go startup.
6. Start only compatible signer/API binaries; prove online append, durable-head
   advancement and checkpoint consistency, including signer restart after tail
   or all-row expiry in disposable fixtures. Routine operation coordinates by
   short transaction locks, not the signer's daemon-lifetime lock. Old signer
   binaries must never run with enabled purge.
7. Run bounded dry-runs using the packaged worker and production-scoped login.
   Compare eligibility and hold behavior to the inventory. Validate timeout,
   overlap, failure exit/logging and rollback of proof/outbox writes. Confirm
   that no dry-run is counted as committed deletion.
8. Demonstrate acknowledged maintenance outbox delivery with the compatible
   `admin-audit-publisher` and signer using a disposable destructive fixture.
   Prove publisher outage leaves durable retryable intent and replay creates no
   duplicate signed receipt. Validate restore/forward-recovery drills and alert
   routing. Only after sign-off set dry-run false and enable the hourly host job.

### Routine Authority Contract

The executable grant/bootstrap procedure must match these exact database
signatures, not a broad `GRANT EXECUTE ON ALL FUNCTIONS`:

| Routine | Runtime authority |
|---|---|
| `public.purge_security_ledger_batch(timestamptz,bigint,bigint[],text[],bytea[],uuid,text)` | Only `identity_ledger_purge` may execute; returns `deleted_count bigint, held_count bigint`. |
| `public.advance_security_ledger_head(bigint,uuid)` | Only the separately scoped signer may execute; validates the expected head and actual inserted terminal row. |

Both SECURITY DEFINER routines belong to `identity_ledger_maintenance_owner`
and use the fixed safe `search_path = pg_catalog, pg_temp` with qualified
application objects. PUBLIC EXECUTE is revoked. Helpers remain migration-owned
and invoker-context; the maintenance owner receives EXECUTE only on
`public.security_ledger_require_owner()`,
`public.security_ledger_chain_time(timestamptz)`,
`public.security_ledger_canonical_body(public.security_event_ledger)`,
`public.security_ledger_account_lock_key(uuid)` and
`public.security_ledger_predecessor(bigint)`. Do not transfer trigger/helper or
table/schema ownership to a runtime login.

Purge arguments are the database cutoff/high-water mark, exact candidate
sequences, expected hashes, canonical bodies, opaque operation UUID and configured
audit subject. Array lengths must agree and contain `1..5000` unique positive
sequences bounded by the captured head. The routine independently acquires
coordination/account locks, checks canonical bytes, live/checkpoint predecessors,
fresh hold eligibility and configured subject, then writes its own bounded
receipt; callers cannot supply arbitrary audit payloads or checkpoint hashes.
Direct SQL callers must use READ COMMITTED with a positive `statement_timeout`
no greater than 15 seconds before invoking the statement. The function enforces
a 2-second lock timeout and its own bounded work; setting `statement_timeout`
from inside an already running statement would not start that statement's timer.

Emergency disablement, executed by the controlled database operator after
disabling the host schedule:

```sql
REVOKE EXECUTE ON FUNCTION public.purge_security_ledger_batch(
    timestamptz, bigint, bigint[], text[], bytea[], uuid, text
) FROM identity_ledger_purge;
```

Verify the grant is absent and wait for/stop any in-flight worker before changing
deployments. Do not revoke signer advancement as a substitute for disabling
purge, grant the owner role to the worker, or drop checkpoints during rollback.

### First-Time Provisioning SQL

Run the following in an authenticated `psql` operator session connected to the
target database after `00011`, with the signer drained and the schedule disabled.
The operator must be authorized to create roles and transfer function ownership;
these are not runtime privileges. Replace the three uppercase role placeholders
with existing, separately provisioned deployment logins. The new owner/worker
roles deliberately fail creation if already present: inspect existing attributes,
memberships, ownership and ACLs instead of silently reusing or resetting a role.
This is an incremental ledger grant set, not replacement API/signer/publisher
provisioning. Existing signer Class C INSERT/sequence/user-lock permissions and
publisher subject-scoped outbox permissions remain required.

```sql
\set ON_ERROR_STOP on
\set signer_role 'DEPLOYED_SIGNER_ROLE'
\set api_role 'DEPLOYED_API_ROLE'
\set metadata_role 'DEPLOYED_METADATA_MAINTENANCE_ROLE'
SELECT current_database() AS ledger_database \gset

BEGIN;
CREATE ROLE identity_ledger_maintenance_owner NOLOGIN NOINHERIT NOSUPERUSER
    NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE identity_ledger_purge LOGIN NOINHERIT NOSUPERUSER
    NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

REVOKE CREATE ON SCHEMA public FROM PUBLIC,
    :"signer_role", :"api_role", :"metadata_role";
REVOKE CREATE ON DATABASE :"ledger_database" FROM PUBLIC,
    :"signer_role", :"api_role", :"metadata_role";
GRANT CONNECT ON DATABASE :"ledger_database" TO identity_ledger_purge;
GRANT USAGE ON SCHEMA public TO identity_ledger_maintenance_owner,
    identity_ledger_purge, :"signer_role", :"api_role";

GRANT SELECT, DELETE ON public.security_event_ledger TO identity_ledger_maintenance_owner;
-- FOR UPDATE needs a column UPDATE grant; the unconditional trigger still rejects UPDATE.
GRANT UPDATE(seq) ON public.security_event_ledger TO identity_ledger_maintenance_owner;
GRANT SELECT, UPDATE ON public.security_ledger_head TO identity_ledger_maintenance_owner;
GRANT SELECT, INSERT, DELETE ON public.security_ledger_checkpoints TO identity_ledger_maintenance_owner;
GRANT SELECT ON public.legal_holds, public.security_ledger_retention_settings TO identity_ledger_maintenance_owner;
GRANT INSERT ON public.event_outbox TO identity_ledger_maintenance_owner;
GRANT EXECUTE ON FUNCTION public.security_ledger_require_owner(),
    public.security_ledger_chain_time(timestamptz),
    public.security_ledger_canonical_body(public.security_event_ledger),
    public.security_ledger_account_lock_key(uuid),
    public.security_ledger_predecessor(bigint) TO identity_ledger_maintenance_owner;
ALTER FUNCTION public.advance_security_ledger_head(bigint, uuid)
    OWNER TO identity_ledger_maintenance_owner;
ALTER FUNCTION public.purge_security_ledger_batch(timestamptz, bigint, bigint[], text[], bytea[], uuid, text)
    OWNER TO identity_ledger_maintenance_owner;

REVOKE ALL ON FUNCTION public.purge_security_ledger_batch(timestamptz, bigint, bigint[], text[], bytea[], uuid, text)
    FROM PUBLIC, :"signer_role", :"api_role", :"metadata_role";
REVOKE ALL ON FUNCTION public.advance_security_ledger_head(bigint, uuid)
    FROM PUBLIC, identity_ledger_purge, :"api_role", :"metadata_role";
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
    ON public.security_ledger_head, public.security_ledger_checkpoints,
    public.security_ledger_retention_settings
    FROM identity_ledger_purge, :"signer_role", :"api_role", :"metadata_role";
REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON public.security_event_ledger
    FROM identity_ledger_purge, :"signer_role", :"api_role", :"metadata_role";
REVOKE INSERT ON public.security_event_ledger
    FROM identity_ledger_purge, :"api_role", :"metadata_role";
GRANT SELECT ON public.security_event_ledger, public.security_ledger_head,
    public.security_ledger_checkpoints, public.legal_holds,
    public.security_ledger_retention_settings TO identity_ledger_purge;
GRANT EXECUTE ON FUNCTION public.purge_security_ledger_batch(timestamptz, bigint, bigint[], text[], bytea[], uuid, text)
    TO identity_ledger_purge;
GRANT SELECT, INSERT ON public.security_event_ledger TO :"signer_role";
GRANT USAGE ON SEQUENCE public.security_event_ledger_seq_seq TO :"signer_role";
GRANT SELECT ON public.security_ledger_head, public.security_ledger_checkpoints TO :"signer_role";
GRANT EXECUTE ON FUNCTION public.advance_security_ledger_head(bigint, uuid) TO :"signer_role";
GRANT SELECT ON public.security_event_ledger, public.security_ledger_head,
    public.security_ledger_checkpoints TO :"api_role";
ALTER ROLE identity_ledger_purge IN DATABASE :"ledger_database" SET statement_timeout = '15s';
ALTER ROLE identity_ledger_purge IN DATABASE :"ledger_database" SET lock_timeout = '2s';
COMMIT;
```

Do not give the worker a table-write, sequence, helper-EXECUTE or owner-membership
grant. The checkpoint owner does not need UPDATE. Deployment roles must have no
inherited ownership/CREATE/bypass grants either; the REVOKEs above do not remove
indirect grants through other roles. Provision the worker's SCRAM credential with
`\password identity_ledger_purge` in the controlled session (or the approved
secret-provisioning path), then deliver it through Infisical and require TLS in
deployed connections. Do not put a password in SQL, shell history or this document;
do not use a trust-authenticated database endpoint for the worker.

### Explicit Head and Subject Bootstrap

This is a one-time initialization, not a repair routine. First verify canonical
history independently with the signer stopped and record the exact terminal
sequence/hash. Replace the placeholder values below with that verified result.
The SQL cross-checks the current terminal but does not itself certify the entire
historical chain. For a demonstrably new ledger only, explicitly set sequence
`0`, a 64-character zero hash and `confirmed_fresh_genesis=true`. The default
false flag forbids inferring genesis from an empty table. Do not reset sequence
allocation state or use this procedure after restoration of initialized proof.

```sql
\set ON_ERROR_STOP on
\set verified_head_seq 'VERIFIED_TERMINAL_SEQUENCE'
\set verified_head_hash 'VERIFIED_TERMINAL_SHA256'
\set confirmed_fresh_genesis false
\set audit_subject 'identity.audit.logs'

BEGIN ISOLATION LEVEL READ COMMITTED;
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '15s';
SELECT pg_advisory_xact_lock(5200002::bigint);
LOCK TABLE public.security_event_ledger IN SHARE MODE;
WITH initialized AS (
    INSERT INTO public.security_ledger_head(singleton, seq, chain_hash)
    SELECT true, :'verified_head_seq'::bigint, :'verified_head_hash'
    WHERE NOT EXISTS (SELECT 1 FROM public.security_ledger_head)
      AND NOT EXISTS (SELECT 1 FROM public.security_ledger_checkpoints)
      AND NOT EXISTS (SELECT 1 FROM public.security_ledger_retention_settings)
      AND (
        (:'verified_head_seq'::bigint > 0 AND EXISTS (
            SELECT 1 FROM public.security_event_ledger
            WHERE seq = :'verified_head_seq'::bigint
              AND chain_hash = :'verified_head_hash'
              AND seq = (SELECT max(seq) FROM public.security_event_ledger)
        ))
        OR (:'confirmed_fresh_genesis'::boolean AND :'verified_head_seq'::bigint = 0
            AND :'verified_head_hash' = repeat('0', 64)
            AND NOT EXISTS (SELECT 1 FROM public.security_event_ledger))
      )
    RETURNING singleton
)
SELECT count(*) = 1 AS head_initialized FROM initialized \gset
\if :head_initialized
INSERT INTO public.security_ledger_retention_settings(singleton, audit_subject)
    VALUES (true, :'audit_subject');
COMMIT;
\else
ROLLBACK;
DO $$ BEGIN
    RAISE EXCEPTION 'Bootstrap refused: existing proof/settings, terminal mismatch, or unapproved genesis.';
END $$;
\endif
```

The selected subject must match `AUDIT_SUBJECT` on worker, publisher and signer.
Keep the schedule disabled while validating deployed ACLs with `psql` metadata
(`\du+`, `\dp`, `\df+`) and the worker's startup probe. For the function matrix
below, only worker/purge and signer/advance must be true; API/metadata maintenance
must be false for both:

```sql
SELECT role_name,
    has_function_privilege(role_name,
        'public.purge_security_ledger_batch(timestamptz,bigint,bigint[],text[],bytea[],uuid,text)',
        'EXECUTE') AS can_purge,
    has_function_privilege(role_name,
        'public.advance_security_ledger_head(bigint,uuid)', 'EXECUTE') AS can_advance
FROM (VALUES ('identity_ledger_purge'), (:'signer_role'),
    (:'api_role'), (:'metadata_role')) AS roles(role_name);

SELECT table_name,
    has_table_privilege('identity_ledger_purge', table_name,
        'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS has_table_write,
    has_any_column_privilege('identity_ledger_purge', table_name,
        'INSERT,UPDATE,REFERENCES') AS has_column_write
FROM (VALUES ('public.security_event_ledger'), ('public.security_ledger_head'),
    ('public.security_ledger_checkpoints'), ('public.security_ledger_retention_settings'),
    ('public.legal_holds'), ('public.event_outbox'), ('public.users')) AS tables(table_name);
```

Every worker write result must be false. Check effective role membership,
function ACL recipients/owners and safe search paths, database/schema CREATE,
table ownership, `session_replication_role` SET privileges and the real-role
denial matrix before destructive enablement. Never turn a failing probe into
success by broadening the worker's grants. These operator SQL examples mirror
the DB integration fixture's grant contract; their deployment execution and the
full history assessment remain explicit release gates.

### Image and Host Scheduling

Build/test the same immutable image that will be deployed. `Dockerfile` builds
all commands and explicitly asserts/copies the retention worker and existing
admin publisher into the non-root runtime. CI checks both with explicit
entrypoint overrides: missing credentials must yield the application's nonzero
structured configuration failure, not an absent executable or accidental API
startup. This packaging check is not the real-role dry-run gate.

The following examples run on a Linux Docker host. Replace the image digest and
Compose network with approved deployed values. Provision separate root-readable
`0600` environment files via Infisical; never put credentials in the command line
or use the repository's broad development `.env` for a maintenance container.
The purge env file contains only its dedicated DSN, bounds, dry-run setting and
`AUDIT_SUBJECT`. The publisher env file contains its separately
scoped `DATABASE_URL`, `NATS_URL` and audit pipeline settings, not the purge DSN.

```bash
IDENTITY_IMAGE='registry.example/identity-api@sha256:APPROVED_DIGEST'
docker run --rm --read-only --network identity_backend --stop-timeout 20 \
  --env-file /etc/identity/security-ledger-purge.env \
  --env SECURITY_LEDGER_PURGE_DRY_RUN=true \
  --entrypoint /usr/local/bin/security-ledger-purge "$IDENTITY_IMAGE"

docker run --rm --read-only --network identity_backend --stop-timeout 20 \
  --env-file /etc/identity/admin-audit-publisher.env \
  --entrypoint /usr/local/bin/admin-audit-publisher "$IDENTITY_IMAGE"
```

After approval, a root-owned `/etc/cron.d` entry can invoke the one-shot worker
hourly. This launches with the file's approved dry-run setting, not an implicit
destructive override. Connect stdout/stderr and nonzero exits to monitoring;
cron mail alone is not a production alerting system.

```cron
IDENTITY_IMAGE=registry.example/identity-api@sha256:APPROVED_DIGEST
0 * * * * root /usr/bin/docker run --rm --read-only --network identity_backend --stop-timeout 20 --env-file /etc/identity/security-ledger-purge.env --entrypoint /usr/local/bin/security-ledger-purge "$IDENTITY_IMAGE"
```

An existing host systemd timer can invoke the same command instead. Do not add
cron inside the image, a new scheduler service or Kubernetes solely for this
worker: distroless contains neither a shell nor cron. Keep the acknowledged
publisher on its own frequent host schedule so outbox intent drains promptly;
the purge worker has no broker connection. Do not run publisher narrative
cleanup implicitly; that mode retains its separate policy and credentials.

### Monitoring and Acceptance

Capture sanitized considered/deleted/held/deferred/failed totals, runtime and
cutoff. Candidate-prefilter exclusions are not individually inspected holds.
Report only known commits; ambiguous commit is a nonzero uncertain outcome,
never a claimed rollback or blindly retried certificate. Overlap is a logged
successful no-op. Bounded contention can defer work; integrity, privilege and
initialization failures must stop the run.

Alert on sustained eligible backlog age/count, repeated failures, invalid proof,
missed schedules, unexpected committed volume and publisher pending-age/attempt
growth. Use bounded diagnostics and no account/event/operation identifiers in
metric labels. Logs and Class C receipts must exclude account refs, source event
IDs, blind indexes, network/device metadata, legal narratives and full checkpoint
histories. The transactional `admin_action` receipt is delivered on the configured
audit subject as `legal.ledger.purged` or `legal.ledger.purge_skipped`, with no
Security context. It is operational accountability, not an external trust anchor.

Run the existing Nx SQL/unit/race/static/build gates, `build-security-ledger-purge`,
`build-audit-signer`, `build-admin-audit-publisher`, `test-security-db`,
`test-admin-integration` and `test-retention-integration`. The last target forces
`REQUIRE_RETENTION_INTEGRATION=1` and requires all three service URLs; missing or
unreachable dependencies must fail rather than skip. It runs worker, retained-proof
and real-role tests with `-tags=integration -count=1 -p=1`. Use disposable PostgreSQL 16, Redis
and NATS JetStream only; serialize schema-resetting suites. Race tests require
Linux/CGO and a C compiler. Validate generated-code reproducibility, image launch,
forward-only downgrade refusal and restoration. The older Task 5.3 test results
above are not evidence that these new gates have passed.

### Rollback and Restore Gates

Disable the schedule and revoke purge EXECUTE first, then stop/wait for in-flight
work and assess committed/uncertain outcomes. Preserve head, checkpoints, holds,
settings and outbox intent. Revocation alone does not cancel a function already
executing; confirm the worker has stopped before declaring purge disabled.
Never revert to a signer/verifier unaware of erased spans. Treat initialized
proof state and deletions as forward-only; repair with a compatible release.
Migration `00011` refuses Down unconditionally, including a seemingly empty
database. Do not run migration down/reset over that history or promise recovery
of erased payloads.

Restore ledger/head/checkpoints/holds/outbox from one consistent backup, validate
before reopening ingestion or purge, reconcile authoritative holds/deletions,
then resume eligible expiry without resetting clocks or bypassing holds. Backup
rotation remains independent. See [disaster recovery](disaster-recovery.md#33-security-ledger-retention-recovery).
Neither a database-relative proof nor a Class C receipt independently detects a
coherent database rewrite or rolled-back backup. External anchoring remains
deferred; Task 5.3 deployment sign-off and Task 5.5 narrative-retention approval
and cleanup are not satisfied by this worker.
