# Task 5.3 admin operations

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
| API | Existing authentication table access; live RBAC SELECT; legal request SELECT/INSERT/UPDATE; restricted context INSERT; admin outbox INSERT; chain SELECT for gated routes; auth epoch sequence USAGE | RBAC membership writes; ledger/audit INSERT, UPDATE, DELETE, TRUNCATE; outbox delivery UPDATE; trigger bypass |
| Admin publisher | Subject-scoped marked outbox SELECT/row locks and UPDATE of `published_at`, `attempts`, `next_attempt_at` | User/role writes; narrative decryption keys; chain writes |
| Signer | Audit/ledger SELECT + INSERT and sequence usage; narrow user-email/FK lookup with compatible locks | Evidence UPDATE/DELETE/TRUNCATE; role writes; legal narratives |
| Operator | Target eligibility/credential and role access, account locks, outbox/context insertion | API network exposure; unrestricted evidence editing |
| Metadata maintenance | Hold checks, subject locks and bounded context/released-narrative cleanup | Ledger DELETE or trigger bypass |

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

Task 5.3 stays open until its complete role/route, concurrency, migration, ingress/privacy and operational acceptance matrix is verified. Task 5.4 owns ledger maintenance with subject locks, retained-island/checkpoint proof, signer-tip coordination and external anchors. Task 5.5 owns operational reviews/transparency; phone attribution, historical key rotation, shared credential stores and immediate downstream JWT revocation remain separately scoped.
