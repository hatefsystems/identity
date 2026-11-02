# Admin and Ledger Retention Operations

The implementation remains opt-in. This document describes the current runtime and outstanding release gates; it is not production sign-off. The inherited acceptance matrix is in `.kilo/plans/1789692893214-task-5-3-admin-rbac-legal-holds.md`; the Task 7.6 panel boundary and required evidence are in `.kilo/plans/1793529257288-dpo-legal-compliance-panel.md`. Neither plan is evidence of completed validation or production approval.

## Enablement

1. Apply additive migrations through `00010` using the migration identity. Inventory existing signed data before rollout; never rewrite hashes to conceal old timestamp defects. Identify an explicit verification boundary if historical segments fail.
2. Deploy account-version-aware issuers on **every** instance and restart old process-local credential stores before moderation is enabled. Ban, suspension, deletion and reactivation advance persistent versions. Old sessions, codes, refresh tokens and step-up grants cannot regain validity. Task 6.2's `ValidateToken` checks that version and live Redis authority; downstream clients using offline JWT verification still retain the configured lifetime, at most ten minutes.
3. Inject the envelope key/version and shared blind-index pepper through the existing secret delivery mechanism. Hold management uses envelope encryption independently of attribution. Without a pepper, SMS OTP and producer-side capture are unavailable; legal attribution stays unmounted without a verified fixture.
4. With intake disabled, run `npm exec -- nx run identity-api:admin-legal -- --operation=backfill` in bounded batches until it reports zero. Each converted row is decrypted and checked before plaintext columns are cleared in the same transaction. Retain a key recovery plan and backups. Check all legacy rows and deployed key versions; startup's crypto probe is not a full inventory of old ciphertexts.
5. Obtain approved numeric `ADMIN_CONTEXT_RETENTION` and `ADMIN_LEGAL_RELEASED_RETENTION` durations and approval for opaque replay tombstones. There are no policy defaults. Schedule `admin-audit-publisher --cleanup-contexts` and `admin-legal --operation=cleanup` with separate maintenance credentials. Both use hold-aware deletion; released holds resume original clocks. Neither command deletes ledger evidence.
6. Run the signer and `admin-audit-publisher` on the same configured audit subject. Publication requires JetStream acknowledgement; delivered metadata is never inferred from an in-memory queue. Signer event-ID deduplication covers redelivery after uncertain acknowledgements. The deletion-event outbox consumer is separate work.
7. With affected intake closed, run `NX_DAEMON=false npm exec -- nx run identity-api:admin-legal -- --operation=lookup-probe` against the **real deployed signer**, actual schema and configured keys. It creates a credential-free synthetic account, publishes a legacy envelope without a producer index, verifies the signer's stored index, deletes only that synthetic account, and verifies the fixture again after deletion. Canonical v2 resolves the fixture event UUID through `security_ledger_chain.event_id`, joining the payload by `seq`, while retaining the synthetic client/event checks and constant-time expected-index comparison. Capture the printed `ADMIN_LOOKUP_FIXTURE_ID` privately and configure every API replica with it. A timeout leaves the identified synthetic account for controlled diagnosis; never substitute a real person's identifier or delete unrelated evidence. A supplied absent/wrong fixture or mismatched key fails startup/readiness; omitting the setting explicitly keeps attribution unavailable while hold/preservation may remain independently usable. Repeat after signer/key deployment changes and keep the existing pepper pinned. Injecting `WithLookup(..., true)` is not equivalent evidence. The probe is neither a chain trust anchor nor proof of complete historical indexing.
8. Configure exact HTTPS `ADMIN_ALLOWED_ORIGINS`, Redis actor/subnet limits and timeouts. Set `ADMIN_ENABLED=true` only after the existing governance, authenticated smoke-test and deployed-ingress gates are satisfied. Startup requires DB, Redis, encryption, audit delivery configuration and approved retention. Readiness probes dependencies; missing step-up leaves mutations and attribution unmounted, not ungated. The Task 7.5/7.6 panels have their own acceptance and rollout gates below; this runbook does not authorize enablement.

## Operator role provisioning

Use `npm exec -- nx run identity-api:admin-roles -- --user-id=<uuid> --role=<role>`; add `--revoke` for revocation. Roles are `super_admin`, `moderator`, `support`, `dpo`. A grant requires an active account with an enrolled passkey or enabled MFA. Revocation works for inactive targets too. Changes serialize with moderation and commit the encrypted target reference plus durable audit intent in one transaction; retries are audited no-ops.

Run from an authenticated, MFA-protected operator environment with separately scoped `DATABASE_URL`. Its trusted launcher supplies `ADMIN_OPERATOR_ID` and `ADMIN_OPERATOR_SPIFFE_ID` from the authenticated identity. These environment values are **attribution, not authentication**; arbitrary callers must not control the launcher or database credentials. Provisioning approval remains an organizational control. No HTTP route assigns roles, no unaudited one-row bootstrap is documented, and no two-person HTTP workflow is claimed.

## Admin Control Panel (Task 7.5)

Task 7.5 supplies `/admin`, `/admin/users`, `/admin/users/[id]`, `/admin/audit-logs`, and `/admin/integrity` within the existing Next app. Task 7.6 adds the separate `/admin/legal` workspace described below. Neither enables production admin access, alters approved retention, or adds password-reset, role-management, bulk, administrative account-deletion or section 1.8 legal-workflow controls. The neutral dashboard entry performs no admin discovery until visited.

Session bootstrap precedes a durably audited capability read. Support gets safe account metadata; Moderator adds PII, exact body-only lookup and status changes; DPO gets audit search and both verifiers; Super Admin gets only the two content-free verifiers. Combined grants expose their union. The fixed capability response is presentation metadata, not authority: every operation checks current primary-database permissions, and every disclosure remains behind the durable-audit boundary. A denied admin capability must not sign out a valid ordinary account session.

Moderation is an explicit fresh-read, verification, reason and confirmation sequence. List/detail/lookup revisions and `expected_revision` are canonical decimal strings. The API compares the pin under existing account locks before status, auth-version, revision or success-intent writes. A conflict requires rereading, reviewing and reverifying; never retry with a silently substituted revision. The panel requires a trimmed 1..2000-byte UTF-8 reason after verification for suspension, ban and reactivation. Grants expire at the earlier grant/session deadline and are never retained after the confirmation lifetime.

Suspension and ban are long-lived until explicit restoration. They are not erasure, do not block re-registration, and cannot retract an already admitted request or shorten an offline consumer's token lifetime. Reactivation never restores old credentials. If delivery may have occurred, show only an unconfirmed outcome and an explicit current-state read. A matching current status does not prove which request changed it. Never replay a moderation write automatically.

Audit queries use explicit UTC windows, initially at most the last 24 hours, with bounded keyset pages and no total. Payload details are inert text. Verification is explicitly paged from genesis with a captured immutable `through_seq`, prior cursor and prior hash. Coordinates remain exact decimal strings through the full nonnegative signed-64-bit range. The API's `complete` flag is authoritative; partial or stopped progress is not full-run success. The panel displays the API's exact explanatory scope: audit segments are relative to their seed, while ledger links and retained payloads are database-relative. An erased node counts within `checked`; `erased_checked` is a subset. Database-relative erasure continuity is not erased-content verification. Initialized-empty and missing-head states are distinct; neither proves that no historical activity occurred. No complete-ingestion guarantee, external anchoring or resistance to a coherent privileged database rewrite is claimed.

The API, panel, and other admin REST clients require a coordinated cutover for mandatory moderation revisions and string-valued account revisions and audit/verification coordinates. Close old admin ingress and drain in-flight requests while replacing incompatible callers and open forms. Before reopening, **every API replica** must enforce mandatory canonical-string `expected_revision` and support the string coordinate contracts, and all callers must be compatible. Do not add numeric or revision-optional fallbacks. Task 7.5 changes the administrative wire contract, not the schema or canonical format.

Rollback must first close admin ingress, then disable/remove the panel entry, then coordinate API/UI rollback with incompatible admin traffic still closed. Retain database state, audit/outbox intent and approved retention/cleanup; do not downgrade storage or rewrite hashes. Reopening after rollback requires the same every-replica contract gate. Existing lifecycle v1/v2 consumer-first rollout requirements remain separate.

Keep `ADMIN_ENABLED=false` unless existing DPO/Legal governance approval, credentials/non-owner database grants, signer/publisher supervision and outbox delivery, approved retention cleanup, exact-origin and ingress/APM-redaction gates are satisfied. Do not enable legal workflows to ship the panel. Local Task 7.5 completion is conditional on all required automated checks passing with dated, worktree-specific evidence, not on fixture governance. Unobserved native hidden-tab/bfcache restoration, physical-authenticator and screen-reader/manual accessibility checks remain separate gates, as do production threat-model review and the existing Task 5.3/5.4/5.5 deployment gates. Local acceptance is not production approval.

## DPO/Legal Panel (Task 7.6)

Use the fixed `/admin/legal` workspace for the five [section 1.7 operations](api-design.md#17-admin--moderation-api): read/apply/release independent holds, record preservation and perform email attribution. Legal Holds, Preservation and Attribution are local capability-gated sections, not separate identity-bearing routes. Seeded DPO permission is required; Super Admin has no legal bypass, and DPO does not gain live account-profile browsing. Combined/legal-only permissions are supported without changing role seeds. Capabilities reflect both permission and actual mount, not an authorization cache or explanation of why a flag is false. Reads can remain available without step-up; writes and each lookup page require fresh WebAuthn UV or advertised TOTP.

Class B and baseline administrative audit are **personal data**. The ledger is pseudonymized, not anonymous or non-PII: original account references, network/device metadata and the secret-key lookup mechanism can support linkage. Baseline audit retains actor/network metadata, action/hold references, timestamps and response digests despite narrative minimization. Handle both under approved access, purpose, retention and privacy controls; neither the UI nor a synthetic fixture approves that processing.

### Controlled Intake and Holds

1. Identify exactly one original nonzero `account_ref` UUID (`users.id`, surviving independently after deletion) from controlled intake or explicitly select one attribution result. Never substitute an email, assume the account still exists, merge historical references or choose the first match automatically. No profile resolver or bulk hold is supplied.
2. Record an operator-supplied operation UUID and the exact **normalized request payload** in the approved external intake record before transmission. The browser deliberately provides neither generated keys nor persisted drafts/recovery APIs. Record request kind (`legal_hold` or `preservation`), original target, reason, authority, normal-hold legal basis and optional date. Idempotency is scoped to `(account_ref, request_kind, key)`, not actor or a globally unique request UUID; the same key on a different subject/kind creates another independent hold.
3. Obtain fresh step-up, then enter and review sensitive details. Trim outer whitespace once; reason is 1..4096 UTF-8 bytes, authority/legal basis 1..255. The API checks supplied lengths before trimming, so use the normalized values. Optional review/expiry dates are RFC3339 UTC in the panel, may be past dates, and must be fixed at microsecond-or-coarser precision for replay. Normal holds require an explicit basis. Preservation fixes `legal_basis=preservation_request` server-side and maps `expires_at` to advisory `review_at`.
4. Confirm the immutable target, kind, operation UUID and normalized inputs. A grant belongs only to this confirmation lifetime and expires no later than the session; changing target/scope discards it. Every additional operation needs another grant. Preservation ("freeze-before-order") does **not** wait for a case workflow or full disclosure order. It does not supply permission to disclose externally.
5. Record confirmed `201` creation separately from `200` replay. A replay reports the request's current state, including already released state; it never reactivates it. For preservation, use top-level `replayed`, not `hold.replayed`, and read the full API note and `observed_at`. Account presence includes soft-deleted rows; ledger presence may include expired/unindexed payloads. Both may be false for a valid hold. These are observations, not completeness guarantees or immutable snapshots; previously displayed lookup evidence may have disappeared before this separate transaction committed.
6. Read holds explicitly with a status and either the original reference or an intentional all-subject choice. Invalid/present-empty references cannot fall back to all subjects. Page/total is one current snapshot; absence from a page is not API `404`. Both normal and preservation requests appear with their request kind. View restricted details deliberately as inert text; `details_purged` means cleaned narrative, not empty original input. Legal browser page size is at most `min(page_size_max, 50)`, even though the API ceiling may be higher.
7. To release, select an authorized list row and confirm exactly its immutable `hold_id` after fresh step-up. Send only the DELETE, with no body, operation key, release reason or revision. Empty `204` means that request is released or was already released, not that this caller necessarily changed it. Other independent holds may remain. Review/expiry dates never auto-release. Once no active hold protects the subject, original retention clocks resume and data may be eligible at the next purge immediately. No clock reset, extended account recovery, restoration of erased data or evidence snapshot is implied.

### Attribution and Scope

- Enter the bare email, authority, case reference, purpose, explicit UTC bounds and selected fields only after fresh verification. Server-side HMAC-SHA256 uses lowercase NFKC/trimmed identity; do not hash locally or introduce account/provider-specific email normalization. Phone/backup-email and live-profile resolution are not offered. The entered email is transient sensitive input, not returned evidence.
- Request core event/reference UUIDs, event type, timestamp, retain-until and exact string sequence only by default. The six optional metadata fields are unchecked opt-ins for the inquiry purpose, not values silently fetched for hidden columns. No blind index/version, credentials, raw identity, full audit payload, action content or chain hash is returned. Missing selected fields mean not present in this projection, not that they never existed.
- Freeze the entire query, including page size and field selection. Each explicit next page requires fresh step-up with the same body plus opaque cursor. Preserve exact string `coverage.through_seq` and original observation time, and display fresh eligibility time and the full coverage note. Use the effective configured `audit_max_window_seconds`, including a smaller/fractional value. Cursors have no implemented age TTL and are not session-bound, but the browser clears them on session changes. Do not decode them, invent an expiry, broaden rejected scope or automatically fetch all pages.
- A final/empty page means no matching **indexed, currently eligible records within scope**, not no historical activity or no account. Later ingestion above the fixed bound is excluded and current hold/retention eligibility is checked per page. Releasing a hold can remove expired matches from later pages. Multiple original references do not establish one real-world person, and no complete-history, historical-pepper coverage or verified inclusion proof is returned. Use the independent integrity tool for its own explicitly limited verification scope.
- Selecting a reference for a hold/preservation keeps an inline form within Attribution. Each subject needs independent review and a new grant. This panel has no export, bulk-copy, upload, external transfer, case/review/response approval, delivery attestation or transparency reporting; section 1.8 and its policies remain separate.

### Interrupted Outcomes and Explicit Retry

The view clears inputs, selected targets, operation IDs, results, cursors and grants on section/route change, cancel, hide/pagehide, session expiry, key/session change and permission loss, including detached controls and late responses. Pending forms also clear on grant expiry. Nothing is recovered from browser storage, navigation URLs, history state, analytics or cross-tab messages. A waiting-TOTP marker retains an operation name only; it cannot restore the target, scope, UUID or a transmitted request. Reentry uses the external intake record.

1. If a write may have been sent but no valid success response arrived, record **outcome unconfirmed**. Lost, malformed, oversized, interrupted responses or a post-commit session-renewal `503` are not proof of rollback. Do not infer success from a subsequent `401`, automatically retransmit, or replace the UUID. Only the explicit pre-handler DPoP nonce challenge permits one automatic retry with the exact body/key and a fresh proof.
2. Reestablish the real session/capabilities if required. `403 forbidden` clears privileged access without signing out a valid ordinary session; an incorrect step-up factor is not session loss. Honor bounded Retry-After feedback without scheduling requests automatically.
3. For an uncertain create, retrieve the **original** target, request kind, operation UUID and every normalized input/date from external intake. Explicitly review and retry that unchanged tuple with fresh step-up. Matching replay returns current state, not a new hold; an already released request remains released. After privacy clearing, the browser cannot reconstruct this tuple for the operator.
4. `409 idempotency_conflict` means the same scoped key has different inputs or cleaned narrative. Stop and reconcile externally; it is not permission to use a new key or reapply a cleaned/released request. A current list can help establish state but cannot prove which uncertain request created it. For release, review the current exact hold before an explicit new release confirmation/grant; do not invent a create-key retry mechanism.
5. Keep confirmed success when a later refresh fails. Lost lookup data instead means no accepted result, not "no match" or an uncertain business mutation; only explicit fresh verification/restart is offered. Oversized reads need an explicitly smaller page/scope, not dropped rows/fields or hidden requests. The shared 4-MiB exception covers only audit-list GET, legal-holds GET and attribution POST; other browser responses retain 256 KiB.

### Release Gates

Coordinate the panel, API and other attribution callers under closed/drained affected old admin ingress. Retire incompatible callers/open forms and deploy canonical-string legal `seq`/`coverage.through_seq` support to **every replica** before reopening, with no numeric fallback or fixture bypass. Run the real signer probe above and separately exercise authenticated post-deletion lookup; a fake verified service is not browser acceptance. Rollback closes affected ingress first, removes new UI entries, then coordinates compatible API/UI versions. Preserve holds, encrypted contexts, request tombstones, accepted audit/outbox intent, signed data and existing retention/cleanup; never reset clocks, downgrade storage or rewrite chains. Restore access only with compatible callers and verified prerequisites.

The [Task 7.6 validation inventory](devops-operations.md#dpolegal-panel-task-76) requires source-specific automated results, sanitized evidence and confirmed cleanup. The local acceptance below does not close manual or production gates. Manual screen-reader, physical-authenticator, native zoom, hidden-tab/bfcache and deployed-ingress checks remain open when unobserved. Keep production `ADMIN_ENABLED` and governance unchanged; do not enable `LEGAL_WORKFLOW_ENABLED` to ship this panel. Baseline approval, encrypted backfill, real non-owner DB grants, approved narrative/replay/ledger retention, signer/publisher delivery, exact-origin/APM redaction, privacy notices, ROPA/DPIA/DSAR duties and Task 5.3/5.4/5.5 statuses remain separate operator gates. Phone attribution, multi-pepper rotation, Class C purge policy and external anchoring are not added.

### Local Acceptance (2026-11-02)

Required automated validation ran on 2026-11-01 and its source fingerprints, image identities and cleanup were reconciled unchanged on 2026-11-02 before recording completion. The tested worktree is based on `b6e9b885a1269dac009e2915626c22d16024e5b2`; its full source manifest before these documentation-only acceptance notes has SHA-256 `6c1deae772a90b6f970bb335bc1ea4e5507a99770ad4d70b0b64179369608d0c`.

- Evidence root: `/tmp/kilo/legal-validation-20261101T115536Z`. `final-summary.json` reconciles all required gates, compiled inputs, image IDs, screenshot hashes and cleanup. `backend/matrix-summary.json`, `frontend-status.json`, `images-status.json` and `browsers-status.json` retain exact commands, environments where relevant, durations, attempts and final exits.
- All 25 backend gates passed, including normal and CGO race tests, standard/integration-tag vet and lint, fixture/operator/API builds, SQL/protobuf generation and reproducibility, and all seven serial PostgreSQL/Redis/JetStream integration suites with zero mandatory skips. The local race run provisioned a disposable GCC environment; it did not change repository toolchain configuration.
- All 586 web tests, 17 shared UI tests and 156 CI/harness tests passed, along with web/UI lint, typechecks, the CI spec typecheck and the production web build. Lint/vet had no findings. Existing Next.js project-reference and Nx historical flake advisories were not represented as new validation failures or production sign-off.
- The real HTTPS admin suite passed all legal workflows and preserved Task 7.5 regressions, with 27 fresh legal verifications and 42 masked light/dark desktop/narrow/zoom-equivalent captures. The ordinary portal suite also passed. `admin-browser/admin-evidence.json` and `portal-browser/portal-evidence.json` record completed teardown and the remaining manual gates.
- Fresh Linux/AMD64 API and web images passed non-root entrypoint and nonce-CSP browser smoke checks. Exact build flags and immutable image IDs are in the evidence registry. Run-owned integration/browser containers, volumes and networks were removed; the two validated local image tags remain available.

Earlier failed attempts remain in the evidence history. They include fixture-isolation errors, responsive-focus defects, observer composition and intentional signer-shutdown issues that were corrected, plus a supervised-log assertion that did not reproduce in the accepted run. No private log text was copied into diagnostics; fixed category/field counts remain available for future failures. Local success is not a blanket certification of existing audit fallback logging or deployed collectors: review those paths and prove redaction before production enablement.

## Database privilege separation

Production identities must be non-owner and non-superuser. Migrations and test owners are not runtime accounts. Apply and verify deployment-specific grants before enabling ingress:

| Identity | Required scope | Must not receive |
|---|---|---|
| API | Existing authentication table access; live RBAC SELECT; legal request SELECT/INSERT/UPDATE; restricted context INSERT; admin outbox INSERT; chain/head/erasure SELECT for gated routes; auth epoch sequence USAGE | RBAC membership writes; ledger/audit/chain INSERT, UPDATE, DELETE, TRUNCATE; `advance_chain_head` EXECUTE; outbox delivery UPDATE; trigger bypass |
| Admin publisher | Subject-scoped marked outbox SELECT/row locks and UPDATE of `published_at`, `attempts`, `next_attempt_at` | User/role writes; narrative decryption keys; chain writes |
| Signer | Audit/ledger/chain SELECT + INSERT and chain-sequence usage; head SELECT and validated `advance_chain_head` EXECUTE; narrow user-email/FK lookup with compatible locks | Payload or chain UPDATE/DELETE/TRUNCATE; direct head mutation; role writes; legal narratives |
| Operator | Target eligibility/credential and role access, account locks, outbox/context insertion | API network exposure; unrestricted evidence editing |
| Metadata maintenance | Hold checks, subject locks and bounded context/released-narrative cleanup | Ledger DELETE or trigger bypass |
| Ledger purge worker | Dedicated `identity_ledger_purge` login; payload `SELECT` + `DELETE`; erasure-index `SELECT` + `INSERT`; outbox `INSERT`; chain/head/hold/settings `SELECT` | Any write on chain, head or erasure index beyond the insert; payload `UPDATE`/`TRUNCATE`; sequence usage; `advance_chain_head` EXECUTE; role/trigger/schema changes; superuser or replication privileges |
| Chain-head routine owner (optional) | `identity_chain_head_owner` NOLOGIN; `advance_chain_head` ownership with chain `SELECT` and head `SELECT`/`UPDATE` | Runtime login; membership granted to API/signer/worker; ownership of application tables/schema/database |

Repository migrations do not create deployment login roles. Database grant/RLS policy deployment and validation remain a release gate. Shared `event_outbox` currently relies on subject/marker predicates in publisher SQL; enforce the same restriction in deployment permissions/RLS. Protect backups, restricted context and all secret delivery paths.

## Audit, logging and monitoring

Every successful privileged response is buffered until audit intent commits. Pre-commit audit failure withholds disclosure and rolls back business changes; `503 audit_unavailable` does not provide a usable result. If the store itself is down, durable recording of the rejection cannot be guaranteed. A lost/invalid response or post-commit `503 temporarily_unavailable` during session renewal can still follow accepted work: treat a transmitted write as unconfirmed, not guaranteed rollback. Alert on sanitized `admin audit storage unavailable` / `admin durable audit failed` diagnostics. Page on publisher backlog growth/age, increasing attempts, delivery deferrals, signer reseed failures, missing-index capture, and key/backfill failures. The publisher emits `pending`, `attempts`, and `oldest_age_seconds`; deployment must connect these signals to its monitoring system and choose operational thresholds.

Never capture admin query strings, bodies, cookies, DPoP proofs, step-up/`Idempotency-Key` headers, cursors, legal narratives/results or referrers in proxy/APM traces. Use static route templates for both `/admin` pages and `/api/v1/admin`, including rejected URLs and lookup requests; template account/hold identifiers rather than logging raw paths. The `account_ref` filter, hold-ID path and operation-ID header are allowed only on their exact authorized API requests, never diagnostics or navigation. The MVP Nginx example in the deployment guide uses an admin-specific log format and suppresses unsanitized error records. For the Traefik successor, disable access/debug/tracing capture unless its collector demonstrably emits only allowlisted method, template, status and duration. Verify synthetic sensitive values are absent from ingress, API, worker and artifact output; capture synthetic probe IDs only through the controlled private provisioning channel. Local route-template tests do not establish deployed collector compliance.

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

Task 5.3 stays open until its complete role/route, concurrency, migration, ingress/privacy and operational acceptance matrix is verified. Task 5.4 owns ledger maintenance with subject locks, erasure-record proof and signer-head coordination; external anchoring is explicitly deferred and remains the largest residual gap, because database-relative verification cannot detect a privileged coherent rewrite. Task 5.5 owns operational reviews/transparency and restricted-narrative retention approval. Task 6.2 supplies shared credential stores and live RPC token revocation, but does not close these deployment gates or change the offline-JWT residual-authority window. Phone attribution and historical key rotation remain separate work.

## Legal Review and Transparency (Task 5.5)

This backend is opt-in and does not confer production approval. `ADMIN_ENABLED`
now requires `ADMIN_GOVERNANCE_POLICY_ID`, resolving to the immutable baseline
installed by the controlled operator. The baseline must match both existing
retention durations exactly. `LEGAL_WORKFLOW_ENABLED=false` remains the default;
enabling it additionally requires `LEGAL_WORKFLOW_POLICY_ID` with an approved
workflow extension. A baseline-only deployment can retain Task 5.3 preservation
without enabling case intake. Backfill and the synthetic lookup probe remain
available before approval; cleanup loads approved persisted policy independently
of intake flags.

### Approval Artifact

The operator supplies a bounded JSON file with these fields. No example numeric
retention values are production defaults:

| Field | Required meaning |
|---|---|
| `id`, `approval_reference`, `fixture` | Immutable UUID, opaque external approval reference, explicit boolean. Fixtures are rejected outside development/test. |
| `context_retention_seconds`, `released_hold_retention_seconds` | Positive approved integer seconds matching configured baseline values. |
| `context_clock`, `released_hold_clock` | Exactly `created_at` and `released_at`. |
| `hold_tombstone_fields`, `hold_tombstone_lifetime` | Exact actual retained field inventory and explicit `no_expiry` approval. |
| `legacy_inventory_reference` | Opaque inventory attestation required when binding existing holds/contexts. Existing context clocks must match; they are never rewritten. |
| `workflow` | Optional baseline extension; required for case intake/reporting. |
| `workflow.max_case_age_seconds`, `workflow.closed_case_retention_seconds` | Positive approved case expiry durations. |
| `workflow.case_clock` | Exactly `created_at_max_closed_at_min`: closure can shorten, never extend the original maximum. |
| `workflow.replay_fields`, `workflow.replay_lifetime` | Exact minimized replay inventory and explicit `no_expiry` approval. |

The existing hold inventory is `id`, `account_ref`, `applied_by`, `is_active`,
`applied_at`, `review_at`, `released_at`, `released_by`, `request_kind`,
`idempotency_key`, `details_purged_at`. These are **linkable pseudonymous records**,
not anonymous tokens. The new erased workflow replay inventory is `operation`,
`scope`, `idempotency_key`, `result_id`, `erased`; it contains no subjects, actors,
narratives or content fingerprints. Neither mechanism implements finite replay
expiry. If governance does not approve its actual inventory and lifetime, intake
must stay disabled until a separately reviewed replay protocol exists.

Run with separately provisioned credentials and trusted launcher attribution:

```sh
npm exec -- nx run identity-api:admin-legal -- --operation=policy-install --policy-file=/approved/legal-policy.json
npm exec -- nx run identity-api:admin-legal -- --operation=workflow-cleanup --limit=500 --dry-run
npm exec -- nx run identity-api:admin-legal -- --operation=workflow-cleanup --limit=500
```

The policy installer records durable audit intent atomically. It does not verify
the law or authenticate the operator from environment strings. First installation
binds the baseline; changing that binding/retention requires a separate migration,
not a new environment value. Schedule cleanup with the existing host scheduler;
the packaged `admin-legal` command runs without a container shell. Cleanups of
legacy action contexts and released hold narratives still use their existing
commands and do not remove ledger evidence.

### Operating Procedure

1. Assign one opaque intake UUID to each actual request and reuse it on retries.
   Record received time separately from entry time, including rejected/no-match
   requests. One request can cover zero or multiple original accounts.
2. Validate authority, legal sufficiency, scope and notification restrictions.
   Record `accepted`, `rejected` or `needs_information` against the content
   revision. Store documents in the approved external evidence system; this API
   stores encrypted references, never uploads or follows their URLs.
3. Apply any needed preservation through Task 5.3 immediately; no case approval is
   a prerequisite. Link the existing hold afterward. Review dates are advisory;
   the separate review queue/history never changes the hold's original replay
   inputs, automatically releases a hold or implies an immutable evidence copy.
4. Prepare the exact response scope/artifact manifest. Data-bearing proposals
   require an accepted current content revision and a different active DPO's
   approval. Editing content/proposals invalidates old approval. Recheck current
   permissions and auth versions when approval is used.
5. Transfer only the approved material through the controlled external channel,
   then record the delivery receipt/time. This is operator attestation, not
   verified transport. Reconcile a failed receipt write with the external record
   and retry its original key; an API failure is never an instruction to resend
   the material. Delivery time must not precede preparation or required approval.
   The first release allows one final response and no
   supplements, reopening or post-delivery correction. Closure never releases a
   hold. Existing investigative lookup remains single-DPO and distinct from
   permission to respond externally.
6. Review exact monthly totals and prepare a completed-year artifact. A second
   DPO approves the frozen artifact; only then download it for manual publication.
   Received and answered are separate time cohorts. No historical totals are
   inferred from hold operations. Late entries invalidate unexported snapshots;
   downloaded artifacts remain historical and are never silently rewritten.

Annual artifacts suppress nonzero totals below 5 and suppress the whole outcome
breakdown if any outcome is 1-4. They contain no monthly/country/authority or
identifier breakdowns. Source data versions stay internal because they can reveal
suppressed counts. Suppression is not proof of anonymity or differential privacy;
public-release review must consider previous publications too.

Coverage begins with the first committed counter, not migration installation or
policy registration. Reports never assert complete real-world collection;
`partial` and `no_coverage` describe collection limitations and late entries may
still contribute earlier-year counts. Approved payloads and replay results use
byte-preserving storage, not JSONB reserialization, so a replay cannot silently
change the artifact behind its digest.

### Workflow Database Grants

Use separate non-owner, non-superuser deployment logins with no inherited owner,
DDL, replication or trigger-bypass authority. Migrations revoke public table
access; they do not create deployment logins or grant production approval.

| Identity | Additional scope |
|---|---|
| API | SELECT policy/baseline; required workflow SELECT/INSERT and state-column UPDATE; append-only encrypted history INSERT; transactional replay/counter/report operations. No policy INSERT, narrative/history DELETE, evidence maintenance, or outbox delivery updates. |
| Policy operator | SELECT/INSERT policy and first baseline binding, legacy inventory reads, outbox INSERT. No workflow cleanup or evidence editing. |
| Workflow maintenance | Policy and workflow/hold reads, subject locks, restricted-history/association cleanup and erased-state updates, outbox INSERT. No user/role writes, policy writes, audit/ledger mutation or ledger-purge EXECUTE. |
| Publisher/signer | Existing Task 5.3/5.4 scopes only; no restricted workflow plaintext or keys. |

Restrict mutable columns rather than granting table-wide rewriting where possible.
Keep report payload/provenance and history immutable. Verify the actual login's
privileges and membership paths, not only grants shown for a group role. Run the
mandatory `identity-api:test-legal-workflow-integration` target against disposable
PostgreSQL, Redis and JetStream; it must not skip missing dependencies.

Validate redaction for these routes at ingress/APM as well as application logs.
The application deliberately omits whole-response hashes and case correlations
from their general audit projection. Alert on overdue reviews, policy failures,
eligible-but-unremoved metadata, key failures and audit backlog, using only
bounded codes and aggregate counts. Production approval, actual numeric policy,
real deployment grants and restore/privacy drills remain external release gates.

The inherited `ADMIN_REQUEST_TIMEOUT` bounds the whole administrative operation
(5 seconds by default, at most 10), including permission/lock waits and audit
commit. Legal case input is capped at 100 historically associated subjects and a
32 KiB encrypted-history plaintext envelope. Detail history is bounded to 200
events and 1 MiB of decrypted input, with `history_truncated` when omitted; it is
not an unbounded document/archive export.

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
- There is no purge-routine owner under canonical format v2. `advance_chain_head`
  is SECURITY DEFINER and deployed owned by the schema owner; re-owning it to a
  dedicated NOLOGIN role (see First-Time Provisioning) is optional hardening. No
  runtime login may inherit, or `SET ROLE` to, whichever role ends up owning it.
  `NOINHERIT` alone is not enough: remove membership paths.
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
  passes. It performs the same locked eligibility and checks but rolls back the
  deletion, the erasure-span records and the outbox receipt, reporting
  `would_delete`.

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
3. Apply additive schema `00015` using the migration identity. **This migration
   is forward-only and its `Down` refuses**, matching 00008 and 00011: reverting
   would reinstate a format whose digests nothing can recompute and would drop the
   chain and erasure tables that are the only surviving record of what was already
   erased. Confirm both ledgers are empty before applying, since 00015 rebuilds
   their payload tables.
4. Provision the separate runtime roles and narrowly scoped grants (First-Time
   Provisioning SQL), then explicitly initialize **both** chain heads from each
   verified terminal record. Genesis is allowed only for a demonstrably new ledger,
   not an unexplained empty table, and at sequence `0` the digest must be the
   chain's derived genesis seed. Normal migrations never initialize a head. A
   missing head after initialization is an error, not permission to restart the
   chain.
5. Validate effective privileges with actual disposable runtime logins, then audit
   deployed grants/ownership. API, signer and metadata cleaners must not be able to
   erase. Worker attempts at chain/head/erasure mutation, `UPDATE`/`TRUNCATE` on the
   payload, `SET ROLE`, trigger/role alteration and search-path/GUC bypass must all
   fail. Verify the worker's startup probe rejects each of those already-granted,
   and that it refuses a disarmed trigger.
6. Start only compatible signer/API binaries; prove online append, durable-head
   advancement and chain verification, including signer restart after an erased
   span and after **every** payload has been erased in disposable fixtures.
   Routine operation coordinates by short transaction locks, not the signer's
   daemon-lifetime lock. Old signer binaries must never run against a v2 schema:
   they write a `chain_hash` column that no longer exists.
7. Run bounded dry-runs using the packaged worker and production-scoped login.
   Compare eligibility and hold behavior to the inventory. Validate timeout,
   overlap, failure exit/logging and rollback of the erasure records and outbox
   receipt. Confirm that no dry-run is counted as committed deletion.
8. Demonstrate acknowledged maintenance outbox delivery with the compatible
   `admin-audit-publisher` and signer using a disposable destructive fixture.
   Prove publisher outage leaves durable retryable intent and replay creates no
   duplicate signed receipt. Confirm a purge still verifies **after** the receipt
   has been chained. Validate restore/forward-recovery drills and alert routing.
   Only after sign-off set dry-run false and enable the hourly host job.

### Routine Authority Contract

Under canonical format v2 there is **no purge routine**. Erasure is an ordinary
bounded `DELETE` executed by the separately credentialed worker, so the authority
contract is a privilege contract rather than a function-ownership contract.

| Surface | Runtime authority |
|---|---|
| `public.security_event_ledger` | `identity_ledger_purge` holds `SELECT` and `DELETE`. Nothing else may delete, and nobody may `UPDATE` (the trigger rejects it), including on columns. |
| `public.security_ledger_erasures` | `identity_ledger_purge` holds `SELECT` and `INSERT`. Append-only for everyone. |
| `public.event_outbox` | `identity_ledger_purge` holds `INSERT` only, for its receipt. |
| `public.security_ledger_chain`, `public.audit_log_chain` | No runtime role holds any write privilege. Append-only for everyone, with no maintenance exemption. |
| `public.advance_chain_head(text,bigint,bigint,bigint,bigint)` | Only the signer may execute. SECURITY DEFINER, pinned `search_path`, PUBLIC EXECUTE revoked. |

The worker's startup probe refuses to run unless all of the following hold, so an
over-provisioned role fails closed at boot rather than at the first erasure:

- `current_user = session_user` and the login is `identity_ledger_purge`;
- no superuser, `CREATEROLE`, `CREATEDB`, `REPLICATION`, `BYPASSRLS`, no role
  membership, no `CREATE` on the schema or database;
- `DELETE` on the payload, `INSERT` on the erasure index and outbox — and
  **nothing** on either chain table, the heads, `advance_chain_head`, or any
  `UPDATE`/`TRUNCATE`/`TRIGGER` on the payload or erasure index;
- both immutability triggers on the payload and both append-only triggers on the
  chain are enabled (`tgenabled IN ('O','A')`), because erasure is only bounded
  while the guards are armed;
- the configured receipt subject is provisioned in
  `security_ledger_retention_settings`.

Eligibility is re-decided under the account advisory locks, and the `DELETE`
restates every predicate: `retain_until < cutoff`, `seq <= highwater`, and no
active hold on the original `account_ref`. A short row count aborts the whole
transaction rather than recording an erasure span that does not describe what was
removed — a wrong span would make a retained payload look lawfully erased.

The transaction is READ COMMITTED with `lock_timeout='2s'` and
`statement_timeout='15s'`, batches are capped at 5000, and the erasure, its span
records and its outbox receipt commit together. Rollback is therefore a
full-fidelity dry run.

Emergency disablement, executed by the controlled database operator after
disabling the host schedule:

```sql
REVOKE DELETE ON public.security_event_ledger FROM identity_ledger_purge;
REVOKE INSERT ON public.security_ledger_erasures FROM identity_ledger_purge;
```

Verify both grants are absent and wait for or stop any in-flight worker before
changing deployments. Do not revoke signer advancement as a substitute for
disabling purge, and do not grant any right on the chain tables during rollback:
the chain rows are the only surviving record of what was already erased.

### First-Time Provisioning SQL

Run the following in an authenticated `psql` operator session connected to the
target database after `00015`, with the signer drained and the schedule disabled.
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

-- Canonical format v2 (migration 00015).
--
-- There is no maintenance-owner role here and no SECURITY DEFINER purge routine
-- to own. Erasure is an ordinary DELETE on the payload table, so the authority
-- question is a plain privilege question, and the purge login is given exactly
-- three write rights: DELETE on the payload, INSERT on the erasure index, and
-- INSERT on the outbox for its receipt. It holds nothing at all on the chain
-- tables, which is what keeps a retention purge from being able to remove
-- tamper-evidence.
BEGIN;
CREATE ROLE identity_ledger_purge LOGIN NOINHERIT NOSUPERUSER
    NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

REVOKE CREATE ON SCHEMA public FROM PUBLIC,
    :"signer_role", :"api_role", :"metadata_role";
REVOKE CREATE ON DATABASE :"ledger_database" FROM PUBLIC,
    :"signer_role", :"api_role", :"metadata_role";
GRANT CONNECT ON DATABASE :"ledger_database" TO identity_ledger_purge;
GRANT USAGE ON SCHEMA public TO identity_ledger_purge, :"signer_role", :"api_role";

-- Nothing but the signer may append, and nothing may ever mutate the chain.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
    ON public.security_ledger_chain, public.audit_log_chain,
       public.security_ledger_head, public.audit_log_head,
       public.security_ledger_erasures, public.security_ledger_retention_settings
    FROM PUBLIC, identity_ledger_purge, :"signer_role", :"api_role", :"metadata_role";
REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
    ON public.security_event_ledger, public.mvp_audit_logs
    FROM PUBLIC, identity_ledger_purge, :"signer_role", :"api_role", :"metadata_role";
REVOKE INSERT ON public.security_event_ledger, public.mvp_audit_logs
    FROM identity_ledger_purge, :"api_role", :"metadata_role";
REVOKE ALL ON FUNCTION public.advance_chain_head(text, bigint, bigint, bigint, bigint)
    FROM PUBLIC, identity_ledger_purge, :"api_role", :"metadata_role";

-- Purge worker: read what it must decide on, erase payloads, record the erasure.
GRANT SELECT ON public.security_event_ledger, public.security_ledger_chain,
    public.security_ledger_head, public.security_ledger_erasures,
    public.legal_holds, public.security_ledger_retention_settings
    TO identity_ledger_purge;
GRANT DELETE ON public.security_event_ledger TO identity_ledger_purge;
GRANT INSERT ON public.security_ledger_erasures TO identity_ledger_purge;
GRANT INSERT ON public.event_outbox TO identity_ledger_purge;

-- Signer: append to both chains and both payloads, and advance a head only
-- through the verifying routine. It deliberately holds no direct UPDATE on the
-- head tables, so it cannot set a head to an arbitrary value.
GRANT SELECT, INSERT ON public.security_event_ledger, public.security_ledger_chain,
    public.mvp_audit_logs, public.audit_log_chain TO :"signer_role";
GRANT USAGE ON SEQUENCE public.security_ledger_chain_seq, public.audit_log_chain_seq
    TO :"signer_role";
GRANT SELECT ON public.security_ledger_head, public.audit_log_head TO :"signer_role";
GRANT EXECUTE ON FUNCTION public.advance_chain_head(text, bigint, bigint, bigint, bigint)
    TO :"signer_role";

-- API: read-only, for the gated verification and disclosure routes.
GRANT SELECT ON public.security_event_ledger, public.security_ledger_chain,
    public.mvp_audit_logs, public.audit_log_chain,
    public.security_ledger_head, public.audit_log_head,
    public.security_ledger_erasures TO :"api_role";

ALTER ROLE identity_ledger_purge IN DATABASE :"ledger_database" SET statement_timeout = '15s';
ALTER ROLE identity_ledger_purge IN DATABASE :"ledger_database" SET lock_timeout = '2s';
COMMIT;
```

**Recommended additional hardening.** `advance_chain_head` is SECURITY DEFINER
and is owned by whichever role ran the migration — normally the schema owner,
which already owns the tables and triggers, so this grants it nothing new. A
tighter deployment re-owns it to a dedicated NOLOGIN role so that replacing the
function would require compromising a principal that can do nothing else:

```sql
CREATE ROLE identity_chain_head_owner NOLOGIN NOINHERIT NOSUPERUSER
    NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT USAGE ON SCHEMA public TO identity_chain_head_owner;
GRANT SELECT ON public.security_ledger_chain, public.audit_log_chain
    TO identity_chain_head_owner;
GRANT SELECT, UPDATE ON public.security_ledger_head, public.audit_log_head
    TO identity_chain_head_owner;
ALTER FUNCTION public.advance_chain_head(text, bigint, bigint, bigint, bigint)
    OWNER TO identity_chain_head_owner;
```

A migration must never create or empower a role, which is why this is an operator
step rather than part of 00015. `internal/retentiondbintegration` asserts the
properties that do not depend on it: SECURITY DEFINER, a pinned `search_path`,
and no PUBLIC EXECUTE.

Do not give the worker a chain-table grant, a sequence grant, or EXECUTE on
`advance_chain_head`. Its startup probe refuses to run if it holds any of them,
so an over-provisioned worker fails closed at boot rather than at the first
erasure. Deployment roles must have no
inherited ownership/CREATE/bypass grants either; the REVOKEs above do not remove
indirect grants through other roles. Provision the worker's SCRAM credential with
`\password identity_ledger_purge` in the controlled session (or the approved
secret-provisioning path), then deliver it through Infisical and require TLS in
deployed connections. Do not put a password in SQL, shell history or this document;
do not use a trust-authenticated database endpoint for the worker.

### Explicit Head and Subject Bootstrap

This is a one-time initialization, not a repair routine. **Both chains need a
head** under canonical format v2: the audit chain no longer infers its tip from
the table, because the v2 split makes a Class C purge possible and "the table
looks empty" must therefore stop meaning "this chain has never been written".

First verify canonical history independently with the signer stopped and record
the exact terminal sequence/digest for each chain. Replace the placeholders below
with that verified result. The SQL cross-checks the current terminal but does not
itself certify the entire historical chain.

For a demonstrably new ledger only, set sequence `0` with
`confirmed_fresh_genesis=true`; the default false flag forbids inferring genesis
from an empty table. At sequence `0` the digest must be the chain's **derived
genesis seed**, which the `CHECK` constraints enforce:

| Chain | Genesis digest |
| --- | --- |
| `security_ledger_head` | `6ece92219999993f2dc5b43d677c333fa6836745079b919355360170f3ea2c54` |
| `audit_log_head` | `5c358544585235f7ae29b4a8370d5541ddd6bd40c81321fc92bbb54b31887ebb` |

These are `SHA-256(chain_prefix || "genesis")`, not 32 zero bytes. v1 used zeros,
which made a blanked or default-initialized column indistinguishable from a real
genesis — so blanking a predecessor could pass a forged record off as the first
one. `internal/audit.GoldenAuditGenesisHex` / `GoldenLedgerGenesisHex` hold the
same constants, and `internal/migrate.TestGenesisMatchesMigration` asserts the
schema and the code agree.

Do not reset sequence allocation state or use this procedure after restoring an
initialized chain.

```sql
\set ON_ERROR_STOP on
\set ledger_head_seq 'VERIFIED_LEDGER_TERMINAL_SEQUENCE'
\set ledger_head_hash 'VERIFIED_LEDGER_TERMINAL_SHA256'
\set audit_head_seq 'VERIFIED_AUDIT_TERMINAL_SEQUENCE'
\set audit_head_hash 'VERIFIED_AUDIT_TERMINAL_SHA256'
\set confirmed_fresh_genesis false
\set audit_subject 'identity.audit.logs'
\set ledger_genesis '6ece92219999993f2dc5b43d677c333fa6836745079b919355360170f3ea2c54'
\set audit_genesis '5c358544585235f7ae29b4a8370d5541ddd6bd40c81321fc92bbb54b31887ebb'

BEGIN ISOLATION LEVEL READ COMMITTED;
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '15s';
SELECT pg_advisory_xact_lock(5200002::bigint);
SELECT pg_advisory_xact_lock(5200003::bigint);
-- SHARE MODE on the chain tables: they are what a terminal claim is checked
-- against, and they are the tables that must not gain a row mid-bootstrap.
LOCK TABLE public.security_ledger_chain, public.audit_log_chain IN SHARE MODE;

WITH initialized AS (
    INSERT INTO public.security_ledger_head(singleton, seq, chain_hash)
    SELECT true, :'ledger_head_seq'::bigint, decode(:'ledger_head_hash', 'hex')
    WHERE NOT EXISTS (SELECT 1 FROM public.security_ledger_head)
      AND NOT EXISTS (SELECT 1 FROM public.security_ledger_erasures)
      AND NOT EXISTS (SELECT 1 FROM public.security_ledger_retention_settings)
      AND (
        (:'ledger_head_seq'::bigint > 0 AND EXISTS (
            SELECT 1 FROM public.security_ledger_chain
            WHERE seq = :'ledger_head_seq'::bigint
              AND chain_hash = decode(:'ledger_head_hash', 'hex')
              AND seq = (SELECT max(seq) FROM public.security_ledger_chain)
        ))
        OR (:'confirmed_fresh_genesis'::boolean AND :'ledger_head_seq'::bigint = 0
            AND :'ledger_head_hash' = :'ledger_genesis'
            AND NOT EXISTS (SELECT 1 FROM public.security_ledger_chain))
      )
    RETURNING singleton
), audit_initialized AS (
    INSERT INTO public.audit_log_head(singleton, seq, chain_hash)
    SELECT true, :'audit_head_seq'::bigint, decode(:'audit_head_hash', 'hex')
    WHERE NOT EXISTS (SELECT 1 FROM public.audit_log_head)
      AND (
        (:'audit_head_seq'::bigint > 0 AND EXISTS (
            SELECT 1 FROM public.audit_log_chain
            WHERE seq = :'audit_head_seq'::bigint
              AND chain_hash = decode(:'audit_head_hash', 'hex')
              AND seq = (SELECT max(seq) FROM public.audit_log_chain)
        ))
        OR (:'confirmed_fresh_genesis'::boolean AND :'audit_head_seq'::bigint = 0
            AND :'audit_head_hash' = :'audit_genesis'
            AND NOT EXISTS (SELECT 1 FROM public.audit_log_chain))
      )
    RETURNING singleton
)
SELECT (SELECT count(*) FROM initialized) = 1
   AND (SELECT count(*) FROM audit_initialized) = 1 AS head_initialized \gset
\if :head_initialized
INSERT INTO public.security_ledger_retention_settings(singleton, audit_subject)
    VALUES (true, :'audit_subject');
COMMIT;
\else
ROLLBACK;
DO $$ BEGIN
    RAISE EXCEPTION 'Bootstrap refused: existing head/erasures/settings, terminal mismatch, or unapproved genesis.';
END $$;
\endif
```

Both heads are initialized in one transaction on purpose. Initializing one and
not the other leaves the signer able to append to a chain whose counterpart it
cannot establish a tip for, which it refuses — so a partial bootstrap presents as
a signer that will not start, with no indication of which half is missing.

The selected subject must match `AUDIT_SUBJECT` on worker, publisher and signer.
Keep the schedule disabled while validating deployed ACLs with `psql` metadata
(`\du+`, `\dp`, `\df+`) and the worker's startup probe.

Privilege audit. Every result in the first query must be `false`; every
`can_erase` and `can_record` must be `true`; and every `can_write_chain` must be
`false`:

```sql
-- Nothing but the signer may execute head advancement, and a head can only move
-- through linkage verification.
SELECT role_name,
    has_function_privilege(role_name,
        'public.advance_chain_head(text,bigint,bigint,bigint,bigint)', 'EXECUTE') AS can_advance
FROM (VALUES ('identity_ledger_purge'), (:'signer_role'),
    (:'api_role'), (:'metadata_role')) AS roles(role_name);

-- The worker may erase payloads and record that it did, and nothing more.
SELECT has_table_privilege('identity_ledger_purge', 'public.security_event_ledger', 'DELETE') AS can_erase,
       has_table_privilege('identity_ledger_purge', 'public.security_ledger_erasures', 'INSERT') AS can_record,
       has_table_privilege('identity_ledger_purge', 'public.event_outbox', 'INSERT') AS can_receipt;

-- No runtime role, including the worker, may touch tamper-evidence.
SELECT role_name, table_name,
       has_table_privilege(role_name, table_name, 'INSERT,UPDATE,DELETE,TRUNCATE') AS can_write_chain
FROM (VALUES ('identity_ledger_purge'), (:'signer_role'), (:'api_role'), (:'metadata_role')) AS roles(role_name)
CROSS JOIN (VALUES ('public.security_ledger_chain'), ('public.audit_log_chain'),
    ('public.security_ledger_erasures'), ('public.security_ledger_head'), ('public.audit_log_head'))
    AS tables(table_name)
WHERE has_table_privilege(role_name, table_name, 'INSERT,UPDATE,DELETE,TRUNCATE');

-- The payload is immutable for everyone: this must report 0 rows.
SELECT role_name FROM (VALUES ('identity_ledger_purge'), (:'signer_role'),
    (:'api_role'), (:'metadata_role')) AS roles(role_name)
WHERE has_table_privilege(role_name, 'public.security_event_ledger', 'UPDATE')
   OR has_any_column_privilege(role_name, 'public.security_event_ledger', 'UPDATE');

-- Both immutability and append-only guards must be armed, or erasure is unbounded.
SELECT c.relname, t.tgname, t.tgenabled
FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
WHERE t.tgname LIKE 'trg\_%' AND c.relname IN
      ('security_event_ledger', 'security_ledger_chain', 'audit_log_chain', 'mvp_audit_logs')
ORDER BY c.relname, t.tgname;
```

Check effective role membership, function ACL recipients/owners and safe search
paths, database/schema CREATE, table ownership, `session_replication_role` SET
privileges and the real-role denial matrix before destructive enablement. Never
turn a failing probe into success by broadening the worker's grants. These
operator SQL examples mirror what `internal/retentiondbintegration` asserts
against disposable databases; their deployment execution and the full history
assessment remain explicit release gates.

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
IDs, blind indexes, network/device metadata or legal narratives. The transactional
`admin_action` receipt is delivered on the configured
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

Disable the schedule and follow the existing [emergency disablement](#routine-authority-contract)
for payload `DELETE` and erasure-index `INSERT`, then stop/wait for in-flight work
and assess committed/uncertain outcomes. Canonical v2 has no purge routine or
purge `EXECUTE` grant to revoke. Preserve both heads, the chain tables, the erasure
index, holds, settings and outbox intent. Revocation alone does not cancel a
statement already executing; confirm the worker has stopped before declaring
purge disabled.

Keep signer and verifier binaries compatible with canonical-v2 storage throughout
rollback. Pre-v2 binaries expect the retired payload/`chain_hash` layout and are
not a recovery path. Treat initialized proof state and erasure as forward-only;
repair with a compatible release, never downgrade storage or rewrite stored
hashes. Migration `00015` refuses Down unconditionally, including against a
seemingly empty database, and `00011` does the same.

Restore the chain tables, both heads, the erasure index, holds and outbox from one
consistent backup, validate before reopening ingestion or purge, reconcile
authoritative holds/deletions, then resume eligible expiry without resetting clocks
or bypassing holds. A restore that includes `security_ledger_chain` but predates
`security_ledger_erasures` will report every erased span as tampering, so verify
the pair together. Backup rotation remains independent. See
[disaster recovery](disaster-recovery.md#33-security-ledger-retention-recovery).
Neither a database-relative proof nor a Class C receipt independently detects a
coherent database rewrite or rolled-back backup. External anchoring remains
deferred; Task 5.3 deployment sign-off and Task 5.5 narrative-retention approval
and cleanup are not satisfied by this worker.
