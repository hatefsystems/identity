# Admin and Ledger Retention Operations

The implementation remains opt-in. This document describes conditional runtime contracts and outstanding release gates, not production sign-off. The active inventory is `.kilo/plans/1793976266705-preproduction-cleanup-launch-hardening.md`; prior technical-closure and panel plans and their dated evidence remain historical. Existing task statuses are unchanged; they do not certify the current bundle. Fresh final-source evidence and the independently unchecked production/manual gates below remain required.

Active schema installation follows the unchanged baseline plus additive registration
migration contract below. Dated acceptance records
and prior plans retain their original migration evidence unchanged; they do not
certify this bundle. New acceptance must be recorded separately only after actual
final runs satisfy [current requirements](#automated-validation).
This documentation update changes no task status or production authorization.

## Enablement

1. Inventory schema/history first using the migration identity and follow [setup](#migration-and-contraction). Apply unchanged `00001_initial_schema.sql` plus additive `00002_registration_attempts.sql` only to a separately approved scoped target, tracked through version 2 in `public.identity_schema_version`. All legacy `public.goose_db_version`, untracked nonempty schemas and contradictory histories are refused. No instruction here authorizes live mutation, resets, adoption, genesis reset or hash rewriting.
2. Deploy account-version-aware issuers on **every** instance and restart old process-local credential stores before moderation is enabled. Ban, suspension, deletion and reactivation advance persistent versions. Old sessions, codes, refresh tokens and step-up grants cannot regain validity. Task 6.2's `ValidateToken` checks that version and live Redis authority; downstream clients using offline JWT verification still retain the configured lifetime, at most ten minutes.
3. Inject one KEK/version and one blind-index pepper/version through the approved secret delivery mechanism. The adapter holds loaded keys locally, with no live Infisical fetch/cache/hot rotation or historical multi-key reader. Hold encryption is independent of attribution; SMS uses its separate required OTP HMAC pepper only when enabled. Preserve retired backup keys and coordinated recovery/rotation obligations. Exact `APP_ENV=development|test|production` is mandatory; test is not development.
4. Verify final encrypted-or-legitimately-purged legal storage and actual key/data inventory before intake. Obsolete legal Backfill/plaintext compatibility is removed; unexpected layouts fail closed. Retain key recovery and consistent backups; startup crypto readiness is not a full real-data/key inventory or restore proof.
5. Obtain approved numeric `ADMIN_CONTEXT_RETENTION` and `ADMIN_LEGAL_RELEASED_RETENTION` durations and approval for opaque replay tombstones. There are no policy defaults. Schedule `admin-audit-publisher --cleanup-contexts` and `admin-legal --operation=cleanup` with separate maintenance credentials. Both use hold-aware deletion; released holds resume original clocks. Neither command deletes ledger evidence.
6. Run the signer and `admin-audit-publisher` on the same configured audit subject with separately scoped non-owner logins. Publication requires JetStream acknowledgement; it is not proof of chaining. Signer event-ID deduplication covers redelivery after uncertain acknowledgement. The separate Task 6.3 lifecycle publisher owns deletion-event delivery, not the admin publisher.
7. With affected intake closed, run `NX_DAEMON=false npm exec -- nx run identity-api:admin-legal -- --operation=lookup-probe` against the **real deployed signer**, actual schema and configured keys. It creates a credential-free synthetic account, publishes a legacy envelope without a producer index, verifies the signer's stored index, deletes only that synthetic account, and verifies the fixture again after deletion. Canonical v2 resolves the fixture event UUID through `security_ledger_chain.event_id`, joining the payload by `seq`, while retaining the synthetic client/event checks and constant-time expected-index comparison. Capture the printed `ADMIN_LOOKUP_FIXTURE_ID` privately and configure every API replica with it. A timeout leaves the identified synthetic account for controlled diagnosis; never substitute a real person's identifier or delete unrelated evidence. A supplied absent/wrong fixture or mismatched key fails startup/readiness; omitting the setting explicitly keeps attribution unavailable while hold/preservation may remain independently usable. Repeat after signer/key deployment changes and keep the existing pepper pinned. Injecting `WithLookup(..., true)` is not equivalent evidence. The probe is neither a chain trust anchor nor proof of complete historical indexing.
8. Configure exact HTTPS `ADMIN_ALLOWED_ORIGINS`, Redis actor/subnet limits and timeouts. Set `ADMIN_ENABLED=true` only after the existing governance, authenticated smoke-test and deployed-ingress gates are satisfied. Startup requires DB, Redis, encryption, audit delivery configuration and approved retention. Readiness probes dependencies; missing step-up leaves mutations and attribution unmounted, not ungated. The Task 7.5/7.6 panels have their own acceptance and rollout gates below; this runbook does not authorize enablement.

## Migration and Contraction

The heading is retained for existing links; installation no longer performs a
staged legacy contraction. The active bundle is unchanged
`00001_initial_schema.sql` plus additive `00002_registration_attempts.sql`.
`migrate up` applies through version 2 in **`public.identity_schema_version`**, not
`public.goose_db_version`. Future changes use `00003` and later bundled
migrations in this new lineage; generic `up-to` is not an old-lineage escape hatch.

Before any migration mutation, the guarded wrapper performs fail-closed read-only
inventory and repeats it under lock-held exclusion. It refuses **all** legacy
`public.goose_db_version` relations regardless of version, row count or apparent
schema equivalence, including old version 1, intermediate history and old version
20. It also refuses both history tables, an untracked nonempty application schema,
malformed relation/column shapes and contradictory new histories. New history
requires exactly one applied zero, unique known versions with true applied flags,
and baseline 1 before later applied versions; zero-row bookkeeping, missing zero,
duplicates, false flags and unknown versions are rejected. Extension-owned objects
and legitimate new tracking-table-owned objects are not leftover application
schema. A valid applied-zero-only history permits retry only with no application
schema. No target is automatically stamped, renamed, cleared, reset or adopted.

Use this procedure with compatible binaries and separately controlled migration
credentials:

1. Identify the exact fresh PostgreSQL 16 database and matching fresh Redis 7/NATS
   JetStream 2.10 resources or isolated service namespaces. Record their ownership
   and isolation; do not assume default Compose names/volumes are fresh. All existing
   Identity data was confirmed disposable, but that is **not** authorization to
   reset an existing named environment. Any reset requires a separate explicit
   request identifying its exact disposable targets. Never run broad volume deletion
   or shared-database schema reset commands.
2. Close affected intake and stop/drain **all old writers**, including API replicas,
   signers, publishers and maintenance workers, before switching. Inventory old
   outbox/broker envelopes separately and retain required keys, backups and original
   clocks. Old sessions/grants, queued events and consumer checkpoints must not
   enter the replacement database. Schema setup does not convert envelopes or change
   wire formats; use compatible consumers and reconcile their isolated baselines.
3. Set the scoped migration `DATABASE_URL`; run `migrate status` then `migrate up`
   (Nx: `identity-api:migrate-status`, `identity-api:migrate-up`). Public status/version
   inspection is read-only and creates no bookkeeping on a fresh target. Verify
   applied version 2 and the new history table; repeated `up` must be a verified
   no-op. A failed baseline transaction leaves no partial application objects or
   applied version-1 record. Migration-2 failure must leave version 1 valid/retryable
   without partial registration objects. Do not bypass refusal to force a retry.
4. Verify final constraints, indexes, effective privileges and exact head advancement:
   observed terminal sequence equals declared `last_seq`, pinned search path/PUBLIC
   revocation remain, audit coordination is `5200004`, ledger coordination `5200002`,
   purge-run lifetime `5200003`. `legal_holds` has no `reason`, `requesting_authority`
   or `legal_basis` columns; ciphertext absence is permitted only for legitimately
   released/purged tombstones. No plaintext fallback or historical data repair is
   an installation step.
5. Provision restricted deployment roles/grants, approved governance and **both**
   explicit genesis heads/subject settings through the operator procedures below.
   The baseline seeds only 4 roles, 13 permissions and 15 role-permission assignments,
   not users, operator grants, heads, runtime history, retention or policy bindings.
   Complete key inventory, real signer probing and existing approval/readiness gates
   before compatible replicas/callers reopen. Keep destructive schedules disabled
   until separately approved.

Baseline `Down` refuses unconditionally; `reset`/`down-to 0` refuse before undoing
even a later migration. No up/down/up reset is supported. Keep historical acceptance
and prior plan files unchanged; they are evidence for their original sources, not
this baseline. Automated tests provision and clean up only run-owned resources,
never named developer/shared environments.

Legacy Backfill commands in dated records are not supported operations in this
bundle. Do not recreate plaintext columns, convert legacy history, stamp metadata
or reset a laboratory environment to make it acceptable. Existing version-1
new-lineage state may advance to reviewed migration 2 only with separately scoped
authorization; this is not permission to adopt an old lineage.

## Production Checklist

Every item remains unchecked here. Local automated acceptance can close a defined
implementation task, never these production/governance/manual authorizations.

- [ ] Approve numeric baseline/workflow/Class B/Class C policies and the actual
  personal/pseudonymous inventories and lifetimes, including `no_expiry` residuals,
  legal basis, privacy notices, ROPA/DPIA and truthful DSAR responses.
- [ ] Inventory real data, ciphertext/key versions, retained backup keys and recovery
  material; verify final encrypted storage and consistent forward recovery. Fresh
  setup never adopts legacy history or exposes obsolete Backfill.
- [ ] Install real externally approved policy through the restricted trusted
  installer and provision operators from an authenticated MFA-protected launcher.
  Environment actor/SPIFFE strings alone are not authentication.
- [ ] Validate effective deployed non-owner grants, PUBLIC/column/sequence ACLs,
  ownership/membership/SET ROLE paths, RLS/subject scoping, armed guards and separate
  API/signer/publisher/purge/maintenance/reconciliation secrets.
- [ ] Close/drain affected intake and coordinate compatible migration, all replicas,
  callers, open forms and v1 envelope inventory before reopening; preserve accepted
  intent, original clocks and rollback compatibility.
- [ ] Run the real deployed signer lookup probe with actual schema/keys, privately
  provision its fixture, and verify authenticated post-deletion attribution.
- [ ] Prove acknowledged outbox delivery, signer dedup/restart and separately
  reconciled chained receipts/manifest coverage; pending intent/PubAck is not chaining.
- [ ] Verify ingress/API/worker/APM redaction with synthetic sensitive sentinels,
  including rejected paths/queries and operator diagnostics.
- [ ] Perform bounded scoped-login dry-runs, consistent deployed restore/forward-
  recovery drills, hold/deletion reconciliation and key recovery without data wiping.
- [ ] Connect aggregate backlog/age/due-review/publisher/failure signals to monitoring
  with approved thresholds and incident ownership; explicitly authorize destructive
  scheduling only after the other gates are satisfied.
- [ ] Complete manual assistive-technology, physical-authenticator, native-browser
  zoom/hidden-tab/bfcache and actual-ingress checks not observed by automated suites.
- [ ] Approve live SMS.ir key/template/parameter, Iranian routing, egress/spend limits
  and an explicitly authorized handset receipt; sandbox success is not delivery.
- [ ] Approve Unicode-mailbox SMTPUTF8 submission, temporary registration retention
  and admission budgets; verify dedicated cleanup supervision before enablement.

## Operator role provisioning

Use `npm exec -- nx run identity-api:admin-roles -- --user-id=<uuid> --role=<role>`; add `--revoke` for revocation. Roles are `super_admin`, `moderator`, `support`, `dpo`. The command first loads the installed baseline (optionally pinned by `ADMIN_GOVERNANCE_POLICY_ID`), validates `APP_ENV`/fixture policy and derives context retention from it. Explicit `ADMIN_CONTEXT_RETENTION` or `ADMIN_LEGAL_RELEASED_RETENTION` mismatch, or absent policy, refuses before role/context/outbox changes. Provisioning rechecks the baseline and context retention in the transaction. Install policy separately first; no pre-baseline unaudited provisioning exception exists. A grant requires an active account with an enrolled passkey or enabled MFA. Revocation works for inactive targets too. Changes serialize with moderation and commit encrypted target reference plus durable audit intent; retries are audited no-ops, and old context expiries are never rewritten.

Run from an authenticated, MFA-protected operator environment with separately scoped `DATABASE_URL`. Its trusted launcher supplies `ADMIN_OPERATOR_ID` and `ADMIN_OPERATOR_SPIFFE_ID` from the authenticated identity. These environment values are **attribution, not authentication**; arbitrary callers must not control the launcher or database credentials. Provisioning approval remains an organizational control. No HTTP route assigns roles, no unaudited one-row bootstrap is documented, and no two-person HTTP workflow is claimed.

Initial operator enrollment uses the ordinary approved registration/passkey flow,
which grants no role or session. Policy installation and an approved role grant
under the trusted launcher are separate actions, never migration seeds or a default
admin account. `admin-roles` is a separately built/checksum-attested operator
artifact, not assumed present in the application image. DB-only operator/cleanup
paths must not require unrelated OIDC/SMS/NATS secrets; help remains independent.

## Admin Control Panel (Task 7.5)

Task 7.5 supplies `/admin`, `/admin/users`, `/admin/users/[id]`, `/admin/audit-logs`, and `/admin/integrity` within the existing Next app. Task 7.6 adds the separate `/admin/legal` workspace described below. Neither enables production admin access, alters approved retention, or adds password-reset, role-management, bulk, administrative account-deletion or section 1.8 legal-workflow controls. The neutral dashboard entry performs no admin discovery until visited.

Session bootstrap precedes a durably audited capability read. Support gets safe account metadata; Moderator adds PII, exact body-only lookup and status changes; DPO gets audit search and both verifiers; Super Admin gets only the two content-free verifiers. Combined grants expose their union. The fixed capability response is presentation metadata, not authority: every operation checks current primary-database permissions, and every disclosure remains behind the durable-audit boundary. A denied admin capability must not sign out a valid ordinary account session.

`POST /api/v1/admin/users/lookup` additionally returns mandatory
`canonical_email` with its selected user. The browser must validate the returned
row's email against that exact server canonical value before displaying/selecting
it, and use it for the lookup-to-moderation pin. No ASCII-only or raw-input fallback
is permitted. This additive response field is sensitive display metadata, not a
new disclosure permission, profile resolver or browser blind-index input.

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

- Enter the bare email, authority, case reference, purpose, explicit UTC bounds and selected fields only after fresh verification. Server canonical identity is NFC/local lowercase/NFC plus strict IDNA lowercase domain; the email-specific HMAC input uses those exact bytes, without generic BlindIndex's second NFKC pass. Do not hash locally or introduce provider alias rules. Phone/backup-email and live-profile resolution are not offered. The entered email is transient sensitive input, not returned evidence.
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

The [Task 7.6 validation inventory](devops-operations.md#dpolegal-panel-task-76) requires source-specific automated results, sanitized evidence and confirmed cleanup. The local acceptance below does not close manual or production gates. Manual screen-reader, physical-authenticator, native zoom, hidden-tab/bfcache and deployed-ingress checks remain open when unobserved. Keep production `ADMIN_ENABLED` and governance unchanged; do not enable `LEGAL_WORKFLOW_ENABLED` to ship this panel. Baseline approval, encrypted storage/key inventory, real non-owner DB grants, approved narrative/replay/ledger retention, signer/publisher delivery, exact-origin/APM redaction, privacy notices, ROPA/DPIA/DSAR duties and Task 5.3/5.4/5.5 statuses remain separate operator gates. Phone attribution, multi-pepper rotation, Class C purge policy and external anchoring are not added.

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
| Admin publisher | Outbox SELECT/row locks and column UPDATE of `published_at`, `attempts`, `next_attempt_at`, `last_error`; enabled RLS with exact configured-subject/`admin_action` SELECT/UPDATE policies required by startup probe | Other table reads/writes, narrative keys, evidence/role writes, payload/subject/marker updates, PUBLIC/extra/widened policies or RLS bypass |
| Signer | Both payloads/chains SELECT + INSERT; chain-sequence USAGE; both heads and ledger erasures SELECT; validated `advance_chain_head` EXECUTE; users SELECT and UPDATE(`id`) for existing FK row locking | Payload/chain UPDATE/DELETE/TRUNCATE, direct head mutation, role/DDL authority, legal narratives; users column UPDATE remains SQL authority, not an enforced lock-only API |
| Operator | Target eligibility/credential and role access, account locks, outbox/context insertion | API network exposure; unrestricted evidence editing |
| Metadata maintenance | Hold checks, subject locks and bounded context/released-narrative cleanup | Ledger DELETE or trigger bypass |
| Ledger purge worker | Dedicated `identity_ledger_purge` login; payload `SELECT` + `DELETE`; erasure-index `SELECT` + `INSERT`; outbox `INSERT`; chain/head/hold/settings `SELECT` | Any write on chain, head or erasure index beyond the insert; payload `UPDATE`/`TRUNCATE`; sequence usage; `advance_chain_head` EXECUTE; role/trigger/schema changes; superuser or replication privileges |
| Receipt reconciliation | Separate SELECT-only login for `security_ledger_erasures`, `event_outbox`, `mvp_audit_logs`, `audit_log_chain`, `audit_log_head`; `LEDGER_RECEIPTS_DATABASE_URL` only | Purge DELETE, outbox/evidence writes, other table reads, sequences, narrative keys, role/DDL authority or fallback to purge/API credentials |
| Chain-head routine owner (optional) | `identity_chain_head_owner` NOLOGIN; `advance_chain_head` ownership with chain `SELECT` and head `SELECT`/`UPDATE` | Runtime login; membership granted to API/signer/worker; ownership of application tables/schema/database |

Repository migrations do not create deployment login roles or deploy RLS policies. Deployment/validation remains a release gate. The publisher startup probe now requires enabled `event_outbox` RLS and the exact two applicable role-specific SELECT/UPDATE policies described below, in addition to trusted subject/marker query predicates. Startup probes inspect effective PUBLIC/table/column/sequence privileges, ownership, membership/SET ROLE paths, database/schema CREATE, replication/trigger bypass and armed guards, not only group-role grants. All maintenance/signer/publisher/reconciliation identities are non-owner NOINHERIT logins without memberships. The trusted Go purge enforces retention/holds; ordinary DELETE is not a database-enforced policy boundary against compromised credentials. Protect backups, restricted context and all secret delivery paths.

### Publisher Row Scope

`ProbePublisher` requires `row_security=on`, table RLS enabled and exactly two
applicable permissive role-only policies: SELECT USING `admin_action AND subject`
equals the exact configured subject; UPDATE uses the identical USING and WITH
CHECK. PUBLIC, extra applicable, missing, widened or malformed policies fail.
The probe matches the canonical `pg_get_expr` form; arbitrary logically equivalent
expressions are not silently accepted. This is row isolation for publisher
delivery, not a SQL proof of purge retention/holds or receipt legal authorization.

Run controlled provisioning after auditing existing policies/ACLs; do not overwrite
conflicting policy names or reuse an owner login. Before enabling table-wide RLS,
provide reviewed policies for **every other non-owner outbox producer/consumer**,
including API/admin/lifecycle writes and publishers, purge receipt INSERT and
receipt-reader SELECT. Missing policies fail closed and can block accepted intent.
The following is the publisher-only portion, not complete outbox provisioning:

```sql
\set publisher_role 'DEPLOYED_ADMIN_PUBLISHER_ROLE'
\set audit_subject 'identity.audit.logs'
BEGIN;
GRANT SELECT ON public.event_outbox TO :"publisher_role";
GRANT UPDATE (published_at, attempts, next_attempt_at, last_error)
    ON public.event_outbox TO :"publisher_role";
ALTER TABLE public.event_outbox ENABLE ROW LEVEL SECURITY;
CREATE POLICY admin_publisher_read ON public.event_outbox FOR SELECT
    TO :"publisher_role" USING (admin_action AND subject=:'audit_subject');
CREATE POLICY admin_publisher_delivery ON public.event_outbox FOR UPDATE
    TO :"publisher_role" USING (admin_action AND subject=:'audit_subject')
    WITH CHECK (admin_action AND subject=:'audit_subject');
COMMIT;
```

Audit effective column grants as well: table REVOKE alone can leave column grants,
and table-wide UPDATE or payload/subject/marker UPDATE is prohibited. Verify the
actual publisher login can read/update only marked rows on the configured subject
and refuses a different configured subject or widened/missing RLS. Reconciliation
has its own SELECT-only credentials/policies; do not expand purge SELECT to receipt
material or give that login delivery/evidence mutation rights.

## Audit, logging and monitoring

Every successful privileged response is buffered until audit intent commits. Pre-commit audit failure withholds disclosure and rolls back business changes; `503 audit_unavailable` does not provide a usable result. If the store itself is down, durable recording of the rejection cannot be guaranteed. A lost/invalid response or post-commit `503 temporarily_unavailable` during session renewal can still follow accepted work: treat a transmitted write as unconfirmed, not guaranteed rollback. Alert on sanitized audit-storage categories, publisher pending count/age, increasing attempts/deferrals, signer reseed failures and invalid capture/key metadata. Diagnostics are fixed categories/counts, never raw upstream/DB errors, identifiers, narrative contents or rejected payloads. Claimed delivery is marked only after the expected JetStream acknowledgement; deferred/poison work must not prevent unrelated bounded progress. Approved quarantine/spool policy and alert thresholds remain operational gates.

Never capture admin query strings, bodies, cookies, DPoP proofs, step-up/`Idempotency-Key` headers, cursors, legal narratives/results or referrers in proxy/APM traces. Use static route templates for both `/admin` pages and `/api/v1/admin`, including rejected URLs and lookup requests; template account/hold identifiers rather than logging raw paths. The `account_ref` filter, hold-ID path and operation-ID header are allowed only on their exact authorized API requests, never diagnostics or navigation. The MVP Nginx example in the deployment guide uses an admin-specific log format and suppresses unsanitized error records. For the Traefik successor, disable access/debug/tracing capture unless its collector demonstrably emits only allowlisted method, template, status and duration. Verify synthetic sensitive values are absent from ingress, API, worker and artifact output; capture synthetic probe IDs only through the controlled private provisioning channel. Local route-template tests do not establish deployed collector compliance.

## Automated validation

### Current Bundle Requirements

Resolve fresh targets from the repository root using `npm exec -- nx show project
identity-api --json` and `npm exec -- nx show project web --json`. The mandatory
normal service matrix has exactly these seven identities:

| Required suite |
|---|
| `identity-api:test-security-db` |
| `identity-api:test-admin-integration` |
| `identity-api:test-retention-integration` |
| `identity-api:test-legal-workflow-integration` |
| `identity-api:test-grpc-integration` |
| `identity-api:test-lifecycle-integration` |
| `identity-api:test-portal-integration` |

Run one suite per owned-service cell with `max-parallel: 1`, `fail-fast: false`,
unchanged 30-minute target and 60-minute job deadlines, `-count=1`, `-p=1` and
mandatory dependency flags. Local exhaustive `--integration` and allowlisted
partial `--integration-target=<unqualified-target>` modes do not alter the frozen
seven identities. Only the exact-seven aggregate can satisfy the normal release
gate: matching source/generated fingerprints, nonzero package/test evidence,
zero failures/skips and verified cleanup are mandatory. Missing/stale/duplicate/
wrong-source/partial reports or zero exit without evidence fail the gate.

Seven affected race packages are a separate serial inventory: `internal/recovery`,
`internal/mfa`, `internal/oidc/clientauth`, `internal/adminaction`, `internal/smsotp`,
`internal/registration` and `internal/audit/signer`. Owned-service race mode uses
Linux CGO, `-json -tags=integration -race -count=1 -p=1 -timeout=20m` and a separate
exact-seven race aggregate; it cannot replace normal suite evidence.

Require final generated-tree reproducibility, lint/vet/typechecks/builds,
image/entrypoint/fixture-exclusion smoke and existing portal/admin/CSP browsers,
plus `web:test-registration-browser` against the checksum-attested immutable
`REGISTRATION_BROWSER_API_IMAGE=sha256:<id>` intended for publication. Retain
sanitized source/generation/image identities and actual exits/counts/cleanup only
after real runs; no current acceptance record is asserted here. See
[commands and image boundaries](devops-operations.md#automated-portal-acceptance).

### Historical 2026-10-01 Record

The following gates passed on 2026-10-01 against the implemented Task 5.3 code:

- `identity-api:test`, `identity-api:lint`, `identity-api:vet`, and `identity-api:sqlc-vet`.
- `identity-api:build`, all three admin command builds, the audit signer build, and the purge worker build.
- `identity-api:test-admin-integration` and `identity-api:test-security-db` against disposable PostgreSQL 16, Redis, and NATS JetStream services.
- `identity-api:test-race` in a Linux Go 1.26 container with CGO and a C compiler enabled. The Windows host had no C compiler; it was not modified.
- Integration-tagged lint for the changed database, HTTP, legal, and session tests, plus two consecutive runs of the database-query suite. Query fixtures now roll back instead of relying on soft deletion to release email reservations.

The new regressions cover hold/purge locking in both orders, independent legal requests and replay, post-deletion/retention-aware disclosure, fail-closed audit rollback, cross-instance credential cutoff, and stale step-up ceremonies. These local checks do not constitute deployment approval or verification of production proxy/DB privileges.

## Verification and rollback

Run the Nx `sqlc-vet`, `lint`, `vet`, `test`, `test-race`, `build`, worker/operator builds, `test-security-db`, and `test-admin-integration` targets. Integration runs require run-owned disposable PostgreSQL 16, Redis and NATS JetStream, serialized and isolated from developer/shared environments. The mandatory admin target fails on missing service configuration.

The unchanged `00001` plus additive `00002` bundle is forward-only; `Down`, reset and rollback to zero refuse. Disable admin ingress/routes first and preserve holds, ciphertext, replay tombstones, auth versions, outbox intent, registration state and evidence. A clean up/down/up is unavailable; test refusal and forward recovery only on run-owned disposable fixtures. Current-bundle acceptance is separate from historical upgrade evidence.

Existing task statuses and historical October/November results are unchanged and do not certify this bundle. Fresh final-source acceptance, forward recovery/consistent local restore, generated outputs, images and browser gates remain required. Production ingress/privacy, policy, deployed privilege/restore and manual checks remain independently open in the [production checklist](#production-checklist). Task 5.4 annotations and receipt reconciliation are database-relative, not legal-policy proof or protection against coherent privileged rewrite. Task 6.2 does not close those gates or change offline-JWT residual authority. Phone attribution and historical key rotation remain separate work.

## Legal Review and Transparency (Task 5.5)

This backend is opt-in and does not confer production approval. `ADMIN_ENABLED`
now requires `ADMIN_GOVERNANCE_POLICY_ID`, resolving to the immutable baseline
installed by the controlled operator. The baseline must match both existing
retention durations exactly. `LEGAL_WORKFLOW_ENABLED=false` remains the default;
enabling it additionally requires `LEGAL_WORKFLOW_POLICY_ID` with an approved
workflow extension. A baseline-only deployment can retain Task 5.3 preservation
without enabling case intake. The separately authorized synthetic lookup probe remains
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
`scope`, `idempotency_key`, `result_id`, `erased`; actor/narrative/content-fingerprint
values are removed from these stubs. However, `hold_review` scope/result IDs join
the surviving hold tombstone and therefore remain subject/actor/time linkable.
Case stubs join an erased case sentinel. This five-field approval does not approve
all permanent report, transparency replay, governance, chain or receipt metadata;
see the [complete retained inventory](data-architecture.md#retained-metadata-inventory).
Neither mechanism implements finite replay
expiry. If governance does not approve its actual inventory and lifetime, intake
must stay disabled until a separately reviewed replay protocol exists.

Run with separately provisioned credentials and trusted launcher attribution:

```sh
npm exec -- nx run identity-api:admin-legal -- --operation=policy-install --policy-file=/approved/legal-policy.json
npm exec -- nx run identity-api:admin-legal -- --operation=workflow-cleanup --limit=500 --dry-run
npm exec -- nx run identity-api:admin-legal -- --operation=workflow-cleanup --limit=500
npm exec -- nx run identity-api:admin-legal -- --operation=workflow-status --limit=500
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
| Workflow maintenance | SELECT cases/replays/subjects/hold reviews/holds/policy/baseline; existing legal_cases UPDATE; replay UPDATE only `erased`, `event_id`; DELETE events/subjects/case-hold links/hold-review state; outbox INSERT. No user/role/policy/evidence mutation, sequences or head EXECUTE. |
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

Read `GET /api/v1/admin/legal-holds/{hold_id}/reviews` for a different operator's
handoff with live `legal.holds.read`, not case-read. The workflow gate remains
required; no workflow UI or permission expansion is added. Response fields are
numeric `version`, nullable UTC `next_review_at`, `history` and
`history_truncated`, using the same 200-event/1-MiB caps. Before the first review,
version is zero, history empty and scheduling uses original `legal_holds.review_at`;
after review, an explicit null schedule remains null. Expired/erased/missing
history is unavailable, not a never-reviewed result. Disclosure audit commits
before response bytes; reads never restore narratives, change replay inputs or
release/reset a hold.

`admin-legal --operation=workflow-status --limit=500` uses the installed baseline in a read-only
REPEATABLE READ snapshot with a 15-second bound. It emits `as_of`, `limit`,
`eligible_expired`, `held_expired`, nullable `oldest_eligible_age_seconds`,
`due_reviews` and `overdue_reviews`. Each category has `count` and `lower_bound`;
at most limit+1 ordered rows per category are aggregated (`1..1000`), so capped
counts are not totals. Candidate discovery remains subject to statement/deadline
bounds, not a claim of constant-cost scanning. Due includes equality; overdue is
strict-before. No subject,
case, hold, policy ID or narrative appears in diagnostics. A baseline-only binding
is sufficient for status; it does not enable intake or approve a workflow extension.
Held expired backlog
is not cleanup's per-run `Held`, which only counts candidates actually rechecked
after locking. Status needs only SELECT on cases/subjects/hold-review/hold/policy/
baseline metadata, no keys, intake enablement, mutation or outbox rights.

Validate CLI options before connecting: baseline cleanup `1..1000`,
workflow cleanup `1..500`, status `1..1000`; `--dry-run` only for workflow cleanup
and `--policy-file` only for policy installation. Status/cleanup use persisted
policy independently of intake flags. Context/released baseline cleanup is
strict-before; workflow expiry is at-or-after equality. Closed-case expiry is
the minimum of original maximum age and closure-relative retention; reviews,
closure retries and hold release never extend/reset clocks. Two-person approval
means distinct authorized accounts, not verified distinct humans; delivery is
still operator attestation.

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
3. Install unchanged `00001_initial_schema.sql` plus additive
   `00002_registration_attempts.sql` in an explicitly scoped fresh PostgreSQL
   environment with matching isolated Redis/NATS through the
   [baseline procedure](#migration-and-contraction). All legacy
   `public.goose_db_version`, untracked nonempty application schemas and contradictory
   histories refuse without mutation. No old proof-format/lineage conversion or adoption is supplied;
   do not reset a named environment or infer genesis from empty payloads. Baseline
   Down/reset refuse; signed bytes and compatible v2 history are never rehashed.
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
| `public.security_event_ledger` | `identity_ledger_purge` holds `SELECT` and `DELETE`; signer may SELECT/INSERT. No other runtime deletion, payload UPDATE or TRUNCATE is permitted. The trigger does not enforce DELETE retention/holds. |
| `public.security_ledger_erasures` | `identity_ledger_purge` holds `SELECT` and `INSERT`. Append-only for everyone. |
| `public.event_outbox` | `identity_ledger_purge` holds `INSERT` only, for its receipt. |
| `public.security_ledger_chain`, `public.audit_log_chain` | Signer SELECT/INSERT; purge SELECT on ledger chain only; API/read tools have their scoped SELECT. No runtime UPDATE/DELETE/TRUNCATE; no maintenance exemption. |
| `public.advance_chain_head(text,bigint,bigint,bigint,bigint)` | Only the signer may execute. SECURITY DEFINER, pinned `search_path`, PUBLIC EXECUTE revoked. |

The worker's startup probe refuses to run unless all of the following hold, so an
over-provisioned role fails closed at boot rather than at the first erasure:

- `current_user = session_user` and the login is `identity_ledger_purge`;
- no superuser, `CREATEROLE`, `CREATEDB`, `REPLICATION`, `BYPASSRLS`, no role
  membership, no `CREATE` on the schema or database;
- required payload/ledger-chain/head/erasures/holds/settings SELECT, payload
  DELETE and erasure/outbox INSERT only; no chain/head writes, payload INSERT/
  UPDATE/TRUNCATE, unrelated reads/writes, sequences or head EXECUTE;
- payload immutable/no-truncate, both chains' append-only/no-truncate and erasure
  append-only/no-truncate guards are armed with their expected functions. Guards
  protect immutability, not retention/hold predicates on ordinary DELETE;
- the configured receipt subject is provisioned in
  `security_ledger_retention_settings`.

Trusted Go code rechecks canonical candidate leaves and eligibility under ordered
coordination/account/row locks, and its `DELETE`
restates every predicate: `retain_until < cutoff`, `seq <= highwater`, and no
active hold on the original `account_ref`. A short row count aborts the whole
transaction rather than recording an erasure span that does not describe what was
removed. An annotation explains missing payloads; it does not prove lawful erasure.
Ordinary table DELETE permits arbitrary DELETE by that credential. Neither the
probe, SQL predicates in the honest worker nor a receipt independently proves
that a compromised purge credential honored retention/holds. Do not claim a SQL
policy-enforcing routine, restored serializer or erased-content verification.

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
separately authorized new-lineage target after bundle version 2 in `public.identity_schema_version`, with
writers stopped and the schedule disabled.
The operator must be authorized to create roles and transfer function ownership;
these are not runtime privileges. Replace the four uppercase role placeholders
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
\set reconciler_role 'DEPLOYED_RECEIPT_RECONCILIATION_ROLE'
SELECT current_database() AS ledger_database \gset

-- Canonical format v2 remains from unchanged 00001; additive 00002 adds registration.
--
-- There is no maintenance-owner role here and no SECURITY DEFINER purge routine
-- to own. Erasure is an ordinary DELETE on the payload table, so the authority
-- question is a plain privilege question, and the purge login is given exactly
-- three write rights: DELETE on the payload, INSERT on the erasure index, and
-- INSERT on the outbox for its receipt. Required ledger-chain SELECT is not a
-- chain write. This isolates tamper-evidence mutation, not retention/hold policy
-- enforcement against a compromised ordinary DELETE credential.
BEGIN;
CREATE ROLE identity_ledger_purge LOGIN NOINHERIT NOSUPERUSER
    NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

REVOKE CREATE ON SCHEMA public FROM PUBLIC,
    :"signer_role", :"api_role", :"metadata_role", :"reconciler_role";
REVOKE CREATE ON DATABASE :"ledger_database" FROM PUBLIC,
    :"signer_role", :"api_role", :"metadata_role", :"reconciler_role";
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
GRANT SELECT ON public.security_ledger_erasures, public.users TO :"signer_role";
GRANT UPDATE (id) ON public.users TO :"signer_role";
GRANT EXECUTE ON FUNCTION public.advance_chain_head(text, bigint, bigint, bigint, bigint)
    TO :"signer_role";

-- API: read-only, for the gated verification and disclosure routes.
GRANT SELECT ON public.security_event_ledger, public.security_ledger_chain,
    public.mvp_audit_logs, public.audit_log_chain,
    public.security_ledger_head, public.audit_log_head,
     public.security_ledger_erasures TO :"api_role";

-- Reconciliation is separate from the purge login. Existing login attributes,
-- ownership, PUBLIC/column ACLs and membership paths must be audited separately.
REVOKE ALL ON public.security_ledger_erasures, public.event_outbox,
    public.mvp_audit_logs, public.audit_log_chain, public.audit_log_head
    FROM :"reconciler_role";
GRANT USAGE ON SCHEMA public TO :"reconciler_role";
GRANT SELECT ON public.security_ledger_erasures, public.event_outbox,
    public.mvp_audit_logs, public.audit_log_chain, public.audit_log_head
    TO :"reconciler_role";

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

A migration must never create or empower a deployment database role, which is why
this is an operator step rather than part of the baseline.
`internal/retentiondbintegration` asserts the properties that do not depend on it:
SECURITY DEFINER, a pinned `search_path`,
and no PUBLIC EXECUTE.

Do not give the worker a chain-table write, a sequence grant, or EXECUTE on
`advance_chain_head`. Required ledger-chain SELECT remains necessary. Its startup
probe refuses to run if it holds any prohibited grant,
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
SELECT pg_advisory_xact_lock(5200004::bigint);
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

Privilege audit. Only the signer in the first query must report `true`; every
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

-- No runtime UPDATE/DELETE/TRUNCATE on chains, erasures or heads.
SELECT role_name, table_name,
       has_table_privilege(role_name, table_name, 'UPDATE,DELETE,TRUNCATE') AS can_write_chain
FROM (VALUES ('identity_ledger_purge'), (:'signer_role'), (:'api_role'), (:'metadata_role'), (:'reconciler_role')) AS roles(role_name)
CROSS JOIN (VALUES ('public.security_ledger_chain'), ('public.audit_log_chain'),
    ('public.security_ledger_erasures'), ('public.security_ledger_head'), ('public.audit_log_head'))
    AS tables(table_name)
WHERE has_table_privilege(role_name, table_name, 'UPDATE,DELETE,TRUNCATE');

-- INSERT is signer-only on chains, purge-only on erasures, and absent on heads.
-- Any row here is an unexpected effective INSERT grant.
SELECT role_name, table_name
FROM (VALUES ('identity_ledger_purge'), (:'signer_role'), (:'api_role'), (:'metadata_role'), (:'reconciler_role')) AS roles(role_name)
CROSS JOIN (VALUES ('public.security_ledger_chain'), ('public.audit_log_chain'),
    ('public.security_ledger_erasures'), ('public.security_ledger_head'), ('public.audit_log_head')) AS tables(table_name)
WHERE has_table_privilege(role_name, table_name, 'INSERT')
  AND NOT (role_name=:'signer_role' AND table_name IN ('public.security_ledger_chain','public.audit_log_chain'))
  AND NOT (role_name='identity_ledger_purge' AND table_name='public.security_ledger_erasures');

-- The payload is immutable for everyone: this must report 0 rows.
SELECT role_name FROM (VALUES ('identity_ledger_purge'), (:'signer_role'),
    (:'api_role'), (:'metadata_role')) AS roles(role_name)
WHERE has_table_privilege(role_name, 'public.security_event_ledger', 'UPDATE')
   OR has_any_column_privilege(role_name, 'public.security_event_ledger', 'UPDATE');

-- Immutability/append-only guards must be armed; they do not police DELETE policy.
SELECT c.relname, t.tgname, t.tgenabled
FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
WHERE t.tgname LIKE 'trg\_%' AND c.relname IN
      ('security_event_ledger', 'security_ledger_chain', 'audit_log_chain', 'mvp_audit_logs', 'security_ledger_erasures')
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

### Receipt Reconciliation

DELETE, erasure spans and durable receipt intent commit together, not a signed
receipt. The compatible publisher retries outbox delivery and the signer appends
the receipt; PubAck/`published_at` only establishes transport acknowledgement, not
chaining. Legitimate pending intent must not prevent signer reseeding/restart.
Actually inspected held-only batches write one `legal.ledger.purge_skipped`
receipt with no erasure rows; prefiltered holds are not inspected skips. Dry-run
rolls back DELETE, spans and receipt intent.

New receipt bodies add `span_manifest_version=1` and lowercase-hex
`span_manifest_sha256` binding the exact ordered inclusive span manifest. Hash
ASCII `identity/security-ledger-erasure-spans/v1`, one NUL byte, unsigned big-endian
64-bit span count, then each `(first_seq,last_seq)` as two unsigned big-endian
64-bit integers. Coordinates are positive signed-int64-range values, sorted,
non-overlapping and maximally coalesced, matching deleted count/high-water. A
held-only receipt commits the empty manifest. This is receipt content, not a new
audit canonical format; old signed bytes/hashes are never rewritten or retroactively
certified. Historical receipts without both manifest fields are legacy/unbound.

```sh
npm exec -- nx run identity-api:admin-legal -- --operation=ledger-receipts --limit=100 --receipt-proof-limit=1000
```

Inject only separately scoped `LEDGER_RECEIPTS_DATABASE_URL`, never purge/API
credentials. Required SELECT is exactly erasures, receipt outbox and Class C
payload/chain/head; no keys, evidence writes or sequence/DDL/role authority.
Options are operation-specific: limit `1..1000`, proof limit `1..10000`, no
dry-run/policy file. One read-only REPEATABLE READ snapshot keyset-pages inventory,
caps span queries and Class C proof work, and has a 15-second deadline.

Sanitized aggregates are `inspected`, `recorded_pending`, `chained`,
`legacy_unbound`, `missing_unavailable`, `invalid`, `incomplete`, `pages`,
`inventory_capped`, `inventory_complete`, `proof_checked`, `proof_complete`,
`proof_verified`. Proof counts/flags refer to bounded Class C chain **linkage**,
not recomputation of unrelated audit narratives. Hash-only pages are at most 100
nodes within the total proof limit; each correlated receipt body/leaf is checked
separately. They correlate operation UUID internally across annotations,
outbox, receipt body/leaf and bounded linkage coverage, but output contains no IDs,
receipt bodies or proof digests. A verified prefix can cover a receipt while
`proof_complete=false`; it is not a full-chain pass. Capped inventory is not full
inventory assurance, and missing retained material is unavailable assurance.
Inventory coverage is limited to operations discoverable from retained erasures,
receipt outbox and Class C receipt material; it is not proof that no lost or
never-ingested historical operation existed.
There is no global pass or independent proof of legal/policy compliance by a
compromised trusted purge credential. Structural verification remains separate;
both operations remain database-relative without an external anchor.

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
hashes. The unchanged `00001` plus additive `00002` bundle refuses Down, including against
a seemingly empty database; reset and rollback to zero are not recovery paths.

Restore `public.identity_schema_version`, both chain/payload tables and sequence
state, both heads, erasure index, holds, governance/workflow, registration attempts, retention settings
and outbox from one
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

## Phase 5 Technical Closure (2026-11-05)

The plan `.kilo/plans/1793893850853-phase-5-technical-closure.md` passed fresh
local automated acceptance against the dirty worktree based on
`fedbe1ebee53be2bfd3dfeb5d66ef6ee2e8749d7`. This is implementation acceptance,
not authorization to enable production admin, purge, legal intake or governance.
The production checklist above remains unchecked.

The complete uncached seven-suite retry used fresh PostgreSQL 16, Redis 7 and
JetStream 2.10, sequentially through the existing Nx harness. Every final exit was
0, every mandatory skip/failure count was 0, and owned service teardown was
affirmatively confirmed. Counts include nested test records and repeated package
coverage across suites, not 6,462 distinct test functions.

| Suite | Passing Package Runs | Passing Test/Subtest Records |
|---|---:|---:|
| `test-security-db` | 19 | 1,577 |
| `test-admin-integration` | 7 | 819 |
| `test-retention-integration` | 3 | 355 |
| `test-legal-workflow-integration` | 4 | 671 |
| `test-grpc-integration` | 4 | 560 |
| `test-lifecycle-integration` | 1 | 370 |
| `test-portal-integration` | 11 | 2,110 |
| Total | 49 | 6,462 |

Coverage included single-connection migration entrypoints and cancellation,
pre-00015 populated/initialized/erased-v1 refusal without lost history,
00019 terminal/coordinator/owner/ACL checks, verified backfill and transactional
00020 contraction, exact legal input preflight before grant consumption, keyless
release, captured query-log privacy sentinels, review GET handoff/expiry and
workflow status, and the effective restricted-login privilege matrices.

The real worker/publisher/signer/reconciler cases covered pending intent during
publisher outage, signer restart, acknowledged redelivery deduplication, both
hold/purge lock orders, simultaneous batches, cutoff/high-water boundaries,
canonical corruption rollback, held-only receipts, manifest tampering, legacy
unbound receipts, and unavailable retained receipt evidence. The uncertainty
test commits a real transaction and then injects a client lost-ack error; it does
not certify actual socket-loss handling or production fault recovery.

`TestForwardRecoveryConsistentRestoreIntegration` passed the refused-20/verified
backfill/forward-20 recovery path, two frozen whole-database TEMPLATE restores,
and a matching PostgreSQL 16 `pg_dump` to `pg_restore` streamed in memory
(78.91 seconds for the matching-client run). It compared all public rows and
sequence state, then verified both chains/heads, retained/erased payloads,
erasures, encrypted holds/replay clocks, governance/settings, pending/chained
receipts, crypto bindings and signer recovery. No raw dump or key material was
retained. This local clone/logical-restore drill is not deployed backup, key
recovery, independent-history or disaster-recovery certification.

Linux unit and CGO race targets, ordinary and integration-tag vet/lint (zero
issues), SQL/Buf checks, all required binary builds, web/UI checks, fresh image
smoke/CSP and both real browser suites also exited 0. Final counts were 177
helpers, 586 web tests and 17 UI tests; the portal browser covered 18 viewports
and six no-JavaScript routes, and admin/legal covered 42 masked layouts and
clean retirement of the actual production signer. Repeated generation preserved
all 24 SQL Go and four protobuf Go files byte-for-byte; migrations 00001-00018
and tracked canonical schema sources were unchanged.

Exact command/exit records, generated-file vectors, sanitized browser evidence
and final source reconciliation are in this run's
`C:\Users\Hatef\AppData\Local\Temp\kilo\phase5-20261105T165058Z\acceptance.json`
and its `admin-browser`/`portal-browser` directories. The
[DevOps acceptance record](devops-operations.md#phase-5-technical-closure-2026-11-05)
records toolchain and immutable image identities. Earlier failures are recorded,
not counted as passes; the obsolete plaintext shadowing fixture was corrected
without removing its negative assertion, followed by a complete seven-suite retry.

Production DPO/Legal numeric policy, joinable-metadata and replay inventories,
real-key backfill, authenticated grants/RLS, deployed ingress/APM redaction,
signer probing, schedule/consumer rollout and backup recovery remain open.
Native bfcache/hidden-tab/zoom, physical authenticators and assistive-technology
review remain unobserved manual gates. The signer `UPDATE(id)` grant is actual
SQL update authority, not a database-enforced lock-only capability. Ordinary
purge grants, erasure annotations and receipts do not prove legal authorization
or policy compliance by a compromised trusted worker. External anchoring remains
deferred. No production flags, deployed credentials or approvals were changed,
and this work was not committed or published.

## Fresh-Baseline Acceptance, November 6, 2026

This record belongs exclusively to
`.kilo/plans/1793914256582-single-migration-baseline.md`. It does not replace the
historical acceptance above. Only newly executed, uncached baseline checks are
reported below. Task statuses and manual/production gates remain unchanged.

### Source And Reference

The unchanged 20-file working-tree chain was frozen before consolidation and
applied through its supported runner to a new PostgreSQL 16 reference database.
The reference is not an existing development or deployed database. All frozen SQL
bytes were independently checked against the original executable's embedded
filesystem; transient loss of temporary copies was recovered with identical
fingerprints, including working-tree migrations that differed from HEAD.

| Artifact | SHA-256 |
|---|---|
| Final `00001_initial_schema.sql` | `1ffe1d6bde9f5d9a80a8d04e9dc2df8410a035af4fdca07c5dc2c0f23a1cc107` |
| Frozen 20-file fingerprint manifest | `e3826b85f52a2d1ba7f40c05003f1b17ebbb14fb78573d7469ba96388146961f` |
| Original supported reference runner | `30dccfa9be6bcc529cc2dfd24935ab54a88c9540bea66229335debab9b496bd2` |
| Latest guarded standalone baseline runner | `5c8345dbf325517da1cc18f1d9a69d45e65a632302184d61eae6e61dba0d9e27` |

The completed admin browser run identified HEAD
`223a156656a8108f125a4e498a1fbaf2124cd719`, staged-diff SHA-256
`80179aba005d3821fd526fcad055e47783ab5e850016e1a1ae02de0243731efa`,
and empty unstaged/untracked content hashes
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
Its start/finish worktree identities matched. This acceptance record was appended
afterward; runtime and test sources were not changed by recording the results.

Reference artifacts remain outside the executable tree in the approved temporary
root `baseline-sql-20261106-070557`: `frozen-reference.zip`, fingerprint manifest,
catalogs, schema dumps, parity/security/smoke reports and recovery provenance.
Only fingerprints and sanitized summaries are retained in this document.

### Schema And Runner

| Evidence | Verified Outcome |
|---|---|
| Executable inventory | Exactly one embedded baseline. No historical SQL remains in runtime, test-fixture, build or sqlc schema inputs; the in-memory future migration is test-only. |
| Complete schema parity | 34 application tables, 242 columns, 153 constraints, 78 indexes, 3 sequences, 11 functions and 17 triggers matched. All 181 non-Goose schema-dump blocks matched after ordering normalization. |
| Security and seeds | Exact 4-role, 13-permission and 15-grant contents, all application row counts, 2,454 bare effective-privilege checks and 19,648 provisioned ownership/grant-option/RLS checks matched. Provisioning comparison transactions were rolled back and catalog parity rechecked. |
| Normalization limits | Incidental OIDs, dropped-column holes, seed timestamps, dump ordering and intentional old/new Goose metadata differences only. No function, expression, predicate, default, grant or application row-count differences were accepted. |
| Lineage and atomicity | Full PostgreSQL migration/CLI tests passed without skips, including immutable legacy version-1/intermediate/20 refusal, coexistence, complete malformed/contradictory histories, permission failures, untracked objects, read-only status/version, lock-held initialization/reinspection and atomic failure/retry. |
| Forward-only and future | Reset/baseline rollback/rollback-to-zero refused before partial rollback, including after a test-only later version. Future exact-version prerequisites, ordinary up/down/reapply, concurrent first install, one-connection retry, cancellation and bad-session lock cleanup passed. |
| Final invariants | Auth epoch/status/deletion semantics, encrypted holds, FK actions, immutable audit/ledger tables, effective PUBLIC execute denial, head-function SECURITY DEFINER/search path/timeout, unchanged genesis vectors and both phantom-terminal refusals passed. |

### Quality, Images And Browsers

All following runs bypassed Nx caches or used `go test -count=1`. Nx remained the
entry point for workspace tasks. Linux test-target command overrides used a
read-only workspace mount, Go 1.26.9 and CGO/GCC for race checks; no assertion was
weakened for the Windows host.

| Gate | Verified Outcome |
|---|---|
| `schemas:lint`, `identity-api:sqlc-vet`, `identity-api:sqlc-generate` | Passed. All 28 generated files reproduced identically on repeat generation. Against the frozen reference, only four query-comment files differed; models, SQL statements, signatures and protobuf output did not change. |
| `identity-api:test` and `identity-api:test-race` | Full Linux unit and race targets passed. A separate integration-tagged, real-PostgreSQL Linux race run passed `internal/migrate` and `cmd/migrate` (502.189s and 1.019s). |
| `identity-api:vet`, `identity-api:lint` | Normal and integration-tagged whole-backend checks passed; lint reported zero issues. A competing-linter attempt was rerun serially. |
| `identity-api:test-portal-fixture` | Passed. |
| CI API/worker/operator binaries | All ten resolved build targets passed uncached: API, admin audit publisher, admin roles, admin legal, lifecycle publisher, audit signer, purge worker, security-ledger purge, deletion notifier and portal fixture. |
| Fresh Linux/amd64 image | Built from the hardened runner. Immutable image ID: `sha256:7ed607ffc66457cb2d5facc617944752382128267400cca6b0a03058eb1fc210`. Maintenance-entrypoint/missing-credential smoke passed. |
| Packaged migrator | Eleven image-level smoke operations passed on an owned database: exactly one pending/applied source, read-only fresh status, history 0/1, repeated/up-to-1 no-ops, immutable down/reset/unknown-target and legacy refusals, and missing-DSN status. The standalone guarded runner's separate 14-check smoke also passed. |
| Consistent restoration | Matching PostgreSQL 16 clients exercised both ordinary and expanded `pg_dump`/`pg_restore` paths plus four repeated frozen TEMPLATE clones: nine checks passed, zero failures/skips. Data, sequences, proofs, crypto/binding, replay, signing and forward-only invariants were retained. This is local restoration evidence, not deployed-backup certification. |
| Existing helper/image harness tests | 142 tests passed, zero skips. |
| Frontend unit/production build | `web:test` passed 25 suites/586 tests; `web:build` passed. |
| `web:test-admin-browser` | Production-built real-API/signing/probe run passed: 42 layout checks and 27 legal verifications. Run `ce30ed9c1bd60a7ada15b24dfaf6995c`; service namespace `b89de3b6a7148ed8600f23719061cd9a`; assertions and teardown passed, worktree identity matched. Windows used the immutable image above for the production signer. |
| `web:test-portal-browser` | Production-built real-API portal/deletion/recovery run passed: 18 light/dark viewports and six no-JavaScript shells; teardown completed. |

Masked browser artifacts and sanitized reports are retained only under the
approved temporary `baseline-admin-browser` and `baseline-portal-browser` roots.
No legal narrative, personal identifier, proof, grant, credential or raw dump is
copied into this record.

### Mandatory Real Services

All suites use the existing `runPortalIntegrationTarget` implementation with its
mandatory flags, `--skipNxCache`, serial packages and zero-skip assertion against
new PostgreSQL 16, Redis 7 and JetStream 2.10 resources. The primary final-source
batch completed five suites before the local harness's 60-minute global deadline
interrupted lifecycle. Its successful suites are not claimed as one complete
uninterrupted job. Lifecycle and portal completed in a second fresh serial batch with
the same implementation and assertions, not reduced test selections.

| Target | Packages | Passed Checks | Failed | Skipped | Final Outcome |
|---|---:|---:|---:|---:|---|
| `test-security-db` | 19 | 2030 | 0 | 0 | Passed. |
| `test-admin-integration` | 7 | 825 | 0 | 0 | Passed. |
| `test-retention-integration` | 3 | 355 | 0 | 0 | Passed. |
| `test-legal-workflow-integration` | 4 | 671 | 0 | 0 | Passed. |
| `test-grpc-integration` | 4 | 560 | 0 | 0 | Passed. |
| `test-lifecycle-integration` | 1 | 370 | 0 | 0 | Passed in the second fresh batch. |
| `test-portal-integration` | 11 | 2110 | 0 | 0 | Passed in the second fresh batch. |

The earlier development batch, started before final fixture corrections, was
deadline-limited and is not accepted as final-source evidence. Scoped migration,
profile, policy, lifecycle, gRPC, Backfill and restore checks were additionally
run on separately owned fixture databases; interrupted development fixtures were
identified and cleaned before their corrected reruns.

### Isolation And Remaining Gates

The reference container `ldp-baseline-sql-20261106-070557-pg16` and its exact owned
anonymous volume were removed after verifying zero active fixture connections
and zero remaining migration/Backfill/restore/packaged-smoke fixture databases.
Frozen files and reports remain in temporary storage. Primary service namespace
`4979b7f0e858c594e704279f4f05cc56` reported completed teardown; its containers and
network were independently confirmed absent. Browser teardown completed.
Second service namespace `f479768ddc9a054ca3a2d2269f6abec6` reported completed
teardown; its containers and network were independently confirmed absent.
Temporary driver-startup namespace `c236bb4ab23fc4cb57998d677c350680` also reported
completed teardown and was independently confirmed absent before the corrected
driver ran either required suite.

No existing named environment or volume was reset or deleted. Every test batch
started without inherited Redis sessions, NATS messages/checkpoints or old
writers. Production writers were not stopped or otherwise modified. No
deployment, approval, production flag or credential was changed by this work.

The native Windows unit run encountered the existing POSIX spool-file mode
assertion (0666 versus 0600); unchanged Linux unit/race assertions passed instead.
The single local 60-minute seven-suite job remains deadline-limited; it must not
be described as an uninterrupted pass. All seven complete target runs passed
across the two final-source serial batches, with zero failures and zero skips.
Physical authenticators, native zoom, assistive technology, deployed HTTPS/log
redaction, actual backup/media recovery, independent mailbox/provider handling,
downstream rollout, real key inventory, operator role/genesis provisioning,
governance/retention approvals and unobserved native hidden-tab/bfcache behavior
remain manual or deployed-system gates. These results do not certify production
readiness, external anchoring or a compromised trusted worker's conduct. No
commit, publication, broad volume deletion or existing-environment reset is
authorized by this record; any later reset needs a separately explicit target.
