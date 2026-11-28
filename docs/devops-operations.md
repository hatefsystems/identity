# Hatef Identity Platform - DevOps & Operational Playbook

This playbook describes MVP operating requirements and later Kubernetes designs,
not deployed gates, executed acceptance or production approval.

Current-source inspection is not target implementation. Planned authentication,
SQL authority and lifecycle changes follow the
[authentication and recovery policy](authentication-and-recovery-policy.md)
and [assessment](security-architecture-assessment.md); activation is blocked on
[security readiness](security-testing-and-readiness.md). Dated acceptance records
below retain their original sources/counts/toolchains, not current-policy passes.

Current executable scope is the
[canonical backlog](../.github/tasks/registration-single-contract-tasks.md).
The [registration snapshot](history/registration-backlog-2026-11-23.md) and
[architecture-plan snapshot](history/security-architecture-plan-2026-11-24.md)
preserve complete superseded historical narratives, not operating instructions.
All temporary paths in dated acceptance records identify historical local
evidence only; they are neither required fresh-clone inputs nor destinations for
new acceptance runs. New artifacts use an explicitly selected run-owned directory.

---

## ⚠️ MVP Phase Disclaimer: Single-Node Deployment (No Kubernetes, No ClickHouse & No Traefik)

The MVP deployment design uses **Docker Compose** on a single node instead of Kubernetes (K8s) to minimize resource and memory overhead. **ClickHouse is bypassed** in this phase (PostgreSQL fallback tables handle logging).

Furthermore, **Traefik is not provisioned in the MVP phase**. Instead, the platform leverages the **existing host-level Nginx** on the Ubuntu host to handle Reverse Proxying, TLS Termination, and path-based routing directly to the Docker containers. Traefik Ingress will be adopted post-MVP when migrating to a production Kubernetes cluster.

The K8s manifests, Traefik IngressRoute, SPIRE daemonsets, and ClickHouse monitoring configurations documented below are strictly for the post-MVP production deployment and **must not be provisioned in the current MVP phase**.

---

## Fresh-Baseline Environment Cutover

### Canonical Packaged Migration Inventory

At inspected HEAD `85abb13a27196c229efa7f59d7ef5beebb1d7e49`,
`apps/identity-api/db/embed.go` embeds `migrations/*.sql`. The actual packaged
inventory is the eleven files below, not historical one/two/four-file bundles.
Other install/restore guides crosslink here rather than defining another inventory.
These are current schema capabilities, not migrations implementing SEC01-SEC16.

| Version | Packaged file under `apps/identity-api/db/migrations/` |
| ------- | ------------------------------------------------------ |
| 1       | `00001_initial_schema.sql`                             |
| 2       | `00002_registration_attempts.sql`                      |
| 3       | `00003_username_reservations.sql`                      |
| 4       | `00004_geography_catalog.sql`                          |
| 5       | `00005_private_account_data.sql`                       |
| 6       | `00006_optional_email_contact_evidence.sql`            |
| 7       | `00007_account_deletion_action_proofs.sql`             |
| 8       | `00008_password_change_action_proofs.sql`              |
| 9       | `00009_first_passkey_enrollment_action_proofs.sql`     |
| 10      | `00010_mfa_enrollment_authorization.sql`               |
| 11      | `00011_contact_management.sql`                         |

Current `migrate up` applies known packaged versions through 11 in
`public.identity_schema_version`. ALL legacy `public.goose_db_version` targets
are refused regardless of their version or apparent equivalence; untracked nonempty
application schemas and contradictory histories also fail closed. There is no
upgrade/adoption of the retired migration lineage or automatic data conversion. Generic
`up-to` is for the new bundled lineage, not the old chain. Baseline Down/reset and
rollback to zero refuse. Historical acceptance and prior plans remain unchanged;
they are not evidence that this baseline passed.

1. Record an explicitly scoped **fresh PostgreSQL 16** database and matching fresh
   Redis 7/NATS JetStream 2.10 resources or isolated namespaces, with exact ownership,
   names and ports. Default Compose names/volumes are not necessarily fresh.
   Historical disposal assertions are not current authority over real data. Any
   reset of an existing named developer/shared environment needs a separate
   explicit request naming exact targets; preserve real data and queued work.
   Do not run broad volume deletion or shared-schema reset commands.
2. Close affected intake and stop/drain all old API, signer, publisher and maintenance
   writers before switching. Inventory queued intent and old envelopes separately;
   do not import old Redis sessions/grants or NATS events/consumer checkpoints into
   the replacement DB. Keep required backups/keys and original legal/retention clocks.
   Wire formats and existing consumer-first v1/v2 compatibility rules are unchanged.
3. Set the scoped migration `DATABASE_URL` and run `identity-api:migrate-status` then
   `identity-api:migrate-up` through workspace-local Nx. Status/version are read-only;
   fresh `up` records versions 1 through 11; repeated `up` verifies a no-op. Do not stamp, rename
   or clear metadata after refusal. Verify packaged embedded inventory and final
   schema before starting compatible binaries.
4. Provision separate non-owner roles, exact grants/RLS, approved governance, both
   explicit genesis heads and retention subject settings using
   [admin operations](admin-operations.md#migration-and-contraction). None of those
   initialization/approval actions is a migration seed. Complete real key inventory,
   readiness and separately authorized deployed signer lookup probing. Obsolete
   legal Backfill/plaintext compatibility is removed, not an install/upgrade step.
5. Reconcile isolated consumer baselines and require fresh authentication before
   compatible every-replica/caller activation. Keep intake/destructive schedules off
   until their existing policy, retention, ingress, manual and production gates pass.
   Automated suites create/tear down only run-owned resources and run serially. The
   coordinator records uncached final-source outcomes separately only after actual
   [required acceptance](admin-operations.md#automated-validation), without reusing
   historical evidence or certifying production readiness.

### Planned SQL Authority and Lifecycle Rollout

SEC09 requires primary PostgreSQL authority for earned primary/MFA evidence,
preauthentication, session issuance/deadlines/revocation, proofs, TOTP replay,
security versions, code generations, contact provenance and the repair barrier.
Current Redis session/challenge/replay records are security-authoritative dependencies,
not disposable caches; SQL version checks do not authenticate their earned claims.
Do not flush/restore them casually or describe the SQL target as implemented.
Future Redis is non-authoritative coordination/acceleration/rate limiting; corruption,
loss or flush must grant no authority and must not silently remove critical abuse limits.

Before separately authorized rollout, agree SQL ownership, primary-only reads,
global lock order and final transaction bindings with T16A/T19A/T21A/T22A.
Mutations, applicable proof consumption/version/barrier and metadata audit/notification
intent share one deciding SQL transaction (SEC10). Keep hashing/native/provider work
outside long-held locks; unknown commits/providers are unconfirmed, with no restored
proof, recreated account or new session. Read-only reconciliation reports facts only.
No SQL+Redis atomicity or exactly-once external delivery is claimed.

| Activation gate                        | Required operational evidence                                                                                                                                                                                                                                             |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Privileged admission (SEC04)           | Policy-verified hardware-backed phishing-resistant UV and independent separately enrolled backup at role grant and use; no consumer recovery/support override or backup-code downgrade. Current passkey/TOTP inventory is insufficient.                                   |
| Code families/repair (SEC05-SEC08)     | Distinct purpose/account/generation-bound keyed verifiers and keys separate from DB; owner-approved inventory of real untyped artifacts; fresh issuance authority, no email/SMS ARC delivery, durable one-repair barrier and 24-hour changed-contact provenance cooldown. |
| Notifications/lifecycle (SEC12, SEC14) | Verified-destination notification foundation, compatible v1/v2 readers before writers, preserved queued bytes/recipients/locale/token/deadline, password/mobile-capable deletion and reclaim with original 30-day grace/holds/retained factors.                           |
| T27 gate retirement                    | Independent verification of alternative identification, ARC repair, notifications, deletion and reclaim before primary-email removal or mobile-only production eligibility. Do not toggle dependencies or infer completeness from nullable SQL.                           |
| Single registration (SEC13)            | Extend current service/route, atomic birth and fresh known-success SQL session issuance under original browser key/expected subject; receipt/replay/result lookup never authenticate.                                                                                     |
| Tokens/consumers/restore (SEC16)       | Durable OAuth grants and confidential-client exchanges, complete interactive OIDC, evidence-bearing privileged consumer admission, reconciled lifecycle baselines and rollback-safe security-state restore.                                                               |

Selected providers require approval for selected contact capabilities; current
signup still requires both owned email and Iranian SMS plus UV passkey. Password or
mobile-only activation is not enabled by this future design. Preserve default-off
login/proof/contact/signup/SMS/admin/legal/deletion/gRPC switches and existing stronger
deletion authorization until independent gates pass. Queue contracts/readers must
precede security-changing writers; do not break real v1/v2 rollback readers.
See [disaster recovery](disaster-recovery.md#36-security-authority-quarantine-and-reconciliation)
for stale-replica, failover and restore quarantine requirements.

## First-Passkey Proofs (T25)

The fixed-purpose fallback is default-off. Enable `FIRST_PASSKEY_PROOFS_ENABLED`
only with an explicitly selected `FIRST_PASSKEY_PROOFS_EMAIL_ENABLED` or
`FIRST_PASSKEY_PROOFS_SMS_ENABLED` channel. It is independent of `LOGIN_ENABLED`;
an unselected disabled channel does not prevent the selected channel from working.
Use the shared `LOGIN_CODE_HMAC_KEY` for contact quotas/lockouts and a distinct
32..64-byte base64 `FIRST_PASSKEY_PROOFS_BINDING_KEY` for complete-contact evidence.
Never reuse deletion/password-change binding keys. Email uses the admitted TLS
`LOGIN_SMTP_*` transport with first-passkey-specific copy. SMS additionally requires
`SMS_ENABLED` and an explicit `FIRST_PASSKEY_SMS_IR_TEMPLATE_ID` distinct from
login, deletion and password-change templates. Provider acceptance is not receipt.

Apply additive forward-only migration
9 from the [canonical inventory](#canonical-packaged-migration-inventory).
Explicitly grant the API role only `SELECT, INSERT, DELETE` on
`public.first_passkey_enrollment_action_proofs`, never `UPDATE` or `TRUNCATE`.
The table stores only a capability digest, bound subject/session/JKT/version,
fixed action/channel, keyed contact MAC and original expiry; cleanup processes at
most 1000 expired rows per minute. No purpose key or recipient belongs in artifacts.

Enrollment spends the proof once in its caller-owned SQL start transaction before
publishing options. The pending ceremony retains the original deadline, not a fresh
lifetime. Cancellation, expiry, failed verification, response loss and uncertain
SQL/Redis outcomes never refund or restore authority and never authorize retries.
Keep standalone Redis available with a non-evicting live account-slot policy before
activation; this is an operational prerequisite, not a shared Redis reconfiguration.
To disable rollout, first close proof-issuance and enrollment-options ingress while
retaining the enabled service, purpose keys and Redis verification dependencies
until original deadlines drain. Only then disable `FIRST_PASSKEY_PROOFS_ENABLED`
or remove support; toggling the switch alone before draining is not finish-safe.
Do not release slots,
rewrite deadlines/identity, remove committed credentials or run a destructive Down.
Inbox/provider receipt, platform authenticators and deployed-ingress acceptance
remain independent unverified release gates.

For the separate MFA-enrollment fallback (T26), all three switches default off:
`MFA_ENROLLMENT_PROOFS_ENABLED`, `MFA_ENROLLMENT_PROOFS_EMAIL_ENABLED` and
`MFA_ENROLLMENT_PROOFS_SMS_ENABLED`. Enable the ceremony only with at least one
explicitly selected channel; an unselected channel needs no provider. Channel
switches cannot remain true with the global switch false. Unlike T25, eligibility
requires `LOGIN_ENABLED` and already-approved admitted username authority, a usable
supported password, zero passkeys, no enabled/configured active TOTP, no role
membership and an exactly evidenced verified selected contact. Do not activate
username policy, add contacts, install provider templates or infer approvals here.

Use shared `LOGIN_CODE_HMAC_KEY` for bounded contact-code quotas/lockouts and a
dedicated 32..64-byte base64 `MFA_ENROLLMENT_PROOFS_BINDING_KEY`; it must differ from
the code, deletion, password-change and first-passkey binding keys. Email uses
the existing verified-TLS `LOGIN_SMTP_*` transport with MFA-enrollment-specific
copy. SMS additionally needs `SMS_ENABLED` and positive explicit
`MFA_ENROLLMENT_SMS_IR_TEMPLATE_ID`, distinct from `SMS_IR_TEMPLATE_ID`,
`ACCOUNT_DELETION_SMS_IR_TEMPLATE_ID`, `PASSWORD_CHANGE_SMS_IR_TEMPLATE_ID` and
`FIRST_PASSKEY_SMS_IR_TEMPLATE_ID`. Keep existing country/key-mode/spend/provider
protections and direct-transport language behavior; UI locale does not choose a
different SMS template, and T26 adds no notification wire version/locale negotiation.
No purpose key, recipient, password, code, proof or setup secret belongs in logs or
browser/CI artifacts. Provider acceptance is not mailbox/handset receipt.

Additive forward-only version 10 in the [canonical inventory](#canonical-packaged-migration-inventory) creates
`public.mfa_enrollment_action_proofs` and adds captured `auth_version`, `jkt`,
`authorization_method`, `channel` and `contact_binding` to the existing
`mfa_totp_enrollments`. Proof rows store only digest, subject/session/JKT/version,
fixed `mfa_enrollment` action, channel, 32-byte keyed evidence and original finite
expiry. New pending rows require complete method-specific bounded metadata:
`webauthn_uv` has no contact fields; `password_contact` requires channel and 32-byte
contact binding. Existing all-null metadata groups remain stored, but readers reject
them before decryption; partial metadata fails constraints. There is no backfill,
inferred authorization or active/pending secret-encryption format change. Provision
only `SELECT, INSERT, DELETE` for the runtime proof table, not `UPDATE`, `TRUNCATE`
or broad grants; bounded cleanup handles at most 1000 expired proofs per minute.

T26 rollout/rollback below is documentation only, not permission to migrate, deploy,
write shared state, reset data, activate policies or install templates:

1. Quiesce and drain old MFA maintenance writers before separately authorized
   schema application. Never run mixed old/new maintenance writers: nullable
   columns do not prevent old code bypassing frozen authorization checks. Inventory
   actual pending enrollments without assuming a legacy population. If live rows
   lacking bindings exist, obtain an explicit owner-approved expiry/restart
   transition; no automatic deletion, reset or account/factor backfill is authorized.
2. Apply the reviewed additive schema and restricted grants under the separately
   authorized migrator/provisioner identities, then admit only new readers/writers
   with proof issuance default-off. Preserve existing normal-session MFA, Origin,
   DPoP, recovery and stronger UV-maintenance paths. There is no T26 management UI.
3. Enable selected proof delivery only after actual admitted-login policy, protected
   key custody and provider/template/budget approvals. Enrollment start consumes
   exactly one UV strong grant OR `mfa_enrollment` proof; final confirmation accepts
   only the bound enrollment/new-secret code. Disable accepts fresh enrolled-TOTP
   or UV Step-up only and rechecks resulting-state password fallback/nonprivileged
   and every-role protection under the common locks. Shared Step-up is not action-scoped.
4. To stop new issuance/delivery, turn the selected channel switches and global
   switch off together while retaining binding readers/keys, DB/encryption/session
   and current-policy dependencies for bounded pending work. Final validation does
   not need an enabled provider. The fixed enrollment deadline is the earliest
   configured ten-minute-default limit, original authorization expiry and initiating
   session idle/absolute expiry; do not rewrite or extend it through renewal/retry.
5. Rollback retains additive 00010 and the unchanged active-secret representation.
   Stop new maintenance writers and resolve bounded pending work before restoring
   any older writer; old code must never redeem new records without frozen binding
   checks. Preserve account/active-factor data, keys and original authority clocks.
   No Down, migration downgrade, authority rewrite or stale-session restore is allowed.

Known-committed setup/no-op outcomes survive renewal failure. Actual enable/removal
invalidates old sessions/tokens/grants/pending authority once and emits only the
existing real-change security events; a pending-only/absent disable emits no
disabled-factor event, version bump or invalidation header. `503 outcome_unknown`
means commit acknowledgement was uncertain, not rollback: expose no tentative
secret/success/success audit, restore no spent strong grant and never auto-retry.
Lost setup output requires an explicit fresh ceremony; uncertain enable/disable
requires ordinary fresh login/current-state inspection, not reconciliation or
setup-secret retrieval. Issuance switches do not weaken enabled required MFA.

No T26 runtime/CI gate was run for this documentation-only alignment. An earlier
documentation note reported unavailable native toolchains; that is not a current
machine/toolchain diagnosis or a T26 passing result. The integrating implementation
owner must run final combined-source gates from
`.github/workflows/identity-api.yml` and resolved Nx targets with the required
toolchains. Historical acceptance remains unchanged and is not T26 evidence.
Real email/SMS receipt, physical-authenticator use, independent Persian security
wording review and deployed-ingress acceptance remain separately unverified.

## Primary Contact Maintenance (T27)

This is an existing-account API extension only. Backup contacts, registration,
login/recovery redesign, notifications and the T38 UI remain separate. Present
primary-email removal is refused with `email_removal_unavailable` until actual
T28 alternative recovery identification and T41 email-absent notification/deletion/
reclaim capabilities are independently implemented and verified. There is no
mandatory-email schema invariant, operator bypass or T27 dependency activation.

Password-contact issuance defaults off through `CONTACT_MANAGEMENT_PROOFS_ENABLED`
and independently selected `CONTACT_MANAGEMENT_PROOFS_EMAIL_ENABLED` /
`CONTACT_MANAGEMENT_PROOFS_SMS_ENABLED`. It requires usable enabled supported
password login and already-admitted immutable username authority, an active
nondeleted password-only account, no enabled/configured independent MFA and no role
membership. New-email ownership is independently opt-in through
`CONTACT_MANAGEMENT_EMAIL_OWNERSHIP_ENABLED`. Strong phone ownership remains under
existing `SMS_ENABLED`; removal/read need no delivery provider.

Use a dedicated base64 32..64-byte `CONTACT_MANAGEMENT_BINDING_KEY`, distinct from
all code/other proof keys. Proof/email issuance uses shared `LOGIN_CODE_HMAC_KEY`.
Strong SMS ownership without that key derives its code key from the existing
`SMS_OTP_HASH_PEPPER` with fixed domain separation, not a new operator secret.
Do not switch key sources or rotate either key while live records require their
original reader. Retain configured binding/code/SMS keys with issuance off; pending
records preserve original expiry, attempt and lockout policy independently of
provider switches. Selected email delivery uses verified-TLS `LOGIN_SMTP_*` and
distinct change/removal/ownership copy. SMS action delivery requires explicit
positive `CONTACT_CHANGE_SMS_IR_TEMPLATE_ID` and
`CONTACT_REMOVAL_SMS_IR_TEMPLATE_ID`, distinct from each other and all existing
purpose templates. New phone ownership keeps the existing ownership template.
UI locale does not choose provider templates or create notification negotiation.

Additive forward-only version 11 is in the [canonical inventory](#canonical-packaged-migration-inventory). Runtime proof and pending tables
`contact_management_action_proofs` / `contact_change_attempts` require only
`SELECT, INSERT, DELETE`, never generic `UPDATE` or `TRUNCATE`. Public authority is
digest-only and the exact pending destination is account/attempt/target/authorization
bound encrypted data. Bounded SQL cleanup is required independently of native
Redis expiry. No password, OTP, token, handle, recipient or evidence ciphertext
belongs in diagnostics or browser artifacts.
The reviewed `tools/docker/contact-management.sql` fragment takes the existing
restricted `runtime_role` through psql identifier quoting; it creates no role,
activates no provider and changes no unrelated table privilege. Its application
requires separate authorization and verification of effective inherited grants.

Rollout and rollback guidance is documentation, not authorization to deploy,
migrate/write shared databases, activate policies, reset data or install templates:

1. Inventory actual pending work and quiesce old phone-maintenance writers before
   switching to frozen-binding writers. Preserve original clocks; do not assume a
   legacy population, infer provenance, backfill records or run destructive Down.
2. Separately admit additive schema/restricted grants and deploy `email_otp`-capable
   durable evidence readers before enabling any new email ownership writer. Keep
   password-proof issuance and email ownership default-off until their actual
   policy/key/provider/template/budget prerequisites are approved and verified.
3. Starts consume authority once before pending commit, reserve shared quotas and
   revalidate exact pending/live state immediately before one send. Submission is
   not receipt. Unknown commit/dispatch/activation returns `outcome_unknown` without
   a tentative handle, refund, automatic retry or reconciliation system.
4. To stop issuance or sending, retain bounded proof/code/pending readers, keys,
   Redis policy, sessions and current account-policy validation through all
   inventoried original deadlines. Final validation must not require an enabled
   sending provider or extend pending expiry during renewal/cleanup.
5. Rollback binaries must retain durable `email_otp` readers and compatible envelope
   keys as long as any stored evidence requires them. Expired/cleaned pending work
   does not make an old method-rejecting binary safe. Never relabel or rewrite
   provenance, restore spent authority or run old unbound writers against new work.

Local automated gate results belong in the delivery record; configuration/test
source does not establish a pass. Real email/SMS receipt, physical authenticators,
independent Persian security wording review and deployed-ingress/log-redaction
acceptance remain separately unverified. T28/T41 activation remains blocked.

## Geography Catalog (T08/T09)

The catalog provides an operator import and bounded anonymous reads.
PostgreSQL is the authoritative runtime source. Source retrieval and validation
are operator work outside the request path. Registration integration remains
under T31–T37.

### T07 Dataset Release

The [JSON-first T07 decision](../.github/tasks/registration-single-contract-tasks.md#t07)
uses local `data/cities.json` and the original `data/types.json` as candidates.
Keep both files out of public Git. The application container contexts exclude
them. Preserve their exact bytes, including source identifiers, names, parent
relationships and type codes. Keep source files, full query results and
restricted provenance out of public CI and browser artifacts. Use synthetic
fixtures for public tests.

The [processed-catalog review](../.github/tasks/registration-single-contract-tasks.md#proposed-t07-criteria-for-the-processed-catalog)
records the owner's transformation account and the verified four-field places
schema with its separate type dictionary. Document the selected coverage and
exclusions of the processed release, with upstream versions and exact
transformation inputs where established. The 1404 publication link can be
credited as a reference without downloading its workbook or refreshing the
existing JSON files.

For each contributing source, retain the publisher, original URL, pinned tag or
commit or dated release, exact input file, and independently verifiable digest
or release record. For a collected dataset, document which files or
records each source supplied, the selection and combination procedure, conflict
decisions and the exact reproducible inputs/tool versions. Match the candidate
IDs, labels, parents and type assignments to the pinned inputs. Have the source
owner or responsible dataset maintainer substantiate the intended geographic
coverage, per-type and per-province counts and any exclusions. Record attribution
to established sources. If an authorized source comparison is needed, use a scoped
read-only identity. A SQL Server comparison is optional release evidence and has
no runtime role.

Stage the release under `datasets/geography/iran/` in the approved custody
location. Pin an immutable version for each complete release:

| Release file          | Contents                                                                                                                                                   |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `iran-geography.json` | Exact candidate places bytes once independently verified.                                                                                                  |
| `types.json`          | Exact original CenterType dictionary for the same release.                                                                                                 |
| `schema.json`         | Versioned schema for places, types and release metadata. The strict parser also checks duplicate keys, exact integer syntax and graph invariants.          |
| `manifest.json`       | Release and schema versions, source references, per-file byte lengths/SHA-256, counts by type and province, coverage and reproduction evidence references. |
| `README.md`           | Provenance, covered snapshot and reproducibility instructions.                                                                                             |
| `SHA256SUMS`          | SHA-256 of exact release file bytes. Pin the manifest or release digest through an independently trusted channel.                                          |

Keep the candidate pair in protected versioned storage or an access-controlled
private repository. Publishing the dataset requires explicit owner approval for
the exact release. Keep release payloads out of application images. Publish or replace an approved
release only once the complete package and its evidence have been validated.

### Complete-Snapshot Procedure

1. Apply the [canonical packaged migration inventory](#canonical-packaged-migration-inventory)
   using the separate migrator identity.
   `geography check` and `geography import` never migrate or perform runtime DDL.
   Existing accounts and credentials are preserved when upgrading.
2. Verify the approved T07 release and its exact places and types files. Prepare
   a separate T08 import manifest as an explicit operator assertion for the
   intended snapshot and database base revision. Its exact fields are `country:"IR"`, `source_release`,
   `cities_sha256`, `types_sha256` (lowercase SHA-256), `cities_bytes`, `types_bytes`,
   `place_count`, `type_count`, `province_count`, `expected_current_revision`
   (`null` initially, otherwise an exact positive decimal string), and
   `complete_snapshot:true`. A script's valid JSON, hashes or measured counts do
   not establish completeness or authorize retirement. Review source release and
   intended coverage before writing that assertion.
3. Inject a separately provisioned reader URL through
   `GEOGRAPHY_CHECK_DATABASE_URL` and run the explicit-path command below. Check
   uses a read-only consistent transaction, emits aggregate additions, edits,
   reparenting, retirements, reactivations and type edits plus `plan_digest` and
   `retirement_digest`, and performs no writes or migrations.
4. Review the aggregate change plan, especially retirements. Inject the importer
   URL through CLI-only `GEOGRAPHY_IMPORT_DATABASE_URL`, then supply the exact
   checked `--apply-plan` and, when retiring identities, `--retirement-digest`.
   Neither CLI falls back to the API's `DATABASE_URL`. Never put credentials in
   flags, tracked environment files, logs or browser configuration.
5. Import repeats strict validation/comparison, takes bounded transaction locks,
   verifies the active pointer and commits the entire immutable snapshot plus
   identity metadata and pointer atomically. A changed input, stale base or wrong
   acknowledgement fails closed and rolls back. Review/check again instead of
   overriding a stale digest. Identical active files are a true no-op, including
   concurrent identical imports against the same checked base. Reusing an older
   snapshot requires a new check and creates a new revision.
6. If the command reports an unknown commit outcome, rerun the import with the
   same manifest and acknowledgement digests. If the original commit landed and
   is still active, the retry returns its revision as a no-op. If the base is
   still active, the original plan can apply. If the catalog advanced to a
   different revision, check the current state and review a fresh plan.

```bash
npm exec -- nx run identity-api:geography-check -- \
  --cities=/absolute/path/cities.json \
  --types=/absolute/path/types.json \
  --manifest=/absolute/path/complete-snapshot.json

npm exec -- nx run identity-api:geography-import -- \
  --cities=/absolute/path/cities.json \
  --types=/absolute/path/types.json \
  --manifest=/absolute/path/complete-snapshot.json \
  --apply-plan=<checked-plan-digest>
```

For a retirement plan add `--retirement-digest=<checked-retirement-digest>` to
import. All operator Nx targets are uncached. File ceilings are 64 MiB for places,
64 KiB for types, 250,000 places, 64 types, 256 Unicode code points/1024 UTF-8 bytes
per label and 32 parent edges. Empty/partial snapshots, duplicate JSON keys/IDs,
invalid UTF-8/numbers/fields, unknown types, missing parents, cycles, self-parenting,
non-province roots and inconsistent ancestry are refused with bounded diagnostics.
Variable depth and type-5-under-type-5 are valid. Original labels remain unchanged.

### Separate Permissions

Provision actual non-owner, non-inheriting reader/importer logins independently;
the application/CLI does not create roles or grant authority. Retain the separately
provisioned migrator identity. Do not grant membership, schema/database CREATE,
trigger bypass, deletion/truncation, account access or grant options to importers.
The operator commands validate their effective restricted privileges.

| Role           | Required catalog grants                                                                                                                                                                                                                        |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Reader / check | `SELECT` on all five geography tables only; schema `USAGE` and database `CONNECT`.                                                                                                                                                             |
| Importer       | Reader grants; `INSERT` on types, places and place versions; column `INSERT` on catalogs' revision/country/source/hash/size/count/importer/normalization metadata; `UPDATE(last_seen_revision)` on places; `UPDATE(active_revision)` on state. |
| Migrator       | Existing independently approved schema authority, not an API/importer credential.                                                                                                                                                              |

`geography_catalogs.imported_at` and `writing_tx` are server-owned, not importer
input. No sequence grant is needed: revisions are allocated under import exclusion.
The SQL guards reject snapshot updates/deletions/truncations and additions after
the writing transaction closes. Permanent source identity and first-seen revision
are immutable; retiring an identity removes current snapshot membership, not its
historical rows. Historical lookups resolve every ancestor in the same revision.

Lock order is shared transaction `MigrationKey` (5300001), exclusive transaction
`GeographyImportKey` (8000001), then the active state row. Migrators acquire exclusive
`MigrationKey` before worker exclusions, so imports cannot overlap schema changes.
Do not reverse this order or take account/worker locks from catalog import code.
Transaction end releases import locks even on cancellation/error.

### Read Limits And Recovery

The public endpoints retain existing same-origin response headers and trusted
client-IP resolution. Defaults: pages 20/max50, query timeout1s, limiter timeout250ms,
120/IP/minute and 600/subnet/minute. Optional `GEOGRAPHY_PAGE_SIZE_DEFAULT`,
`GEOGRAPHY_PAGE_SIZE_MAX`, `GEOGRAPHY_QUERY_TIMEOUT`, `GEOGRAPHY_LIMITER_TIMEOUT`,
`GEOGRAPHY_PER_IP_PER_MINUTE` and `GEOGRAPHY_PER_SUBNET_PER_MINUTE` may only tighten
the implemented ceilings; resolve current config/tests before changing them.
Uninitialized catalog/database/limiter failures return503, never empty success.
`catalog_changed` requires explicit browser restart/retry, not cursor rebinding.

Roll back compatible application binaries without deleting immutable catalog
history or changing stored IDs/revisions. The geography migration in the
[canonical inventory](#canonical-packaged-migration-inventory) is forward-only.
Recovery uses an approved consistent backup or a newly reviewed complete import. A lookup
without revision cannot reconstruct an old reference's original meaning. Future
T10 must revalidate and encrypt `catalog_revision` with IDs, bound to account/purpose.

### Geography Acceptance

Use `identity-api:test-geography`, the owned
`--integration-target=test-geography-integration` cell, owned
`--integration-race-package=./internal/geography` cell and
`web:test-geography-browser`, in addition to the final required regression gates.
The browser fixture is built only in a disposable test application, never a
production route or opt-in production build mode. Source identity, exact nonzero
package/test inventories, zero unexpected skips and confirmed cleanup are required.
API unit tests and headless keyboard/RTL/focus assertions do not certify manual
screen-reader/native-touch or professional Persian review.

`identity-api:geography-performance` requires explicit external source and manifest
paths, creates run-owned PostgreSQL, imports through the real restricted CLI and
reports aggregate timings/index sizes and sanitized `EXPLAIN (ANALYZE, BUFFERS)`
structure only. It never uses inherited/shared database credentials. Warmed query
p95 target is below200ms across100 representative browse/prefix/empty/later-page
queries; retain misses as failures and diagnose plans, never weaken bounds. Actual
local PASS/FAIL/NOT RUN results, hosted CI and unperformed manual/platform/deployed
ingress gates must be reported separately; test existence is not execution evidence.

## User Lifecycle Publisher (Task 6.3)

`lifecycle-publisher` ships in the same non-root backend image. Run it as a
separate MVP worker, not in request handlers or the audit signer. It needs no
Redis, encryption keys or SPIRE. Broker outages accumulate durable intent instead
of turning into log-only delivery.

| Mode                | Credentials and behavior                                                                                                                                                      |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `provision`         | Broker/topology credentials only. Create `IDENTITY_USERS` or validate compatible existing topology; never overwrite drift or the audit stream.                                |
| `publish` (default) | Scoped `DATABASE_URL` and `NATS_URL`. Open existing topology, claim committed intent, mark delivered only after the expected stream's PubAck.                                 |
| `cleanup-published` | Separate `LIFECYCLE_CLEANUP_DATABASE_URL` and approved `LIFECYCLE_OUTBOX_RETENTION`, no broker/API secrets. Bounded, hold-aware deletion of acknowledged lifecycle rows only. |

The stream uses the four exact lifecycle subjects, File storage, Limits retention,
DiscardNew, a two-minute deduplication window, a 16-KiB message limit and one
replica. Default capacity is 128 MiB. `LIFECYCLE_STREAM_MAX_AGE` and
`LIFECYCLE_OUTBOX_RETENTION` require explicit positive finite production values;
stream age must exceed the duplicate window. Their `168h` defaults apply only with
explicit `APP_ENV=development` and are not production policy approval. One replica
is not broker HA. Size disk/capacity for the approved replay horizon;
acknowledgements do not free history early under Limits retention.

1. Complete the [fresh-baseline cutover](#fresh-baseline-environment-cutover), which
   includes lifecycle revisions/outbox. Drain old mutation writers and deploy
   compatible producers, profile RPC and worker together. Revision defaults remain
   0; no registrations or historical events are synthesized by schema setup.
2. Provision with a separately approved broker identity. Ordinary publishers must
   not mutate topology. Each service needs independent durable/grant permissions.
   API DB roles may insert intent, not mark it delivered; publishers cannot mutate
   users/audits; cleanup access is separate. Verify deployed grants/RLS, not merely
   SQL predicates.
3. Establish authoritative consumer baselines/checkpoints before activation.
   Lost/recreated/expired history requires reconciliation, not starting at latest.
   No bulk bootstrap or snapshot API is supplied. Follow the
   [consumer contract](client-integration.md#4-user-lifecycle-consumption).
4. Select `/usr/local/bin/lifecycle-publisher` as the image entrypoint. Defaults
   are 50 rows/batch, 5s/publish, 30s/batch, 1s polling and 15s startup. Shutdown
   stops new claims and bounds in-flight work. Uncertain commits can replay a stable
   ID; consumer idempotency remains mandatory.
5. Monitor aggregate pending count, oldest age, accumulated attempts and invalid
   rows from structured diagnostics/`Backlog`, plus broker storage and consumer lag.
   Alert on sustained failures/growth, invalid envelopes and age approaching the
   replay horizon. No Prometheus endpoint, alert rules or paging route is installed
   by this change; approved thresholds/routing are production release gates.
6. Schedule cleanup only after retention approval. Unpublished intent never expires;
   held candidates are excluded and rechecked under account locking. Malformed
   published rows are retained/reported and require controlled repair, not silent
   erasure to clear a backlog. Never disable holds or manually mark rows delivered
   to hide failures. Cleanup does not purge broker history or legal evidence.
7. Rollback preserves revisions/accepted intent; the baseline is forward-only.
   Stop incompatible writers, restore related database state consistently, and
   reconcile baselines/deletions before reopening traffic.

Task 6.3 validation does not grant production permissions, approve retention,
deploy consumers or remove earlier tasks' production enablement gates.

## User Portal Cutover (Task 7.3)

The portal serves existing passkey-enabled accounts. Separately enabled signup
can create accounts only after the owned-email/phone/resident-UV proof contract;
it adds no password login, OAuth consent or downstream deployment. The
browser and API must be released as one compatible boundary, not a mixed fleet of
new DPoP-required and old cookie-only replicas.

1. Complete the [fresh-baseline cutover](#fresh-baseline-environment-cutover) first.
   Profile/key names default to empty; do not synthesize historical profile events.
   Verify deployed DB grants
   for profile reads/writes and transactional outbox insertion.
2. Deploy dual-version lifecycle publishers/readers and upgrade actual downstream
   consumers before deploying writers that emit display-name/private-profile v2 events. V1 and
   legacy revision-less deletion adaptation remain supported. Validate mixed
   replay and gRPC name/revision snapshots. External consumer deployment and
   baseline/checkpoint reconciliation are operator prerequisites, not implied by CI.
3. For current code, use shared standalone Redis for browser sessions, DPoP nonce/replay, step-up
   claims and `webauthn:challenge:v1:<sha256 challenge>`. Configure appropriate
   ACLs/TLS, capacity and availability; in current code credential state is
   authority, not a cache. SEC09's SQL replacement must precede treating Redis
   as non-authoritative.
   WebAuthn state is capped at 64 KiB, native TTL at fifteen minutes (five-minute
   default), and operations at two seconds. Anonymous login options/verification
   and reclaim options share 30 requests/subnet/minute, including nonce retries.
   Redis faults fail closed.
4. Drain old API processes and in-flight memory ceremonies, then deploy the new
   API and compatible frontend together. Existing unbound cookies require fresh
   passkey login. Do not rebind them or mix acceptance rules across replicas.
   Keep signing material and `STEPUP_REPLAY_HMAC_KEY` consistent across the fleet.
5. Set one canonical `PORTAL_ORIGIN`, matching the `OIDC_ISSUER` origin and an exact
   `WEBAUTHN_RP_ORIGINS` entry. Use HTTPS, no trailing slash/path/query/default port.
   Serve only the canonical host. Pages/assets route to Next; `/api` routes directly
   to Go. Preserve Origin, DPoP, `X-Portal-Session`, `X-Step-Up-Auth`, cookies and
   nonce/error responses. There is no CORS/BFF workaround.
6. Keep `SESSION_COOKIE_NAME=__Host-session` and `SESSION_COOKIE_SECURE=true`.
   Defaults are `SESSION_ABSOLUTE_TTL=24h` and `SESSION_IDLE_TTL=2h`. Explicit
   loopback HTTP experimentation is development-only; do not weaken cookies or
   production Next CSP for browser acceptance. The `.env.example` uses local
   HTTPS at `https://localhost:8443` and requires an ingress, not separate origins.
7. Verify private/no-store/no-referrer on API errors and empty responses as well
   as successful reads. Next's document policy does not cover `/api`. Disable
   shared API/HTML caching and redact request bodies, credentials, proofs, names,
   grants, recovery batches and identity-bearing URLs at ingress/APM/log shippers.
   Use constant route-template diagnostics, not `$request_uri` or `$request`.
8. Rehearse login, names, UV/TOTP step-up, individual/current revocation and
   one-time-code exports through the actual deployed HTTPS ingress. A successful
   local harness cannot prove deployed proxy forwarding, redaction, workload
   grants or downstream compatibility. Already admitted requests may finish after
   revocation; do not promise immediate erasure of another browser's rendered DOM.

Rollback must stop/drain new writes while preserving accepted intent and
v2-compatible publication/consumption for the full outbox/replay horizon. Keep
the additive columns; never run a strict-v1 worker on v2 rows. Do not restore old
Redis authority/replay snapshots or re-enable cookie-only access. A rollback that
requires old auth code must withdraw portal traffic and coordinate reauthentication.
Existing audit/legal/retention and private-gRPC deployment gates remain in force.

### Registration Enablement and Cleanup

`APP_ENV` is mandatory and exactly `development`, `test`, or `production`.
Missing/empty/whitespace/unknown modes fail before listeners/connections; test is
not a development exemption. Only explicit development permits ephemeral signing
keys, missing-client seeding, local HTTP and selected memory seams. Enabled paths
never downgrade after dependency failure. The exact public all-zero 32-byte
KEK/pepper samples are rejected in production, not by arbitrary entropy guesses.

`REGISTRATION_ENABLED=false` and `SMS_ENABLED=false` are independent safe defaults.
Disabled SMS requires no provider credentials and retains DB-only removal/recovery.
Enable only after separately approved state, logins, private secrets, budgets and
operational gates; `.env.example` supplies no usable public registration budgets.

| Required enabled configuration                                                                                        | Contract                                                                                                                                                                                           |
| --------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `REGISTRATION_PENDING_CAPACITY`                                                                                       | Explicit `1..10000`; finite SQL pending-state admission, not approved public capacity.                                                                                                             |
| `REGISTRATION_GLOBAL_DAILY_LIMIT`                                                                                     | Explicit `1..100000`, shared finite registration admission budget.                                                                                                                                 |
| `REGISTRATION_EMAIL_HOURLY_LIMIT`                                                                                     | Explicit `1..10`, canonical-email admission budget.                                                                                                                                                |
| `SMS_PROVIDER`, `SMS_IR_KEY_MODE`                                                                                     | Exactly `smsir`; enabled registration requires explicit `live`. Standalone nonproduction SMS may explicitly use `sandbox`; production is live-only.                                                |
| `SMS_GATEWAY_API_KEY`, `SMS_IR_TEMPLATE_ID`, `SMS_IR_CODE_PARAMETER`                                                  | Private key, positive integer template, exact case-sensitive parameter without `#`. No sample key/template is operator authorization.                                                              |
| `SMS_OTP_HASH_PEPPER`                                                                                                 | Independent private HMAC secret, required when SMS is enabled.                                                                                                                                     |
| `SMS_OTP_GLOBAL_PER_DAY`, `SMS_OTP_MAX_PENDING_SIGNUP`                                                                | Explicit finite send budget and pending cap; cap must equal registration capacity. Shared signup/enrollment phone/subnet/global send bounds apply.                                                 |
| `REGISTRATION_SMTP_HOST`, `PORT`, `TLS_MODE`, `USERNAME`, `PASSWORD`, `FROM`, `TIMEOUT`, `CA_BUNDLE`, `PUBLIC_ORIGIN` | Variable prefix is `REGISTRATION_SMTP_` for each field. Authenticated verified TLS, ASCII system sender/auth, positive timeout at most 5s; canonical public origin exactly equals `PORTAL_ORIGIN`. |
| `REGISTRATION_CLEANUP_DATABASE_URL`                                                                                   | Dedicated actual non-owner NOINHERIT login, separate from API pool; required for enabled startup's nonmutating privilege/schema probe.                                                             |
| `REGISTRATION_CLEANUP_BATCH_SIZE`                                                                                     | `1..500`, default 100, for the packaged maintenance command.                                                                                                                                       |

These ceilings are engineering safety bounds, **not approved operator budgets**.
SMS.ir uses fixed POST `https://api.sms.ir/v1/send/verify`, Iranian
`+989xxxxxxxxx` destinations submitted as `Mobile: "9xxxxxxxxx"` (10 digits), and
one named six-digit code string preserving leading zeros. No GET fallback,
redirect/provider override, automatic billed retry or real provider test credential
is supplied. Sandbox uses the same endpoint and success-shaped replies but sends
nothing. ID/cost/ACK cannot establish key provenance or handset receipt. Before
live enablement, approve the key/template/parameter, country routing, public egress
and spend limits, then separately authorize/attest an actual received message.

Startup/readiness checks for enabled signup require final schema, local key
round-trip, DB/shared Redis, dedicated cleanup-login admission and verified SMTP
TLS/post-TLS EHLO/actual authentication. `Check(ctx,true)` requires SMTPUTF8 before
AUTH and sends no MAIL/RCPT/DATA or test message. Real Unicode-mailbox receipt,
relay/provider policy and cleanup supervision are external gates; flags or a
successful capability check cannot attest them. ASCII local parts with IDNA ASCII
domains can use an ASCII relay outside Unicode signup requirements; never reroute
a Unicode mailbox to an ASCII approximation.

Packaged `/usr/local/bin/registration-cleanup [once|check]` uses only explicit
environment, its dedicated DSN and batch setting. `check` validates actual login/
schema/privileges without mutation; `once` runs one bounded batch. Each invocation
has a fixed **30s total deadline**, not a polling loop. An externally supervised
schedule and monitoring are required before enablement. Cleanup login needs only
SELECT/DELETE on registration attempts and SELECT on legal holds, no membership,
owner/superuser/API/evidence/role privileges or unrelated secrets. Completed receipt
cleanup takes the subject lock before rechecking holds; held/contended rows defer
without blocking unrelated progress. Pending/failed rows have no user subject.

Pending/email/passkey/receipt validity is 15m/10m/at-most-5m/1h. Expiry blocks
authority even if cleanup is unavailable or a hold retains a receipt; expiry alone
is not physical deletion. Completion clears transient encrypted contacts/tokens/
ceremony state; resulting-user FK cascade must not prevent lawful purge. No
exactly-once email/SMS promise, email-based capability recovery, role/session/
password/new-mailbox bootstrap or relaxation of general mutation retries is added.
Preserve registration/migration state in consistent forward restores. Stop signup
intake before incompatible rollback, retain accepted accounts/events/receipts and
original clocks; no Down/reset/adoption or automatic laboratory transformation.

### Username Policy and Preflight Gates

[T04A](../.github/tasks/registration-single-contract-tasks.md#t04a) verifies
the namespace and [approved assignment policy](registration-contract.md#approved-initial-username-assignment-policy)
on disposable PostgreSQL. Feature development consumes that local evidence.
[T04B](../.github/tasks/registration-single-contract-tasks.md#t04b) owns actual
production inventory and separately authorized activation. It gates public
launch through T42.

The [registration contract](registration-contract.md) adds username support to
the existing email-link + mobile-SMS + resident-UV flow, not the final one-contact
or password flow. Schema/config/operator code is not a live installation. The owner approved the exact lengths and six canonical reservations on
2026-11-27. Deployment privileges, cutover timing and zero-pause operation
require separate operational review.
The version-3 migration in the [canonical inventory](#canonical-packaged-migration-inventory) preserves existing NULLs, creates the unique
reservation/immutability boundary and seeds an **uninstalled** authority record,
not an active policy. It provisions no runtime/maintenance login or reindex bypass.

| Username configuration                          | Required meaning when enabled                                                                                                                                                                                                                                                                       |
| ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `USERNAME_ENABLED`                              | Explicit username enablement, including authenticated reads when signup is off. Enabled registration requires username support; no username-less fallback.                                                                                                                                          |
| `USERNAME_REGEX`                                | One bounded Go expression, compiled once with whole-string anchoring against NFC display. Initial syntax is the approved Persian repertoire and Arabic Yeh/Kaf aliases with single internal dots.                                                                                                   |
| `USERNAME_POLICY_JSON`                          | Explicit keys `id` (nonzero UUID), `normalization` (`nfc-four-fold-v1`), `folds` (the exact four `{from,to}` scalar pairs), `min_letters`, `max_code_points` and the six approved exact `reserved_names`. Both limits, the exact regex and the pinned Unicode/normalizer version are fingerprinted. |
| `USERNAME_LOOKUP_KEY`, `USERNAME_LOOKUP_KEY_ID` | Dedicated base64 secret of at least 32 random bytes and explicit ID; never email/phone/ledger pepper. Actual key verifier must match database authority, not just its label.                                                                                                                        |

The approved initial values are `min_letters: 4` after NFC excluding dots and
`max_code_points: 40` after NFC including dots. The decoder requires integer
values satisfying `1 <= min_letters <= max_code_points <= 512`. At most 512
two-byte letters fit the technical ceiling, even when no single-byte dots are
present. The schema revision is pinned in the artifact as `hatef.username.v2`.
Changing either bound changes the fingerprint and requires a new artifact ID
and the separately approved installation and activation path. If earlier
artifacts are discovered on the actual target, reconcile them under T04B
before activation.

Missing enabled configuration,
same-ID changed content, wrong secret under a key ID, malformed/duplicate/unknown
artifact fields, unsafe mappings and invalid/empty/over-budget regexes fail closed.
No hot reload, env-only override/rollback, concurrent active namespaces or transparent
HMAC rotation is permitted. Input/normalized bytes, regex source and artifact have
independent technical ceilings of 1024/4096 bytes and 16 KiB, respectively.

Operator entry points are `cmd/username install` and `cmd/username preflight`.
Identify the actual intended production database, schema revision and scoped
operator identity before connecting. Read-only access, inactive installation,
activation and deployment require separate owner authorization. Confirm the
exact approved regex and policy fingerprint, approved reserved inventory,
dedicated key ID and actual verifier from approved key custody before namespace
operations. Provision secrets through the existing secret manager. Run each mode with its own process environment;
both read **`DATABASE_URL`**, not dedicated username-specific DSN variables.

| Mode              | Database identity and environment                                                                                                                                                                                                                                                                                                                                                              |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Both              | `APP_ENV` (`development`, `test` or `production`), `USERNAME_ENABLED=true`, and all four policy/lookup variables above. These configure the operator; they do not enable API traffic or activate a policy.                                                                                                                                                                                     |
| `install`         | Separate non-owner installer `DATABASE_URL`; SELECT/INSERT only on `username_policy_artifacts` and `username_lookup_keys`, with no active-row/account mutation, role assumption, grant options, DDL or trigger bypass. Loads the candidate from `USERNAME_*`; no envelope, review, SMS or Redis secret is required.                                                                            |
| `preflight`       | Separate non-owner read-only scanner `DATABASE_URL`; SELECT on `users`, `username_policy_artifacts`, `username_lookup_keys` and `username_active_policy`, with no application writes/DDL/role assumption. If authority exists, `USERNAME_*` must match its current artifact and actual key verifier; on the uninstalled baseline it describes the installed candidate.                         |
| Preflight secrets | Independent base64 `USERNAME_REVIEW_KEY` (32..1024 decoded bytes) for restricted opaque review references, never the lookup/envelope/pepper secret. `ENVELOPE_MASTER_KEK` is the actual 32-byte base64 decryption key and `ENVELOPE_MASTER_KEK_VERSION` its actual version (`0..255`, default `1`); unavailable/wrong-key records block clearance. No `ENVELOPE_BLIND_INDEX_PEPPER` is needed. |

The commands probe effective restricted privileges; an API/schema-owner credential
is not an acceptable substitute. These prerequisites do not provision any role or
grant. With the appropriate mode-specific environment already supplied, the
workspace-root targets are:

```bash
npm exec -- nx run identity-api:username-install
npm exec -- nx run identity-api:username-preflight
```

Run them separately with different `DATABASE_URL` identities, never as an automatic
install/activate chain. Targets depend on `sqlc-generate`; neither runs migrations.
Install success reports `{"installed":true,"active":false}`: it inserts immutable
artifact/key-verifier registry entries only. It cannot open/close admission, change
the active row, reindex or assign usernames. There is **no activation helper**.

| CLI flags                                                                              | Exact bounds / meaning                                                                                                                                                                                                                                                                                                                                                                                                           |
| -------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--page-size`, `--max-rows`, `--max-issues`, `--timeout`                               | Defaults `250`, `100000`, `100`, `5m`; permitted ranges `1..1000`, `1..1000000`, `1..1000`, `1s..1h`. A row cap is incomplete, not a clean prefix. An issue cap sets `issues_truncated`; it cannot turn a nonclean scan into clearance.                                                                                                                                                                                          |
| `--candidate-policy`, `--candidate-regex`, `--candidate-key-id`, `--candidate-key-env` | Optional **preflight-only, all-or-none** comparison against an already inactive-installed candidate. First two are bounded policy-JSON/regex-source file paths; regex bytes are exact, with no trimming. Last two are the candidate key ID and the name of an environment variable holding its base64 key (at least 32 decoded bytes), never the secret itself. Without these flags, candidate equals configured current policy. |

Preflight JSON reports `snapshot_only`, `complete`, `clean`, aggregate counts and
restricted issue references, with `reason`/`issues_truncated` where applicable.
Exit `0` requires successful complete **and** clean preflight; exit `1` covers
nonclean, incomplete, invalid configuration/privileges and operation/report failure.
Write the report to the authorized protected destination outside the public
repository. Record the verified target identity, migration revision, artifact
fingerprint, key ID and provenance decision, snapshot counts, completeness and
no-split result. Restrict report and review-key access. Ordinary diagnostics
contain only counts and non-sensitive status. Activation requires its own
authorization and a fenced rescan. T04A's disposable database evidence applies
to the local run. Production evidence remains pending under T04B.

The active database policy/key identity is checked under a shared guard for each
username read/assignment, held through its deciding transaction. Hard deletion and
maintenance coordinate before account locking; startup/readiness checks alone are
not a writer fence. Reservation spans all surviving statuses/soft deletion; only
physical account deletion releases it. Populated tuples cannot be renamed/cleared.
Do not assume migrations installed non-owner runtime/maintenance roles: any reindex
exception stays disabled until reviewed effective ACLs prove the application cannot
invoke it, alter the guard or assume the maintenance role.

Preflight must be operator-only and read-only, using a bounded
`REPEATABLE READ READ ONLY` snapshot, keyset pagination and explicit completeness.
Inventory every surviving claimed row and reviewed reserved name; count NULL
unclaimed rows separately. Decrypt original display with account/purpose/provenance
checks, derive candidate keys and detect collisions across pages. Unreadable,
unknown-policy or inconsistent rows, collisions, timeouts and capped/incomplete
scans block clearance. For a newly provisioned target, establish its identity
and use authorized read-only inspection to verify the actual schema and zero
account rows. The complete namespace preflight must also show `scanned = 0`
for an empty production baseline. A zero `claimed` count can coexist with real
unclaimed rows. A collision-clean report with unclaimed rows requires explicit
owner review of that observed population before activation. Preserve the
accounts and their data during that review.

Controlled installation/evolution requires separate operational approval:

1. Use explicitly authorized read-only access to establish the actual target
   and inventory scope. Verify the approved policy and key provenance. With
   separate installation authorization, install only the immutable inactive
   candidate if required by the preflight. Complete the read-only preflight
   against that target, including reserved names. Review any actual collisions
   before activating a unique namespace.
2. Prove no protected equivalence class splits: for the retained alphabet/aliases,
   `C_new(C_old(x)) = C_new(x)`, with NFC/dots unchanged. Additional mergers still
   require separately approved semantics; a new ID and clean scan are insufficient.
3. Close the database username-writer gate, drain shared guards and fence/stop
   pre-feature registration replicas and every ownership-changing writer, including
   hard deletion. Nullable columns alone cannot stop old username-less registration.
4. Revalidate the complete current inventory while fenced. An earlier clean snapshot
   does not close the scan-to-activation race. Any incomplete/colliding/unreadable
   inventory, changed immutable identity or no-split failure blocks activation.
5. Preserve the old unique namespace until all candidate rows are verified; atomically
   switch the complete digest/encrypted-payload/provenance set and active authority.
   Re-seal when canonical/provenance changes, preserving NFC display/account/purpose/
   owner; expose no mixed namespace. Failed transition retains the old namespace.
6. Admit only replicas matching the exact active artifact and key verifier before
   reopening. Software rollback must support active policy; a downgrade that splits
   classes is refused. Key replacement uses the same fenced approved path.

These are gates, not claims that activation/reindex tooling, maintenance access or
live installation has been delivered. T12 public one-time username claim is out of
scope, not deferred implementation. Mandatory production username ownership must
be satisfied by registration and reviewed constraints, not a hypothetical legacy
lane. Neither generic step-up nor an initial-assignment primitive authorizes a
public claim POST/UI. Keep accepted
accounts/receipts, original deadlines, history and unrelated session policy intact.
Real-data inventory, serial disposable-database races/rollback, bilingual browser
checks, deployed ingress/redaction, real delivery/physical authenticators and
independent Persian security/legal review require separately observed evidence.

### Automated Portal Acceptance

From the workspace root, with npm dependencies, Go 1.26.5+ and Docker available:

```bash
npm exec -- nx show project web --json
npm exec -- nx show project identity-api --json
npm exec -- nx run identity-api:test-portal --skipNxCache
npm exec -- nx run identity-api:test-portal-fixture --skipNxCache
npm exec -- nx run-many -t build,build-deletion-notifier,build-portal-fixture -p identity-api --skipNxCache
npm exec -- nx run web:build --skipNxCache
npm exec -- playwright install --with-deps chromium
npm exec -- nx run web:test-portal-browser --skipNxCache
npm exec -- nx run identity-api:build-registration-cleanup --skipNxCache
# After an approved owned candidate build, inject its immutable publication API ID
# and matching acceptance manifest; never silently rebuild the API for this check.
npm exec -- nx run web:test-registration-browser --skipNxCache
```

Registration browser requires `REGISTRATION_BROWSER_API_IMAGE=sha256:<id>`,
absolute `REGISTRATION_BROWSER_API_MANIFEST` and
`REGISTRATION_BROWSER_ARTIFACT_DIR` paths, and the matching
checksum/source/generated-image acceptance manifest. It must use
that immutable image's packaged migrate/API/cleanup commands, run-owned isolated
services, a production-configured SMS.ir-contract TLS fixture at internal
`api.sms.ir` and SMTPUTF8 relay, with external egress blocked. No host DNS/trust
edits, real provider credentials, production fake-provider flag or seeded fixture
account substitutes for signup. Required report identity must match publication;
adding/resolving a target or source-level tests is not browser/image acceptance.

PostgreSQL, Redis, JetStream and the API belong only to the run-owned internal
network, without published service ports. Docker may report null host bindings
for these private services; startup uses verified container IDs and private
addresses, not host-port discovery. Only the fixture Node controller joins the
separate ingress network. Its gateway accepts fixed authentication/readiness
routes to the owned API, never caller-selected destinations or CONNECT tunnels;
SMS and SMTP listeners bind only to its private interface. JetStream provisioning
uses the controller's owned private broker address. Do not expose backing services
or relax production transport admission to repair fixture connectivity.

The final normal service gate is exactly eight one-suite cells under
`max-parallel: 1`, `fail-fast: false`, unchanged target/job deadlines (30m/60m),
nonzero executed evidence, zero failures/skips and verified run-owned cleanup.
The [eight-suite inventory](admin-operations.md#automated-validation) is explicit;
new package coverage is additive and overlapping runs must remain. Thirteen affected
Linux CGO race cells/aggregate are separate, with `-json -tags=integration -race
-count=1 -p=1 -timeout=20m`, never replacements for normal suite evidence.

From the repository root, set `REPO` to the exact absolute checkout directory.
Use shared explicit `ACCEPTANCE_RUN_ID` across local partial cells and their
aggregate; use an approved run-owned artifact directory. Example entrypoints:

```bash
npm exec -- nx exec -p schemas -- node "$REPO/.github/scripts/portal-harness.mjs" --integration
npm exec -- nx exec -p schemas -- node "$REPO/.github/scripts/portal-harness.mjs" --integration-target=test-security-db
npm exec -- nx exec -p schemas -- node "$REPO/.github/scripts/portal-harness.mjs" --integration-race-package=./internal/recovery
```

Partial mode identifies itself as partial and cannot satisfy publication. Require
exact-eight unique normal and exact-thirteen unique race results, source/generated/run identity,
test/package evidence and cleanup; missing/stale/duplicate/wrong-source reports,
zero exit without tests or any skip fail. Resolve final targets before running.
Never overlap independent service or browser harnesses against the same Docker
daemon: the restartable lifecycle broker intentionally uses `admin-test-nats`.
On a Windows host using a Linux execution bridge, verify actual native Linux
Go/CGO/GCC capabilities rather than changing Node's reported platform. Confirm
owned native descendants have retired before removing backing services; a bridge
exit alone is not proof. Retain installed tooling and evidence through acceptance,
and remove only verified run-owned resources, never name-matched foreign state.
For focused Go commands, Nx exec traverses dependency cwd: use
`npm exec -- nx exec -p identity-api -- go -C /absolute/path/to/ldp/apps/identity-api test ...`
with the actual absolute backend path, never `--excludeTaskDependencies`.

`web:test-portal-browser` owns disposable PostgreSQL/Redis/JetStream containers,
loopback ports and fresh volumes. Each stack starts two real production-configured
Go APIs, Next.js and HTTPS ingress; Chromium trusts only its ephemeral certificate
SPKI. Deletion/reclaim uses a separate stack with the real notifier and an owned
authenticated TLS SMTP sink, so earlier scenarios cannot exhaust its production
subnet limit. Ceremony starts use A and completions B, including anonymous reclaim.
No development cookie/CSP exceptions or inherited database/secrets are used.

`cmd/portal-fixture` is included only with `-tags=portalfixture` and is absent from
normal builds/runtime images. It refuses unarmed/production invocations,
missing/invalid modes and any mode other than explicit development/test (admin
fixtures are test-only),
non-loopback/run-mismatched databases and unowned/nonempty Redis. The harness
seeds random accounts, eight-byte anonymized handles and matching real ES256
COSE/CDP credentials through that private command, never an HTTP endpoint or magic
account. Fixture secrets travel over child-process pipes, not checked-in files,
browser storage snapshots or CI artifacts. Only this run's session TTLs can be
shortened for expiry checks. Cleanup removes only run-owned containers/volumes.

The separate focused database target requires explicitly configured disposable
`DATABASE_URL`, `REDIS_URL` and `NATS_URL`, and fails if they are absent:

```bash
npm exec -- nx run identity-api:test-portal-integration --skipNxCache
```

Run database suites serially using only run-owned disposable resources; never reset
an existing environment. Lifecycle tests can restart their explicitly identified
disposable NATS container.
Never point them at shared development or deployed data. CI keeps the existing
security, lifecycle, gRPC, generated-code, vet/lint/Linux race, image and CSP suites;
it adds focused portal integration and a separate `portal-browser` release gate.
The existing `web-csp.browser.mjs` still validates the actual non-root web image,
strict parser-inserted attack probes and inactive public forms.

For the changed registration UI, disabled password/reset/neutral-TOTP and
JavaScript-disabled forms remain required CSP/browser assertions; historical
inactive-signup evidence does not certify the enabled registration contract.

Set optional `PORTAL_BROWSER_ARTIFACT_DIR` for masked layout screenshots and
`portal-evidence.json`. The suite does not persist plaintext recovery downloads,
browser traces, cookies, proofs or fixture private keys. It records whether native
hidden-tab/bfcache transitions were observed; injected resume events and browser
clock advancement are not a claim of native platform coverage. Missing native
coverage, manual assistive-technology/authenticator review, real-ingress checks and
downstream-consumer validation remain explicit release gates. Record actual test
results before task completion; adding these commands does not establish a pass.

## Admin Control Panel (Task 7.5)

The admin panel uses the same canonical HTTPS origin, secure cookie, DPoP key, session intent and strict document CSP as the account portal. It does not enable `ADMIN_ENABLED`, install production governance, or introduce a BFF/CORS exception. Coordinate deployment of the panel, API and all admin REST clients with old admin ingress closed and in-flight requests drained. Before reopening ingress, **every API replica** must enforce mandatory canonical-string `expected_revision` and support string-valued account revisions and audit/verifier sequence/cursor fields. Retire incompatible callers and pending forms; do not add numeric or revision-optional fallbacks. No new schema migration or cryptographic format is needed. Lifecycle v1/v2 downstream readiness remains an independent rollout requirement.

Rollback must proceed in this order:

1. Close admin ingress.
2. Disable/remove the dashboard Admin entry.
3. Coordinate API/UI rollback while incompatible admin traffic remains closed. Reopening still requires every API replica and caller to satisfy the contract above and the existing production gates.

Retain database state, audit/outbox intent and approved retention/cleanup throughout rollback. Do not downgrade storage, discard accepted intent or rewrite hashes; keep canonical-v2-compatible signer/verifier binaries. The panel rollback does not change grants, retention policy or legal workflows.

The required uncached browser gate owns fresh PostgreSQL 16, Redis 7 and NATS 2.10 services, production-built Next/API binaries, two API replicas, a real signer and admin publisher, and HTTPS ingress. Its excluded `portalfixture` command installs a **fixture-only** governance baseline and canonical-v2 genesis heads before starting the signer. Admin mode explicitly uses `APP_ENV=test` and `LEGAL_WORKFLOW_ENABLED=false`; it retains all production cookie, Origin, DPoP, step-up, live-RBAC, audit and CSP enforcement. Approved fixture durations are not production retention defaults. No fixture HTTP routes or production fixture binaries are added.

```bash
npm exec -- nx run identity-api:test-portal-fixture --skipNxCache
npm exec -- nx run web:test-admin-browser --skipNxCache
node .github/scripts/portal-harness.mjs --integration
```

The browser target builds its API/web/fixture/signer/publisher/notifier dependencies; Task 7.6 also requires `identity-api:build-admin-legal` for the real signer lookup probe. The integration orchestrator runs all eight CI suites in CI order: `test-security-db`, `test-admin-integration`, `test-retention-integration`, `test-legal-workflow-integration`, `test-grpc-integration`, `test-lifecycle-integration`, `test-geography-integration`, and `test-portal-integration`, through Nx serially on disposable PostgreSQL 16, Redis 7 and JetStream 2.10; missing configuration or skipped tests fail the run. Its 60-minute total deadline includes startup, with a maximum 30-minute target deadline; interruption/deadline failures terminate the owned process tree before removing services. Migration and retention Go package budgets are explicitly 20 minutes while production transaction/lock limits remain unchanged. `LOCALAPPDATA` is retained solely for the Windows Go build cache; credentials, peppers and feature flags are not inherited. A collision on the reserved restart broker name fails rather than reusing or removing another run's container. Never point reset-schema suites at shared Compose volumes, development or deployed databases. Successful teardown is explicitly confirmed. Required API SQL generation/reproducibility checks, unit/race/vet/lint, operator builds, frontend/UI checks (including spec typechecks), helper/fixture-safety checks, existing portal tests, CSP and image smoke remain separate automated gates. Linux race validation requires CGO and a C compiler; use the CI-pinned Go/linter toolchain rather than silently skipping it.

Windows cannot deliver a graceful Go `SIGTERM` using Node's process kill. For Windows admin browser acceptance, first build and inspect the fresh production API image, then set `ADMIN_BROWSER_SIGNER_IMAGE` to its immutable `sha256:` image ID before running `web:test-admin-browser`. The harness uses its real non-root `/usr/local/bin/audit-signer` on the private run-owned service network and `docker stop` for graceful retirement; it still requires exit 0 before destructive fixtures. The signer and publisher receive separate restricted real logins, and publisher reads/delivery updates use its exact subject/marker RLS policies. No production image is inferred from a mutable tag and no forced termination is accepted as clean signer shutdown. Linux CI retains the normal locally built signer binary.

CI requires the separate `admin-browser` job before image publication in addition to the existing quality, security, frontend and portal-browser jobs. For acceptance, set `ADMIN_BROWSER_ARTIFACT_DIR` to an absolute fresh run-specific directory under the execution environment's temporary directory (`TMPDIR`, `TEMP` or `TMP`, as applicable) for masked desktop/320px light/dark screenshots and sanitized `admin-evidence.json`. Do not retain raw traces, storage snapshots, fixture credentials, proofs, grants, account identifiers or audit bodies. Diagnostic output is restricted to route templates, counts, static failure categories and sanitized scenario labels; require confirmed cleanup of all run-owned services.

Local Task 7.5 completion may be recorded in `tasks.md` only after all required automated gates pass. Record the date, tested worktree, exact commands and final exit statuses, fresh sanitized evidence and successful teardown. Existing JSON, partial runs or test source alone are not passing evidence. Until then, leave Task 7.5 uncompleted; this runbook does not assert a pass. After successful validation, reconcile only Task 7.5's local status and leave unrelated task statuses and production enablement unchanged.

Native hidden-tab and bfcache restoration, physical-authenticator behavior, and screen-reader/manual accessibility review remain separate gates until directly evidenced. Injected events/history tests, virtual authenticators and headless layout/keyboard assertions do not close those gates. Record remaining manual gates explicitly alongside any future local automated completion.

Before production enablement, validate exact forwarding and no-referrer/private-no-store behavior through the deployed ingress for both `/admin/*` pages and `/api/v1/admin/*` APIs. Suppress or template account identifiers and exclude query strings, lookup bodies, status reasons, audit payloads, cookies, proofs, grants and referrers from proxy/APM/error logs; absence in a local harness is not operational evidence. Keep `ADMIN_ENABLED=false` unless existing governance approval, credentials/grants, outbox delivery and publisher/signer health, approved retention cleanup and exact-origin gates are satisfied. Review production threat-model assumptions independently; do not enable legal workflows to ship the panel. Production/governance and Task 5.3/5.4/5.5 deployment gates remain open independently of local Task 7.5 automated acceptance.

## DPO/Legal Panel (Task 7.6)

This is an extension of the existing admin surface at fixed `/admin/legal`, not a new service, authentication boundary or approval to enable production intake. It implements only [API section 1.7](api-design.md#17-admin--moderation-api) hold/preservation/attribution operations. Keep `ADMIN_ENABLED` and production governance unchanged and `LEGAL_WORKFLOW_ENABLED=false` for panel acceptance. No schema migration, role-seed expansion, new retention period or cryptographic format is part of this release. Phone attribution, multi-pepper rotation, Class C purge/retention policy, external anchoring and general governance remediation remain separate work.

### Coordinated Rollout

1. Inventory the UI, every API replica and other attribution REST callers. Close affected **old admin ingress**, drain in-flight requests and retire incompatible clients/open forms before changing the wire boundary. Keep unrelated account portal and section 1.8 policies/statuses unchanged. Do not let a numeric-sequence caller reach a mixed fleet.
2. Deploy compatible API/UI/callers to every affected replica before reopening. Legal `items[].seq` and `coverage.through_seq` are canonical nonnegative decimal strings through `9223372036854775807`, with **no numeric fallback**. Existing Task 7.5 mandatory revision/string-coordinate rules still apply. Internal `int64`, signed canonical bytes, stored hashes, encrypted contexts, tombstones and opaque cursor encoding remain unchanged. Legal capabilities derive from actual mounts plus current permissions, including legal-only principals; the read flags do not require step-up, but all writes/lookup pages do.
3. Start the compatible real signer using the actual schema, protected audit subject and pinned key configuration, then run `admin-legal --operation=lookup-probe` with controlled operator credentials while affected ingress is closed. Canonical v2 must join `security_ledger_chain.event_id` to payload by `seq`; it cannot search the removed payload `id`. The command publishes an unindexed legacy envelope for a credential-free synthetic account, verifies the signer's expected index, deletes only that account and verifies again. Capture its fixture ID privately, then start both acceptance APIs (or all deployed replicas) with `ADMIN_LOOKUP_FIXTURE_ID`. Do not inject a fake verified service or bypass marker/index checks. Repeat after signer/key changes. This verifies current signer/index compatibility, not a trust anchor, all historical pepper generations or complete ingestion.
4. Exercise omission, a supplied absent/wrong fixture and mismatched keys separately. A supplied invalid fixture must fail startup/readiness rather than return "no match"; omission keeps lookup unmounted while independently configured hold/preservation can remain usable. Validate authenticated post-deletion attribution separately from the CLI's direct fixture check. Preserve synthetic evidence needed for the configured fixture; loss/expiry requires controlled re-probing, not weakening readiness. Reconcile a failed probe's identified synthetic account only after diagnosing delayed signer work, never using real identifiers.
5. Verify same-origin routing to Go, exact Origin/session intent/DPoP/step-up forwarding, and `Idempotency-Key` on the two create POSTs through the deployed ingress. Verify private/no-store/no-referrer on success, errors and empty responses. Legal POSTs/release reject query strings, including a bare `?`; GET holds accepts only the documented strict query. The authorized account filter/hold-ID path/key header must not enter browser navigation/history or proxy/APM diagnostics. Use route templates and omit bodies, emails, legal narratives, IDs, cursors, grants, proofs, responses and referrers from logs/artifacts. Preserve strict CSP without inline-style or external-origin exceptions. Reopen only after compatible callers and all current operational prerequisites are verified.

The capability window `audit_max_window_seconds` applies to attribution as well as audit search, including smaller/fractional durations. Do not round it upward in clients. The API page default/max remain numeric (defaults 50/200); hold-list GET clamps an excessive in-range limit but lookup POST rejects it. The legal UI uses at most `min(page_size_max, 50)`, with a bounded current page only. Browser 4-MiB exceptions are exactly audit-list GET, legal-holds GET and legal-inquiry POST; all other requests retain 256 KiB. Both declared and streamed bytes must be checked; serialized legal request bodies are capped at 32 KiB before a grant is consumed. No silent row/field truncation or automatic smaller requests are acceptable.

### Recovery and Rollback

The controlled external intake record, not browser persistence, must retain the original `(account_ref, request_kind, operation UUID, normalized payload)` before a create is sent. Preserve optional date/omission and stable microsecond-or-coarser UTC values. An uncertain create may be retried **only explicitly**, with that unchanged tuple and fresh step-up; `409 idempotency_conflict` requires reconciliation, not a new UUID. Keys are subject/kind scoped, so reusing one after changing the target/kind creates another independent request. A released replay never reactivates a hold; a cleaned narrative tombstone conflicts. There is no by-key recovery endpoint or browser-persisted draft. See the [operator recovery procedure](admin-operations.md#interrupted-outcomes-and-explicit-retry).

Lost, malformed, oversized or interrupted write responses and a `503` after commit/session renewal leave the outcome unconfirmed. Do not automatically resend, infer success from `401`, or promise rollback. Only the pre-handler DPoP nonce challenge permits one retry with the exact body/key/grant. Current-state reads cannot identify which uncertain request created a hold; confirmed writes remain confirmed after a failed refresh. Lost lookup data means no accepted result, not no activity. Dates are advisory: holds override erasure until explicit release; release of one independent request does not release others, reset original retention, extend recovery or restore erased data.

Rollback **first closes affected ingress**, then removes/disables the new UI entries, then coordinates compatible API/UI/caller rollback. Preserve holds, encrypted contexts, request tombstones, accepted audit/outbox intent, signed chain data and existing cleanup. Do not downgrade storage, reset retention clocks, drop evidence or rewrite hashes. Keep signer/verifier binaries compatible with canonical-v2 storage. Restore access only when every replica/caller agrees on the wire contract and current signer/crypto/governance prerequisites are verified; removing the UI alone is not an API rollback.

### Required Evidence

This section lists the required validation inventory; dated local results are recorded below. Use the checked-in `.github/workflows/identity-api.yml` commands/flags with `NX_DAEMON=false npm exec -- nx run <project>:<target> --skipNxCache`; do not substitute cached or earlier-task evidence. Resolve the current targets before execution. The inventory is:

| Gate                                  | Required coverage                                                                                                                                                                                                                                                                                                                                                         |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Backend quality                       | `identity-api:test`, `test-race` on Linux with CGO/compiler, `vet`, `lint`, `test-portal-fixture`, plus the existing integration-tag vet/lint flags.                                                                                                                                                                                                                      |
| Generated contracts                   | `identity-api:sqlc-vet`, `sqlc-generate`; `schemas:lint`, `generate`; repeat Go/TypeScript/SQL generation and compare as current CI does. No schema/protobuf change is intended.                                                                                                                                                                                          |
| Serial real services                  | `identity-api:test-security-db`, `test-admin-integration`, `test-retention-integration`, `test-legal-workflow-integration`, `test-grpc-integration`, `test-lifecycle-integration`, `test-portal-integration` on disposable PostgreSQL 16/Redis 7/JetStream 2.10. Workflow tests are regressions, not added panel scope. Missing/skipped mandatory integrations must fail. |
| Current additional service/race gates | `test-geography-integration` completes the exact eight normal suites; thirteen race packages are listed in [current validation](admin-operations.md#current-bundle-requirements). Historical seven-suite records remain unchanged.                                                                                                                                        |
| Frontend/helpers                      | `web:lint`, `ui:lint`, `web:typecheck`, `ui:typecheck`, `web:test`, `ui:test`, `web:build` and the existing Nx-executed `.github/scripts/*.test.mjs` suite.                                                                                                                                                                                                               |
| Binaries/images                       | `identity-api:build`, all existing quality-job operator/worker targets including `build-admin-legal`, fresh API/web images and existing entrypoint/image-CSP smoke.                                                                                                                                                                                                       |
| Production browsers                   | Uncached `web:test-admin-browser` and `web:test-portal-browser`, retaining the independent image/CSP suite and existing `admin-browser` CI/image-release dependency, not a new parallel release job.                                                                                                                                                                      |

The admin browser target needs `identity-api:build-admin-legal` as an explicit dependency so its standalone CI job can execute the real probe. It extends the existing production Next.js/two-real-API harness with signer/admin publisher, a run-owned synthetic governance baseline and the repaired real probe **before** starting the APIs. Keep `APP_ENV=test`, `LEGAL_WORKFLOW_ENABLED=false`, production security enforcement and build-tagged private fixtures only. No public fixture route or production fixture binary is permitted. Run legal scenarios before destructive ledger-state tests; deliberately restart the owned APIs with fixture omission when testing that unavailable state rather than bypassing a deleted fixture's readiness check. Before intentionally removing a signed head, drain real delivery and verify the owned signer's clean retirement; do not race its correct fail-closed missing-head behavior or exempt any other process from health checks.

Required legal scenarios include seeded DPO success and Support/Moderator/Super-Admin denial, legal-only/combined grants, direct-route and revoked-capability handling, strict query/body errors, exact sequences above JavaScript safe integers, both create forms, independent/replayed/released/cleaned holds, deleted-account reference selection, opt-in metadata and fresh step-up on every page. Exercise current retention/hold eligibility, real audit-outage rollback and committed-but-lost create/release responses with no automatic retransmission. Prove clearing of detached controls, grants, queries/results and late replies on cancellation/hide/navigation/session/permission changes, plus no-JavaScript, desktop/320px, light/dark, keyboard/focus/dialog and CSP behavior.

Store fresh masked evidence in an absolute run-specific directory under the execution environment's temporary directory (`TMPDIR`, `TEMP` or `TMP`, as applicable), using `ADMIN_BROWSER_ARTIFACT_DIR` and `PORTAL_BROWSER_ARTIFACT_DIR`. Mask legal narrative paragraphs and result regions explicitly, not just inputs/tables. Allowed retained evidence is sanitized scenarios/status/counts and masked screenshots; no raw traces, storage snapshots, emails, narratives, account/hold/operation IDs, cursors, proofs, grants or result bodies. Restrict temporary in-memory capture/API-probe exceptions to exact authorized route/method/header combinations, with template-only diagnostics. Run schema-resetting suites serially and verify teardown of every run-owned service/volume. The acceptance record must name the dated source/worktree, exact commands, final exit statuses, sanitized evidence and cleanup. Plans, test source and partial runs are not passes and must not alter unrelated task statuses.

### Local Acceptance (2026-11-02)

The required inventory passed on 2026-11-01 and was reconciled against unchanged tested source on 2026-11-02. See the [source-specific acceptance record](admin-operations.md#local-acceptance-2026-11-02) and `/tmp/kilo/legal-validation-20261101T115536Z/final-summary.json`. All final exits are zero, including all seven serial integration targets, 586 web/17 UI/156 helper tests, both real-browser targets and fresh API/web image smoke/CSP checks. The admin run retained 42 masked captures and verified 27 fresh legal step-ups. The registry includes earlier failed attempts, exact invocation/source metadata, generated-output reconciliation, immutable image IDs and verified teardown; it is not a claim that every initial attempt passed.

The API/web image builds used saved proxy settings with `--pull --network=host`, without inline proxy credentials. Existing Next.js project-reference and historical Nx flake advisories remain visible; lint/vet results are clean. Only local Task 7.6 completion is reconciled. No production flags, seeded roles, retention policy or Task 5.3/5.4/5.5 status changed.

Manual screen-reader, physical-authenticator, native zoom, hidden-tab/bfcache and deployed-ingress checks remain **unfinished until separately observed**. Injected events, virtual authenticators and headless screenshots do not satisfy those gates. Production baseline-policy approval, encrypted backfill, effective non-owner DB grants, approved narrative/replay/ledger retention, signer/publisher delivery, exact-origin/APM redaction, privacy notices and ROPA/DPIA/DSAR duties remain operator responsibilities. Fixture approval is not legal approval, and local Task 7.6 validation does not close Task 5.3/5.4/5.5 or authorize `ADMIN_ENABLED`.

## Right to Be Forgotten (Task 7.4)

The live routes are `/dashboard/privacy` and anonymous `/recover-account`.
`GDPR_DELETION_ENABLED=false` is the default. Enablement is an operator decision,
not proof supplied by a checkbox or SMTP acknowledgement. Recovery and draining
accepted notices must remain available when new deletion requests are switched off.

1. Complete the [fresh-baseline cutover](#fresh-baseline-environment-cutover), including
   deletion notification storage, before new API writers/workers. Verify API privileges
   for transactional request/outbox insertion.
   Inventory any legacy pending requests without encrypted delivery intent; hashes
   cannot reconstruct their tokens. Reconcile them through an approved procedure,
   preserving the original deadline, before enabling new requests.
2. Deploy recovery UI/API first, then `deletion-notifier run` under the existing
   Compose/host service supervision. The API image contains this non-root entrypoint;
   `once` is a bounded drain for diagnostics, not a replacement for supervision.
   The API never needs SMTP credentials and does not synchronously send mail.
3. Inject `DELETION_NOTIFIER_DATABASE_URL`, `DELETION_SMTP_HOST`,
   `DELETION_SMTP_USERNAME`, `DELETION_SMTP_PASSWORD`, `DELETION_SMTP_FROM`, and
   `DELETION_SMTP_PUBLIC_ORIGIN` using existing secret management. Use the canonical
   portal origin, not a request Host or redirect parameter. Both required STARTTLS
   and implicit TLS verify certificates/hostnames; an optional `CA_BUNDLE` extends
   trust for a private relay, never disables it. Defaults and bounds are in
   `.env.example` and `internal/config/deletion_notifier.go`.
4. Keep API/worker envelope keys and necessary versions available for pending/held
   payloads. The current environment-backed KMS provider is not an external KMS
   integration. Production API, purge and notification policy must use `720h`;
   email retries, holds and hold release never restart the recovery clock.
5. Confirm that at least one configured recipient remains accessible without this
   IdP after deactivation. Approve sender identity, SPF/DKIM/DMARC, provider terms
   and message retention, public privacy wording, the encrypted payload cleanup
   policy and existing ledger/audit retention gaps. Contact enrollment, another
   recovery channel and an email-only bypass are not supplied by this task.
6. Rehearse actual delivery and keyless recovery through deployed HTTPS ingress,
   including operator mail access after deactivation. Then enable new requests.
   Preserve exact Origin/proof/session-intent headers and no-store/no-referrer;
   redact tokens, full links, message bodies, addresses and SMTP replies in every
   proxy, log shipper, APM and mail-system diagnostic.

### Restricted Delivery Role

Use a separate runtime login inheriting a role like the following, provisioned by
an operator. Never reuse the API/schema-owner login. Account/request reads are one
minimal snapshot under the shared advisory lock, so the worker needs no write
permission on account IDs, status, credentials or reclaim authority.

```sql
CREATE ROLE identity_deletion_delivery NOLOGIN;
GRANT USAGE ON SCHEMA public TO identity_deletion_delivery;
GRANT SELECT (id, status, auth_version, deleted_at)
  ON users TO identity_deletion_delivery;
GRANT SELECT (id, user_id, token_hash, expires_at, consumed_at,
  failed_attempts, requested_auth_version)
  ON deletion_requests TO identity_deletion_delivery;
GRANT SELECT (account_ref, is_active)
  ON legal_holds TO identity_deletion_delivery;
GRANT SELECT ON deletion_notifications TO identity_deletion_delivery;
GRANT UPDATE (payload_encrypted, lease_token, lease_until, attempts,
  next_attempt_at, accepted_at, failed_at, last_error_code)
  ON deletion_notifications TO identity_deletion_delivery;
```

Provision the login and membership through secret management; the SQL intentionally
contains no password. Integration tests verify delivery/cleanup with these grants
while contact/IP reads and account/request mutation are denied.

### Delivery and Rollback

Track worker availability, oldest due age, retries, permanent failures, leases and
bounces. Structured logs and minimal queue columns support alerts; SMTP acceptance
is not inbox delivery. A lost acknowledgement can duplicate a message with the same
ID/token/deadline. Repair relay failures and explicitly requeue only still-valid
work; never mint a replacement token or extend expiry as an automatic retry.

Successful/invalid/expired delivery payloads become cleanup candidates. Cleanup
takes the shared subject lock and preserves active/unknown holds. Held data is not
permission to deliver an expired or cancelled token. Ciphertext is never published
through lifecycle events or ordinary audit payloads. This is the scheduled-deletion
notice, not a final-erasure email or proof that downstream content/backups vanished.

Rollback first disables new requests, while keeping recovery, the compatible worker,
required encryption keys and additive schema. Do not restore revoked authority,
remove already-issued recovery routes, drop pending intent, or weaken UV/DPoP gates.

Local automated acceptance passed on 2026-10-27: full backend unit/race/vet, clean
standard lint, SQL generation/vet, real PostgreSQL/Redis/JetStream security/admin/
lifecycle/portal suites, 271 web and 17 UI tests, 102 CI/harness checks, production
API/worker/web builds and non-root smoke/CSP checks. HTTPS tests exercised real UV
versus TOTP denial, worker stop/restart and SMTP retry/cleanup, revoked old authority,
lost DELETE/reclaim responses, keyless UV/TOTP reclaim, six no-JavaScript routes and
eighteen viewports. Native bfcache/hidden-tab transitions were not observed; injected
events/history checks do not close those or manual assistive-technology/authenticator
and deployed-ingress gates. Dependency installation also reported existing npm audit
findings; no dependency upgrades or audit-policy changes were made in this task.

## 1. Kubernetes Deployment & Networking

Post-MVP examples propose **Traefik** ingress and **SPIRE** workload identities.
They are not deployed infrastructure, current HA or operator approval.

### 1.0 MVP Phase: Host-Level Nginx Configuration (Reverse Proxy & TLS Termination)

In the MVP phase, we use the host's existing **Nginx** web server running on Ubuntu. Nginx handles SSL/TLS termination, routes the traffic to the corresponding Docker containers (Next.js frontend on port `3000`, Go Backend on port `8080`), and handles base HTTP security headers. Port `8080` must be published only on loopback or a private container network; it must never be reachable from an untrusted network that can bypass Nginx.

The API trusts `X-Forwarded-For` only when its immediate socket peer is listed in `TRUSTED_PROXY_CIDRS`. For host Nginx connecting over loopback, use `TRUSTED_PROXY_CIDRS=127.0.0.1/32` (and `::1/128` only when that path is actually used). If Docker NAT makes the peer appear as a bridge gateway, inspect the API's observed peer and allow only that exact address or narrowly controlled ingress CIDR. Empty means no proxy is trusted, malformed entries and `/0` networks are rejected, and broad Docker or public ranges are prohibited. Nginx must overwrite any client-supplied forwarding chain with `$remote_addr`; do not use `$proxy_add_x_forwarded_for` at this single public edge. The API deliberately ignores `X-Real-IP` and `True-Client-IP`.

The Nginx sketch below is illustrative, not a validated deployable configuration.
Current install/configuration authority is [container deployment](container-deployment.md)
and `tools/docker/nginx.production.conf.example` / `tools/docker/proxy-headers.conf`.
Verify routing, sensitive-page diagnostics and actual TLS/CSP/Origin behavior
against deployed ingress; copying the sketch does not close gates.

```nginx
# http{} scope: constant route template, never request URI/query/referrer/headers.
log_format admin_safe '$request_method /api/v1/admin/* $status $request_time';
log_format admin_page_safe '$request_method /admin/* $status $request_time';
log_format portal_api_safe '$request_method /api/* $status $request_time';
server {
    listen 443 ssl http2;
    server_name identity.hatef.ir;
    # This vhost must not serve a sibling/unknown host as its default site.
    if ($host != identity.hatef.ir) { return 421; }

    # SSL Certificate Configuration (Certbot / Let's Encrypt)
    ssl_certificate /etc/letsencrypt/live/identity.hatef.ir/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/identity.hatef.ir/privkey.pem;

    # Secure SSL Protocols and Ciphers
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Secure HTTP Headers (XSS, Framing, Content-Type sniffing)
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # Admin documents also contain sensitive route references; never log raw URLs.
    location ^~ /admin {
        access_log /var/log/nginx/admin-page-access.log admin_page_safe;
        error_log /dev/null crit;
        proxy_cache off;
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # 1. Route for public UI, dashboard, and OAuth authorize/error screens (Next.js)
    location ~ ^/(login|register|forgot-password|reset-password|verify-email|dashboard|admin|_next|static) {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        # Overwrite untrusted inbound forwarding headers at the public edge.
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSockets support for Next.js Fast Refresh
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # OIDC UI Page Exceptions
    location = /oauth2/authorize {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location = /oauth2/error {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Admin prefix wins over the general API regex, including rejected legacy GETs.
    location ^~ /api/v1/admin {
        access_log /var/log/nginx/admin-access.log admin_safe;
        # Nginx error records can embed raw URLs; use sanitized API diagnostics.
        error_log /dev/null crit;
        proxy_cache off;
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Origin $http_origin;
        proxy_set_header DPoP $http_dpop;
        proxy_set_header X-Portal-Session $http_x_portal_session;
        proxy_set_header X-Step-Up-Auth $http_x_step_up_auth;
    }

    # First-party browser API: no BFF, shared cache, request-URI or body logging.
    # The longer admin prefix above retains its separate access-log contract.
    location ^~ /api/ {
        access_log /var/log/nginx/portal-api-access.log portal_api_safe;
        error_log /dev/null crit;
        proxy_cache off;
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Origin $http_origin;
        proxy_set_header DPoP $http_dpop;
        proxy_set_header X-Portal-Session $http_x_portal_session;
        proxy_set_header X-Step-Up-Auth $http_x_step_up_auth;
        # Preserve upstream Set-Cookie, DPoP-Nonce, WWW-Authenticate,
        # Cache-Control: private, no-store and Referrer-Policy: no-referrer.
    }

    # 2. Route for Core IdP API operations, token exchange, and JWKS endpoints (Go Backend)
    location ~ ^/(api|\.well-known|oauth2) {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Forward OAuth Authorization and DPoP headers verbatim
        proxy_pass_header Authorization;
        proxy_pass_header DPoP;
    }

    # 3. Default route (routes back to Next.js frontend app)
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### Portal Document CSP (Task 7.1)

The standalone Next.js server owns the portal's enforcing `Content-Security-Policy`. Its proxy generates a new nonce per request and the root layout renders HTML on demand, including static-content pages and the application 404. This does not enable backend CSP, Trusted Types, static export, SSG, ISR, or PPR. See the [frontend policy contract](frontend-pages.md#52-client-side-sender-constrained-tokens-dpop--strict-nonce-csp).

- Forward the application's single CSP header unchanged in every Next.js location above, including OAuth UI exceptions and the default route. Do not add a second CSP, replace it with a constant nonce, or hide the upstream header in Nginx/Traefik.
- Preserve `Cache-Control: private, no-store` on portal HTML (Next may add stricter no-cache directives). Do not enable shared HTML caching or override these headers at the reverse proxy/CDN. Reusing cached HTML with a new response nonce breaks script execution; reusing the nonce itself violates the security contract.
- Continue serving `/_next/static` JS/CSS with their public, immutable cache headers. The proxy excludes framework assets and the existing favicon from document nonce handling. Do not globally disable asset caching to solve an HTML-cache issue.
- Run the production image with `NODE_ENV=production`. Development relaxations are only for local Next.js tooling. New external origins and inline-style components require explicit policy compatibility work.
- During an operator-approved release, fetch `/` and an unknown/dotted URL repeatedly through the real HTTPS ingress. Verify the expected 200/404 status, exactly one enforcing CSP, matching HTML/header nonces, different nonces between document responses, and private/no-store headers. Verify scripts, CSS, and client navigation in a browser and confirm immutable asset caching. Container tests cannot establish ingress behavior.
- Upstream outage pages and responses emitted before the Next.js proxy are outside its coverage. Rollback must restore the matching application image and header behavior together; do not weaken the CSP independently to hide a rendering failure.

Frontend CI runs nonce/cache checks and Chromium enforcement tests against the actual non-root image before release export. The browser tests verify clean rendering and hydrated client navigation, then separately verify allowed nonced code and blocked parser-inserted scripts, handlers, and styles. The release publication smoke remains dependency-free and does not require browser packages. No publish or deployment is implied by local test completion.

To repeat the browser check after building an image, from the repository root with npm dependencies installed:

```bash
npm exec -- playwright install --with-deps chromium
npm exec -- nx exec -p web -- node "$PWD/.github/scripts/web-csp.browser.mjs" identity-web:ci
```

### 1.0.1 Private IdentityService Runtime (Task 6.2)

The API can also host private TLS 1.3 gRPC on `GRPC_ADDR` (default
`127.0.0.1:9090`). It is disabled by default and must not be added to the public
Nginx/Traefik routes above. `GRPC_ENABLED=true` requires PostgreSQL, standalone
Redis, a maintained local SPIRE Workload API, an explicit canonical trust domain,
exact method grants and audience/origin policies. This implements application
support, not permission to provision the post-MVP SPIRE/Kubernetes manifests.
See [client configuration](client-integration.md#34-runtime-configuration-and-rollout)
for the environment contract and a non-production example.

Build from the repository root so the existing schemas Go module is available:

```bash
docker build --file apps/identity-api/Dockerfile --tag identity-api:dev .
```

The Dockerfile-specific ignore rules exclude secrets, unrelated workspace
content and local generated outputs. The image regenerates schema Go and sqlc
code using pinned local tools before building all existing API/worker binaries.
Generated Go remains uncommitted; Go 1.26.5 or later is required. No remote
TypeScript generator is needed for this backend build.

Before enabling consumers, deploy the shared-state-aware issuers on all API
instances, drain process-local sessions and require reauthentication. New user
tokens bind to their browser session, OAuth grant and captured account version.
Legacy unlinked JWTs cannot pass the RPC. Task 7.3 additionally shares WebAuthn
ceremonies and enforces bound browser sessions across API replicas. Client-assertion
claims use shared Redis outside development, scoped client/audience/JTI through the
entire accepted exp+60s leeway window with no memory fallback. Temporal admission
and atomic absolute expiry use Redis `TIME`; permit `TIME` directly and inside
the replay Lua script in the authorized Redis ACL. A denied or malformed clock
reply fails authentication rather than using a replica-local clock. Independent offline grants and
consent UI completion remain separate tasks.

For current code, operate Redis as security authority: use appropriate ACLs/TLS and an eviction
policy that does not silently treat credential state as expendable cache data.
Missing records invalidate credentials, while errors/corruption fail validation
with Unavailable. Runtime clients honor context deadlines, have bounded I/O, and
do not transparently retry consumptive commands. Never roll Redis back to a
snapshot that could restore revoked grants or forget consumed proofs; discard
credential/replay namespaces and reauthenticate instead under controlled incident
handling. Clearing sessions alone cannot repair rollback of SQL credentials/spent
codes/replay or recreate critical abuse limits. SEC09/SEC16 require primary SQL
authority and independent rollback-safe reconciliation before reopening.

Enabled `/readyz` verifies the private listener, current usable SVID/bundle,
PostgreSQL and Redis; `/healthz` remains dependency-independent. SVID acquisition
is bounded to ten seconds. Connections age out after five minutes with
30-second grace; requests default to a two-second deadline. On either listener's
failure or termination, both stop admissions and drain under the shutdown bound,
then force-close if needed before audit/source/backing-resource cleanup.
Monitor readiness, dependency errors, forced shutdowns and certificate renewal;
no successful token response is a reusable authorization cache entry.

Use `npm exec -- nx run identity-api:test-grpc-integration --skipNxCache` with
disposable PostgreSQL/Redis and run database suites serially. Missing test
dependencies fail rather than skip. Unit transport tests use real mTLS and
generated clients. Production enablement still needs approved workload grants,
socket access controls, private networking and verified consumer error/nonce
forwarding. Disable/drain the listener for rollback; never silently weaken a
consumer to an offline or unauthenticated fallback.

### 1.1 Traefik Ingress Configuration

To ensure optimal performance and isolate concerns, path-based routing separates Next.js (web frontend) from the Go IdP API engine.

```yaml
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: hatef-identity-ingress
  namespace: identity
spec:
  entryPoints:
    - websecure
  routes:
    # 1. Route for public UI, dashboard, admin panel, and OAuth authorize/error screens (Next.js)
    - match: Host(`identity.hatef.ir`) && (PathPrefix(`/login`) || PathPrefix(`/register`) || PathPrefix(`/forgot-password`) || PathPrefix(`/reset-password`) || PathPrefix(`/verify-email`) || PathPrefix(`/dashboard`) || PathPrefix(`/admin`) || Path(`/oauth2/authorize`) || Path(`/oauth2/error`) || PathPrefix(`/_next`) || PathPrefix(`/static`))
      kind: Rule
      services:
        - name: hatef-frontend-service
          port: 3000

    # 2. Route for Core IdP API operations, token exchange, and JWKS endpoints (Go Backend)
    - match: Host(`identity.hatef.ir`) && (PathPrefix(`/api`) || PathPrefix(`/.well-known`) || (PathPrefix(`/oauth2`) && !Path(`/oauth2/authorize`) && !Path(`/oauth2/error`)))
      kind: Rule
      middlewares:
        - name: rate-limit-middleware
        - name: security-headers-middleware
      services:
        - name: hatef-idp-core-service
          port: 8080
  tls:
    certResolver: letsencrypt
    options:
      name: strict-tls@kubernetescrd
```

#### 1.1.1 Security Middlewares Configuration:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: security-headers-middleware
  namespace: identity
spec:
  headers:
    browserXssFilter: true
    contentTypeNosniff: true
    forceSTSHeader: true
    stsSeconds: 31536000
    stsPreload: true
    stsIncludeSubdomains: true
    frameDeny: true
    # Next.js owns per-request document CSP nonces; Go API headers are separate.
    # This proposed ingress must preserve application headers verbatim.
```

### 1.2 SPIRE Runtime Environment Agent Deployment

To assign secure cryptographic identities to workloads, a SPIRE Agent runs as a Kubernetes `DaemonSet` on every node, communicating directly with the central SPIRE Server.

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: spire-agent
  namespace: spire
spec:
  selector:
    matchLabels:
      app: spire-agent
  template:
    metadata:
      labels:
        app: spire-agent
    spec:
      hostPID: true # Required for the agent to inspect process attributes on the node
      containers:
        - name: spire-agent
          image: ghcr.io/spiffe/spire-agent:1.8.0
          args: ['-config', '/run/spire/config/spire-agent.conf']
          resources:
            requests:
              cpu: '100m'
              memory: '128Mi'
            limits:
              cpu: '500m'
              memory: '256Mi'
          volumeMounts:
            - name: spire-config
              mountPath: /run/spire/config
              readOnly: true
            - name: spire-agent-socket
              mountPath: /run/spire/sockets
            - name: cgroup
              mountPath: /host/sys/fs/cgroup
              readOnly: true
      volumes:
        - name: spire-config
          configMap:
            name: spire-agent-config
        # Unix Domain Socket exposed to the applications on the host node
        - name: spire-agent-socket
          hostPath:
            path: /run/spire/sockets
            type: DirectoryOrCreate
        - name: cgroup
          hostPath:
            path: /sys/fs/cgroup
```

Workloads access the SPIFFE Workload API by mounting the local folder hosting `/run/spire/sockets/agent.sock` into their application containers.

---

## 2. Secrets Injection & Configuration

Current application crypto uses operator-injected environment values: one loaded
`ENVELOPE_MASTER_KEK`/version and one blind-index pepper/version in process-local
custody, with real AES-GCM and exact email/generic HMAC input profiles. There is no
live Infisical fetch/cache/offline fallback, automatic retired-key retrieval or
hot-rotation subscription. Infisical/SOPS/Sealed Secrets are provisioning options;
the ESO example below is a post-MVP deployment design, not implemented application
KMS behavior or evidence of deployed synchronization.

Inventory and protect all retired keys needed for retained ciphertext/backups.
Changing the one loaded KEK/version or pepper cannot transparently rotate existing
data; plan controlled draining, inventory/re-encryption/recovery and consistent
rollout separately. Do not rehash signed history or assume a version byte provides
a multi-key reader. Restore drills, private key custody and actual secret injection
are operational gates, not established by primitive unit tests.

```
+------------------+         +----------------------------+         +-------------------+
|    Infisical     | ======> |  External Secrets Operator | ======> | Kubernetes Secret |
| (Central Vault)  |  (Sync) |       (ESO Controller)     | (Write) |   (Local Pods)    |
+------------------+         +----------------------------+         +-------------------+
```

### 2.1 ExternalSecret Definition

The ESO Controller polls Infisical at a set interval (e.g., 5 minutes) and updates the Kubernetes Secret objects dynamically.

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: hatef-idp-secrets
  namespace: identity
spec:
  refreshInterval: '5m' # Sync frequency with Infisical
  secretStoreRef:
    name: infisical-backend-store
    kind: ClusterSecretStore
  target:
    name: idp-runtime-secrets
    creationPolicy: Owner
  data:
    - secretKey: POSTGRES_PASSWORD
      remoteRef:
        key: /production/database/postgres_password
    - secretKey: ENVELOPE_MASTER_KEK
      remoteRef:
        key: /production/crypto/envelope_master_kek
    - secretKey: SMS_GATEWAY_API_KEY
      remoteRef:
        key: /production/services/sms_gateway_api_key
    - secretKey: STEPUP_REPLAY_HMAC_KEY
      remoteRef:
        key: /production/crypto/stepup_replay_hmac_key
```

In that later design, pods bind the generated secret as environment variables or
files; process restart/coordinated rollout is still required to load changes:

```yaml
env:
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: idp-runtime-secrets
        key: POSTGRES_PASSWORD
  - name: STEPUP_REPLAY_HMAC_KEY
    valueFrom:
      secretKeyRef:
        name: idp-runtime-secrets
        key: STEPUP_REPLAY_HMAC_KEY
```

### 2.2 Step-up Replay Key Deployment and Rotation

`STEPUP_REPLAY_HMAC_KEY` is an independent secret for deriving opaque Redis replay-key names; it is not the OIDC signing key. Supply standard base64 that decodes to at least 32 random bytes (for example, `openssl rand -base64 32`). It is required outside explicit development, must be identical on every API replica, and requires a healthy shared Redis deployment. Redis `SET NX` claims enforce one redemption across the cluster and replay-guard errors fail closed.

Do not rotate this key with an ordinary mixed-version rolling deployment. Replicas using different values create disjoint replay domains, allowing the same still-valid grant or TOTP proof to be claimed once per domain. The current implementation does not support dual-key overlap. Use this coordinated runbook:

1. Stop issuing and accepting Step-up-protected operations, then drain or stop all API replicas.
2. From the last issued grant, wait at least the larger of the configured grant lifetime and TOTP replay window. With the current policy, the maximum `STEPUP_TOKEN_TTL` is five minutes and is the controlling interval.
3. Replace the Infisical/ExternalSecret value, ensure every replica observes the same decoded key, and restart all replicas as one coordinated cutover.
4. Restore protected traffic, verify Redis health and a single-use grant across replicas, and let old versioned replay entries expire naturally by TTL.

---

## 3. Prometheus Monitoring & Alerting

Observability is core to detecting anomalies, token-theft attempts, and system exhaustion.

### 3.1 Core Operational Metrics

The metrics and rules below are a proposed observability inventory, not implemented
Go/Next `/metrics` endpoints or deployed alerts. Verify actual instrumentation,
units, template-only labels, thresholds and paging ownership before installation.
Do not infer global session revocation or delivery from an illustrative alert string.

| Metric Name                            | Type      | Labels                             | Description                                                    |
| :------------------------------------- | :-------- | :--------------------------------- | :------------------------------------------------------------- |
| `idp_http_request_duration_seconds`    | Histogram | `path`, `method`, `status`         | Latency distribution of external REST requests.                |
| `idp_grpc_request_duration_seconds`    | Histogram | `method`, `status`                 | Latency distribution of internal validation RPCs.              |
| `idp_database_pool_active_connections` | Gauge     | `pool`                             | Active connections to PostgreSQL and Redis.                    |
| `idp_otp_failures_total`               | Counter   | `channel` (`sms`, `totp`)          | Unsuccessful OTP login attempts.                               |
| `idp_rtr_breach_detections_total`      | Counter   | `client_id`                        | Number of times a revoked/replayed Refresh Token was detected. |
| `idp_envelope_encryption_errors_total` | Counter   | `operation` (`encrypt`, `decrypt`) | Cryptographic failures in envelope encryption logic.           |

### 3.2 Prometheus Alerting Rules

```yaml
groups:
  - name: hatef-identity-alerts
    rules:
      # 1. Alert for Refresh Token Rotation Breach (Potential Session Theft)
      - alert: RefreshTokenRotationBreach
        expr: rate(idp_rtr_breach_detections_total[1m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: 'Potential Token Theft Breach Detected'
          description: 'A client attempted to present an already-used Refresh Token. All user active sessions have been automatically invalidated by the system.'

      # 2. Alert for Sudden Spike in SMS OTP Failures (Potential Brute-force / Toll-fraud)
      - alert: HighOTPFailuresRate
        expr: rate(idp_otp_failures_total{channel="sms"}[5m]) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: 'High volume of SMS OTP failures'
          description: 'SMS OTP failures exceed 10/minute over 5m, indicating possible automated enumeration or brute-force attempts.'

      # 3. Alert for Envelope Cryptographic Failures
      - alert: EnvelopeEncryptionFailure
        expr: rate(idp_envelope_encryption_errors_total[1m]) > 0
        for: 0m
        labels:
          severity: page
        annotations:
          summary: 'Application-Layer Cryptographic Operations Failure'
          description: 'Database row envelope encryption or decryption is failing. This indicates KEK/DEK mismatch or corruption.'

      # 4. Alert for Database Connection Pool Exhaustion
      - alert: DBConnectionPoolExhausted
        expr: idp_database_pool_active_connections / idp_database_pool_max_connections > 0.90
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: 'Database connection pool utilization is critically high'
          description: 'Active database connections are over 90% of pool limits, risking query queuing and increased request latencies.'
```

### Admin deployment gate

Before enabling `/api/v1/admin`, follow [admin operations](admin-operations.md): forward-only bundle, role separation, approved retention, actual key/data inventory, version-aware issuers, acknowledged outbox delivery, signer lookup probe and ingress validation. Obsolete legal Backfill is unavailable. The Traefik successor must disable admin access/debug/tracing capture or allowlist only method/template/status/duration. Request paths/lines, queries, bodies, cookies, proofs, grants and referrers must not reach logs. Test body-only canonical-email lookup and rejected legacy GET with synthetic identities; this example does not certify a deployed collector.

## Phase 5 Technical Closure (2026-11-05)

Fresh local automated acceptance of the Phase 5 closure plan passed on
2026-11-05. It is separate from production enablement and the unchecked
[operator checklist](admin-operations.md#production-checklist). The final
seven-suite run produced 6,462 passing test/subtest records over 49 package runs,
zero failures/skips and confirmed teardown; the detailed suite counts and
restore/trust limitations are recorded in
[admin operations](admin-operations.md#phase-5-technical-closure-2026-11-05).

The actual host toolchain was Node 24.18.0, npm 11.16.0, Go 1.26.5 and
golangci-lint 2.12.2. Linux unit/race execution used Go 1.26.9 and Alpine GCC
15.2.0; race execution had `CGO_ENABLED=1` and current source/module-cache mounts
were read-only. The existing POSIX spool-permission test fails on Windows and
was not weakened: the complete named unit and race targets passed on Linux.
Only dependency generation was excluded after its explicit successful fresh
run, not test execution or cache misses. All test gates were uncached.

These exact final commands exited 0:

```powershell
npm exec -- nx run identity-api:sqlc-generate --skipNxCache
npm exec -- nx run schemas:lint --skipNxCache
npm exec -- nx run-many -t lint,vet,test-portal-fixture,sqlc-vet -p identity-api --skipNxCache --excludeTaskDependencies
npm exec -- nx run identity-api:lint --skipNxCache --excludeTaskDependencies --args="--build-tags=integration"
$env:GOFLAGS='-tags=integration'; npm exec -- nx run identity-api:vet --skipNxCache --excludeTaskDependencies
npm exec -- nx run-many -t build,build-admin-audit-publisher,build-admin-roles,build-admin-legal,build-lifecycle-publisher,build-audit-signer,build-purge-worker,build-security-ledger-purge,build-deletion-notifier,build-portal-fixture -p identity-api --skipNxCache --excludeTaskDependencies
npm exec -- nx run-many -t lint,typecheck,build -p web,ui --skipNxCache --parallel=1
npm exec -- nx run web:test --skipNxCache --ci --runInBand
npm exec -- nx run ui:test --skipNxCache --ci --runInBand
npm exec -- nx exec -p schemas -- node --test "D:/Projects/hatef.ir/ldp/.github/scripts/*.test.mjs"
npm exec -- nx exec -p schemas -- node "D:/Projects/hatef.ir/ldp/.github/scripts/portal-harness.mjs" --integration
```

The complete named Linux unit/race commands also exited 0 and removed their
owned containers:

```powershell
npm exec -- nx run identity-api:test --skipNxCache --excludeTaskDependencies --command='docker run --rm --name ldp-phase5-unit-final2-20261105T165058Z --network none --volume D:/Projects/hatef.ir/ldp:/workspace:ro --volume C:/Users/Hatef/go/pkg/mod:/go/pkg/mod:ro --env CGO_ENABLED=0 --env GOFLAGS=-mod=readonly --entrypoint sh identity-api-race:ci -c "go test -count=1 ./..."'
npm exec -- nx run identity-api:test-race --skipNxCache --excludeTaskDependencies --command='docker run --rm --name ldp-phase5-race-final2-20261105T165058Z --network none --volume D:/Projects/hatef.ir/ldp:/workspace:ro --volume C:/Users/Hatef/go/pkg/mod:/go/pkg/mod:ro --env CGO_ENABLED=1 --env GOFLAGS=-mod=readonly --entrypoint sh identity-api-race:ci -c "go test -race -count=1 ./..."'
```

Fresh API and web builds used `--platform linux/amd64 --pull --network=host`;
no inline proxy credentials, push or publication was performed. Immutable
accepted image IDs were:

- API/maintenance: `sha256:a1b533cffdc7d6a16de13a240b75080f0ee6ff860826b42047c2123c97ed41b8`.
- Web: `sha256:b7539e32e78ee3c7f85f14f709ea63f98575831724c52674e0e9d7fa8961b5eb`.

```powershell
docker build --platform linux/amd64 --pull --network=host --file apps/identity-api/Dockerfile --tag identity-api:phase5-20261105T165058Z .
docker build --platform linux/amd64 --pull --network=host --file apps/web/Dockerfile --tag identity-web:phase5-20261105T165058Z .
npm exec -- nx exec -p schemas -- node "D:/Projects/hatef.ir/ldp/.github/scripts/smoke-image.mjs" api sha256:a1b533cffdc7d6a16de13a240b75080f0ee6ff860826b42047c2123c97ed41b8
npm exec -- nx exec -p web -- node "D:/Projects/hatef.ir/ldp/.github/scripts/web-csp.browser.mjs" sha256:b7539e32e78ee3c7f85f14f709ea63f98575831724c52674e0e9d7fa8961b5eb
$env:PORTAL_BROWSER_ARTIFACT_DIR='C:/Users/Hatef/AppData/Local/Temp/kilo/phase5-20261105T165058Z/portal-browser'; npm exec -- nx run web:test-portal-browser --skipNxCache
$env:ADMIN_BROWSER_SIGNER_IMAGE='sha256:a1b533cffdc7d6a16de13a240b75080f0ee6ff860826b42047c2123c97ed41b8'; $env:ADMIN_BROWSER_ARTIFACT_DIR='C:/Users/Hatef/AppData/Local/Temp/kilo/phase5-20261105T165058Z/admin-browser'; npm exec -- nx run web:test-admin-browser --skipNxCache
```

All four smoke/browser commands exited 0. Helpers passed 177 tests with zero
skips, web passed 586, UI passed 17, and the real browsers produced 18 portal
viewports/six no-JavaScript routes and 42 masked admin/legal layouts. Signer
retirement used the immutable production binary and required clean exit before
destructive fixtures. All browser and integration resources were confirmed
removed, and `docker ps -a --filter label=ldp.run` returned no owned containers.

Repeated SQL/protobuf generation preserved every byte in all 24 generated SQL
Go files and four protobuf Go files. Their ordered `git hash-object --no-filters`
vector has SHA-256
`79c724165e0057fd93d4795a8e742524fa0775092c3947f4fededd4c37367991`;
complete filename/object vectors are in the sanitized external acceptance JSON.
Tracked migrations 00001-00018 and canonical schema sources were unchanged.

The accepted implementation snapshot was dirty, based on
`fedbe1ebee53be2bfd3dfeb5d66ef6ee2e8749d7`, with empty staged diff,
unstaged-diff SHA-256
`6bf21a0e22bac832dcf3d848d8d7a00b286ca8365dba24a7949f3f2f013633e8`
and untracked-content SHA-256
`f865a882e6bf71f00b6963355a17e8292658fdd0d0da48f91f3a84b5ebac9866`.
After validation only acceptance/task bookkeeping was changed; the resulting
final worktree fingerprint is recorded externally to avoid a self-referential
hash in these runbooks. The earlier post-browser changes were a test-only
contracted-schema shadowing fixture and POSIX-only integration interruption
teardown, checked by the full fresh serial retry and strengthened helpers;
the successful Windows/browser/runtime-image paths were unchanged.

Run-specific evidence is under
`C:\Users\Hatef\AppData\Local\Temp\kilo\phase5-20261105T165058Z`:
`acceptance.json`, `admin-browser/admin-evidence.json` and
`portal-browser/portal-evidence.json`, with masked captures only. Raw diagnostic
traces, private keys, account/operation identifiers, proofs and legal narratives
were not retained. Earlier prerequisite/concurrent-generation/fixture failures
were corrected and retried, not counted as passing evidence. Existing non-lint
Next project-reference/toolchain and npm dependency advisories (62 reported by
the image install) remain recorded caveats; dependency remediation was not
silently added to this plan and no lint negatives or test failures were waived.
Production release still requires its separate dependency/security review and
all manual/operator gates. No commit, push, deployed governance or production
enablement occurred.
