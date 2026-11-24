# Registration Backlog Archive, 2026-11-23

> **HISTORICAL, SUPERSEDED, NON-EXECUTABLE.** This complete archival snapshot
> preserves original task definitions and dated evidence through 2026-11-23.
> It is not a second active backlog, operating procedure, implementation
> authorization or final-current-source verification. Imperatives, handoff
> examples and Completed statuses below have historical meaning only.

Current authority is the [authentication and recovery policy](../authentication-and-recovery-policy.md),
[Proposed ADR](../adr/0001-authentication-recovery-and-security-state-authority.md)
and [canonical execution backlog](../../.github/tasks/registration-single-contract-tasks.md).
The [registration contract](../registration-contract.md) owns current product
shape; [assessment](../security-architecture-assessment.md) and
[readiness](../security-testing-and-readiness.md) distinguish current-source
findings from required new acceptance. Historical contact-only login, legacy-email
identification, code-only recovery and `/my-account` wording do not govern the
target. T12 remains excluded. Old passes do not certify new policy requirements.

## Provenance and Sanitization

- Original bytes SHA-256: `786730c137a37ba8e2a915fbb9e62182958b5eaca6f9cc8b68ab824ac6164c24`.
- Normalized archived body SHA-256: `4877e6bd257ff52b9d223a058cb686de8ede168f80d284518c7a18f3bcb2bc56`.
  Compared against the reviewed original after only the documented link rebasing
  and repository Markdown formatting. The fingerprint does not certify runtime
  behavior or the availability of historical raw artifacts.
- Published 2026-11-24 from the completely reviewed 619-line local source;
  historical source ID: `.kilo/plans/registration-single-contract-tasks.md`.
  The archive date denotes the latest dated record, not a claimed original
  creation date. The local original remains unchanged.
- The entire original narrative follows, including T01-T42 definitions, T12's
  exclusion, scope/acceptance, statuses, source identities, hashes, dates,
  toolchains, command/results, rejected attempts and unperformed gates. Dated
  acceptance prose is preserved, not rewritten into current evidence.
- Original `../../docs/` link destinations are rebased to `../` for this location.
  The unavailable T04 implementation-plan link is replaced with the literal
  historical ID `.kilo/plans/1794725069602-complete-t02-t04.md`; it is neither a
  hyperlink nor an active instruction. Repository source paths keep their
  original repository-root meaning.
- All `/tmp/kilo` locations and local-plan/agent-state descriptions inside the
  snapshot are historical evidence identifiers only, not current dependencies or
  promises that those artifacts are available. No private instructions, local
  agent configuration, secrets, credentials, raw browser artifacts or temporary
  logs/reports are copied. Only the reviewed public task/evidence narrative is
  published.
- The separate [architecture-plan archive](security-architecture-plan-2026-11-24.md)
  records subsequent planning; its stale findings are resolved by the current
  assessment, not by changing this historical acceptance record.

## Original Backlog Snapshot

# Registration and Account Security: Single-Contract Task Backlog

## Purpose

This file contains the incremental launch tasks with their original identifiers. T12 is excluded: usernames are chosen during registration, not claimed by legacy accounts. It replaces the previous all-at-once implementation approach and the proposed parallel registration-v2 architecture.

This is a backlog, not authorization to execute the whole project. Implement only the task explicitly requested by the owner. Do not automatically implement its dependencies, the next task, or unrelated improvements.

No existing code, data, or implementation is declared deleted by this document. Verify the actual baseline before each requested task and preserve unrelated work.

## Fixed Rules

- Maintain one registration implementation: extend the existing service, client, form, and routes.
- Preserve the public `/register` route.
- Do not introduce `/register/v2`, `RegistrationV2Service`, a second registration client, or parallel registration contracts.
- Add compatibility behavior only for actual, confirmed stored data or consumers, not hypothetical older clients.
- Apply new required personal fields to registration without fabricating missing attributes for existing accounts.
- Keep public/cosmetic display names separate from private account attributes.
- Never use a fabricated mailbox or an empty-string email digest to support phone-only accounts.
- Treat migration numbers as database change ordering, not a second application version.
- Do not introduce a new audit/lifecycle format merely to label this feature as a new version. Preserve existing signed history and verify actual consumer requirements before changing a current contract.
- Do not commit, deploy, reset data, delete code, change staging, or write to the source SQL Server unless separately authorized.
- Write repository code, comments, documentation, and task files in English. Authentic Persian translations and fixtures remain permitted where required.

## Per-Task Delivery

- Confirm the requested task ID and its bounded scope before editing.
- Reuse existing patterns and make the smallest correct change.
- If a prerequisite is absent, report the dependency; do not implement it automatically.
- Include focused unit, HTTP, integration, or UI tests appropriate to the task.
- Use the repository's Nx targets and package-manager-prefixed commands for verification.
- Report changed files, observed test results, and remaining limitations.
- Do not repeat unchanged successful broad suites merely to show progress. Re-run affected checks when a new change invalidates their evidence.
- Do not equate mocks, queued messages, provider acceptance, or virtual authenticators with real delivery or physical-device acceptance.

## Execution Order

The task numbers provide a suggested sequence, not a command to execute every task. A future instruction such as `Implement T03` authorizes only T03.

## Part 1: Scope and Validation

### T01 - Define the Existing Registration Contract

**Status:** Completed (repository contract audit, 2026-11-15). The authoritative contract defines all final fields, the six stages and current/deferred requests for the single existing registration implementation. This is contract completion, not implementation or deployment of the deferred target.

**Scope:** Define the final fields, stages, and requests for the existing registration implementation. Do not implement the other features.

**Acceptance:** One agreed contract covers names, birthday, gender, username, contact, authentication method, location, and legal acceptance. There is no second registration service or versioned registration route.

**Contract:** [Authoritative registration contract](../registration-contract.md) separates the existing flow, username increment and deferred final target. Its confirmed username policy supersedes historical T03 syntax below (no `7..40`, Latin mode or ZWNJ). This reference does not mark T02-T42 or the deferred legacy-claim/proof work complete.

### T02 - Validate Given and Family Names

**Status:** Completed (standalone validator and required local gates, 2026-11-15). `apps/identity-api/internal/profile/name.go` now has one separate `NormalizePersonalName` validator for either required private field, with NFC, Persian Yeh/Kaf normalization, the explicit private-name repertoire, ASCII-space normalization, structural separators and independent 1..80-code-point/1024-byte bounds. Focused table/property tests and 16 native fuzz seeds run in the ordinary unit gate. The confirmed rules are in the [authoritative contract](../registration-contract.md#confirmed-private-name-validation-t02). Cosmetic `NormalizeName` behavior and callers are unchanged. Current registration endpoints do not yet require, accept or store private names; no legacy values were inferred.

**Scope:** Implement required Persian-script names, permitted spaces/contextual ZWNJ, and consistent Persian/Arabic Yeh/Kaf normalization.

**Acceptance:** Invalid and missing names are rejected with focused Unicode tests. Existing public/cosmetic `display_name` validation is unchanged.

### T03 - Validate Usernames

**Status:** Completed under the superseding [authoritative username policy](../registration-contract.md#username-namespace) (repository audit and focused unit tests, 2026-11-15). `apps/identity-api/internal/username/{normalize,policy}.go` implements bounded UTF-8 admission, full-match configured regex validation, NFC display and a separate folded security name. Its Unicode, normalization, boundary and rejection tests pass. Historical `7..40`, Latin-mode and ZWNJ syntax below is not the completed policy; production policy review/activation and later registration endpoint work are separate.

**Scope:** Implement 7..40 canonical Unicode code points, Persian letters by default, explicit Latin mode, rejection of all numeral scripts and underscores, and the approved dot/ZWNJ rules.

**Acceptance:** Return validated display and canonical values with boundary, normalization, mixed-script, and Unicode rejection tests. Do not add registration endpoints in this task.

### T04 - Index and Reserve Usernames

**Status:** Partially implemented; approval-pending, not completed (implementation and required local gates, 2026-11-15). Dedicated domain-separated HMAC indexing, unconditional uniqueness, all-status reservation, immutable assignments and hard-delete-only release remain implemented. Real run-owned database tests now cover an active nonempty synthetic canonical reserved set, all four folds, exact-only near matches, all-absent rejected tuples and closed/stale authority, through actual restricted API-login transactions. Username integration is included last in the existing required portal suite and its exact inventory. This proves infrastructure behavior, not approval of official reservations. No authorized real database/schema or complete approved inventory snapshot, read-only scanner access, policy/key provenance, protected-report destination or explicit final artifact approval was supplied. Existing-account collisions remain unknown. The five Persian review candidates remain only in the implementation plan (unavailable historical ID: `.kilo/plans/1794725069602-complete-t02-t04.md`); none was installed or activated. See [policy and preflight gates](../devops-operations.md#username-policy-and-preflight-gates).

**Scope:** Add a dedicated domain-separated HMAC lookup key and database uniqueness for canonical usernames. Reserve reviewed system/support names.

**Acceptance:** Every surviving account row reserves its username through suspension and pending/soft deletion. Only hard deletion releases it. Renaming is not supported. No transparent lookup-key rotation or generic mailbox normalization is introduced.

**T01-T04 Audit Evidence (2026-11-15):** Inspected source commit `3515e8a564395e17e64b7bf0f022e347b9be496a` with a clean initial working tree. `npm exec -- nx run identity-api:test-username --skipNxCache` passed all three packages (`internal/username`, `cmd/username`, `internal/migrate`), including the Nx generation dependencies, using Node `24.18.0`, npm `11.21.0` and Go `1.26.10` (`GOTOOLCHAIN=local`). An explicit verbose username run also passed all 18 `TestUsername*` tests without skips. Integration/race suites, Go lint, CI release/container policy tests, retention integration and browser acceptance were not run for this documentation-only status update; no runtime/deployment acceptance is claimed. T05-T42 and deferred legacy-claim/proof work remain unchanged.

**T02/T04 Implementation Evidence (2026-11-15):** The later implementation pass
used the same baseline commit, a clean index and the final combined unstaged
implementation. Its acceptance source SHA-256 was
`2dcc8b71c3a4a429dfe86a993ba769032585fc96bffbccadfe5d67a70a646c21`.
Generated inputs remained unchanged: 26 database files
(`e158bd6709fa67c2519a95357fc6b815067bf4f5405ed5497a4c8cf53959290b`),
four Go schema files
(`da3d8a24bf7b547633784fa7b52b391f3c564093e2dec8e954e054efdb65b2cf`),
and three TypeScript schema files
(`71a073141ebcc4680c92cfe64933b3ab38327a6c9c6874aeef92a5915afc97d5`).
Toolchain: Node `24.18.0`, npm `11.21.0`, Go `1.26.10`, golangci-lint
`2.12.2`, native Ubuntu GCC `13.3.0`, Linux amd64 and compiler-enabled CGO.
The following commands ran from the repository root with that toolchain on PATH;
owned-service harnesses ran sequentially and adopted no inherited credentials.

| Required command                                                                                                                      | Observed final result                                                                                                                                                                                                                           |
| ------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `npm exec -- nx run identity-api:test --skipNxCache`                                                                                  | Passed; 60 test-bearing packages, three packages with no test files. Private-name deterministic properties and all 16 fuzz seeds ran; no extended fuzz campaign was run. Ordinary nonverbose output does not provide a test-level skip count.   |
| `CGO_ENABLED=1 npm exec -- nx run identity-api:test-race --skipNxCache`                                                               | Passed with native GCC; same 60 test-bearing packages and three packages with no test files. This is not integration-tagged username race evidence.                                                                                             |
| `npm exec -- nx run identity-api:vet --skipNxCache`                                                                                   | Passed.                                                                                                                                                                                                                                         |
| `GOFLAGS=-tags=integration npm exec -- nx run identity-api:vet --skipNxCache`                                                         | Passed.                                                                                                                                                                                                                                         |
| `npm exec -- nx run identity-api:lint --skipNxCache`                                                                                  | Passed; zero issues after correcting a test-label spelling diagnostic and rerunning affected checks.                                                                                                                                            |
| `npm exec -- nx run identity-api:lint --skipNxCache --args='--build-tags=integration'`                                                | Passed; zero issues.                                                                                                                                                                                                                            |
| `npm exec -- nx exec -p schemas -- node --test "$PWD"/.github/scripts/*.test.mjs`                                                     | Passed; 420 tests, zero failures/skips/cancellations.                                                                                                                                                                                           |
| `npm exec -- nx exec -p schemas -- node "$PWD/.github/scripts/portal-harness.mjs" --integration-target=test-portal-integration`       | Passed; exact 16-package inventory including username, 2703 reported tests, zero failures/skips, confirmed owned-service teardown. Existing registration/privacy and username immutability/concurrency/deletion fixtures remained in this gate. |
| `npm exec -- nx exec -p schemas -- node "$PWD/.github/scripts/portal-harness.mjs" --integration-race-package=./internal/registration` | Passed; one package, 156 reported tests, zero failures/skips, Linux/CGO/Go/GCC proof and confirmed teardown.                                                                                                                                    |
| `npm exec -- nx exec -p schemas -- node "$PWD/.github/scripts/portal-harness.mjs" --integration-target=test-retention-integration`    | Passed; three packages, 355 reported tests, zero failures/skips, confirmed teardown.                                                                                                                                                            |
| `npm exec -- nx run web:test-admin-browser --skipNxCache`                                                                             | Passed; fresh production dependencies, both `en` and `fa-IR`, 28 reported checks and 70 layouts per locale, all assertions passed, unchanged worktree through each run and confirmed teardown.                                                  |

Sanitized race/retention artifacts are in `/tmp/kilo/t02-t04-integration` and
bilingual browser evidence is in `/tmp/kilo/t02-t04-admin`. The browser runs bound
the same unstaged-diff SHA-256
`a346c9dad105d791a0d824b68bc288a16d88b5cd41fdc59db395bb17a2990b65`,
with no staged or untracked changes. These evidence/status additions were made
after runtime verification; they change only this backlog, not the tested
implementation, configuration or toolchain. Markdown formatting and referenced
paths/commands are checked separately after this documentation-only amendment.

All plan-required local gates passed; no final required gate is failed or unrun.
Full seven-suite/seven-race CI aggregation was not run locally: the plan calls for
the affected portal/retention cells and registration race cell, not a full release
claim. The dedicated username integration target was not run bare and no
integration-tagged username race pass is claimed. No SQL/protobuf sources changed,
so no additional migration/schema gates were added. Operational collision review
and final policy approval remain blocked by the missing authorization/access and
approved artifact above. Deployment, real provider delivery, physical
authenticators, native browser zoom and assistive-technology certification remain
unverified. Native hidden-tab and bfcache transitions were not observed; browser
visibility/history cleanup was exercised using the documented real-API probes.
No production policy/list edits, installations, activations, shared database
writes, account repairs or commits were performed. T05-T42 remain unchanged.

### T05 - Validate Date-Only Birthdays

**Status:** Completed (standalone validator, source review and required local
gates, 2026-11-15). `internal/profile.NormalizeBirthday` admits the
explicit three-script digit grammar, validates the selected calendar, derives one
equivalent Gregorian/Jalali pair with the MIT-attributed pinned integer converter,
and applies the inclusive Gregorian range using a trusted Tehran clock. The
[confirmed contract](../registration-contract.md#confirmed-birthday-and-gender-validation-t05t06)
records source review, reference provenance and supported limits. Current HTTP
requests do not accept, require or store birthday; no routing, storage or UI work
was delivered. Final gate evidence is recorded below.

**Scope:** Accept an explicit Gregorian/Jalali input calendar, normalize permitted numeric date digits, and use one pinned/reviewed converter.

**Acceptance:** Validate Gregorian dates from `1900-01-01` through the current server-side Tehran civil date. Produce equivalent Gregorian/Jalali date-only values, including leap boundaries. Never parse or store DOB as a timestamp.

### T06 - Require Explicit Gender

**Status:** Completed (standalone validator and required local gates,
2026-11-15). `internal/profile.ValidateGender` admits only
exact `female`/`male`, returning a zero string-backed `Gender` and static error on
missing/unsupported input. Current endpoints and profile reads are unchanged; no
preselected controls, legacy inference, models, migration or backfill was added.
Final gate evidence is recorded below.

**Scope:** Accept exactly `female` and `male` without a preselected value.

**Acceptance:** Missing or unsupported new-registration values are rejected. An unset legacy value remains unset rather than being inferred or backfilled.

**T05/T06 Implementation Evidence (2026-11-15):** Implementation started from
clean commit `37dceb618cad97fb6696bf8183bdfe768d79e101`. The final combined
source SHA-256, including all five new Go files and the updated contract, is
`f8d5b0b990af08648e8e45046a29f75ffab7d73178ec7fc2c0843621e8dd91ea`.
Generated inputs remained unchanged: 26 database files
(`e158bd6709fa67c2519a95357fc6b815067bf4f5405ed5497a4c8cf53959290b`),
four Go schema files
(`da3d8a24bf7b547633784fa7b52b391f3c564093e2dec8e954e054efdb65b2cf`),
and three TypeScript schema files
(`71a073141ebcc4680c92cfe64933b3ab38327a6c9c6874aeef92a5915afc97d5`).
Toolchain: Node `24.18.0`, npm `11.21.0`, Go `1.26.10` with
`GOTOOLCHAIN=local`, golangci-lint `2.12.2` built with that Go version, GCC
`13.3.0`, native Linux amd64 and compiler-enabled CGO. Commands ran from the
repository root with these tools on PATH. Owned-service harnesses ran sequentially
with fresh disposable services and no adopted database credentials.

| Required command                                                                                                                   | Observed final result                                                                                                                                                                         |
| ---------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `npm exec -- nx run identity-api:test --skipNxCache`                                                                               | Passed; 60 test-bearing packages and three packages with no test files. Ordinary nonverbose output does not provide a test-level skip count.                                                  |
| `CGO_ENABLED=1 npm exec -- nx run identity-api:test-race --skipNxCache`                                                            | Passed with native GCC; same 60 test-bearing packages and three packages with no test files. No integration-tagged race claim.                                                                |
| `npm exec -- nx run identity-api:vet --skipNxCache`                                                                                | Passed.                                                                                                                                                                                       |
| `GOFLAGS=-tags=integration npm exec -- nx run identity-api:vet --skipNxCache`                                                      | Passed.                                                                                                                                                                                       |
| `npm exec -- nx run identity-api:lint --skipNxCache`                                                                               | Passed; zero issues.                                                                                                                                                                          |
| `npm exec -- nx run identity-api:lint --skipNxCache --args='--build-tags=integration'`                                             | Passed; zero issues.                                                                                                                                                                          |
| `npm exec -- nx exec -p schemas -- node --test "$PWD"/.github/scripts/*.test.mjs`                                                  | Passed; 420 tests, zero failures/skips/cancellations.                                                                                                                                         |
| `npm exec -- nx exec -p schemas -- node "$PWD/.github/scripts/portal-harness.mjs" --integration-target=test-retention-integration` | Passed; exact three-package inventory, 355 reported tests, zero failures/skips and confirmed owned-service teardown.                                                                          |
| `npm exec -- nx run web:test-admin-browser --skipNxCache`                                                                          | Passed on final rerun; fresh real dependencies for both `en` and `fa-IR`, 28 checks and 70 layouts per locale, all assertions passed, unchanged source/index identity and confirmed teardown. |

Focused profile tests also passed with zero skips: three pinned upstream vectors,
11 independently sourced/derived authority and ICU anchors including leap ends,
all 46,340 civil days from `1900-01-01` through fixed Tehran `2026-11-15`, all
6,561 script mixtures per input calendar, exact grammar/size/month/leap bounds,
both-calendar inclusive lower/today/next-day limits, midnight/year rollover,
historical DST/current non-DST and location-equivalent clocks, unusable clocks,
atomic/redacted error and idempotence properties, and strict gender admission.
The 20 birthday and 11 gender fuzz seeds ran in ordinary unit/race tests; existing
profile/name tests were unchanged and passed. No extended fuzz campaign was run.
Independent read-only port review compared every arithmetic expression, break
table, signed division/remainder, bounds and full MIT notice with jalaali-js
`f592be0e06867d2752f93924fa3e338f366ce4f4`; no findings. The authority-derived
reference table and ICU fixture pins and astronomical/proleptic limits are in the
contract and test comments. Original authority PDF access and official-calendar
certification are not claimed.

The first English browser attempt passed assertions and teardown but failed its
final identity check because external staging moved these same source bytes into
the index. It was not accepted as passing evidence. External staging was preserved;
content/generated fingerprints were unchanged, so only the invalidated browser
gate was rerun. Both final locale reports bind staged-diff SHA-256
`4438b12cd632161b95a3f9d036906c54c5820afbfee591252a46d33b1c959617`,
with no unstaged or untracked changes during the rerun. Sanitized retention
evidence is in `/tmp/kilo/t05-t06-integration`; final bilingual browser evidence
is in `/tmp/kilo/t05-t06-admin`. These backlog-only status/evidence amendments
follow verification and do not change runtime source, configuration, index or
toolchain. Go/Markdown formatting and references were checked separately.

All nine plan-required final gates passed; no required gate remains failed or
unrun. Full seven-suite/seven-race release aggregation, deployment, real provider
delivery, physical authenticators, native browser zoom and assistive-technology
certification were not run or established. Native hidden-tab/bfcache transitions
were not observed; existing real-API event/history probes passed. No registration
HTTP birthday/gender rejection, UI selection/no-default behavior, private storage,
migration, source SQL Server access, shared database write or commit was delivered.
T01-T04 evidence is unchanged; T07-T42 remain separately scoped and incomplete.

## Part 2: Geographic Reference Data

### T07 - Export IranData Safely

**Scope:** Prepare a checksummed reference-data export from local SQL Server `.` using Windows integrated authentication and database `IranData`.

**Acceptance:** Access `dbo.CenterType` and `dbo.CityData` with SELECT-only operations. Preserve observed source IDs, labels, and hierarchy. Do not write to the source or check in its dataset without usage/redistribution permission.

### T08 - Import Geography into PostgreSQL

**Scope:** Add reference tables and a transactional, repeatable importer that preserves source identities.

**Acceptance:** Reject missing parents, cycles, duplicate IDs, and incorrect province ancestry. Preserve retired references instead of deleting places used by saved accounts. No production identity request depends on the developer SQL Server.

### T09 - Search Provinces and Localities

**Scope:** Add bounded province/locality search using the PostgreSQL catalog and original source labels.

**Acceptance:** Support only country `IR`, require a province, allow an optional related locality, distinguish duplicate names, and resolve saved retired IDs. Do not fabricate translations or silently rename a source type as a city.

## Part 3: Private Account Data

### T10 - Store Protected Private Attributes

**Scope:** Store names, the atomic birthday pair, gender, and location using authenticated account/purpose-bound encryption. The existing protected username assignment remains the sole source of username display data.

**Acceptance:** No duplicate plaintext DOB/gender/location columns are introduced. Protected values cannot be substituted across accounts or purposes. Public display names remain independent.

### T11 - Read and Edit Private Attributes

**Scope:** Add authenticated private-data GET/PATCH behavior with exact decimal revisions and optimistic concurrency.

**Acceptance:** A real edit commits the data, one revision increment, and one metadata-only intent together. A no-op changes none of them. Birthday representations are updated atomically and stale edits fail safely.

### T13 - Represent Absent Email Truthfully

**Scope:** Prepare models, adapters, bootstrap, and presentation for optional email, then remove the database's mandatory-email constraint when readers are compatible.

**Acceptance:** Absence is represented by NULL/typed absence, not a placeholder mailbox or empty string. Existing readers compile and pass present/absent tests. Phone-only registration is not enabled by this task alone.

### T14 - Persist Contact Verification Evidence

**Scope:** Bind verification provenance to the exact canonical email/mobile destination and server verification time.

**Acceptance:** Account status or a populated contact is not treated as proof of ownership. Unknown legacy provenance remains unknown. Contact changes invalidate incompatible proofs.

## Part 4: Login and Session Security

### T15 - Bound Password Policy and Hashing

**Scope:** Implement new-password validation and shared finite Argon2 admission.

**Acceptance:** Require at least 15 Unicode code points and at most 1024 UTF-8 bytes, reject reviewed local compromised choices, and preserve exact bytes including spaces. Stored legacy hashes are verified without applying new creation-strength rules. Cancellation does not release a hash slot while computation continues.

### T16 - Record Earned Session Authentication

**Scope:** Extend the current session machinery with truthful authentication method, actual assertion UV, independent MFA completion, and authentication time.

**Acceptance:** Available factors do not become earned evidence. Unknown legacy evidence is not fabricated. Any actual stored-record compatibility requirement is handled within the existing implementation rather than creating a parallel registration/session system.

### T17 - Fence Role Changes and Session Use

**Scope:** Check authoritative account/MFA/privileged policy at issuance and relevant session/token use boundaries. Invalidate old authority on actual role changes.

**Acceptance:** Promotion cannot upgrade a low-assurance session into administrative authority. No-op role changes do not revoke unnecessarily. Checks apply even when the administrative HTTP feature is disabled.

### T18 - Implement Password Login

**Scope:** Add username identification and an explicit legacy-email identification path using the existing session and browser-proof infrastructure.

**Acceptance:** Missing-account and wrong-password failures do not enumerate accounts. Required MFA produces only bounded preauthentication, never a premature normal session.

### T19 - Implement Purpose-Isolated Contact Codes

**Scope:** Add email/SMS code issuance and verification with keyed code protection, quotas, original expiry, and one-time consumption.

**Acceptance:** Registration, login, and sensitive-action purposes cannot exchange authority. A disabled alternate provider does not disable the selected channel. Unknown delivery or commit results do not trigger automatic unsafe retries.

### T20 - Sign In through Verified Contact

**Scope:** Permit contact-code login for passkey-only, password-only, and dual-credential accounts through the identified account's already verified destination.

**Acceptance:** A shared mobile number cannot select an arbitrary account. Contact-only authentication cannot bypass mandatory MFA or privileged protections. Session evidence truthfully records contact-code authentication.

### T21 - Complete Login MFA

**Scope:** Complete bounded password/contact-code preauthentication using the existing independent TOTP factor and shared replay protection.

**Acceptance:** No normal cookie exists before success and final account-policy validation. Browser/account/version binding, original expiry, attempts, and single-use completion remain enforced.

## Part 5: Sensitive Actions and Recovery

### T22 - Authorize One Sensitive Action

**Scope:** For eligible password-only accounts, combine fresh password verification and an OTP to their verified contact into a narrowly scoped action proof.

**Acceptance:** Bind account, session, JKT, earned account version, expiry, and action. Consume the proof in the action's transaction. Do not create a general password Step-up grant or permit unrelated/admin/legal use. Preserve existing WebAuthn UV and TOTP-supported scopes.

### T23 - Preserve the Last Primary Factor and Contact

**Scope:** Enforce shared factor/contact invariants under the common account lock.

**Acceptance:** An account cannot lose its final password/passkey, required verified contact, or privileged/MFA protection. OTP contact control is not a primary credential. Real security changes invalidate stale authority; cosmetic key renames do not.

### T24 - Manage Passwords

**Scope:** Add, change, and remove passwords using the shared hasher and an appropriate fresh authorization proof.

**Acceptance:** Hash outside long-lived account transactions, recheck current authority before commit, preserve exact bytes, and invalidate prior authority on real changes. Removing a password cannot leave the account without a primary factor.

### T25 - Enroll the First Passkey on a Password Account

**Scope:** Authorize the first native enrollment with a specific fresh proof instead of requiring an unavailable existing passkey.

**Acceptance:** Require actual UV, preserve immutable identity, defer handle persistence until successful verification, and protect concurrent first enrollment. Cancelled or ambiguous results cannot replay authority automatically.

### T26 - Manage MFA on Password Accounts

**Status:** Completed (existing implementation and required local verification,
2026-11-23). Password/contact authorization is enrollment-only; existing earned
UV-passkey/TOTP maintenance authority remains separate. Pending enrollment freezes
session, JKT, account version, method, contact binding and the original minimum
deadline. MFA owns the deciding transaction. Disable retains current locked
resulting-state and privileged-account protections. Migration `00010` is additive
and forward-only. This is local source/fixture acceptance, not deployment, policy
activation, provider delivery or T38 management UI completion.

**Scope:** Start MFA enrollment and disable an existing factor using the appropriate scoped/fresh authorization.

**Acceptance:** Preserve required MFA and current privileged-account policy. Pending enrollment remains session/version-bound, finite, and one-use. Do not nest conflicting account transactions.

**T26 Final Verification Evidence (2026-11-23):** The supplied baseline was
`54eb6b78bbfb7bd445d319fdddedcb9956430586`. At inspection, its 39-file T26 handoff
was already committed as `67ba7b7116f8f252269843f44f49dc9e09f2ffb8`, with a clean
index and worktree; this verification turn did not create that commit. All 39
files, including seven added files and the four existing documentation updates,
were inspected. No production web, Compose manifest, registration contract route
or new management UI implementation was added by this turn.

Verification corrected only T26-related failures: exported-method lint comments
and equivalent conditional expressions; exact migration-10 history/table
expectations; distinct synthetic replacement-phone indexes; custom-role labels in
encrypted fixture audit context rather than the unchanged general-audit allowlist;
a never-assigned username fixture instead of attempting to clear an immutable
assignment; and the excluded browser fixture's missing finite TOTP-completion
deadline. Its existing test double now rejects absent/expired/infinite deadlines.
No Unicode assertion, lint configuration, restore check, database trigger or
security policy was weakened.

The final acceptance source SHA-256 is
`0c7cef63b95ea86abdd3046b16bb020a373c119443a8718916cc3e3bc0127c6a`, using the
existing `acceptanceIdentity` inventory, which excludes plan/agent state and
separately fingerprints ignored generated outputs. HEAD remained
`67ba7b7116f8f252269843f44f49dc9e09f2ffb8`. Final generated inventories are:

| Generated tree                  | Files | SHA-256                                                            |
| ------------------------------- | ----- | ------------------------------------------------------------------ |
| `apps/identity-api/internal/db` | 31    | `b2bfd798d0f5ed69a429d6184665b44088d5d2b29e95d43d7c92a467347b30e2` |
| `libs/schemas/gen/go`           | 4     | `75587d9200428ef0535ad7a880a20f341929b111b2be2db397629dd3118f5c2a` |
| `libs/schemas/gen/ts`           | 3     | `c13d5649d6d94d8a873d085c565d777ded166ae7647a5bc09c00e16f0eb90c50` |

Both generators were repeated uncached and all three complete trees compared
identically with `diff -ru`, as in the workflow. Later fixes did not change
SQL/protobuf/generator inputs; all later generated fingerprints remained identical.
Ignored generated outputs were not staged.

Executable resolution and actual versions were verified before dependent commands:
Node `24.18.0` and npm `11.21.0` from the installed NVM version; Go `1.26.10`
from the existing cached Linux-amd64 toolchain, satisfying `go.mod`'s `1.26.5`
minimum with `GOTOOLCHAIN=local`; golangci-lint `2.12.2` from an existing cached
binary built with Go `1.26.10`; native GCC `13.3.0`, target
`x86_64-linux-gnu`, Linux amd64 and `CGO_ENABLED=1`; PostgreSQL `16.15` clients
(`psql`, `pg_dump`, `pg_restore`) from `/usr/lib/postgresql/16/bin`; Docker Engine
client/server `29.9.3`, Compose `5.7.0`; installed Chromium `156.0.8078.4`
successfully launched through Playwright. Existing amd64 PostgreSQL 16, Redis 7 and
NATS 2.10 fixture images were available. Host Go `1.27.3` and a Go-1.27-built
linter were identified and not selected for acceptance.

Every independent command used verified local PATH prefixes. The inherited
`NODE_TLS_REJECT_UNAUTHORIZED=0` was removed locally, without weakening TLS or
editing global settings. Initial remote TypeScript generation returned HTTP 403
after the temporary runner omitted the existing egress proxy; restoring that
proxy locally made the unchanged command pass. Owned-service harnesses retained
their own clean-environment boundary and adopted no inherited database credentials.
Tools, providers and global configuration were not installed or changed.

`identity-api`, `schemas` and `web` were resolved with
`npm exec -- nx show project <name> --json`; the current workflow and resolved
targets were the command authority. Commands below ran from the repository root.
Earlier failed or invalidated attempts are not the final results. Only affected
checks were rerun after fixes; final integration/race reports were rerun to bind
the exact final source, and all six report identities/inventories were validated.

| Required command                                                                                                                     | Observed final result                                                                                                                                                                                     |
| ------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `npm exec -- nx run schemas:lint --skipNxCache`                                                                                      | Passed.                                                                                                                                                                                                   |
| `npm exec -- nx run schemas:generate --skipNxCache`                                                                                  | Passed; repeated generation reproduced Go/TypeScript bytes.                                                                                                                                               |
| `npm exec -- nx run identity-api:sqlc-vet --skipNxCache`                                                                             | Passed.                                                                                                                                                                                                   |
| `npm exec -- nx run identity-api:sqlc-generate --skipNxCache`                                                                        | Passed; repeated generation reproduced database bytes.                                                                                                                                                    |
| `npm exec -- nx run identity-api:test --skipNxCache`                                                                                 | Passed; 68 test-bearing packages, three packages with no test files. Nonverbose output does not establish a test-level count or skip inventory.                                                           |
| `CGO_ENABLED=1 npm exec -- nx run identity-api:test-race --skipNxCache`                                                              | Passed; same 68 test-bearing packages and three packages with no test files, native Linux/GCC/CGO. Nonverbose output does not establish a test-level count or skip inventory.                             |
| `npm exec -- nx run identity-api:vet --skipNxCache`                                                                                  | Passed.                                                                                                                                                                                                   |
| `GOFLAGS=-tags=integration npm exec -- nx run identity-api:vet --skipNxCache`                                                        | Passed.                                                                                                                                                                                                   |
| `npm exec -- nx run identity-api:lint --skipNxCache`                                                                                 | Passed; zero issues.                                                                                                                                                                                      |
| `npm exec -- nx run identity-api:lint --skipNxCache --args='--build-tags=integration'`                                               | Passed; zero issues.                                                                                                                                                                                      |
| `npm exec -- nx run identity-api:build --skipNxCache`                                                                                | Passed; browser targets also rebuilt production dependencies uncached.                                                                                                                                    |
| `npm exec -- nx run identity-api:build-migrate --skipNxCache`                                                                        | Passed.                                                                                                                                                                                                   |
| `npm exec -- nx exec -p schemas -- node --test "$PWD"/.github/scripts/*.test.mjs`                                                    | Passed; 482 tests, zero failures/skips/cancellations.                                                                                                                                                     |
| `npm exec -- nx exec -p schemas -- node "$PWD/.github/scripts/portal-harness.mjs" --integration-target=test-security-db`             | Passed; exact 22-package inventory, 3,262 reported tests, zero failures/skips, confirmed teardown. Includes real migration lineage, concurrent migrators and forward-recovery dump/restore checks.        |
| `npm exec -- nx exec -p schemas -- node "$PWD/.github/scripts/portal-harness.mjs" --integration-target=test-portal-integration`      | Passed; exact 20-package inventory, 4,173 reported tests, zero failures/skips, confirmed teardown. Includes MFA transaction/authority/concurrency/failure fixtures.                                       |
| `npm exec -- nx exec -p schemas -- node "$PWD/.github/scripts/portal-harness.mjs" --integration-race-package=./internal/mfa`         | Passed; exact one-package inventory, 127 reported tests, zero failures/skips, verified race toolchain and teardown.                                                                                       |
| `npm exec -- nx exec -p schemas -- node "$PWD/.github/scripts/portal-harness.mjs" --integration-race-package=./internal/actionproof` | Passed; exact one-package inventory, 169 reported tests, zero failures/skips, verified race toolchain and teardown.                                                                                       |
| `npm exec -- nx exec -p schemas -- node "$PWD/.github/scripts/portal-harness.mjs" --integration-race-package=./internal/contactcode` | Passed; exact one-package inventory, 79 reported tests, zero failures/skips, verified race toolchain and teardown.                                                                                        |
| `npm exec -- nx exec -p schemas -- node "$PWD/.github/scripts/portal-harness.mjs" --integration-target=test-retention-integration`   | Passed; exact three-package inventory, 355 reported tests, zero failures/skips, confirmed teardown.                                                                                                       |
| `npm exec -- nx run web:test-admin-browser --skipNxCache`                                                                            | Passed; fresh real dependencies, both `en`/`fa-IR`, 29 reported checks, 70 layouts and 12 integrated-login journeys per locale; assertions, source/index freeze and teardown passed.                      |
| `npm exec -- nx run web:test-portal-browser --skipNxCache`                                                                           | Passed on final rerun; fresh real dependencies, both `en`/`fa-IR`, 18 reported checks, 30 viewport surfaces and six no-JavaScript checks per locale; assertions, source/index freeze and teardown passed. |

The additional current-workflow fixture gate,
`npm exec -- nx run identity-api:test-portal-fixture --skipNxCache`, passed its
one test-bearing package. Its ordinary nonverbose output does not establish a
test-level count or skip inventory. The focused 69-case MFA writer-order diagnostic
also passed with confirmed fresh-service teardown; it supplements, not replaces,
the final required suites.

Owned-service and browser runs were sequential, with fresh disposable services and
complete teardown. An early interrupted security run produced no accepted test
inventory; its three containers and network were verified by immutable IDs and
`ldp.run` and retired using the existing ownership helper. Existing unrelated
stopped containers were left untouched. Final harness reports confirm teardown;
no current run-owned containers or broker remained. Policy-test mock artifacts in
`/tmp/kilo/t26-verification/integration` are not acceptance evidence.

External staging was preserved throughout. The final admin run's two locale
reports bind staged-diff SHA-256
`96936f8cf020f4b3e4d8685f1e1e55881e7933c4f6b28bccf24c858a5f11bbe9` and
unstaged-diff SHA-256
`0ad32dc8ccb6ef93212c7ac3694c4aab91c051c0c0deddea4586b9dbad042018`;
both report `worktreeMatchesAtFinish=true`, and the outer complete-command freeze
also passed. Later external staging moved the same remaining fixture bytes into
the index during the first otherwise-successful portal run. Its outer freeze
failed, so that portal attempt was rejected and only portal was rerun. The final
portal command and final service gates bind staged-diff SHA-256
`aee15047c81e2691ebfb63d5afd7364333ed324255081c4f09d0c94c9a3b4e43`, with empty
unstaged/untracked inventories during acceptance. Both browser commands used the
same final runtime source/generated bytes; no browser acceptance is claimed for
an index-changing run.

This verification turn changed eleven existing Go/test files:
`cmd/portal-fixture/{main.go,main_test.go}`,
`internal/actionproof/{integration_test.go,mfa_enrollment_integration_test.go,password_change_integration_test.go}`,
`internal/contactcode/service.go`,
`internal/legalhold/registration_restore_integration_test.go`,
`internal/mfa/service.go`, `internal/migrate/safety_test.go`,
`internal/server/mfa_integration_test.go` and `internal/smsotp/login.go`, all under
`apps/identity-api/`. The only later documentation edit is this T26 backlog section.
The existing backlog is ignored by `.gitignore`'s `.kilo` rule and is not in HEAD;
it remains a local evidence update, with no force-add or staging operation.
The combined baseline-relative implementation inventory is 43 files, or 44 with
this backlog amendment. User staging was not changed by this turn; the eleven
fix files were externally staged. This post-verification backlog amendment is
checked separately for formatting/references and does not alter tested runtime
source, configuration, generated inputs or toolchains.

Sanitized final reports are in
`/tmp/kilo/t26-verification/final-integration`,
`/tmp/kilo/t26-verification/admin-final` and
`/tmp/kilo/t26-verification/portal-final`; commands, attempts, identities and logs
are retained under `/tmp/kilo/t26-verification`. All 21 T26-required local gates
passed; none remains failed or not run. Full eight-suite/twelve-race release
aggregation, exact-release-image registration and full-stack Compose acceptance
were not run in this bounded T26 pass. No GitHub CI, deployment, shared-database
write, production username/MFA policy activation, provider-template installation,
data reset or commit is claimed or performed. Real email/SMS receipt, physical
authenticator acceptance, Persian security/legal wording review, deployed ingress,
native zoom and assistive-technology certification remain unverified. Native
hidden-tab/bfcache transitions were not observed; the documented real-API
visibility/history probes passed. Other task statuses and historical evidence are
unchanged; T27 and T38 remain separately scoped.

### T27 - Change or Remove Contacts

**Status:** Implemented; final combined-source verification in progress
(2026-11-23). The unified contact manager, action/target-bound password/contact
proofs, frozen strong authority, separate exact new-destination ownership, truthful
current-contact read and additive forward-only `00011` are implemented. See the
[API contract](../api-design.md#primary-contact-maintenance-t27) and
[rollout/rollback gates](../devops-operations.md#primary-contact-maintenance-t27).
Present-primary-email removal remains operation-gated on independently verified
T28 recovery identification and T41 email-absent notification/deletion/reclaim
compatibility. Authorized absent-email removal and email-absent accounts remain
supported. No T28/T41, backup-contact, registration or T38 UI work is completed by
this increment; real provider/physical-device/deployed acceptance is not claimed.

**Scope:** Keep authorization against the old verified contact separate from ownership proof of the new destination.

**Acceptance:** Preserve the last required contact and a usable account identifier. Persist exact new provenance atomically and invalidate stale authority/proofs. Do not reinterpret signup authority as contact-change authority.

### T28 - Consume Backup Recovery Codes

**Scope:** Complete backup-code recovery with explicit username/legacy-email identification, browser JKT binding, expiry, and single-use consumption.

**Acceptance:** High-entropy recovery codes remain SHA-256 protected, not Argon2 hashed. Recovery never creates dashboard authority. Preserve `/recover-account` for deletion cancellation and keep lost-factor recovery separate.

### T29 - Repair One Unavailable Factor

**Scope:** Replace an unavailable password, TOTP, or passkey through a finite authority specifically earned for that repair.

**Acceptance:** Repair cannot change contacts, disable required MFA, mint a broad grant, or open the portal. Expired/spent/wrong-bound and ambiguous results have explicit safe handling.

### T30 - Delete a Password-Only Account Safely

**Scope:** Connect the specific deletion proof to the existing account-deletion transaction and post-commit behavior.

**Acceptance:** Preserve the 30-day grace period, return/reclaim possibility, legal holds, and credential invalidation. Do not weaken the existing stronger authorization route or duplicate the deletion system.

## Part 6: Complete the Existing Registration Service

### T31 - Support One Contact and Selected Credentials

**Scope:** Extend the existing registration service for verified email OR mobile and passkey, password, or both.

**Acceptance:** Validate all required fields, legal versions, and a server-verified primary credential before account creation. Code-only account creation is rejected. No parallel registration service/client/route is introduced.

### T32 - Commit Registration Atomically

**Scope:** Commit the account, protected attributes, chosen verified contact, accepted legal versions, selected primary credentials, and creation intent in one transaction.

**Acceptance:** Failures and equivalent-username races cannot create partial accounts or attach credentials to another account. Password-bearing completion fingerprints are keyed; result reconciliation cannot duplicate creation.

### T33 - Sign In Only after a Fresh Registration Commit

**Scope:** Add a cookie-capable completion boundary to the current registration flow and issue the normal session after a known successful SQL commit.

**Acceptance:** Keep the same browser key and expected new subject. Result lookup and replayed receipts never mint sessions. Failed session delivery reports the committed account and permits ordinary login without recreating it.

## Part 7: Frontend Journeys

### T34 - Build the Existing Form's Six-Stage Shell

**Scope:** Extend the existing form in this order: names; personal information; username; contact verification; authentication method; location and final review.

**Acceptance:** Back navigation, language/calendar changes, and opening legal links preserve ordinary progress and original meaning without replaying API/native work or extending deadlines.

### T35 - Add Personal and Username Controls

**Scope:** Connect names, date-only birthday, explicit gender, and username controls to server-authoritative validation.

**Acceptance:** Provide typed English/Persian messages, explicit input calendars, no preselected gender, accessible feedback, and no timestamp conversion of DOB. Do not fabricate legacy values.

### T36 - Add Contact and Credential Choice UI

**Scope:** Add email/mobile selection, code entry, explicit resend, and passkey/password/both choice to the existing form.

**Acceptance:** Preserve expiry/budgets, keep secrets transient, allow paste/password managers, and keep confirmation client-only. Native cancellation never silently downgrades `both` or triggers automatic fallback/delivery.

### T37 - Review and Complete Registration

**Scope:** Show location, both birthday representations, configured legal links, and separate explicit acceptance before the final action.

**Acceptance:** Validate the complete form before native enrollment. After a confirmed fresh session, discard old authority and bootstrap exactly the expected account once before entering `/my-account`.

### T38 - Connect Login and Private Account Editing

**Scope:** Keep passkeys as the default login and connect password/contact/MFA alternatives and the private-attribute editor to their existing current APIs.

**Acceptance:** Present absent data honestly, preserve independent cosmetic display names and immutable usernames, and support both locales/themes/directions. Locale changes do not rebootstrap authentication or replay API work.

### T39 - Explain Windows Hello and Recovery Truthfully

**Scope:** Distinguish WebAuthn API support, platform-authenticator availability, and a matching credential for the current RP.

**Acceptance:** Never request a Windows PIN in the web application or disable USB/hybrid alternatives based on a negative platform check. Native prompts require explicit user action. Report physical-device acceptance separately from virtual tests.

## Part 8: Consumers and Final Delivery

### T40 - Extend Private Snapshots and Change Metadata

**Scope:** Extend the current gRPC snapshot and metadata-only change contract for private attributes after verifying real consumer requirements.

**Acceptance:** Require explicit per-field grants, truthful absence, inactive/deleted privacy behavior, and one consistent revision. Events contain no DOB/gender/location values. Do not introduce a second registration or hypothetical parallel consumer contract.

### T41 - Notify and Audit Accounts without Email

**Scope:** Adapt deletion/return and security-change notifications to a real verified available destination, and handle absent email deliberately in audit/ledger consumers.

**Acceptance:** Never invent a mailbox, hash an empty email, or silently lose attribution. Preserve queued recipient/token/locale/deadline and old signatures/history without rewriting them. Queued or provider-accepted is not delivered. Unknown transport/commit outcomes do not cause unsafe replay.

### T42 - Integrate, Verify, and Document

**Scope:** Connect only completed prerequisites, run affected focused/integration/browser checks, and document the single implementation and non-destructive rollout/rollback boundaries.

**Acceptance:** Report passed, failed, blocked, skipped, and unrun evidence separately. Source-data rights, approved legal documents, real email/SMS receipt, physical Windows Hello/security keys, Persian security/legal review, and deployed ingress are not established by fixtures or configuration flags. This task does not authorize deployment or destructive cleanup.

## Handoff Example

An instruction such as `Implement T03 using this task backlog` selects only the username-validation task. Its report must state what changed, which focused tests ran, and which dependency remains. Wait for a separate instruction before starting any other task.
