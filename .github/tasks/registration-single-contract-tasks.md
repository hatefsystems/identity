# Registration and Account Security: Target Task Backlog

## Authority and Boundary

This is the revised execution backlog for the owner-confirmed target, dated
2026-11-24. It does not authorize application implementation, deployment,
installation, database access, data cleanup, Git mutations or execution of the
next task. A future owner instruction selects only its named executable task.
Missing dependencies must be reported, not silently implemented.

The [authentication and recovery policy](../../docs/authentication-and-recovery-policy.md)
owns SEC01-SEC16 and admission/lifecycle decisions. The
[assessment](../../docs/security-architecture-assessment.md) owns current-source
findings; [readiness](../../docs/security-testing-and-readiness.md) owns release
evidence. The [ADR](../../docs/adr/0001-authentication-recovery-and-security-state-authority.md)
was accepted by the project owner under [CP01](#t01) on 2026-11-26. The
[registration contract](../../docs/registration-contract.md) owns the single
registration shape. Do not invent a second registration/authentication service or
public route. `/register` remains registration; `/recover-account` remains
exclusively deletion cancellation/reclamation.

Execution source was reported as HEAD
`85abb13a27196c229efa7f59d7ef5beebb1d7e49`. The architecture plan's historical
`f9d2119ff15927d382d860b7f62584682c5b5f31` was unavailable: no same-source or
baseline-diff claim is made. Static inspection is not runtime acceptance.
Current-source strengths remain reusable, not evidence that the new policy is
implemented. In particular enabled TOTP already gates normal login; the current
code-based unauthorized passkey mutation is not a universal TOTP bypass.

Historical [tasks.md](../../tasks.md) was read completely and remains unchanged.
It uses Phase 1-7/Task 1.1-7.6, not T01-T42. The complete original T backlog was
also read (619 lines) and is published as the
[superseded registration backlog archive](../../docs/history/registration-backlog-2026-11-23.md).
The [architecture-plan archive](../../docs/history/security-architecture-plan-2026-11-24.md)
preserves the original static planning input. Both archives are non-executable
history; local originals remain unchanged. The original
T01-T27 product definitions and dated evidence are preserved below. This file
supersedes their active guidance only where stated; no old Completed status
certifies this target. T02/T05-T11/T15 product rules are unchanged. Actual nullable
records, signed formats, v1/v2 readers and queued work are concrete preservation
dependencies, not a hypothetical legacy-user design. T12 is excluded.

## Inventory and Historical Aliases

There are **42 primary IDs, 65 executable target records, seven aggregate aliases
and one excluded ID: 73 distinct IDs in total**. This is not a fixed 42-task
implementation count. Aggregates select no implicit implementation; callers must
name their executable children. Planned work requires owner authorization and
independently completed dependencies. Blocked names an approval, lifecycle or
acceptance prerequisite. A dated documentation delivery establishes only the
recorded documentation evidence.

| Primary ID | Target Executable IDs / Alias     | Historical T Status                                 | Target Disposition                                    |
| ---------- | --------------------------------- | --------------------------------------------------- | ----------------------------------------------------- |
| T01        | T01                               | Completed contract audit, 2026-11-15                | Documentation complete, 2026-11-26                    |
| T02        | T02                               | Completed standalone validator, 2026-11-15          | Planned unchanged-rule verification                   |
| T03        | T03                               | Completed superseding configured policy, 2026-11-15 | Approved length revision verified 2026-11-27          |
| T04        | Aggregate: T04A, T04B             | Partially implemented; approval-pending             | T04A verified 2026-11-27, T04B required before launch |
| T05        | T05                               | Completed standalone validator, 2026-11-15          | Planned unchanged-rule verification                   |
| T06        | T06                               | Completed standalone validator, 2026-11-15          | Planned unchanged-rule verification                   |
| T07        | T07                               | No explicit status recorded                         | Blocked source-access/data-rights authorization       |
| T08        | T08                               | No explicit status recorded                         | Planned unchanged catalog contract                    |
| T09        | T09                               | No explicit status recorded                         | Planned unchanged search contract                     |
| T10        | T10                               | No explicit status recorded                         | Planned unchanged protected-data contract             |
| T11        | T11                               | No explicit status recorded                         | Planned unchanged editing contract                    |
| T12        | Excluded; no executable record    | Excluded by original purpose and AGENTS.md          | Out of scope, no claim lane                           |
| T13        | T13                               | No explicit status recorded                         | Planned truthful optional email                       |
| T14        | T14                               | No explicit status recorded                         | Planned exact verified-contact evidence               |
| T15        | T15                               | No explicit status recorded                         | Planned unchanged exact-byte hashing                  |
| T16        | T16, T16A                         | No explicit status recorded                         | Planned evidence contract and SQL authority           |
| T17        | T17, T17A                         | No explicit status recorded                         | Planned role fences and hardware admission            |
| T18        | T18, T18A                         | No explicit status recorded                         | Planned primary login and deliberate identifiers      |
| T19        | T19, T19A                         | No explicit status recorded                         | Planned isolated codes and durable admission          |
| T20        | T20                               | No explicit status recorded                         | Planned contact proof; normal login denied            |
| T21        | T21, T21A                         | No explicit status recorded                         | Planned primary-bound MFA and durable replay          |
| T22        | T22, T22A                         | No explicit status recorded                         | Planned scoped proof and deciding checks              |
| T23        | T23, T23A                         | No explicit status recorded                         | Planned resulting-state and repair barrier            |
| T24        | T24                               | No explicit status recorded                         | Planned policy-aligned password management            |
| T25        | T25                               | No explicit status recorded                         | Planned policy-aligned first passkey                  |
| T26        | T26                               | Completed local verification, 2026-11-23            | Planned target revalidation, not historical closure   |
| T27        | T27, T27A                         | Implemented; verification in progress, 2026-11-23   | Planned maintenance/cooldown; keep email gate         |
| T28        | Aggregate: T28A, T28B, T28C       | No explicit status recorded                         | Planned distinct code families/uses                   |
| T29        | Aggregate: T29A, T29B, T29C       | No explicit status recorded                         | Planned three bounded repairs                         |
| T30        | Aggregate: T30A, T30B             | No explicit status recorded                         | Planned deletion transaction and reclaim              |
| T31        | T31                               | No explicit status recorded                         | Blocked validated fields/legal/full mobile lifecycle  |
| T32        | T32                               | No explicit status recorded                         | Planned atomic birth                                  |
| T33        | T33                               | No explicit status recorded                         | Planned fresh-only normal session                     |
| T34        | T34                               | No explicit status recorded                         | Planned six-stage shell                               |
| T35        | T35                               | No explicit status recorded                         | Planned personal/username controls                    |
| T36        | T36                               | No explicit status recorded                         | Planned selected contact/credentials                  |
| T37        | T37                               | No explicit status recorded                         | Blocked approved legal documents/fresh session        |
| T38        | Aggregate: T38A, T38B, T38C, T38D | No explicit status recorded                         | Planned four independent UI responsibilities          |
| T39        | T39                               | No explicit status recorded                         | Blocked independent physical acceptance               |
| T40        | Aggregate: T40A, T40B             | No explicit status recorded                         | Planned private snapshot and early event contract     |
| T41        | Aggregate: T41A, T41B, T41C       | No explicit status recorded                         | Planned foundation/attribution; Blocked activation    |
| T42        | T42A, T42B, T42C, T42D, T42       | No explicit status recorded                         | Planned bounded prerequisites; Blocked final release  |

Historic Phase aliases are references, not one-to-one equivalences or inherited
target completion: Task 4.1 -> T16/T16A; 4.2/4.3 -> T17A/T18A/T25/T39;
4.4 -> T21/T21A/T26; 4.5 -> T19/T19A; 4.6 -> T28A/T28B/T28C;
4.7 -> T22/T22A; 5.1 and 7.4 -> T30A/T30B/T41;
5.2-5.5 -> preserved audit/legal contracts plus T41B/T42;
6.1/6.2 -> T40A/T42C; 6.3 -> T40B/T41A;
7.1 -> preserved request-time CSP; 7.2/7.3 -> T34-T39;
7.5/7.6 -> preserved admin/legal UI and T17A/T42C. Phase 1-3 historical
infrastructure/protocol deliveries remain recorded in tasks.md, with T42A/T42B
explicitly reopening target token/IdP gaps rather than deleting that history.

## Dependency Graph and Parallel Boundaries

The Dependencies section of each executable record is the graph's authoritative
edge list: listed IDs are prerequisites, never aggregate/excluded IDs. External
approval/evidence gates are not task nodes. This topological ordering is an
implementation DAG, not numerical ordering; each row waits on earlier rows only.

| Wave | Executable Nodes                  |
| ---- | --------------------------------- |
| 0    | T01, T02, T05, T06, T07, T15, T39 |
| 1    | T03, T08, T13, T16, T34           |
| 2    | T04A, T09, T14, T40B              |
| 3    | T10, T16A, T19, T23               |
| 4    | T11, T19A                         |
| 5    | T20, T41A, T41B, T38D             |
| 6    | T17, T22                          |
| 7    | T17A                              |
| 8    | T18, T40A, T42A                   |
| 9    | T18A, T21, T22A                   |
| 10   | T21A, T27                         |
| 11   | T23A, T27A, T42B                  |
| 12   | T24, T28A, T42C                   |
| 13   | T25, T26, T28B, T28C, T42D        |
| 14   | T29A, T29B, T29C, T30A, T38A      |
| 15   | T30B, T38B, T38C                  |
| 16   | T41C                              |
| 17   | T31                               |
| 18   | T32, T35, T36                     |
| 19   | T33, T04B                         |
| 20   | T37                               |
| 21   | T42                               |

T04A supports development against disposable PostgreSQL. T18/T18A and T31/T32/T35
depend on T04A. T04B is a mandatory pre-launch dependency of T42 and carries
the actual-target preflight and separately authorized activation evidence.

T34's shell can proceed after T01 but cannot enable final submission. T38D can
proceed after T11/T13 without waiting for unrelated recovery UI.
Contract and reader work T40B/T41A precedes code/recovery/deletion writers and
has no dependency on those writers, breaking notification/recovery cycles.
T40A private snapshots are independent of early T40B security-event design.
Foundations, reference-data work, notifications and non-authoritative shells can
run in parallel only after shared authority/contracts are reviewed. UI owners
consume those contracts; they do not invent new proofs, routes or deadlines.

Security checkpoints require explicit review artifacts before downstream writes:
CP01 policy and ADR approval; CP02 SQL ownership/lock/replay/rollback design;
CP03 primary/MFA/privileged/code issuance admission; CP04 repair/barrier/cooldown;
CP05 complete password/mobile lifecycle and T27 activation; CP06 registration
and fresh-session authority; CP06b token, interactive OIDC, and privileged-consumer
authority; CP07 independent final launch review.
Documentation alone completes none of these implementation dependencies.

## Per-Record Delivery Rules

Each executable record below has exactly 15 named sections. Criteria use stable
`<task>-F01` functional, `-S01` security, `-U01` unit, `-I01` SQL/HTTP,
`-X01` concurrency/failure, `-B01` browser, `-D01` documentation and `-C01`
completion IDs; multiple outcomes in one criterion are conjunctive. Do not rename
criterion IDs when adding tests; append new IDs. N/A is justified explicitly.

Shared gate GATE01: satisfy every listed criterion with source-bound observed
results, exact commands/toolchain, counts/skips, generated/image identities where
applicable and confirmed run-owned teardown. An unperformed, skipped, cached,
different-source or uncertain gate is not passed. The integrating owner runs the
required current CI/Nx gates once on the final combined source, then only
invalidated gates again. Do not install tools, change targets, weaken assertions
or adopt inherited database credentials to obtain green evidence.

Shared gate GATE02: preserve strict authentication cookies, exact same-origin
unsafe-request protections, browser JKT/session/account/purpose/target/version
bindings, no-store/redaction, original absolute deadlines and existing tighter
budgets. Expired/spent/revoked/cancelled/unknown evidence earns no authority.
Final primary-SQL checks occur after lock waits, using the policy/data design's
global order; hashing, native/provider work stays outside long-held locks.

Shared gate GATE03: owned UI uses complete typed English/Persian messages,
explicit accessible names, logical styles and unchanged wire/clipboard bytes.
Test both locales, desktop/tablet/mobile, light/dark, keyboard/focus/status,
privacy clearing, no-JavaScript safety and structurally masked screenshots.
Physical authenticator/Windows Hello, screen reader/native zoom/bfcache,
professional Persian/security/legal, real provider receipt and deployed ingress
are independently observed gates, not virtual/synthetic substitutions.

## Executable Records

### T01

| Section                         | Requirement                                                                                                                                            |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| ID/title                        | T01 - Align the Single Registration Contract. Documentation complete, 2026-11-26.                                                                      |
| Objective                       | Reconcile the existing contract with SEC01-SEC16 without labeling deferred behavior current.                                                           |
| Scope                           | One existing service/client/form, mandatory private fields/username, one selected verified contact, password/passkey/both and approved legal versions. |
| Explicit out of scope           | Implementation, registration-v2, T12, fabricated old-account attributes or new public routes.                                                          |
| Dependencies                    | None. The owner approved CP01 on 2026-11-26. Application tasks require separate authorization.                                                         |
| Security invariants             | SEC01, SEC02, SEC13, SEC15.                                                                                                                            |
| Authorization requirements      | Contract review is not registration/action/login authority; future API operations retain GATE02.                                                       |
| Functional acceptance           | T01-F01: every current and planned request/stage/response is labeled; six stages and one final contract resolve all fields without duplicate services. |
| Security acceptance             | T01-S01: code-only birth, session by receipt/result and implicit email/mobile fallback are expressly denied.                                           |
| Unit tests                      | T01-U01: N/A for documentation contract; identify validator owners and exact request-schema tests required by T31/T32.                                 |
| Database/HTTP integration tests | T01-I01: N/A for documentation execution; map each planned birth/proof/session outcome to T31-T33 real SQL/HTTP criteria.                              |
| Concurrency/failure tests       | T01-X01: contract explicitly describes losing username races, unknown commit and failed session delivery without recreation.                           |
| Browser/accessibility tests     | T01-B01: N/A for contract-only work; map six stages to T34-T37/GATE03 without claiming observed browser acceptance.                                    |
| Documentation updates           | T01-D01: align registration/API/policy/ADR links and retain historical contract completion distinction.                                                |
| Completion criteria             | T01-C01: GATE01, reviewed request/field traceability and CP01 decision recorded; no application completion inferred.                                   |

The [canonical contract](../../docs/registration-contract.md) records the inspected
source and [request/field trace](../../docs/registration-contract.md#planned-stage-to-request-trace),
including the [future acceptance mapping](../../docs/registration-contract.md#t01-verification-trace).
This delivery is distinct from the [2026-11-15 historical audit](#h01---original-t01-t04-reports-2026-11-15).

GATE01 scope for this delivery is the final combined documentation diff,
formatting, local references and reviewer trace against the inspected source.
T01-U01, T01-I01 and T01-B01 retain their stated documentation-only N/A reasons.
Application CI, SQL/HTTP, browser, provider and deployed checks belong to separate
implementation or release work.

**CP01 decision, 2026-11-26 (Asia/Tehran).** The project owner explicitly stated
“I approve CP01” in the workspace conversation, in response to the request to
approve the delivered authentication and recovery policy, ADR 0001, architecture,
supporting documents and revised backlog. The checkout at approval was HEAD
`bdc4cf4da699ea5fa21fe8034329e3ba3c642fc6`. [ADR 0001](../../docs/adr/0001-authentication-recovery-and-security-state-authority.md#status)
records Accepted and [readiness G01](../../docs/security-testing-and-readiness.md#release-gates)
records the approval. T01-C01 is satisfied for the documentation contract and its
reviewed request and field trace. Each application task retains its own
authorization and acceptance requirements.

### T02

| Section                         | Requirement                                                                                                                                                           |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T02 - Validate Given and Family Names. Status: Planned; unchanged product definition.                                                                                 |
| Objective                       | Preserve the separate required-private-name validator, not cosmetic display-name rules.                                                                               |
| Scope                           | NFC, Arabic Yeh/Kaf folds, admitted Persian letters/hamza distinctions, ASCII-space collapse, contextual internal space/ZWNJ, 1..80 code points and 1024-byte bounds. |
| Explicit out of scope           | New alphabets, legal-name proofing, username folds, cosmetic-name changes, storage/registration activation or inferred old attributes.                                |
| Dependencies                    | None.                                                                                                                                                                 |
| Security invariants             | SEC14, SEC15; private input stays outside catalogs/diagnostics.                                                                                                       |
| Authorization requirements      | Validation earns no account/proof/session authority; storage is separately authorized by T10/T31.                                                                     |
| Functional acceptance           | T02-F01: shared given/family validation preserves allowed hamza/alef distinctions and documented separators; cosmetic NormalizeName remains unchanged.                |
| Security acceptance             | T02-S01: invalid UTF-8, mixed scripts, numerals, bidi/control/ZWJ/unsupported whitespace and invalid separators return static redacted failures, not stripped values. |
| Unit tests                      | T02-U01: table/property/fuzz seeds cover empty/space-only, 80/81 points, 1024/1025 raw bytes, aliases, NFC idempotence and forbidden separators.                      |
| Database/HTTP integration tests | T02-I01: N/A for standalone validator; T31 rejects missing/invalid required names and T10 verifies protected storage separately.                                      |
| Concurrency/failure tests       | T02-X01: concurrent deterministic normalization has identical output/no races; malformed input cannot panic or log private values.                                    |
| Browser/accessibility tests     | T02-B01: N/A for validator; T35 owns bilingual accessible controls and no cosmetic-name substitution.                                                                 |
| Documentation updates           | T02-D01: preserve confirmed-private-name contract and original 2026-11-15 evidence without retesting claims.                                                          |
| Completion criteria             | T02-C01: GATE01 and unchanged-rule fixtures pass; no signup/storage delivery asserted by validator acceptance.                                                        |

### T03

| Section                         | Requirement                                                                                                                                                             |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T03 - Reconcile Username Validation Policy. Status: Approved revision verified 2026-11-27.                                                                              |
| Objective                       | Apply the approved four-letter minimum and 40-code-point maximum through the authoritative server normalizer.                                                           |
| Scope                           | Fingerprint both explicit length bounds. Count NFC letters excluding dots and total code points including dots. Preserve the four folds and immutable namespace.        |
| Explicit out of scope           | New alphabet or normalization, prefix reservations, rename, T12, production access and policy activation.                                                               |
| Dependencies                    | T01.                                                                                                                                                                    |
| Security invariants             | SEC01, SEC09, SEC10.                                                                                                                                                    |
| Authorization requirements      | Availability is advisory and never ownership; assignment requires active authoritative policy and owner-approved artifact.                                              |
| Functional acceptance           | T03-F01: one server normalizer applies the configured NFC lengths at every assignment boundary. Lookup retains the existing security domain.                            |
| Security acceptance             | T03-S01: malformed, missing or unsafe bounds and stale policy/key fail closed. Existing input and identifier restrictions apply.                                        |
| Unit tests                      | T03-U01: verify 3/4 letters with and without dots, 40/41 total code points, NFC before counting, aliases, fingerprints and unchanged technical limits.                  |
| Database/HTTP integration tests | T03-I01: real validation, availability, registration start and final assignment agree. Stale authority denies admission, and lookup keeps the existing identity domain. |
| Concurrency/failure tests       | T03-X01: policy switch while validating cannot commit under stale policy; losing requests retain no ownership/proof.                                                    |
| Browser/accessibility tests     | T03-B01: N/A for normalization service; T35 covers explicit validation and truthful absence/no-claim states.                                                            |
| Documentation updates           | T03-D01: record owner approval and trace both superseded length rules to the authoritative registration and operations contract.                                        |
| Completion criteria             | T03-C01: GATE01 passes for the exact approved policy. T04B owns actual-target production verification and launch evidence.                                              |

**T03-C01 verification, 2026-11-26 (Asia/Tehran).** Reviewed the configured
whole-string assignment expression, NFC display and four separate security
folds, and lookup that preserves the admitted ownership domain. The PostgreSQL
regression observes a blocked assignment across a policy switch and checks
stale assignment, availability and lookup denial, absence of partial ownership,
and successful assignment under the current policy.

- The uncached `identity-api:test-username` target passed three packages. The
  uncached `identity-api:test-username-integration` target passed 557 checks
  across username and migration packages with zero failures or skips, the Go
  race detector, and confirmed run-owned service teardown. Go lint and vet
  passed with default and integration build tags.
- The release and container policy tests passed 524 checks with zero skips.
  The `test-retention-integration` run passed 355 checks in three packages with
  zero skips and confirmed teardown. The tested runtime sources and toolchain
  match this delivery.
- The portal harness ran `test-portal-integration` with directly connected,
  run-owned PostgreSQL and Redis on their Docker bridge after reproducing a
  connection refusal on the published loopback route. The full target passed
  4,577 checks across 21 packages with zero failures or skips and confirmed
  teardown using the existing test target and assertions.
- The uncached `web:test-admin-browser` target passed all assertions in both
  `en` and `fa-IR`, with confirmed teardown and unchanged source at finish.
  The Linux build used the cached Next.js 16.1.7 SWC binary verified against
  the dependency lockfile and loaded from a temporary directory.

The portal and browser gates ran against HEAD
`228548064c53de0b5f3553b1ce5a799fda08c2a4`, with unstaged diff SHA-256
`a7c2b696e3399d1ab73630a6f4e26d706b1d9000afe59e1a965fb3726930a887`.
The portal harness source fingerprint was
`33454de7bc33765b7ee3993d4629378320493b77e8b3d55c056cc3ca3e8a481a`.
Verification used Linux amd64, Node 24.21.0, npm 11.21.0, Nx 23.1.0, local
Go 1.26.11, GCC 15.2.0 and golangci-lint 2.12.2.
This dated evidence was added after runtime verification. T04A uses it as an
implementation prerequisite. T04B retains separate production approval and
actual inventory requirements.

### T04

This aggregate refers to [T04A](#t04a) for local implementation and verification
and [T04B](#t04b) for the mandatory pre-launch production gate. The original
T04-F01, T04-U01 and T04-X01 are preserved in T04A. The original security,
integration, documentation and completion criteria are covered by both records
within their respective scopes. T04-B01 remains N/A in both records for the
reasons recorded there.

### T04A

| Section                         | Requirement                                                                                                                                                                                                                                                                    |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| ID/title                        | T04A - Username Namespace Implementation and Verification. Status: Approved revision verified 2026-11-27.                                                                                                                                                                      |
| Objective                       | Verify immutable ownership and the approved initial Persian policy on isolated PostgreSQL.                                                                                                                                                                                     |
| Scope                           | Dedicated HMAC, unconditional uniqueness, canonical equivalence, protected assignment, the approved regex, length fields and six exact reservations and real isolated PostgreSQL evidence.                                                                                     |
| Explicit out of scope           | Production database access, policy activation, approved inventory claims, generated old usernames, account creation for reserved names, rename, transparent key rotation or T12.                                                                                               |
| Dependencies                    | T03.                                                                                                                                                                                                                                                                           |
| Security invariants             | SEC01, SEC10, SEC12.                                                                                                                                                                                                                                                           |
| Authorization requirements      | The owner approved the exact limits, schema and six reservations on 2026-11-27. Isolated PostgreSQL and synthetic identities are authorized.                                                                                                                                   |
| Functional acceptance           | T04A-F01: surviving active/suspended/banned/pending/deleted owners reserve the whole equivalence class; committed physical deletion alone releases it.                                                                                                                         |
| Security acceptance             | T04A-S01: restricted SQL rejects partial tuples, clear/rename/substitution and stale-key/policy writes. Existing all-absent records are represented truthfully. T04B checks mandatory assignment at the production birth and admission boundaries implemented by T32 and T18A. |
| Unit tests                      | T04A-U01: load the exact approved regex and JSON. Verify length boundaries, input syntax, four folds, no-split, HMAC separation and exact reservations.                                                                                                                        |
| Database/HTTP integration tests | T04A-I01: real restricted logins verify all-status uniqueness, immutability, the approved reservations, assignment length consistency, protected assignment and hold/purge lifetime. A disposable preflight may prove only its own snapshot.                                   |
| Concurrency/failure tests       | T04A-X01: separate connections exercise equivalent-name collision, policy switch and purge races. Rollback preserves prior ownership and leaves no partial assignment or release.                                                                                              |
| Browser/accessibility tests     | T04A-B01: N/A for SQL reservation. T35 owns public conflict feedback and disclosure checks. Shared GATE01 still applies.                                                                                                                                                       |
| Documentation updates           | T04A-D01: preserve original dated evidence, publish the approved artifact and reservation list and identify the separate pre-launch gate.                                                                                                                                      |
| Completion criteria             | T04A-C01: GATE01 passes for the exact approved source artifact, including real isolated SQL. T04B verifies the actual production target and activation evidence.                                                                                                               |

The 2026-11-26 record below applies to pre-approval policy ID
`dea9253a-a92c-4ae6-adac-d1ccd88527e2`. The registration contract now links its
approved successor.

**T04A verification, 2026-11-26 (Asia/Tehran).** The tested candidate is the
exact regex and JSON linked from the [registration contract](../../docs/registration-contract.md#approved-initial-username-assignment-policy).
It exercises the existing assignment path, including normalized aliases,
dedicated HMAC, unconditional uniqueness, immutability, policy/assignment races,
and rollback. The restricted-role candidate test rejected all six reservations
and their aliases, showed no partial ownership and admitted a distinct dotted
name. Read-only preflight observed zero accounts before fixture account
creation and one claimed account after assignment. Those counts describe the disposable database only.

- Uncached Nx `identity-api:test-username` passed three packages. Normal and
  integration-tagged `identity-api:lint` and `identity-api:vet` passed. The
  release-policy script tests passed 524 checks with zero failures or skips.
- Uncached `identity-api:test-username-integration` passed 559 checks in two
  packages with the Go race detector. The official harness targets
  `identity-api:test-retention-integration` and `identity-api:test-portal-integration`
  passed 355 checks in three packages and 4,579 in 21 packages, respectively.
  All three disposable service runs had zero failed or skipped tests and
  confirmed teardown. The local username and portal harnesses routed to the
  run-owned PostgreSQL and Redis bridge addresses with the same test targets.
- The uncached Nx `web:test-admin-browser` target passed all assertions in
  `en` and `fa-IR` with matching worktree identities and completed teardown.
  Two earlier attempts stopped on a disposable login fixture exit and a
  numeric match in the audit-signer log privacy assertion, respectively.
  Both completed teardown. The passing rerun used the unchanged target and
  a lockfile-verified cached Linux Next.js 16.1.7 SWC binary.
- Formatting, combined diff review and the references-only documentation checker
  passed. The checker verified 65 executable records, 520 criteria and 287
  dependency edges. The original historical evidence was preserved byte-for-byte.

The runtime runs used HEAD `2a8c6903018f0cb8db1a12180f53303defbbec88` plus the
T04A/T04B working-tree edits, including the untracked proposal and unit test.
The three SQL reports agree on source SHA-256
`2fb5b32ff9866bad008cb90abe1386894575197f01387151ba29a35354f66ccf`
and their generated outputs. Verification used Linux amd64, Node 24.21.0,
npm 11.21.0, Nx 23.1.0, Go 1.26.11, GCC 15.2.0 and golangci-lint 2.12.2.
This dated record was added after runtime verification. Production approval,
key provenance and actual-target evidence remain under T04B.

**Owner decision, 2026-11-27 (Asia/Tehran).** The project owner explicitly
approved configurable NFC counts of four admitted letters minimum (separator
dots excluded) and 40 total Unicode code points maximum (separator dots
included), the policy JSON schema revision, and the six exact canonical
reservations listed in the [registration contract](../../docs/registration-contract.md#approved-initial-username-assignment-policy).
This decision supersedes the historical 7–40 canonical-code-point requirement
and the later unbounded business-length policy. It authorizes implementation,
testing and documentation for T03 and T04A. T04B retains separate authorization
for actual-target inventory, installation, activation and deployment.

**T03-C01 and T04A-C01 revised verification, 2026-11-27 (Asia/Tehran).** The exact
approved artifact is `e9fa486e-db81-4dd0-8225-1e99e5399c1d`. Its canonical
SHA-256 fingerprint is
`a2a74767ae7f42bdcd7e08ab6e65e21985f1dd9130e7d989b3ecf2220ad588cb`.
The unit, PostgreSQL and registration HTTP/browser fixtures used the approved
limits and reservation list. The checks covered NFC before counting, aliases,
boundary lengths, fail-closed JSON, fingerprint changes, preserved lookup,
restricted-store availability and final assignment, uniqueness, rollback and
a blocked waiter across a length-policy switch.

- Fresh Nx `identity-api:test` and `identity-api:test-race` each passed 69 Go
  packages. `identity-api:test-username` passed three packages. Normal and
  integration-tagged Go lint and vet passed. The release-policy scripts passed
  524 tests with zero skips.
- `identity-api:test-username-integration` passed 577 race checks in two packages.
  The owned-service harnesses passed 4,604 portal checks in 21 packages, 355
  retention checks in three packages, 161 registration race checks and 3,530
  security database checks in 22 packages. All runs had zero skips and confirmed
  teardown. The security database rerun used matching PostgreSQL 16 clients
  from its run-owned container.
- Uncached Nx `web:test-admin-browser` passed in `en` and `fa-IR` with matching
  worktree identities and confirmed teardown. Uncached
  `web:test-registration-browser` passed 36 checks with four journeys per
  locale on the checksum-verified API image
  `sha256:0b2fb6419dfc0b5f5e79d8ee88f05c722111af0738d13b5e4784f69d2b81e271`.
  The manifest verifier passed and teardown completed. Earlier attempts stopped
  on inherited debug configuration and a Persian browser evaluation. The
  passing rerun used the same image and unchanged assertions.
- Packaged API smoke, registration Compose and the full Compose HTTPS, restart,
  persistence and teardown checks passed. Local containers supplied disposable
  services and simulated providers. Formatting, combined diff review and the
  references-only documentation checker passed.

Runtime evidence used HEAD `2a8c6903018f0cb8db1a12180f53303defbbec88` plus the
combined staged and working-tree edits. SQL, the API manifest and registration
browser agreed on source SHA-256
`8fd625abce339164273b1ef8f46443a110ca2fb9c15e6fae05c2815a49049021`
and generated fingerprints. Verification used Linux amd64, Node 24.21.0,
npm 11.21.0, Nx 23.1.0, Go 1.26.11, GCC 15.2.0 and golangci-lint 2.12.2.
This dated record follows runtime verification. T04B still requires separately
authorized actual-target inventory, key provenance and activation evidence.

### T04B

| Section                         | Requirement                                                                                                                                                                                                                                                                            |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T04B - Production Username Namespace Preflight and Activation. Status: Blocked by production authorization and evidence.                                                                                                                                                               |
| Objective                       | Verify the actual intended production namespace and record explicit activation clearance before public launch.                                                                                                                                                                         |
| Scope                           | Approved regex/policy/reserved names, authenticated key provenance, scoped read-only production inventory, protected report, fenced installation and activation under separate authorization.                                                                                          |
| Explicit out of scope           | Speculative legacy compatibility, inferred empty baseline, public reports, deletion/rename/backfill/merge, or implied installation, activation or deployment permission.                                                                                                               |
| Dependencies                    | T04A, T18A, T32 and verification of the approved artifact, key provenance, scoped read-only access and a protected evidence destination.                                                                                                                                               |
| Security invariants             | SEC01, SEC09, SEC10, SEC12, SEC13.                                                                                                                                                                                                                                                     |
| Authorization requirements      | Verify the owner-approved artifact ID, fingerprint, length limits and exact six reservations on the authorized target. Inventory uses a restricted read-only identity. Installation, activation and deployment each require separate owner authorization.                              |
| Functional acceptance           | T04B-F01: verify the actual intended database and schema, exact approved length fields, regex and six reservations, and key provenance. A newly provisioned baseline needs a complete observed zero-account inventory.                                                                 |
| Security acceptance             | T04B-S01: unknown, incomplete, colliding, inconsistent or unreadable inventory blocks activation. Preserve real data, equivalent names and protected security guarantees. Restrict the report outside the public repository and keep production keys in the approved custody boundary. |
| Unit tests                      | T04B-U01: N/A for the operational gate. T04A owns configuration and algorithm tests.                                                                                                                                                                                                   |
| Database/HTTP integration tests | T04B-I01: complete a bounded read-only snapshot on the authorized target and record source/schema, policy/key identity, no-split results and actual counts in protected evidence. Verify all production human birth and admission paths require an assigned username before reopening. |
| Concurrency/failure tests       | T04B-X01: drain/fence writers and revalidate the full actual inventory before separately authorized activation. Failed or uncertain cutover retains last proven safe authority and keeps affected writers fenced until reconciled.                                                     |
| Browser/accessibility tests     | T04B-B01: N/A for restricted operator and database checks. T35 owns public conflict feedback and T42 owns final release acceptance.                                                                                                                                                    |
| Documentation updates           | T04B-D01: record review and operation decisions and non-sensitive outcome references. Retain protected inventory and collision reports outside the public repository.                                                                                                                  |
| Completion criteria             | T04B-C01: verify the approved artifact and key provenance, complete actual-target no-split preflight, store protected evidence and observe separately authorized activation. Mandatory before public launch under T42.                                                                 |

### T05

| Section                         | Requirement                                                                                                                                                   |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T05 - Validate Date-Only Birthdays. Status: Planned; unchanged product definition.                                                                            |
| Objective                       | Preserve one civil Gregorian/Jalali birthday pair, never a timestamp or inferred age.                                                                         |
| Scope                           | Explicit gregorian/jalali input; allowed three digit scripts; pinned integer converter; 1900-01-01 through server Tehran today inclusive.                     |
| Explicit out of scope           | Alternate converters, unlimited calendar certification, timezone-derived DOB timestamps, age policy, UI defaults or inferred old birthdays.                   |
| Dependencies                    | None.                                                                                                                                                         |
| Security invariants             | SEC14, SEC15.                                                                                                                                                 |
| Authorization requirements      | Server supplies one trusted instant/Tehran civil date; client time/preference is not admission authority.                                                     |
| Functional acceptance           | T05-F01: selected-calendar leap/month validity and reverse-checked equivalent ASCII pairs match pinned/reviewed fixtures.                                     |
| Security acceptance             | T05-S01: malformed grammar, unsupported calendar/digits, future/lower-bound breach or unusable clock returns a zero pair and static redacted error.           |
| Unit tests                      | T05-U01: pinned upstream/authority-derived anchors, all documented script mixtures, leap ends, civil round trips, midnight/DST and unusable-clock seeds pass. |
| Database/HTTP integration tests | T05-I01: N/A for standalone conversion; T10/T31 reject independently supplied mismatching pairs and store only server-derived values.                         |
| Concurrency/failure tests       | T05-X01: deterministic concurrent conversion and clock failure cannot panic, roll dates over or expose DOB in errors.                                         |
| Browser/accessibility tests     | T05-B01: N/A for validator; T35/T37 test explicit input calendar and both inert date-only representations under preference changes.                           |
| Documentation updates           | T05-D01: preserve converter license/pin, supported range/reference caveats and dated acceptance counts.                                                       |
| Completion criteria             | T05-C01: GATE01 and unchanged calendar contract pass; no physical/official-calendar certification or signup integration inferred.                             |

### T06

| Section                         | Requirement                                                                                                                                  |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T06 - Require Explicit Gender. Status: Planned; unchanged product definition.                                                                |
| Objective                       | Preserve exact female/male input with no preselected or inferred value.                                                                      |
| Scope                           | Shared string-backed Gender validation, static errors and required final-registration field.                                                 |
| Explicit out of scope           | New gender product values, aliases/case folding/coercion, default, backfill or unrelated profile-read changes.                               |
| Dependencies                    | None.                                                                                                                                        |
| Security invariants             | SEC14, SEC15.                                                                                                                                |
| Authorization requirements      | Validation is not permission to disclose private gender or modify an account.                                                                |
| Functional acceptance           | T06-F01: exactly female or male succeeds; absence stays structurally absent outside required new-registration input.                         |
| Security acceptance             | T06-S01: missing, padded, localized, numeric or case-altered values return zero Gender/static error without inference.                       |
| Unit tests                      | T06-U01: exact valid values and all unsupported/malformed/fuzz seed cases pass unchanged.                                                    |
| Database/HTTP integration tests | T06-I01: N/A for standalone validator; T31 rejects missing new-registration gender and T10/T11 preserve absent existing attributes honestly. |
| Concurrency/failure tests       | T06-X01: concurrent calls have no mutable shared default; malformed input cannot panic or log private input.                                 |
| Browser/accessibility tests     | T06-B01: N/A for validator; T35 owns explicit keyboard-accessible selection with no default in either locale.                                |
| Documentation updates           | T06-D01: preserve confirmed rule and original local evidence; no inferred migration population.                                              |
| Completion criteria             | T06-C01: GATE01 and unchanged-rule tests pass independently of UI/storage delivery.                                                          |

### T07

| Section                         | Requirement                                                                                                                                                   |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T07 - Export IranData Safely. Status: Blocked by source-access/data-rights authorization.                                                                     |
| Objective                       | Preserve observed geography source identities using a separately authorized read-only export.                                                                 |
| Scope                           | Local SQL Server dot instance, Windows integrated authentication, IranData dbo.CenterType/dbo.CityData, checksummed complete source export.                   |
| Explicit out of scope           | Source writes, source-schema changes, shared data access in this documentation task, dataset redistribution or production dependency on developer SQL Server. |
| Dependencies                    | None; external named source access and usage/redistribution permission.                                                                                       |
| Security invariants             | SEC14, SEC16; source labels/provenance are protected data, not test artifacts.                                                                                |
| Authorization requirements      | SELECT-only scoped identity; owner approval names exact source and permissible output destination.                                                            |
| Functional acceptance           | T07-F01: export preserves original IDs, types, labels and hierarchy with hashes/counts and explicit completeness assertion.                                   |
| Security acceptance             | T07-S01: attempted INSERT/UPDATE/DELETE/DDL is denied; unavailable/partial source is failure, never fabricated empty success.                                 |
| Unit tests                      | T07-U01: synthetic export encoding/checksum/count/duplicate-ID fixtures pass without committing real source records.                                          |
| Database/HTTP integration tests | T07-I01: separately authorized actual read-only source/export comparison proves SELECT scope; no HTTP endpoint is added.                                      |
| Concurrency/failure tests       | T07-X01: interrupted/inconsistent export is rejected as incomplete and cannot replace an approved complete snapshot.                                          |
| Browser/accessibility tests     | T07-B01: N/A for operator export; no browser or public dataset artifacts.                                                                                     |
| Documentation updates           | T07-D01: record source-rights/access provenance, hashes and approved storage; do not publish private labels/results.                                          |
| Completion criteria             | T07-C01: GATE01 and actual scoped source/right evidence; synthetic fixtures do not satisfy source authorization.                                              |

### T08

| Section                         | Requirement                                                                                                                                                            |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T08 - Import Geography into PostgreSQL. Status: Planned; unchanged product definition.                                                                                 |
| Objective                       | Preserve immutable complete catalog revisions and original source identities.                                                                                          |
| Scope                           | Transactional repeatable importer, explicit checked complete manifest, active-pointer guard, retired identity/history preservation and restricted importer/read roles. |
| Explicit out of scope           | Dataset-rights approval, source re-export, runtime DDL, partial snapshots, account storage or registration stage changes.                                              |
| Dependencies                    | T07.                                                                                                                                                                   |
| Security invariants             | SEC09, SEC10, SEC14.                                                                                                                                                   |
| Authorization requirements      | Separate importer/migrator/read-only check identities; import requires exact reviewed plan/retirement digest and admitted base revision.                               |
| Functional acceptance           | T08-F01: identical import is a true no-op; changed complete snapshot commits all rows/pointer once and preserves retired references.                                   |
| Security acceptance             | T08-S01: cycles, missing parents, duplicate IDs/types, wrong province ancestry and changed plan/base are denied without partial writes.                                |
| Unit tests                      | T08-U01: strict JSON/UTF-8/number/bounds/hierarchy, variable depth and type-5-under-type-5 fixtures pass.                                                              |
| Database/HTTP integration tests | T08-I01: real restricted importer/read logins prove allowed grants and denied deletion/trigger/schema/account access; historical same-revision ancestry resolves.      |
| Concurrency/failure tests       | T08-X01: concurrent identical/different imports and migration exclusion preserve one active complete revision; cancellation/unknown commit never rewrites history.     |
| Browser/accessibility tests     | T08-B01: N/A for operator importer; T09 owns read selector behavior.                                                                                                   |
| Documentation updates           | T08-D01: preserve immutable catalog/manifest/rights contract and canonical packaged-migration link, not obsolete installation numbers.                                 |
| Completion criteria             | T08-C01: GATE01 with complete snapshot/restricted-role evidence; catalog import alone does not enable registration.                                                    |

### T09

| Section                         | Requirement                                                                                                                                                      |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T09 - Search Provinces and Localities. Status: Planned; unchanged product definition.                                                                            |
| Objective                       | Serve bounded IR geography selections from PostgreSQL with truthful source labels.                                                                               |
| Scope                           | Required province, optional related locality, duplicate-label disambiguation, exact decimal IDs/revision, historical retired lookups and bilingual selector.     |
| Explicit out of scope           | Fabricated translations, renaming source type to city, source redistribution, private location persistence or final registration wiring.                         |
| Dependencies                    | T08.                                                                                                                                                             |
| Security invariants             | SEC09, SEC14, SEC15.                                                                                                                                             |
| Authorization requirements      | Anonymous reads are bounded/rate-limited, not account/proof authority; new selections use active server snapshot.                                                |
| Functional acceptance           | T09-F01: IR-only ancestry and original labels distinguish duplicates; saved retired IDs resolve under their actual historical revision.                          |
| Security acceptance             | T09-S01: wrong country/province/revision, oversized page/query and unavailable catalog return denial/unavailability, never silently empty or reparented success. |
| Unit tests                      | T09-U01: prefix normalization, cursor/decimal bounds, duplicate-label and active-versus-retired fixtures pass.                                                   |
| Database/HTTP integration tests | T09-I01: bounded real SQL/HTTP browse/search/lookup uses one snapshot; measure required warmed query performance without weakening ceilings.                     |
| Concurrency/failure tests       | T09-X01: catalog change invalidates old cursor explicitly; SQL/limiter outage denies reads rather than inventing an empty catalog.                               |
| Browser/accessibility tests     | T09-B01: GATE03 selector supports keyboard/prefix/clear/duplicate labels and catalog-changed restart without leaking private selections.                         |
| Documentation updates           | T09-D01: preserve source labels/types, exact IDs/revisions, selector contract and unresolved rights/manual review.                                               |
| Completion criteria             | T09-C01: GATE01/GATE03 and bounded/performance evidence; source access is not a production request dependency.                                                   |

### T10

| Section                         | Requirement                                                                                                                                         |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T10 - Store Protected Private Attributes. Status: Planned; unchanged product definition.                                                            |
| Objective                       | Preserve account/purpose-authenticated private data without duplicate plaintext fields.                                                             |
| Scope                           | Names, atomic birthday pair, gender and server-validated location/catalog revision; username display remains its sole protected assignment source.  |
| Explicit out of scope           | New product rules, duplicate username/DOB/gender/location plaintext, legacy inference, dataset changes or automatic registration integration.       |
| Dependencies                    | T02, T05, T06, T09.                                                                                                                                 |
| Security invariants             | SEC10, SEC14.                                                                                                                                       |
| Authorization requirements      | Normal live bound account and exact private-edit authority; encryption validates account/purpose/revision, not ciphertext presence alone.           |
| Functional acceptance           | T10-F01: protected payload contains one server-derived birthday pair and exact location revision/ancestry; absent values stay absent.               |
| Security acceptance             | T10-S01: cross-account/purpose/revision ciphertext, invalid pair/location and plaintext fallback are denied without private diagnostics.            |
| Unit tests                      | T10-U01: envelope substitution/tamper/version bounds and unchanged validator vectors pass.                                                          |
| Database/HTTP integration tests | T10-I01: real restricted SQL writes persist only protected fields and preserve independent public display/username storage.                         |
| Concurrency/failure tests       | T10-X01: encryption or SQL failure rolls back private data/revision/intent together; concurrent catalog change cannot authorize stale new location. |
| Browser/accessibility tests     | T10-B01: N/A for protected persistence; T38D owns actual private editor/GATE03.                                                                     |
| Documentation updates           | T10-D01: document actual encryption/revision/location evidence without changing signed event formats or declaring signup fields mounted.            |
| Completion criteria             | T10-C01: GATE01 with substitution/privacy rollback evidence; historical source capability is not new final target acceptance.                       |

### T11

| Section                         | Requirement                                                                                                                                      |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| ID/title                        | T11 - Read and Edit Private Attributes. Status: Planned; unchanged product definition.                                                           |
| Objective                       | Preserve exact revision optimistic concurrency and atomic metadata intent.                                                                       |
| Scope                           | Existing authenticated GET/PATCH, exact decimal revisions, independent private/public data, real edits versus no-ops and atomic birthday update. |
| Explicit out of scope           | Product validator changes, JS-number revisions, profile-based authentication, username rename/claim or new event format.                         |
| Dependencies                    | T10.                                                                                                                                             |
| Security invariants             | SEC10, SEC14.                                                                                                                                    |
| Authorization requirements      | Live account/session/JKT and exact expected revision; private fields require existing scoped grants/status policy.                               |
| Functional acceptance           | T11-F01: real edit commits one revision and one metadata intent; no-op changes neither data, revision nor intent.                                |
| Security acceptance             | T11-S01: stale revision, inactive/deleted privacy status, cross-account request or unauthorized field disclosure is denied.                      |
| Unit tests                      | T11-U01: decimal values above JS precision, normalization-equivalent no-op and birthday-pair equality vectors pass.                              |
| Database/HTTP integration tests | T11-I01: GET/PATCH real SQL returns one consistent snapshot; no private values enter metadata-only events.                                       |
| Concurrency/failure tests       | T11-X01: two edits at one revision have one winner; audit/outbox/SQL failure rolls back and unknown result is not replayed.                      |
| Browser/accessibility tests     | T11-B01: N/A for API service; T38D tests conflicts preserving ordinary unsaved drafts and clearing private data on session changes.              |
| Documentation updates           | T11-D01: preserve exact revision/no-op contract and actual readers; map T40A snapshot obligations.                                               |
| Completion criteria             | T11-C01: GATE01 and exact snapshot/no-op/concurrency evidence, without upgrading historical acceptance.                                          |

### T13

| Section                         | Requirement                                                                                                                            |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T13 - Represent Absent Email Truthfully. Status: Planned.                                                                              |
| Objective                       | Preserve actual optional-email readers and remove fabricated-email assumptions only after compatible reader inventory.                 |
| Scope                           | Models/adapters/bootstrap/presentation/SQL nullable email, optional protobuf field and current present/absent privacy behavior.        |
| Explicit out of scope           | Fabricated mailbox/empty digest, protobuf field removal, phone-only launch, T27 gate retirement or silent notification fallback.       |
| Dependencies                    | T01.                                                                                                                                   |
| Security invariants             | SEC01, SEC12, SEC14.                                                                                                                   |
| Authorization requirements      | Email absence is data, not identity fallback; primary-email identification still requires current verified unique association.         |
| Functional acceptance           | T13-F01: NULL/typed absence flows through existing HTTP/gRPC/storage readers; present email bytes and wire presence remain compatible. |
| Security acceptance             | T13-S01: no empty-email blind index, UUID-shaped CLIENT-to-human substitution or placeholder identity is admitted.                     |
| Unit tests                      | T13-U01: present/NULL/empty-invalid and optional protobuf presence vectors pass across inventoried adapters.                           |
| Database/HTTP integration tests | T13-I01: real present/mobile-only synthetic rows produce truthful minimized reads and no fabricated audit attribution.                 |
| Concurrency/failure tests       | T13-X01: reader-first/schema transition and rollback preserve actual stored/queued contracts; incompatible reader prevents activation. |
| Browser/accessibility tests     | T13-B01: GATE03 truthful absent email/name states expose no inferred identity and retain technical LTR bytes.                          |
| Documentation updates           | T13-D01: inventory actual optional readers and link T41C full lifecycle activation gate; do not erase current nullable support.        |
| Completion criteria             | T13-C01: GATE01/GATE03 and compatible reader evidence; mobile-only production stays blocked on T41C.                                   |

### T14

| Section                         | Requirement                                                                                                                                          |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T14 - Persist Exact Contact Verification Evidence. Status: Planned.                                                                                  |
| Objective                       | Treat ownership as server-recorded destination-specific provenance, not account status or populated text.                                            |
| Scope                           | Exact canonical email/mobile association, proof method/time, current verification state and invalidation on change/removal.                          |
| Explicit out of scope           | Provenance backfill, assuming old unknown history eligible, cooldown implementation T27A, login by mobile or new contact schema in a second service. |
| Dependencies                    | T13.                                                                                                                                                 |
| Security invariants             | SEC01, SEC08, SEC09, SEC10.                                                                                                                          |
| Authorization requirements      | Verification proves only its account/channel/destination/purpose; new ownership cannot authorize changing old contact.                               |
| Functional acceptance           | T14-F01: each verified current association carries original server time/method; initial registration provenance is explicit and immutable.           |
| Security acceptance             | T14-S01: absent/unknown/stale/mismatched provenance cannot identify by email or authorize contact/recovery operations.                               |
| Unit tests                      | T14-U01: canonical destination/method/channel/account substitution, absent evidence and exact timestamp vectors pass.                                |
| Database/HTTP integration tests | T14-I01: registration/current maintenance records evidence transactionally; existing email_link/email_otp/sms_otp readers remain valid.              |
| Concurrency/failure tests       | T14-X01: concurrent association replacement/removal invalidates old proofs at deciding commit; replay never restamps verification time.              |
| Browser/accessibility tests     | T14-B01: N/A for provenance storage; T36/T38B/T38C render verified/unknown/cooling states without granting authority.                                |
| Documentation updates           | T14-D01: record provenance/invalidation contracts and distinguish T27A recovery eligibility from simple verification.                                |
| Completion criteria             | T14-C01: GATE01 with real exact-destination proof evidence; populated fixture contacts are not proof.                                                |

### T15

| Section                         | Requirement                                                                                                                                                                                                               |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T15 - Bound Password Policy and Hashing. Status: Planned; unchanged product definition.                                                                                                                                   |
| Objective                       | Preserve exact-byte password creation/verification and finite native hashing admission.                                                                                                                                   |
| Scope                           | At least 15 Unicode code points, at most 1024 UTF-8 bytes, reviewed local compromised choices, shared Argon2 admission and actual stored-hash verification.                                                               |
| Explicit out of scope           | Trim/NFC/password localization, high-entropy-code Argon2, arbitrary policy tuning or hypothetical compatibility hashes.                                                                                                   |
| Dependencies                    | None.                                                                                                                                                                                                                     |
| Security invariants             | SEC02, SEC10, SEC14, SEC15.                                                                                                                                                                                               |
| Authorization requirements      | Password verification alone earns only the appropriate primary/purpose evidence; full policy still controls normal authority.                                                                                             |
| Functional acceptance           | T15-F01: spaces/Unicode bytes remain exact, creation bounds/blocklist apply, existing stored hashes verify without new-creation-strength rejection.                                                                       |
| Security acceptance             | T15-S01: oversized/invalid/compromised new input and exhausted admission fail boundedly; no secret logging or unbounded hash work.                                                                                        |
| Unit tests                      | T15-U01: 14/15 points, 1024/1025 bytes, spaces, Unicode exactness, blocklist and stored-hash parameter/serialization vectors pass.                                                                                        |
| Database/HTTP integration tests | T15-I01: N/A for the standalone hasher. T18-I01, T24-I01, T29A-I01, and T32-U01 observe the shared exact-byte verifier and admission. T32-U01 observes that no unkeyed password-bearing completion fingerprint is stored. |
| Concurrency/failure tests       | T15-X01: cancellation retains hash slot until native computation actually finishes; overload stays within configured finite concurrency.                                                                                  |
| Browser/accessibility tests     | T15-B01: N/A for hasher; T36/T38A support paste/password managers and client-only confirmation without byte normalization.                                                                                                |
| Documentation updates           | T15-D01: preserve exact-byte contract and explicit NIST NFC SHOULD divergence, not a false compliance claim.                                                                                                              |
| Completion criteria             | T15-C01: GATE01 and finite concurrency/exact-byte evidence; no stronger account assurance inferred from password length.                                                                                                  |

### T16

| Section                         | Requirement                                                                                                                                                               |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T16 - Specify Truthful Earned Authentication Evidence. Status: Planned.                                                                                                   |
| Objective                       | Separate primary, actual UV, actual TOTP, consumed backup and original authentication time.                                                                               |
| Scope                           | Extend existing evidence/session contracts with primary credential/method/time, independent completion, versions/JKT/deadlines and distinct normal/preauth/repair states. |
| Explicit out of scope           | Inventory-as-authentication, reused TOTP booleans for backup, new session service or SQL implementation T16A.                                                             |
| Dependencies                    | T01.                                                                                                                                                                      |
| Security invariants             | SEC02, SEC03, SEC04, SEC07, SEC09.                                                                                                                                        |
| Authorization requirements      | Only verified eligible primary plus complete current required policy earns normal authority; unknown evidence is denied, never fabricated.                                |
| Functional acceptance           | T16-F01: actual UV/TOTP/backup remain independently represented and original auth_time is unchanged by refresh/preferences.                                               |
| Security acceptance             | T16-S01: enrollment UV/UP/factor inventory/contact-only/backup-only cannot become old-primary evidence or a normal session.                                               |
| Unit tests                      | T16-U01: exhaustive evidence-policy matrix includes UV with/without required MFA, backup with TOTP=false and unknown-field denials.                                       |
| Database/HTTP integration tests | T16-I01: typed normal/preauth/restricted profiles cannot bootstrap or use an inappropriate route; existing actual readers are inventoried.                                |
| Concurrency/failure tests       | T16-X01: serialization/version mismatch fails closed; session renewals do not refresh factor times or convert partial evidence.                                           |
| Browser/accessibility tests     | T16-B01: N/A for evidence contract; T38A/T38B separately test normal versus restricted bootstrap.                                                                         |
| Documentation updates           | T16-D01: update policy/data/API/client evidence definitions and compatibility inventory for actual stored records.                                                        |
| Completion criteria             | T16-C01: GATE01 and CP02 evidence schema review; contract alone does not complete SQL authority T16A.                                                                     |

### T16A

| Section                         | Requirement                                                                                                                                                    |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T16A - Persist SQL-Earned Session Authority. Status: Planned.                                                                                                  |
| Objective                       | Make primary PostgreSQL the deciding authority for evidence, normal/preauth/session issuance, expiry and revocation.                                           |
| Scope                           | Existing session/login services, durable evidence/session IDs/versions/deadlines, primary-only reads, full-policy issuance and fresh-login barrier-reset hook. |
| Explicit out of scope           | Redis authority, replica-earned evidence, SQL+Redis atomicity, token prerequisite T42A or automatic reauthentication after unknown commit.                     |
| Dependencies                    | T16, T40B.                                                                                                                                                     |
| Security invariants             | SEC02, SEC03, SEC07, SEC09, SEC10, SEC11.                                                                                                                      |
| Authorization requirements      | Recheck earned SQL facts, account/category/policy/session/JKT and absolute bounds in issuance transaction after locks; GATE02.                                 |
| Functional acceptance           | T16A-F01: durable normal/preauth states survive restart; normal issuance occurs only after complete policy and genuinely fresh login may invoke T23A reset.    |
| Security acceptance             | T16A-S01: forged/lost Redis evidence, stale SQL replica, absent UV/required MFA and revoked/expired session never grant authority or clear a barrier.          |
| Unit tests                      | T16A-U01: evidence combinations and exact earliest-deadline/revocation/time semantics match SEC02/SEC03; backup never restamps TOTP.                           |
| Database/HTTP integration tests | T16A-I01: real SQL/HTTP across two replicas proves one issuance, live revocation and normal versus preauth route denial.                                       |
| Concurrency/failure tests       | T16A-X01: lock-wait expiry, concurrent role/revocation and Redis flush/corruption/SQL outage deny; ambiguous commit does not reissue evidence/session.         |
| Browser/accessibility tests     | T16A-B01: GATE03 bootstrap rejects restricted/preauth/stale cookie and same-key wrong-subject responses; no preference-triggered session renewal.              |
| Documentation updates           | T16A-D01: document primary SQL tables/roles/lock order, non-authoritative cache and source-bound failover assumptions.                                         |
| Completion criteria             | T16A-C01: GATE01/GATE02/GATE03, CP02 approval and forged-cache/one-winner evidence; failover safety still requires T42D.                                       |

### T17

| Section                         | Requirement                                                                                                                                                                                                                                              |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T17 - Fence Role Changes and Session Use. Status: Planned.                                                                                                                                                                                               |
| Objective                       | Prevent promotion/category change from upgrading already earned low-assurance authority.                                                                                                                                                                 |
| Scope                           | Authoritative account/MFA/category checks at issuance and relevant HTTP/gRPC/token use; real-change version fences versus no-op role updates.                                                                                                            |
| Explicit out of scope           | Role CRUD expansion, support bypass, inherited privileged assurance or hardware verification T17A.                                                                                                                                                       |
| Dependencies                    | T16A, T23, T40B, T41A.                                                                                                                                                                                                                                   |
| Security invariants             | SEC03, SEC04, SEC07, SEC09, SEC10.                                                                                                                                                                                                                       |
| Authorization requirements      | Live authoritative policy regardless of disabled admin HTTP feature; actual earned evidence must satisfy the current operation/category.                                                                                                                 |
| Functional acceptance           | T17-F01: real role change fences stale account/category/session authority and commits metadata/notification intent; no-op leaves versions/sessions/intents unchanged. T28A later integrates saved-family revocation into this same mutation transaction. |
| Security acceptance             | T17-S01: promoted password/UP/UV-without-required-backup sessions cannot access privileged APIs/tokens; role labels alone confer no assurance.                                                                                                           |
| Unit tests                      | T17-U01: ordinary/promoted/demoted/no-op and independent-MFA policy matrices include consumer recovery denial.                                                                                                                                           |
| Database/HTTP integration tests | T17-I01: real role/policy/session changes fence HTTP and gRPC even with admin feature disabled; no-op transaction leaves intent/version unchanged.                                                                                                       |
| Concurrency/failure tests       | T17-X01: issuance/mutation versus promotion/demotion has serialized admission; stale policy/cache and unknown update outcome never upgrade authority.                                                                                                    |
| Browser/accessibility tests     | T17-B01: GATE03 capability loss clears privileged content without inventing assurance or signing out unrelated valid ordinary authority.                                                                                                                 |
| Documentation updates           | T17-D01: map role/category use boundaries, code-family revocation and consumer obligations to T17A/T42C.                                                                                                                                                 |
| Completion criteria             | T17-C01: GATE01/GATE02/GATE03 with no-op versus real-change and disabled-feature boundary evidence.                                                                                                                                                      |

### T17A

| Section                         | Requirement                                                                                                                                              |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T17A - Verify Privileged Hardware and Independent Backup. Status: Planned; activation awaits approved admission policy.                                  |
| Objective                       | Replace passkey-or-TOTP eligibility with verified hardware-backed phishing-resistant UV plus separately enrolled independent backup.                     |
| Scope                           | Approved attestation/provenance admission, evidence schema, independent backup enrollment and issuance/use fences for privileged accounts.               |
| Explicit out of scope           | AAGUID/UV/transport/backup-flags as hardware proof, consumer ARC recovery, backup downgrade, support/admin override or new total-loss procedure.         |
| Dependencies                    | T17, T16A; external approved hardware/backup policy and actual device evidence.                                                                          |
| Security invariants             | SEC02, SEC03, SEC04, SEC09.                                                                                                                              |
| Authorization requirements      | Fresh verified admitted hardware UV and required independent evidence at privileged issuance/use; unavailable/unknown hardware or backup is denied.      |
| Functional acceptance           | T17A-F01: privileged evidence identifies admitted hardware provenance and separately enrolled backup rather than credential labels/inventory counts.     |
| Security acceptance             | T17A-S01: software/synced/unknown-provenance authenticator, missing backup, consumer ARC/backup downgrade and all total-loss override routes are denied. |
| Unit tests                      | T17A-U01: hardware attestation/provenance/independence acceptance and unknown/revoked policy vectors pass without equating UV to hardware.               |
| Database/HTTP integration tests | T17A-I01: real privileged HTTP/gRPC/session/token boundary fixtures require both admitted properties; ordinary policy remains separate.                  |
| Concurrency/failure tests       | T17A-X01: backup removal/hardware revocation/role promotion while waiting invalidates authority; stale cache cannot retain privileged admission.         |
| Browser/accessibility tests     | T17A-B01: GATE03 denial is truthful; independent physical security-key/Windows Hello evidence is recorded separately from virtual tests.                 |
| Documentation updates           | T17A-D01: record hardware policy/provenance and backup independence, explicit total-loss blocker and no AAL3/FAL claim.                                  |
| Completion criteria             | T17A-C01: GATE01/GATE02/GATE03, CP03 approval and actual admitted hardware/backup evidence; no unreviewed privileged recovery lane.                      |

### T18

| Section                         | Requirement                                                                                                                                                                                             |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T18 - Authenticate an Eligible Primary. Status: Planned.                                                                                                                                                |
| Objective                       | Preserve intentional username/password login and require actual UV for every passkey authentication.                                                                                                    |
| Scope                           | Existing login/session/browser-proof infrastructure, eligible exact-byte password or passkey assertion, bounded preauth for required independent MFA.                                                   |
| Explicit out of scope           | Contact-only normal login, mobile identifier, implicit fallback, assertion UP acceptance or automatic session by recovery.                                                                              |
| Dependencies                    | T15, T16A, T17A, T04A.                                                                                                                                                                                  |
| Security invariants             | SEC01, SEC02, SEC03, SEC04, SEC09.                                                                                                                                                                      |
| Authorization requirements      | Verify eligible pre-existing primary and actual assertion UV for passkeys; full authoritative policy decides normal versus preauth.                                                                     |
| Functional acceptance           | T18-F01: ordinary no-MFA password/UV passkey login earns normal; required MFA earns bounded preauth only, with original primary/auth_time.                                                              |
| Security acceptance             | T18-S01: wrong/missing primary, UP-only, unknown/revoked account/policy and contact-only requests return sanitized denial without premature cookie.                                                     |
| Unit tests                      | T18-U01: exact password and WebAuthn origin/RP/challenge/signature/counter/UV policy matrix covers every primary/MFA category.                                                                          |
| Database/HTTP integration tests | T18-I01: real login across two replicas verifies current credential/policy and no normal session before complete MFA. Password login uses the shared exact-byte verifier and finite admission from T15. |
| Concurrency/failure tests       | T18-X01: concurrent credential/role changes and lock-wait expiry deny stale assertions; SQL/Redis loss/unknown commit grants no session.                                                                |
| Browser/accessibility tests     | T18-B01: GATE03 explicit password/passkey actions, paste/managers and cancelled native prompt do not trigger contact fallback.                                                                          |
| Documentation updates           | T18-D01: replace UP/contact-normal guidance with current-versus-target admission; T18A owns explicit verified-email/enumeration remediation.                                                            |
| Completion criteria             | T18-C01: GATE01/GATE02/GATE03 and actual-UV/full-policy evidence; independent MFA completion still requires T21A/T28B.                                                                                  |

### T18A

| Section                         | Requirement                                                                                                                                                         |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T18A - Bind Explicit Email Identification and Hide Passkey Inventories. Status: Planned.                                                                            |
| Objective                       | Admit intentional current verified unique primary-email identification without credential-count enumeration.                                                        |
| Scope                           | Explicit identifier kind, shared username normalization, eligible email association and discoverable/named passkey option/error shape.                              |
| Explicit out of scope           | Legacy-email label, mobile identification, identifier guessing/fallback, owner/status/credential inventory disclosure or universal timing-immunity claim.           |
| Dependencies                    | T18, T03, T04A, T14, T17A.                                                                                                                                          |
| Security invariants             | SEC01, SEC02, SEC04, SEC09.                                                                                                                                         |
| Authorization requirements      | Selection is not proof; primary-email association must be current/verified/unique and final primary policy still applies.                                           |
| Functional acceptance           | T18A-F01: explicit username/email and discoverable flows select only eligible accounts; known shared/unverified/stale email does not choose an arbitrary subject.   |
| Security acceptance             | T18A-S01: missing versus real 0/1/multi-key accounts expose no account-specific descriptor count/length/status response; client-side residual risks are documented. |
| Unit tests                      | T18A-U01: explicit kind/normalization/verified uniqueness and equal-shaped 0/1/multi-key decoy vectors pass.                                                        |
| Database/HTTP integration tests | T18A-I01: real named options/errors compare counts/lengths across account populations; contact replacement invalidates old email identification.                    |
| Concurrency/failure tests       | T18A-X01: lookup versus email verification/removal/policy changes is primary-authoritative; SQL outage never becomes available/not-found evidence.                  |
| Browser/accessibility tests     | T18A-B01: GATE03 explicit identifier controls and discoverable passkey prompts reveal no credential list; wrong identifier does not silently switch kinds.          |
| Documentation updates           | T18A-D01: update API/client/threat enumeration claims and verified-email intention, retain no universal constant-time/O(1) guarantee.                               |
| Completion criteria             | T18A-C01: GATE01/GATE02/GATE03 with key-count/length population evidence and residual browser risk review.                                                          |

### T19

| Section                         | Requirement                                                                                                                                                      |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T19 - Isolate Contact Code Purposes. Status: Planned.                                                                                                            |
| Objective                       | Preserve exact destination/purpose-bound email/SMS ownership proofs, never a primary credential.                                                                 |
| Scope                           | Keyed code verifiers, selected-channel providers, finite quotas/attempts, one-use generation and original absolute expiry.                                       |
| Explicit out of scope           | Contact-only login, ARC/MFA Backup delivery, general action proof, provider-accepted-as-delivered or automatic uncertain retry.                                  |
| Dependencies                    | T14.                                                                                                                                                             |
| Security invariants             | SEC02, SEC05, SEC08, SEC10, SEC11.                                                                                                                               |
| Authorization requirements      | Exact account/ceremony/channel/destination/purpose/JKT binding; disabled unrelated provider does not disable selected admitted channel.                          |
| Functional acceptance           | T19-F01: registration/contact maintenance/ARC contact/issuance purposes remain distinct; explicit resend invalidates superseded proof without renewing ceremony. |
| Security acceptance             | T19-S01: cross-purpose/account/destination/generation, expired/spent and oversized code attempts are denied within existing tighter budgets.                     |
| Unit tests                      | T19-U01: keyed verifier encoding, exact six-digit leading-zero API grammar, channel-purpose and selected-provider matrices pass.                                 |
| Database/HTTP integration tests | T19-I01: real SQL/HTTP one-use proof consumption binds original destination and deadlines; provider transport statuses remain separate.                          |
| Concurrency/failure tests       | T19-X01: verify/resend races have one valid generation; unknown provider/SQL result retains uncertainty and stable identity without unsafe retry.                |
| Browser/accessibility tests     | T19-B01: N/A for provider service; T36/T38B test explicit send/resend, paste and no preference-triggered API work.                                               |
| Documentation updates           | T19-D01: document each purpose/expiry/error/provider status and distinguish current email-link readers from planned code writers.                                |
| Completion criteria             | T19-C01: GATE01/GATE02 with purpose isolation; durable critical admission separately required by T19A.                                                           |

### T19A

| Section                         | Requirement                                                                                                                                                                     |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T19A - Make Security-Critical Admission Durable. Status: Planned.                                                                                                               |
| Objective                       | Prevent Redis loss/corruption from granting proof authority or silently erasing critical abuse limits.                                                                          |
| Scope                           | SQL-authoritative proof/attempt/generation/deadline/admission state and documented fail-closed outage behavior; Redis acceleration/rate coordination remains non-authoritative. |
| Explicit out of scope           | Redis-earned verification, SQL+Redis atomicity, raising production budgets, flushing shared buckets or new provider installation.                                               |
| Dependencies                    | T19, T16A.                                                                                                                                                                      |
| Security invariants             | SEC09, SEC10, SEC11.                                                                                                                                                            |
| Authorization requirements      | Durable current admission and proof binding are rechecked in primary SQL before issuance/consumption; unavailable critical limit denies action.                                 |
| Functional acceptance           | T19A-F01: restarts/replicas share finite attempt and generation truth; a Redis denial may reject early but cannot manufacture success.                                          |
| Security acceptance             | T19A-S01: forged records, flush, eviction, loss/failover and bypassed cache cannot increase authorized proof attempts or resurrect spent evidence.                              |
| Unit tests                      | T19A-U01: durable budget/window/deadline boundaries and unavailable-store fail-closed combinations pass.                                                                        |
| Database/HTTP integration tests | T19A-I01: real SQL/Redis/HTTP verifies critical limit survival and purpose consumption across two replicas.                                                                     |
| Concurrency/failure tests       | T19A-X01: concurrent admission/resend/consume and Redis partition/forgery have bounded one-winner behavior; ambiguous SQL does not restore attempts/proofs.                     |
| Browser/accessibility tests     | T19A-B01: N/A for durable limiter; T36/T38B show rate-limited/unavailable distinctly without automatic resend.                                                                  |
| Documentation updates           | T19A-D01: record durable versus accelerated limits, fail-closed policy, operational indexes/contention and primary-only reads.                                                  |
| Completion criteria             | T19A-C01: GATE01/GATE02 and actual forged/lost Redis plus bounded concurrency evidence; no cache-flush-as-clean-acceptance shortcut.                                            |

### T20

| Section                         | Requirement                                                                                                                                                      |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T20 - Verify Contact Ownership Without Normal Login. Status: Planned; original contact-login definition superseded.                                              |
| Objective                       | Remove contact-code-only normal authority while preserving explicit purpose-isolated ownership flows.                                                            |
| Scope                           | Existing contact-login issuance/completion/use boundaries and clients; deny normal/preauth by OTP alone and guide users to primary login or admitted ARC repair. |
| Explicit out of scope           | OTP-to-primary conversion, mobile identifier, implicit password/passkey fallback, bypassing MFA or automatic recovery.                                           |
| Dependencies                    | T19A, T14, T16A.                                                                                                                                                 |
| Security invariants             | SEC01, SEC02, SEC03, SEC04, SEC05.                                                                                                                               |
| Authorization requirements      | Email/SMS proof alone authorizes only its explicitly admitted non-login purpose; it cannot earn primary/preauth/session/OAuth/admin authority.                   |
| Functional acceptance           | T20-F01: valid contact OTP remains usable for selected ownership purpose but former normal-login completion cannot issue any normal cookie/token.                |
| Security acceptance             | T20-S01: passkey-only/password-only/both/required-MFA/privileged accounts all deny OTP-only normal/preauth admission, including shared mobile.                   |
| Unit tests                      | T20-U01: exhaustive account/category/code-only matrix confirms denial with truthful contact evidence and no primary method.                                      |
| Database/HTTP integration tests | T20-I01: real existing contact-login endpoints and alternate completion/session boundaries cannot mint normal authority after successful OTP.                    |
| Concurrency/failure tests       | T20-X01: old pending/contact Redis records, endpoint races and restart cannot promote contact evidence; unknown result never issues cookie.                      |
| Browser/accessibility tests     | T20-B01: GATE03 no contact-sign-in success or silent fallback; present explicit primary-login/lost-factor actions with no portal bootstrap.                      |
| Documentation updates           | T20-D01: supersede historical T20/T21 contact-login wording; label current conflict and approved target denial in API/client/UI.                                 |
| Completion criteria             | T20-C01: GATE01/GATE02/GATE03 and all former/alternate issuance boundary denials observed; documentation alone does not remove runtime behavior.                 |

### T21

| Section                         | Requirement                                                                                                                                      |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| ID/title                        | T21 - Complete Primary-Bound Independent MFA. Status: Planned.                                                                                   |
| Objective                       | Preserve TOTP completion only after eligible password or actual-UV passkey primary, never contact-only preauth.                                  |
| Scope                           | Existing bounded primary preauthentication, independent actual TOTP/time-step and full-policy normal completion.                                 |
| Explicit out of scope           | Contact/ARC primary, backup-as-TOTP, general Step-up use, preauth management authority or replay persistence T21A.                               |
| Dependencies                    | T18, T16A.                                                                                                                                       |
| Security invariants             | SEC02, SEC03, SEC04, SEC09.                                                                                                                      |
| Authorization requirements      | Current SQL primary evidence/account/JKT/version/original deadline and admitted independent TOTP; no normal cookie before complete policy.       |
| Functional acceptance           | T21-F01: enabled MFA remains mandatory after UV; TOTP completion records actual TOTP/time-step without replacing original primary/auth_time.     |
| Security acceptance             | T21-S01: wrong-account/key/version/expired or contact-only preauth and missing required independent MFA never issue normal session.              |
| Unit tests                      | T21-U01: primary+TOTP account/category/window/attempt matrix and exact earliest completion deadlines pass.                                       |
| Database/HTTP integration tests | T21-I01: real preauth endpoints deny portal/OAuth/admin use before completion and emit normal authority only after locked current policy checks. |
| Concurrency/failure tests       | T21-X01: simultaneous complete/revoke/role-change is one-winner; lost response cannot replay preauth completion.                                 |
| Browser/accessibility tests     | T21-B01: GATE03 TOTP paste/leading zero and safe app-switch resume retain original ceremony, no automatic submit or resend.                      |
| Documentation updates           | T21-D01: preserve current independent-TOTP strength, supersede contact preauth, map durable replay T21A and backup completion T28B.              |
| Completion criteria             | T21-C01: GATE01/GATE02/GATE03; target durable completion requires T21A, not an old Redis marker.                                                 |

### T21A

| Section                         | Requirement                                                                                                                                           |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T21A - Persist SQL MFA Completion and TOTP Replay. Status: Planned.                                                                                   |
| Objective                       | Make TOTP unseen/consumption and full-policy completion durable under loss/restart.                                                                   |
| Scope                           | Primary-SQL preauth/evidence completion, account/factor-generation/time-step replay claims and deciding session issuance.                             |
| Explicit out of scope           | Redis-unseen fallback, broad token issuance, resetting auth_time or barrier through refresh, and TOTP-window loosening.                               |
| Dependencies                    | T21, T16A, T17A, T19A.                                                                                                                                |
| Security invariants             | SEC03, SEC07, SEC09, SEC10, SEC11.                                                                                                                    |
| Authorization requirements      | Consume current preauth/replay claim with final policy/JKT/session/deadline checks in one deciding transaction; GATE02.                               |
| Functional acceptance           | T21A-F01: one actual TOTP step completes at most one admitted use in its defined replay domain and durably records complete-policy authentication.    |
| Security acceptance             | T21A-S01: Redis marker loss/forgery, stale replicas, previous MFA generation and expired/revoked preauth cannot become unseen/normal evidence.        |
| Unit tests                      | T21A-U01: replay-domain/time-step/generation encoding and exact accepted-window boundaries preserve current tighter rules.                            |
| Database/HTTP integration tests | T21A-I01: real SQL/HTTP verifies replay claims, full-policy session issuance and no preauth route authority across replicas/restarts.                 |
| Concurrency/failure tests       | T21A-X01: simultaneous completion, factor replacement, lock-wait expiry and ambiguous commit have one winner; lost SQL/Redis grants no new authority. |
| Browser/accessibility tests     | T21A-B01: GATE03 uncertain completion does not retransmit TOTP or bootstrap guessed subject; new explicit login is required if evidence is lost.      |
| Documentation updates           | T21A-D01: record primary-only replay/locking/domain design and actual TOTP versus backup truth in data/API/readiness.                                 |
| Completion criteria             | T21A-C01: GATE01/GATE02/GATE03 with durable replay/one-winner/failure evidence, not cache existence.                                                  |

### T22

| Section                         | Requirement                                                                                                                                             |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T22 - Authorize One Sensitive Action. Status: Planned.                                                                                                  |
| Objective                       | Keep password-plus-old-contact authority action-scoped for eligible ordinary password-only accounts.                                                    |
| Scope                           | Dedicated fresh password/contact proof purpose, exact action/target/account/session/JKT/version/deadline and caller-owned consumption.                  |
| Explicit out of scope           | General password Step-up, code-family issuance via reused proof, repair grant, privileged/admin/legal use or new-contact-as-old-ownership.              |
| Dependencies                    | T15, T14, T16A, T19A.                                                                                                                                   |
| Security invariants             | SEC02, SEC04, SEC05, SEC06, SEC10.                                                                                                                      |
| Authorization requirements      | Fresh exact-byte password and admitted old verified contact, normal bound session and allowed action/category; existing stronger UV/TOTP scopes remain. |
| Functional acceptance           | T22-F01: matching proof authorizes one named ordinary action only, with original minimum expiry and immutable target.                                   |
| Security acceptance             | T22-S01: wrong action/target/account/key, signup code, ARC/backup, unknown old contact and admin/legal/privileged requests are denied.                  |
| Unit tests                      | T22-U01: action-purpose-target/category matrix and dedicated issuance-purpose separation vectors pass.                                                  |
| Database/HTTP integration tests | T22-I01: real caller-owned action transaction consumes proof exactly once without nesting conflicting account transactions.                             |
| Concurrency/failure tests       | T22-X01: proof reuse versus competing action/version/contact change has one winner; uncertain commit does not restore proof.                            |
| Browser/accessibility tests     | T22-B01: N/A for actionproof service; T38C tests pinned target/fresh confirmation and no automatic uncertain replay.                                    |
| Documentation updates           | T22-D01: document exact purpose inventory and stronger scopes; link T22A final deciding transaction checks.                                             |
| Completion criteria             | T22-C01: GATE01/GATE02 and action substitution/one-use evidence; new code-family issuance requires T28A's own purpose.                                  |

### T22A

| Section                         | Requirement                                                                                                                                                  |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| ID/title                        | T22A - Recheck Fresh Action Authority in the Deciding Transaction. Status: Planned.                                                                          |
| Objective                       | Prevent stale grant/session/deadline authority from surviving lock waits or being reduced to booleans.                                                       |
| Scope                           | Existing actionproof/Step-up consumers and immutable earned bindings; final live primary-SQL policy/session/target/version checks and global lock order.     |
| Explicit out of scope           | Generic proof widening, admin/legal scope downgrade, consumed-grant reconstruction, nested transaction shortcuts or external delivery under account locks.   |
| Dependencies                    | T22, T17A, T16A.                                                                                                                                             |
| Security invariants             | SEC04, SEC07, SEC09, SEC10, SEC11.                                                                                                                           |
| Authorization requirements      | Preserve exact earned evidence IDs/deadlines until caller-owned deciding transaction and recheck after every applicable lock wait; GATE02.                   |
| Functional acceptance           | T22A-F01: proof consumption and matching mutation/version/intents commit atomically; no-op semantics remain operation-specific and truthful.                 |
| Security acceptance             | T22A-S01: expired/revoked session/grant, changed target/policy/contact/barrier and wrong JKT cannot commit even when admitted before waiting.                |
| Unit tests                      | T22A-U01: complete binding propagation and minimum deadline comparisons include expiry exactly at equality.                                                  |
| Database/HTTP integration tests | T22A-I01: real sensitive consumers prove exact live session/evidence consumption with final SQL checks; denied action leaves no mutation/intent.             |
| Concurrency/failure tests       | T22A-X01: forced lock-wait expiry/revocation, multi-lock order probes and unknown commit never restore spent authority or deadlock via reversed acquisition. |
| Browser/accessibility tests     | T22A-B01: N/A for deciding transaction; T38C/T30A exercise stale-dialog/uncertain mutation without replay.                                                   |
| Documentation updates           | T22A-D01: enumerate consumer ownership and global lock order in policy/data/API; link deletion-specific T30A remediation.                                    |
| Completion criteria             | T22A-C01: GATE01/GATE02, CP02 review and real blocked-lock negative evidence at each applicable consumer.                                                    |

### T23

| Section                         | Requirement                                                                                                                                  |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T23 - Preserve Resulting-State Primary and Contact Policy. Status: Planned.                                                                  |
| Objective                       | Prevent factor/contact management from destroying required primary, verified contact or independent/privileged protection.                   |
| Scope                           | Shared account-locked resulting-state checks, real security version invalidation and cosmetic no-op/rename distinction.                      |
| Explicit out of scope           | OTP as primary, email-only mandatory domain assumption, barrier implementation T23A or hypothetical legacy-account exemptions.               |
| Dependencies                    | T13, T14, T16.                                                                                                                               |
| Security invariants             | SEC01, SEC02, SEC03, SEC04, SEC08, SEC10.                                                                                                    |
| Authorization requirements      | Live action authority plus locked resulting state with mandatory username, at least one primary/contact and unchanged required policy.       |
| Functional acceptance           | T23-F01: legitimate multi-factor removal preserves eligible primary/contact; cosmetic key name change does not revoke security authority.    |
| Security acceptance             | T23-S01: last primary/verified contact, required MFA/hardware/backup removal or policy downgrade is denied, including simultaneous removals. |
| Unit tests                      | T23-U01: resulting-state matrix covers password/passkey/both, verified versus unknown contacts and privileged independent backup.            |
| Database/HTTP integration tests | T23-I01: all password/passkey/TOTP/contact mutation endpoints share the same account serialization and live resulting-state guard.           |
| Concurrency/failure tests       | T23-X01: simultaneous last-factor/contact removals have at most one safe winner; rollback leaves protected factors and versions unchanged.   |
| Browser/accessibility tests     | T23-B01: N/A for guard; T38C presents blocked last-factor actions, with backend denial independent of button state.                          |
| Documentation updates           | T23-D01: document shared guard and distinguish last verified contact from T27A's last recovery-eligible contact.                             |
| Completion criteria             | T23-C01: GATE01/GATE02 and complete endpoint/resulting-state negative coverage; no management exception weakens SEC04.                       |

### T23A

| Section                         | Requirement                                                                                                                                                                         |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T23A - Enforce a Durable One-Repair Barrier. Status: Planned.                                                                                                                       |
| Objective                       | Block recovery chaining and equivalent credential/MFA management bypass until genuinely fresh full-policy login.                                                                    |
| Scope                           | SQL per-account repair barrier/provenance/version, common management guards and reset only inside fresh normal-login admission.                                                     |
| Explicit out of scope           | Time/refresh/contact/ARC/regeneration reset, disabling MFA to make repaired primary sufficient, support bypass or a second recovery service.                                        |
| Dependencies                    | T16A, T17A, T21A, T22A, T23, T40B.                                                                                                                                                  |
| Security invariants             | SEC03, SEC04, SEC06, SEC07, SEC09, SEC10.                                                                                                                                           |
| Authorization requirements      | Barrier set with successful repair; while set deny further repair/equivalent factor changes. Reset requires new SQL-recorded normal login satisfying entire current policy.         |
| Functional acceptance           | T23A-F01: repaired password can reset ordinary password-only account after fresh login; with required MFA it yields preauth only until actual TOTP/admitted backup completes.       |
| Security acceptance             | T23A-S01: repaired primary is not surviving independent evidence for another repair; old sessions, refresh, OTP, extra ARC, new challenge or regenerated codes never clear barrier. |
| Unit tests                      | T23A-U01: full transition/property matrix includes multi-factor loss lockout and password-only versus required-MFA reset clarification.                                             |
| Database/HTTP integration tests | T23A-I01: every password/passkey/TOTP/recovery alternate endpoint sees the same SQL barrier across replicas; required-policy downgrade is denied.                                   |
| Concurrency/failure tests       | T23A-X01: repair/login/role/factor races, restart/Redis flush and stale sessions cannot bypass; ambiguous reset commit cannot earn new authority.                                   |
| Browser/accessibility tests     | T23A-B01: GATE03 restricted result requires explicit fresh normal login; settings cannot offer a barrier-clearing downgrade or retry chain.                                         |
| Documentation updates           | T23A-D01: publish endpoint inventory, transition/reset matrix, durable evidence and deliberate multi-loss lockout in policy/API/readiness.                                          |
| Completion criteria             | T23A-C01: GATE01/GATE02/GATE03 and CP04 cross-endpoint/restart/reset evidence; each T29 writer must atomically set the barrier.                                                     |

### T24

| Section                         | Requirement                                                                                                                                                                                                         |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T24 - Manage Passwords Without Recovery Bypass. Status: Planned.                                                                                                                                                    |
| Objective                       | Preserve add/change/remove behavior with fresh exact action and complete resulting-state/barrier policy.                                                                                                            |
| Scope                           | Existing shared hasher, outside-lock native work, final SQL authority, real-change version fence and metadata/notification intent.                                                                                  |
| Explicit out of scope           | ARC repair via management endpoint, general password Step-up, byte normalization, removing final primary or required-MFA downgrade.                                                                                 |
| Dependencies                    | T15, T22A, T23A, T41A.                                                                                                                                                                                              |
| Security invariants             | SEC02, SEC03, SEC04, SEC07, SEC10, SEC11.                                                                                                                                                                           |
| Authorization requirements      | Normal fresh action-specific authority and barrier clear; recheck account/JKT/session/version/deadline after hashing/locks.                                                                                         |
| Functional acceptance           | T24-F01: real password mutation commits hash/security version/intents once; removal retains an eligible primary and required policy.                                                                                |
| Security acceptance             | T24-S01: repair grant/contact-only/expired proof, barrier-set account and last-primary/MFA downgrade are denied.                                                                                                    |
| Unit tests                      | T24-U01: add/change/remove/no-op matrix, exact bytes and action-purpose/category resulting-state checks pass.                                                                                                       |
| Database/HTTP integration tests | T24-I01: real management endpoints share caller-owned SQL consumption and metadata-only intent with no password exposure. Add, change, and verify use the shared exact-byte verifier and finite admission from T15. |
| Concurrency/failure tests       | T24-X01: hash-time version/revocation change and competing removals fail safe; unknown commit is read-only reconciliation, not retry with restored proof.                                                           |
| Browser/accessibility tests     | T24-B01: GATE03 paste/managers, pinned action, transient password clearing and uncertain result prevent repeated submissions.                                                                                       |
| Documentation updates           | T24-D01: preserve current password endpoint evidence and separate T29A restricted repair; lifecycle saved-code retention follows policy table.                                                                      |
| Completion criteria             | T24-C01: GATE01/GATE02/GATE03 and barrier/last-primary/final-binding evidence with transactional intent.                                                                                                            |

### T25

| Section                         | Requirement                                                                                                                                                    |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T25 - Enroll the First Passkey on a Password Account. Status: Planned.                                                                                         |
| Objective                       | Admit specific fresh ordinary first-enrollment authority without an unavailable old passkey requirement or recovery bypass.                                    |
| Scope                           | Existing native enrollment with UV, immutable username/handle identity, final SQL proof/session/version and first-enrollment serialization.                    |
| Explicit out of scope           | New passkey UV as old-factor proof, general recovery grant, privileged hardware assumption, automatic native prompt or handle persistence before verification. |
| Dependencies                    | T24, T22A, T23A, T41A.                                                                                                                                         |
| Security invariants             | SEC01, SEC02, SEC04, SEC07, SEC10, SEC15.                                                                                                                      |
| Authorization requirements      | Dedicated fresh eligible normal-session enrollment proof; actual new credential UV and full current/barrier/resulting-state checks.                            |
| Functional acceptance           | T25-F01: successful verified first passkey commits stable handle/credential/intents once; cancellation leaves no assigned handle or credential.                |
| Security acceptance             | T25-S01: wrong RP/origin/challenge/account/key, UP-only, stale proof/session and barrier-set enrollment are denied.                                            |
| Unit tests                      | T25-U01: UV/handle/name/purpose/category and final binding vectors pass without proving hardware from inventory.                                               |
| Database/HTTP integration tests | T25-I01: real options/verify transactions defer handle assignment and preserve username/primary policy.                                                        |
| Concurrency/failure tests       | T25-X01: simultaneous first enrollments, role/revoke/expiry during locks and unknown native/SQL result produce no replayed authority.                          |
| Browser/accessibility tests     | T25-B01: GATE03 explicit native action/cancel and late response cleanup; USB/hybrid alternatives remain available.                                             |
| Documentation updates           | T25-D01: distinguish first normal enrollment from T29B repair and preserve actual installed credential/readers.                                                |
| Completion criteria             | T25-C01: GATE01/GATE02/GATE03 and one-winner/actual-UV/final-session evidence; no privileged admission inferred.                                               |

### T26

| Section                         | Requirement                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T26 - Manage MFA Without Policy Downgrade. Status: Planned; historical local completion retained separately.                                                                                                                                                                                                                                                                                                                              |
| Objective                       | Revalidate existing enrollment/disable implementation against durable authority, independent truth and repair barrier.                                                                                                                                                                                                                                                                                                                    |
| Scope                           | Existing TOTP routes, enrollment-only password/contact purpose, fresh strong disable, frozen pending bindings and SQL factor-generation/replay/code consequences.                                                                                                                                                                                                                                                                         |
| Explicit out of scope           | Registration stages, contact-only normal login, optional-MFA flag, T38 UI, disabling required MFA during repair or backup-as-TOTP.                                                                                                                                                                                                                                                                                                        |
| Dependencies                    | T22A, T23A, T28A, T41A.                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Security invariants             | SEC03, SEC04, SEC05, SEC07, SEC10.                                                                                                                                                                                                                                                                                                                                                                                                        |
| Authorization requirements      | Exact enrollment purpose for eligible ordinary account; disable needs admitted fresh strong authority and locked resulting state, never enrollment proof/ARC/repair grant.                                                                                                                                                                                                                                                                |
| Functional acceptance           | T26-F01: pending start spends proof once; verified completion retains original minimum deadline and fences old MFA/replay without restamping session MFA. Revoke the `mfa_backup` generation created by T28A on verified ordinary TOTP enablement or on disablement authorized by fresh strong proof. T29C owns recovery-driven replacement. Unspent ARCs remain valid if their family is uncompromised and the account remains eligible. |
| Security acceptance             | T26-S01: required/privileged MFA downgrade, barrier-set management, wrong session/JKT/version/contact or expired pending state is denied.                                                                                                                                                                                                                                                                                                 |
| Unit tests                      | T26-U01: enrolled versus pending/new TOTP, purpose/disable policy and family-generation transition matrices pass.                                                                                                                                                                                                                                                                                                                         |
| Database/HTTP integration tests | T26-I01: real existing routes prove caller-owned mutation transaction, actual replay claims and compatible historical evidence/readers.                                                                                                                                                                                                                                                                                                   |
| Concurrency/failure tests       | T26-X01: enrollment/disable/repair/role races and blocked-lock expiry cannot remove required protection; unknown completion does not restore proof or old generation.                                                                                                                                                                                                                                                                     |
| Browser/accessibility tests     | T26-B01: N/A for API maintenance; T38C owns bilingual management; existing browser harness still verifies unchanged authentication regressions.                                                                                                                                                                                                                                                                                           |
| Documentation updates           | T26-D01: retain 2026-11-23 source/toolchain/21-gate evidence, explicitly separate new target remediations and remaining production/UI gates.                                                                                                                                                                                                                                                                                              |
| Completion criteria             | T26-C01: GATE01/GATE02 and target barrier/durable replay/disable evidence; historical Completed does not satisfy these new criteria.                                                                                                                                                                                                                                                                                                      |

### T27

| Section                         | Requirement                                                                                                                                                               |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T27 - Change or Remove Contacts Safely. Status: Planned; existing email-removal gate retained.                                                                            |
| Objective                       | Keep old authorization distinct from exact new ownership and prevent unsafe lifecycle activation.                                                                         |
| Scope                           | Existing normal-session unified contact manager, action/target proof, current-contact reads, new provenance and stale-authority invalidation.                             |
| Explicit out of scope           | T12, signup authority reuse, backup-contact product expansion, new-contact login/repair authority or present-email gate retirement.                                       |
| Dependencies                    | T22A, T23, T41A.                                                                                                                                                          |
| Security invariants             | SEC01, SEC08, SEC10, SEC12, SEC14.                                                                                                                                        |
| Authorization requirements      | Fresh admitted old-contact/strong authority and separate new-destination ownership; normal session with final target/JKT/version/deadline checks.                         |
| Functional acceptance           | T27-F01: safe change/removal commits provenance/version/intents together; already-NULL email is supported truthfully; present-email removal remains blocked pending T41C. |
| Security acceptance             | T27-S01: final required verified contact/identifier loss, signup/recovery proof reuse, stale target/session or new ownership as old authorization is denied.              |
| Unit tests                      | T27-U01: present/absent email/phone, exact action-target and old/new ownership matrices include current temporary gate.                                                   |
| Database/HTTP integration tests | T27-I01: real routes persist canonical exact provenance and metadata/notification intents with compatible email_link/email_otp/sms_otp readers.                           |
| Concurrency/failure tests       | T27-X01: replace/remove versus role/session/proof changes uses final SQL validation; rollback/unknown outcome cannot fabricate verification or reopen gate.               |
| Browser/accessibility tests     | T27-B01: N/A for contact API; T38C renders truthful current/absent/gated states under GATE03.                                                                             |
| Documentation updates           | T27-D01: preserve historical verification-in-progress record and explicit T41C dependency; link T27A cooldown/last-eligible guard.                                        |
| Completion criteria             | T27-C01: GATE01/GATE02 with gate-present and exact provenance evidence; this record does not activate mobile-only production.                                             |

### T27A

| Section                         | Requirement                                                                                                                                                                            |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T27A - Enforce Contact Recovery Provenance and Cooldown. Status: Planned.                                                                                                              |
| Objective                       | Prevent rapid attacker-added contact recovery and preserve the last recovery-eligible destination.                                                                                     |
| Scope                           | Durable association/history/verification UTC, initial-registration exemption, absolute recovery_eligible_at, 24-hour cooldown and pending-authority fences.                            |
| Explicit out of scope           | Unknown-as-eligible backfill, client/preference time, shortening existing deadline/budgets, mobile identifier or retiring T27's broader gate.                                          |
| Dependencies                    | T27, T14, T19A, T23.                                                                                                                                                                   |
| Security invariants             | SEC01, SEC08, SEC09, SEC10, SEC12.                                                                                                                                                     |
| Authorization requirements      | Recovery uses current verified association with known provenance and eligible UTC boundary; removal requires another verified eligible destination.                                    |
| Functional acceptance           | T27A-F01: initial registration is explicitly exempt; added/replaced verified contacts become eligible no earlier than original verification+24h; unchanged old contact remains usable. |
| Security acceptance             | T27A-S01: unknown/revoked/removed/re-added/young contact cannot earn recovery; removal/replacement destroying last eligible destination is denied.                                     |
| Unit tests                      | T27A-U01: just-before/equal/after 24h, registration exemption, reverification/re-add history and missing provenance vectors pass.                                                      |
| Database/HTTP integration tests | T27A-I01: real SQL/HTTP contact and repair admission use current association/absolute UTC and invalidate conflicting in-flight proofs/grants.                                          |
| Concurrency/failure tests       | T27A-X01: concurrent last-eligible removals, cooldown crossing/role/proof changes, restart/Redis loss preserve eligibility and one safe winner.                                        |
| Browser/accessibility tests     | T27A-B01: GATE03 locale/calendar/zone/navigation never changes eligible_at or sends new proofs; cooling/unknown feedback is accessible and private.                                    |
| Documentation updates           | T27A-D01: publish contact history/eligibility transition matrix and preserve T41C activation dependency.                                                                               |
| Completion criteria             | T27A-C01: GATE01/GATE02/GATE03, CP04 review and boundary/re-add/last-eligible/concurrent evidence.                                                                                     |

### T28A

| Section                         | Requirement                                                                                                                                                                                                                                                                                                                                                        |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| ID/title                        | T28A - Issue, Regenerate and Revoke Distinct Saved Code Families. Status: Planned.                                                                                                                                                                                                                                                                                 |
| Objective                       | Separate MFA Backup Codes from ARCs and provide independently authorized lifecycle operations.                                                                                                                                                                                                                                                                     |
| Scope                           | At least 128 random bits/code, purpose/account/generation-bound HMAC-SHA-256, dedicated external key/distinct domains, one-use saved artifacts and bounded transient viewer.                                                                                                                                                                                       |
| Explicit out of scope           | Argon2 for saved codes, untyped code interpreted as both families, automatic replacement/contact delivery, recovery-grant issuance or universal HMAC/constant-time SQL claims.                                                                                                                                                                                     |
| Dependencies                    | T17, T23A, T27A, T22A, T41A, T40B; external owner-approved handling of inventoried real untyped artifacts/readers.                                                                                                                                                                                                                                                 |
| Security invariants             | SEC03, SEC04, SEC05, SEC07, SEC09, SEC10, SEC11.                                                                                                                                                                                                                                                                                                                   |
| Authorization requirements      | Own fresh family issuance purpose; ordinary password-only ARC issuance requires fresh password+eligible old-contact proof, not generic Step-up. Required MFA needs full policy; privileged consumer ARC/downgrade denied.                                                                                                                                          |
| Functional acceptance           | T28A-F01: separate generations/statuses and once-only output; saved codes remain usable until use/revocation/regeneration/deletion/ineligibility, not viewer/grant expiry.                                                                                                                                                                                         |
| Security acceptance             | T28A-S01: family substitution, unknown key/generation, repair/receipt authority, automatic ARC email/SMS and regeneration-as-barrier-reset are denied.                                                                                                                                                                                                             |
| Unit tests                      | T28A-U01: CSPRNG entropy/encoding bounds, domain/account/generation vectors and constant-time application comparison where applicable; no constant-time SQL assertion.                                                                                                                                                                                             |
| Database/HTTP integration tests | T28A-I01: real issuance/revoke/regenerate commits verifier/generation/derived-authority fences and metadata/notification intent once, without stored plaintext or retrieval GET. A real role or admitted-assurance change revokes both unspent mfa_backup and arc families and their derived grants in that same transaction. A no-op role update revokes nothing. |
| Concurrency/failure tests       | T28A-X01: regeneration versus use/repair and role/deletion/TOTP changes have one consistent lifecycle; unknown commit loses plaintext without cache recovery/reissue.                                                                                                                                                                                              |
| Browser/accessibility tests     | T28A-B01: GATE03 explicit Copy/Download, independent-offline-storage warning, no account filename, no auto-copy/mail, original viewer deadline and privacy cleanup.                                                                                                                                                                                                |
| Documentation updates           | T28A-D01: policy lifecycle table, actual artifact/reader inventory, HMAC-versus-current-high-entropy-SHA rationale and NIST issuance applicability gaps recorded.                                                                                                                                                                                                  |
| Completion criteria             | T28A-C01: GATE01/GATE02/GATE03, CP03 code review and explicit artifact-handling approval; old SHA codes are not declared inherently insecure/deleted.                                                                                                                                                                                                              |

### T28B

| Section                         | Requirement                                                                                                                                                                      |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T28B - Complete Primary-Bound MFA with an Admitted Backup Code. Status: Planned.                                                                                                 |
| Objective                       | Allow one policy-eligible MFA Backup Code after an eligible primary without pretending TOTP or granting repair authority.                                                        |
| Scope                           | Existing SQL preauth completion, family/generation/code consumption, full-policy ordinary normal session and truthful backup evidence.                                           |
| Explicit out of scope           | Backup-only login, ARC completion, privileged downgrade, credential management/repair or generic Step-up by backup code.                                                         |
| Dependencies                    | T28A, T21A, T17A.                                                                                                                                                                |
| Security invariants             | SEC02, SEC03, SEC04, SEC05, SEC07, SEC09, SEC10.                                                                                                                                 |
| Authorization requirements      | Fresh current primary-bound preauth with same account/JKT/policy/version/deadline and policy-admitted MFA Backup Code. Privileged backup-code downgrade is denied.               |
| Functional acceptance           | T28B-F01: one backup completes admitted ordinary primary-bound MFA, records consumed backup and TOTP=false, retains original auth_time and follows T23A fresh-full-policy reset. |
| Security acceptance             | T28B-S01: backup alone, ARC, wrong family/account/key/generation, stale preauth, expired/spent/revoked code and privileged downgrade earn no normal authority.                   |
| Unit tests                      | T28B-U01: primary/backup/category/evidence truth matrix includes actual UV with independent MFA and repaired-primary preauth.                                                    |
| Database/HTTP integration tests | T28B-I01: real SQL consumption/preauth completion/session issuance/notification intent is one transaction across replicas, with no TOTP boolean reuse.                           |
| Concurrency/failure tests       | T28B-X01: duplicate backup use, regeneration/TOTP/role change, lock-wait expiry and ambiguous commit have one winner and no code restoration.                                    |
| Browser/accessibility tests     | T28B-B01: GATE03 explicit backup alternative after primary, exact bytes/paste/transient clearing and no ARC-family confusion or premature portal mount.                          |
| Documentation updates           | T28B-D01: API/client/policy/readiness record primary-bound backup semantics, code lifetime and truthful MFA evidence.                                                            |
| Completion criteria             | T28B-C01: GATE01/GATE02/GATE03 and one-use/full-policy/privileged-denial evidence; no new repair scope inferred.                                                                 |

### T28C

| Section                         | Requirement                                                                                                                                                                                                        |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| ID/title                        | T28C - Earn One Restricted ARC-and-Old-Contact Repair Grant. Status: Planned.                                                                                                                                      |
| Objective                       | Replace recovery-code-only enrollment with two explicitly bound ordinary recovery proofs and exactly one repair purpose.                                                                                           |
| Scope                           | Explicit username/eligible primary-email identification, ARC plus fresh current recovery-eligible old email/mobile proof, ten-minute absolute ceremony and grant at most five minutes/remaining original deadline. |
| Explicit out of scope           | Contact/ARC-only mutation, normal/OAuth/admin/legal/contact/deletion/Step-up authority, privileged consumer recovery, automatic fallback or new ten-minute budget per stage.                                       |
| Dependencies                    | T28A, T18A, T19A, T27A, T23A, T41A.                                                                                                                                                                                |
| Security invariants             | SEC01, SEC04, SEC05, SEC06, SEC07, SEC08, SEC09, SEC10, SEC11.                                                                                                                                                     |
| Authorization requirements      | Barrier clear, ordinary eligible category, one unspent ARC/current family and fresh old association proof; TOTP-target grant additionally binds eligible pre-existing primary.                                     |
| Functional acceptance           | T28C-F01: primary SQL ARC consumption creates one named factor-repair grant with account/JKT/factor/version/provenance/original deadline, never a normal cookie.                                                   |
| Security acceptance             | T28C-S01: unknown/young/re-added contact, new-device UV as old proof, wrong account/purpose/key, barrier set, privileged and missing pre-existing primary for TOTP are denied.                                     |
| Unit tests                      | T28C-U01: complete policy/proof/target/expiry matrices include 24h boundary, saved-code versus short grant lifetime and deliberate multi-loss lockout.                                                             |
| Database/HTTP integration tests | T28C-I01: real SQL/HTTP consumes ARC+matching contact evidence with grant/metadata intent once; every normal/Step-up/deletion/consumer route denies the grant.                                                     |
| Concurrency/failure tests       | T28C-X01: competing grants/regen/contact/role changes and lock-wait expiry have one winner; lost admission response never restores ARC or reissues grant via result read.                                          |
| Browser/accessibility tests     | T28C-B01: GATE03 lost-factor journey remains separate from /recover-account, explicit proof sends and no portal mount; locale changes preserve ceremony/JKT/deadline.                                              |
| Documentation updates           | T28C-D01: publish restricted purpose/deny matrix and current-code vulnerability remediation, no compliance claim from saved-plus-issued proof.                                                                     |
| Completion criteria             | T28C-C01: GATE01/GATE02/GATE03 and CP04 old-contact/barrier/privileged/one-grant evidence; repair mutations remain separate T29 children.                                                                          |

### T29A

| Section                         | Requirement                                                                                                                                                                                                                            |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T29A - Repair One Password. Status: Planned.                                                                                                                                                                                           |
| Objective                       | Consume one password-target repair grant and atomically set the anti-chaining barrier without normal authority.                                                                                                                        |
| Scope                           | Shared exact-byte bounded hasher outside locks; final SQL bindings, password mutation, consumption/version/barrier/code consequences and transactional intents.                                                                        |
| Explicit out of scope           | Passkey/TOTP/contact repair, automatic MFA removal, general grant/session, unapproved unrelated credential revocation or support override.                                                                                             |
| Dependencies                    | T28C, T23A, T15, T22A, T41A.                                                                                                                                                                                                           |
| Security invariants             | SEC02, SEC03, SEC04, SEC06, SEC07, SEC09, SEC10, SEC11.                                                                                                                                                                                |
| Authorization requirements      | Exact unspent password-repair grant from ordinary ARC+eligible old-contact ceremony, current factor/provenance/JKT/version/session/deadline after hash/locks.                                                                          |
| Functional acceptance           | T29A-F01: one password changes with barrier/security version/intents and no session; fresh ordinary password-only login may reset, required-MFA account gets preauth until independent completion.                                     |
| Security acceptance             | T29A-S01: wrong target/family/grant, expired/revoked authority, barrier-set second repair and MFA downgrade are denied; repaired password cannot independently authorize a second repair.                                              |
| Unit tests                      | T29A-U01: exact password policy, repair purpose and full-policy reset matrix cover password-only and multi-factor-loss lockout.                                                                                                        |
| Database/HTTP integration tests | T29A-I01: real SQL/HTTP validates original authority after locks, changes one password and commits consumption/barrier/intents atomically. The replacement password uses the shared exact-byte verifier and finite admission from T15. |
| Concurrency/failure tests       | T29A-X01: duplicate repair, contact/role/regeneration changes during hashing/locks and unknown commit yield one winner/no restored grant.                                                                                              |
| Browser/accessibility tests     | T29A-B01: GATE03 transient password/confirmation/paste, uncertain result without replay and explicit normal-login destination after known repair.                                                                                      |
| Documentation updates           | T29A-D01: distinguish T24 ordinary management and repaired-password reset clarification; report no automatic dashboard authority.                                                                                                      |
| Completion criteria             | T29A-C01: GATE01/GATE02/GATE03 and atomic barrier/final-binding/reset-denial evidence, including alternate management endpoints.                                                                                                       |

### T29B

| Section                         | Requirement                                                                                                                                                                            |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T29B - Repair One Passkey with Actual UV. Status: Planned.                                                                                                                             |
| Objective                       | Bind one approved replacement/enrollment to one restricted grant while retaining unrelated uncompromised credentials.                                                                  |
| Scope                           | Existing native WebAuthn enrollment, stable username/handle/RP identity, target credential/provenance, final SQL grant/version/barrier and transactional intents.                      |
| Explicit out of scope           | New-device UV as old ownership/hardware proof, multi-passkey repair, normal session, TOTP/contact changes or deleting unrelated keys.                                                  |
| Dependencies                    | T28C, T23A, T22A, T41A, T39.                                                                                                                                                           |
| Security invariants             | SEC01, SEC02, SEC04, SEC06, SEC07, SEC09, SEC10, SEC15.                                                                                                                                |
| Authorization requirements      | Current ordinary passkey-target ARC+old-contact grant and actual new assertion/registration UV; final live grant/session/JKT/provenance/deadline validation.                           |
| Functional acceptance           | T29B-F01: exactly one approved credential mutation commits consumption/barrier/version/intents; unrelated uncompromised keys/immutable identity survive; return to fresh normal login. |
| Security acceptance             | T29B-S01: UP-only/wrong RP/origin/challenge/key/target, stale session/expired grant after wait, privileged or barrier-set repair is denied.                                            |
| Unit tests                      | T29B-U01: actual UV and stable target/handle/grant bindings cover invalid authenticator data and unrelated-key preservation.                                                           |
| Database/HTTP integration tests | T29B-I01: real options/finish across replicas checks exact live restricted authority at deciding SQL transaction; no normal cookie or management access.                               |
| Concurrency/failure tests       | T29B-X01: simultaneous finishes, regen/revoke/role/contact change and expiry during lock wait allow at most one repair; unknown finish is not replayed.                                |
| Browser/accessibility tests     | T29B-B01: GATE03 explicit native enrollment/cancel and late-response clearing, USB/hybrid alternatives, no deadline renewal or repaired-key repair chain.                              |
| Documentation updates           | T29B-D01: source-grounded recovery sequencing remediation and distinct first-normal-enrollment T25; separate physical hardware evidence.                                               |
| Completion criteria             | T29B-C01: GATE01/GATE02/GATE03 and one-credential/actual-UV/final-expiry/barrier evidence; no privileged consumer recovery.                                                            |

### T29C

| Section                         | Requirement                                                                                                                                                                                                                                                                                             |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T29C - Replace TOTP Only after Pre-Existing Primary and Verified New TOTP. Status: Planned.                                                                                                                                                                                                             |
| Objective                       | Preserve active old TOTP until one fully authorized new-secret replacement commits atomically.                                                                                                                                                                                                          |
| Scope                           | Ordinary TOTP-target grant, fresh eligible pre-existing primary, ARC+eligible old-contact proof, staged secret/new-code verification and durable replay/generation swap.                                                                                                                                |
| Explicit out of scope           | Newly repaired primary as surviving evidence, disable-before-verify, privileged recovery, MFA downgrade, pending-enrollment normal authority or unrelated ARC revocation.                                                                                                                               |
| Dependencies                    | T28C, T21A, T23A, T22A, T41A.                                                                                                                                                                                                                                                                           |
| Security invariants             | SEC03, SEC04, SEC05, SEC06, SEC07, SEC09, SEC10, SEC11.                                                                                                                                                                                                                                                 |
| Authorization requirements      | Bind pre-existing primary evidence, account/factor/JKT/version/old contact/grant and original minimum expiry; verify new TOTP under durable replay before deciding swap.                                                                                                                                |
| Functional acceptance           | T29C-F01: old TOTP remains active through pending, cancellation and failure. The verified recovery commit swaps one factor, revokes the MFA Backup generation, sets the barrier and records intents. Other unspent ARCs remain valid if their family is uncompromised and the account remains eligible. |
| Security acceptance             | T29C-S01: ARC+contact without pre-existing primary, repaired-primary chain, expired/spent/revoked grant, wrong new code and required-policy downgrade are denied.                                                                                                                                       |
| Unit tests                      | T29C-U01: old-active/pending/new-verified transitions, pre-existing evidence identity and replay/generation policy vectors pass.                                                                                                                                                                        |
| Database/HTTP integration tests | T29C-I01: real SQL/HTTP new-code verification/replay, old-factor swap, grant consumption/version/barrier/intents commit together or preserve old factor entirely.                                                                                                                                       |
| Concurrency/failure tests       | T29C-X01: two replacements, normal MFA use/role/regen/contact changes and lock-wait expiry have one serialized winner; ambiguous/cancelled finish never deactivates old TOTP speculatively.                                                                                                             |
| Browser/accessibility tests     | T29C-B01: GATE03 explicit secret/code display, transient QR/code cleanup, exact deadline/app-switch and no disable-then-repair fallback.                                                                                                                                                                |
| Documentation updates           | T29C-D01: atomic old/new TOTP and backup-generation consequences, deliberate insufficient-surviving-factor lockout and fresh full-policy reset.                                                                                                                                                         |
| Completion criteria             | T29C-C01: GATE01/GATE02/GATE03 and old-factor-retention/primary-binding/replay/barrier evidence for all negative outcomes.                                                                                                                                                                              |

### T30A

| Section                         | Requirement                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T30A - Join Exact Deletion Authority to the Existing Transaction. Status: Planned.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Objective                       | Preserve stronger deletion policy and exact live evidence through final SQL deletion request, including ordinary password-only authorization.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Scope                           | Existing privacy service/caller-owned transaction, specific deletion proof plus frozen earned session/grant/deadline/JKT, status/version/code revocation and notification/audit intent.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Explicit out of scope           | Duplicated deletion service, ARC/backup/repair grant reuse, weakening UV stronger route, shortening 30 days or releasing holds/username/reclaim factors.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Dependencies                    | T22A, T23A, T27A, T28A, T41A, T41B.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Security invariants             | SEC04, SEC07, SEC09, SEC10, SEC11, SEC12, SEC14.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Authorization requirements      | Existing stronger UV route retains its requirements; eligible ordinary password-only deletion uses its own fresh password+old-contact deletion purpose, never generic/contact-only authority.                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Functional acceptance           | T30A-F01: the deletion commit consumes exact authority, sets pending deletion, starts the original 30-day grace, advances the auth version, revokes both unspent saved-code families (`mfa_backup` and `arc`) and their derived grants, preserves username reservation and required reclaim factors, and queues immutable intent. From commit, live checks reject sessions, preauthentication, refresh exchanges and online access-token use bound to the old version even if post-commit session or refresh-family cleanup fails. Offline access-token validation retains only the original remaining lifetime, at most ten minutes. Already admitted requests may finish. |
| Security acceptance             | T30A-S01: stale/expired/revoked session/grant after lock wait, wrong action/JKT, recovery artifacts and unauthorized privileged downgrade cannot request deletion.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Unit tests                      | T30A-U01: strong versus password-specific admission, exact retained factor/hold/deadline/code lifecycle and post-commit response matrices pass.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Database/HTTP integration tests | T30A-I01: real SQL/HTTP final live evidence reaches deciding transaction; hold-aware purge, username reservation and nullable notification intents remain compatible.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Concurrency/failure tests       | T30A-X01: forced grant/session expiry/revoke while waiting, concurrent delete/repair/hold and unknown commit never drop bindings, retry authority or purge held data.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Browser/accessibility tests     | T30A-B01: GATE03 stronger deletion dialog offers no weaker fallback; confirmed/unconfirmed screens clear private state and say queued, not delivered.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Documentation updates           | T30A-D01: preserve 30-day/hold/retention distinctions and existing stronger contract; identify separate T30B/T41C reclaim/activation blockers.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Completion criteria             | T30A-C01: GATE01/GATE02/GATE03 and final-live-authority/retained-factor/hold evidence; no mobile-only launch yet.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |

### T30B

| Section                         | Requirement                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| ID/title                        | T30B - Cancel Deletion/Reclaim with Password or Mobile-Capable Lifecycle. Status: Planned.                                                                                                                                                                                                                                                                                                                                     |
| Objective                       | Complete the independent deletion-cancellation path for real verified available destinations and retained account factors.                                                                                                                                                                                                                                                                                                     |
| Scope                           | Existing /recover-account contract, immutable deletion token/recipient/deadline, password/passkey-appropriate retained factors, required MFA and verified SMS notification/reclaim support.                                                                                                                                                                                                                                    |
| Explicit out of scope           | Lost-factor ARC recovery, normal session issuance, contact-only reclaim, hold release, username transfer, token regeneration or grace extension.                                                                                                                                                                                                                                                                               |
| Dependencies                    | T30A, T29A, T29B, T29C, T41A, T41B, T17A.                                                                                                                                                                                                                                                                                                                                                                                      |
| Security invariants             | SEC02, SEC03, SEC04, SEC07, SEC10, SEC11, SEC12, SEC14.                                                                                                                                                                                                                                                                                                                                                                        |
| Authorization requirements      | Original valid deletion token plus independently retained eligible factor/current complete cancellation policy, exact pending-deletion subject/destination/deadline; no ARC/backup/repair substitution.                                                                                                                                                                                                                        |
| Functional acceptance           | T30B-F01: eligible email/mobile/password/passkey account cancellation restores allowed account state within the original grace and preserves the repair barrier. Cancellation issues no normal session. The pre-deletion auth version, sessions, refresh families and saved-code authority remain invalid. Online validation continues to reject pre-deletion access tokens and offline validation uses their original expiry. |
| Security acceptance             | T30B-S01: expired/spent/wrong token/contact/key/factor, insufficient required MFA, purged/banned state and consumer recovery grant are denied.                                                                                                                                                                                                                                                                                 |
| Unit tests                      | T30B-U01: retained factor/category/destination/deadline matrix includes pending deletion with nullable email and exact 30-day equality cutoff.                                                                                                                                                                                                                                                                                 |
| Database/HTTP integration tests | T30B-I01: real SQL/HTTP/verified selected-provider sink tests deletion/cancellation/purge/hold and all email/password/mobile combinations, preserving existing v1/v2 bytes/readers.                                                                                                                                                                                                                                            |
| Concurrency/failure tests       | T30B-X01: cancel versus purge/hold/factor change, duplicate token use and provider/commit uncertainty have one winner/no token/session recreation.                                                                                                                                                                                                                                                                             |
| Browser/accessibility tests     | T30B-B01: GATE03 fragment scrubbing/explicit action, no cookie/DPoP/grant leakage in anonymous reclaim, safe app switch and known versus unconfirmed outcomes.                                                                                                                                                                                                                                                                 |
| Documentation updates           | T30B-D01: complete password/mobile reclaim matrix, independent receipt/platform gates and original deadline/retained-factor/hold rules.                                                                                                                                                                                                                                                                                        |
| Completion criteria             | T30B-C01: GATE01/GATE02/GATE03 plus actual selected-channel receipt and lifecycle evidence; T41C alone can retire activation gate after review.                                                                                                                                                                                                                                                                                |

### T31

| Section                         | Requirement                                                                                                                                                                    |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| ID/title                        | T31 - Extend One Registration Service for Complete Fields and Selected Credentials. Status: Blocked by approved legal documents/full mobile lifecycle.                         |
| Objective                       | Implement the final contract in the existing service, with one verified contact and no code-only human accounts.                                                               |
| Scope                           | Mandatory private names/birthday/gender/username/location, one email OR mobile, password/passkey/both, approved terms/privacy versions and verified selected primary.          |
| Explicit out of scope           | Second service/client/versioned route, username-less production accounts, inferred old data, unselected fabricated contact, automatic both downgrade or code-family issuance.  |
| Dependencies                    | T01, T02, T03, T04A, T05, T06, T09, T10, T13, T14, T15, T19A, T23, T41C; external approved legal versions/source-data rights.                                                  |
| Security invariants             | SEC01, SEC02, SEC08, SEC12, SEC13, SEC15.                                                                                                                                      |
| Authorization requirements      | Original registration capability/JKT/attempt/deadlines; exact selected contact proof and server-verified selected primary, complete field/legal validation before native work. |
| Functional acceptance           | T31-F01: every supported final field/stage validates under existing authoritative validators; passkey/password/both require exactly corresponding credential inputs.           |
| Security acceptance             | T31-S01: missing username/contact/primary/legal acceptance, wrong proof/channel/key, unapproved legal versions and code-only/mismatched both inputs are denied.                |
| Unit tests                      | T31-U01: exact request subsets/unknown fields, selected-contact/credential matrices and unchanged T02/T05-T11/T15 rules pass.                                                  |
| Database/HTTP integration tests | T31-I01: real existing registration endpoints accept only final admitted contracts, preserve default-off incomplete composition and current concrete reader compatibility.     |
| Concurrency/failure tests       | T31-X01: resend/policy/catalog/legal changes, stale capability and unknown provider results never rebind candidate or extend attempt.                                          |
| Browser/accessibility tests     | T31-B01: N/A for API field contract; T34-T37 own GATE03 final six-stage implementation.                                                                                        |
| Documentation updates           | T31-D01: label exact mounted versus deferred API requests and selected-provider/legal/T41C prerequisites; public /register is unchanged.                                       |
| Completion criteria             | T31-C01: GATE01/GATE02, approved legal/data inputs and CP05 lifecycle evidence; final atomic birth/session remain T32/T33.                                                     |

### T32

| Section                         | Requirement                                                                                                                                                                                                                                                                 |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T32 - Commit One Atomic Account Birth. Status: Planned.                                                                                                                                                                                                                     |
| Objective                       | Ensure account/attributes/username/proofs/credentials/legal evidence/intents share one known deciding SQL transaction.                                                                                                                                                      |
| Scope                           | Existing registration store/service, final authoritative validation/locks, keyed password-bearing intent fingerprint, exact receipt/result reconciliation and creation metadata.                                                                                            |
| Explicit out of scope           | Two-phase partial account birth, account recreation by retry/result, unkeyed password digest, normal session T33 or exactly-once external delivery claim.                                                                                                                   |
| Dependencies                    | T31, T16A, T40B, T41A, T04A.                                                                                                                                                                                                                                                |
| Security invariants             | SEC01, SEC02, SEC09, SEC10, SEC11, SEC13, SEC14.                                                                                                                                                                                                                            |
| Authorization requirements      | Recheck original capability/JKT/contact proof/credential/policy/catalog/legal/deadline after locks; native/hash results are bound and earned outside long-held locks.                                                                                                       |
| Functional acceptance           | T32-F01: one commit persists all required birth rows/evidence/intent and explicit initial-contact exemption; no-op receipt/result reads mutate nothing.                                                                                                                     |
| Security acceptance             | T32-S01: expired/spent/wrong proof/key/policy/subject, equivalent-name loser or mismatched candidate cannot create partial account or attach credential to winner.                                                                                                          |
| Unit tests                      | T32-U01: keyed fingerprint/domain/candidate equality and full required-row/receipt invariants cover password/passkey/both. Password birth uses the shared exact-byte verifier and finite admission from T15, and stores no unkeyed password-bearing completion fingerprint. |
| Database/HTTP integration tests | T32-I01: real SQL failure injection at every write rolls back all birth rows/proofs/intents; successful commit produces exactly one expected subject.                                                                                                                       |
| Concurrency/failure tests       | T32-X01: separate-connection equivalent-username/contact/policy races have one winner; ambiguous commit reports known/absent/unknown read-only outcome without authority/recreation.                                                                                        |
| Browser/accessibility tests     | T32-B01: GATE03 explicit protected result checking never returns plaintext password/proof or authenticates receipt; no automatic native/body retransmission.                                                                                                                |
| Documentation updates           | T32-D01: publish deciding transaction/lock/fingerprint/unknown-outcome contract and actual stored compatibility inventory.                                                                                                                                                  |
| Completion criteria             | T32-C01: GATE01/GATE02/GATE03 and all-write rollback/one-birth/reconciliation-denial evidence, not only mock transactions.                                                                                                                                                  |

### T33

| Section                         | Requirement                                                                                                                                                                                |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| ID/title                        | T33 - Issue a Normal Session Only after Known Fresh Birth. Status: Planned.                                                                                                                |
| Objective                       | Bind authenticated completion to one known fresh successful account creation and original browser key.                                                                                     |
| Scope                           | Existing cookie-capable completion boundary, SQL-authoritative expected new subject/full-policy session and failed-delivery ordinary-login outcome.                                        |
| Explicit out of scope           | Session by result/receipt/replay/unknown commit, replacement browser key, guessed subject, account recreation or premature cookie.                                                         |
| Dependencies                    | T32, T16A, T17A, T21A.                                                                                                                                                                     |
| Security invariants             | SEC02, SEC03, SEC09, SEC10, SEC11, SEC13, SEC15.                                                                                                                                           |
| Authorization requirements      | Known fresh birth result with same original JKT and exact expected subject; current account/full-policy and session issuance checks use primary SQL.                                       |
| Functional acceptance           | T33-F01: only fresh successful completion may issue one normal session; failed issuance/delivery leaves committed account available for ordinary login.                                    |
| Security acceptance             | T33-S01: /result, repeated receipt/body, old completion, unknown birth and key/subject mismatch mint no session or new account.                                                            |
| Unit tests                      | T33-U01: fresh/replayed/known/absent/unknown birth and same/wrong JKT/subject cookie-capable matrices pass.                                                                                |
| Database/HTTP integration tests | T33-I01: real SQL/HTTP completion verifies strict cookies, original key, exact subject and complete admission; reconciliation response remains unauthenticated.                            |
| Concurrency/failure tests       | T33-X01: duplicate completions, role/revocation between birth/session and lost Set-Cookie response never produce replay authentication or recreated birth.                                 |
| Browser/accessibility tests     | T33-B01: GATE03 expected-subject bootstrap runs once after known fresh session; wrong subject/late reply/failed delivery goes to ordinary login, not portal.                               |
| Documentation updates           | T33-D01: exact fresh-only session and failed-delivery/result contracts in registration/API/client/readiness.                                                                               |
| Completion criteria             | T33-C01: GATE01/GATE02/GATE03 with replay/result/key/subject denials and fresh-only issuance evidence; CP06 registration and fresh-session authority reviewed. CP06b is outside this task. |

### T34

| Section                         | Requirement                                                                                                                                                                   |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T34 - Extend the Existing Six-Stage Form Shell. Status: Planned.                                                                                                              |
| Objective                       | Preserve ordinary progress and stable mounted security identities through navigation/preferences without replay.                                                              |
| Scope                           | Existing /register form stages: names, personal information, username, contact verification, authentication method, location/final review.                                    |
| Explicit out of scope           | Duplicate form/client/provider, enabling missing backend contracts, auto-send/native prompt, authority persistence or deadline extension.                                     |
| Dependencies                    | T01.                                                                                                                                                                          |
| Security invariants             | SEC13, SEC15.                                                                                                                                                                 |
| Authorization requirements      | Shell/draft progress earns no proof or session; security side effects require explicit user action/current ceremony.                                                          |
| Functional acceptance           | T34-F01: back/legal-link/language/calendar/timezone/theme navigation preserves ordinary field meaning while provider/JKT/attempt identity and original deadlines stay stable. |
| Security acceptance             | T34-S01: preference/render/remount/page-load effects cannot send/resend, invoke native credentials, rebootstrap, recover cleared secrets or renew authority.                  |
| Unit tests                      | T34-U01: stage reducer/provider identity and effect-call counts remain zero on preference/back navigation; secret cleanup generation guards ignore late replies.              |
| Database/HTTP integration tests | T34-I01: real API request counters observe zero security work on shell/preference transitions; N/A for new database writes.                                                   |
| Concurrency/failure tests       | T34-X01: double navigation/save/late reply, hide/pagehide/key loss and interrupted send preserve original lifetime and do not resume transmitted mutation.                    |
| Browser/accessibility tests     | T34-B01: GATE03 six-stage labels/progress/focus/back/reflow, disabled no-JS shell and both-locale stable-identity/deadline assertions pass.                                   |
| Documentation updates           | T34-D01: document current versus final shell, exact stage order and lifetime/privacy/navigation behavior in frontend/localization.                                            |
| Completion criteria             | T34-C01: GATE01/GATE02/GATE03 with stable identity/zero implicit side-effect evidence; final submit remains unavailable until T37.                                            |

### T35

| Section                         | Requirement                                                                                                                                                            |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T35 - Connect Personal and Username Controls. Status: Planned.                                                                                                         |
| Objective                       | Bind the existing shell to unchanged server validators with complete bilingual accessible feedback.                                                                    |
| Scope                           | Given/family names, exact date-only calendar input/pair, explicit gender and advisory username validation; typed status descriptors.                                   |
| Explicit out of scope           | New name/gender/geography/password rules, inferred defaults, DOB timestamp, client username regex or availability as reservation.                                      |
| Dependencies                    | T34, T31, T02, T03, T04A, T05, T06.                                                                                                                                    |
| Security invariants             | SEC01, SEC13, SEC14, SEC15.                                                                                                                                            |
| Authorization requirements      | Validation is advisory only; authoritative final birth revalidates every field/policy. Preferences affect presentation, not canonical values.                          |
| Functional acceptance           | T35-F01: field errors/normalized results match server validators, birthday keeps explicit calendar/date-only pair and gender has no preselection.                      |
| Security acceptance             | T35-S01: rejected private text never reaches catalogs/diagnostics/artifacts; stale availability or policy response cannot authorize ownership or silent normalization. |
| Unit tests                      | T35-U01: typed en/fa-IR catalog structure/ICU slots, validator response mappings, exact birthday bytes and non-default gender fixtures pass.                           |
| Database/HTTP integration tests | T35-I01: real validation calls bind current candidate and ignore stale replies; invalid/missing final fields remain denied by T31 independently of client state.       |
| Concurrency/failure tests       | T35-X01: overlapping validation/preferences/back edits retain current draft/message descriptor, no stale success or repeated API/native action.                        |
| Browser/accessibility tests     | T35-B01: GATE03 visible labels, first-error focus/status, Persian input/keyboard, isolated technical values and both date representations preserve meaning.            |
| Documentation updates           | T35-D01: frontend/localization exact controls and accessible names, no private-value catalog/allowlist expansion.                                                      |
| Completion criteria             | T35-C01: GATE01/GATE02/GATE03 and real validator/stale response/typed bilingual evidence, not disconnected fixture success.                                            |

### T36

| Section                         | Requirement                                                                                                                                                             |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T36 - Connect Selected Contact and Credential Choice. Status: Planned.                                                                                                  |
| Objective                       | Support explicit email/mobile and password/passkey/both within the same registration attempt and fixed deadlines.                                                       |
| Scope                           | Selected contact send/verify/resend, transient codes/passwords, paste/managers/client-only confirmation and explicit native enrollment after full candidate validation. |
| Explicit out of scope           | Auto-send/auto-submit/native effect, saved secret storage, normalization of password/saved-code bytes, both downgrade or weakened budgets.                              |
| Dependencies                    | T34, T31, T19A, T15, T39.                                                                                                                                               |
| Security invariants             | SEC02, SEC08, SEC11, SEC13, SEC15.                                                                                                                                      |
| Authorization requirements      | Original capability/JKT/selected destination/generation/deadline; credential choice does not replace actual primary/contact verification.                               |
| Functional acceptance           | T36-F01: selected channel only receives explicit bounded sends, exact codes verify, paste/managers work and both requires both despite native cancellation.             |
| Security acceptance             | T36-S01: preference/navigation/retry cannot extend original expiry, resend automatically, transfer proof/channel/key or silently fall back from both.                   |
| Unit tests                      | T36-U01: choice/state/deadline/provider identity, code digit conversion rules, exact password bytes and cancellation/late reply vectors pass.                           |
| Database/HTTP integration tests | T36-I01: real selected-channel flow preserves quotas/generations and rejects wrong destination/capability/JKT; provider ACK is not delivery UI success.                 |
| Concurrency/failure tests       | T36-X01: double send/verify, key change/hide/abort/provider uncertainty and locale switch never replay body/native assertion or resurrect cleared secrets.              |
| Browser/accessibility tests     | T36-B01: GATE03 paste/autofill/leading zero/password visibility, explicit native prompts and disabled no-JS states across both locales/palettes/viewports.              |
| Documentation updates           | T36-D01: selected-channel/native/byte/deadline behavior and real-provider/physical gates in frontend/localization/readiness.                                            |
| Completion criteria             | T36-C01: GATE01/GATE02/GATE03 plus actual selected-channel behavior, with physical/native and provider receipt evidence separately identified.                          |

### T37

| Section                         | Requirement                                                                                                                                                                                    |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T37 - Review and Complete One Registration. Status: Blocked by approved legal documents/fresh-session prerequisites.                                                                           |
| Objective                       | Validate complete final candidate before native work and enter existing portal only after one expected-subject bootstrap.                                                                      |
| Scope                           | IR location/ancestry, both date-only birthdays, approved configured legal links/separate acceptance, final review and known fresh-session handoff.                                             |
| Explicit out of scope           | Unapproved legal default, automatic both downgrade, /my-account route invention, receipt login, guessed subject or pre-bootstrap private SSR.                                                  |
| Dependencies                    | T35, T36, T09, T33, T39; external approved terms/privacy versions.                                                                                                                             |
| Security invariants             | SEC01, SEC11, SEC13, SEC14, SEC15.                                                                                                                                                             |
| Authorization requirements      | Server complete-candidate/legal validation before explicit native action; exact original JKT and known new subject/session before portal mount.                                                |
| Functional acceptance           | T37-F01: final review shows exact location and both birthdays, independent legal acceptance; after fresh completion old authority clears and existing portal bootstraps expected subject once. |
| Security acceptance             | T37-S01: invalid location/field/legal version, unknown/replayed completion, wrong subject/key and failed session delivery never enter portal or recreate account.                              |
| Unit tests                      | T37-U01: review/canonical legal tuples, validate-before-native order and once-only expected-subject handoff matrices pass.                                                                     |
| Database/HTTP integration tests | T37-I01: real full registration/birth/session/bootstrapped subject matches review and approved versions; result read cannot authenticate.                                                      |
| Concurrency/failure tests       | T37-X01: double final submit/native cancellation, policy/catalog/legal change and post-commit response loss produce one birth with explicit read-only result/ordinary-login paths.             |
| Browser/accessibility tests     | T37-B01: GATE03 final review/links/separate checkboxes, focus/status and preference/back preservation; full invalid candidate prevents native invocation.                                      |
| Documentation updates           | T37-D01: current portal route and full fresh-handoff/legal evidence in registration/frontend/client/readiness, supersede historical /my-account wording.                                       |
| Completion criteria             | T37-C01: GATE01/GATE02/GATE03, approved legal content and complete expected-subject real-stack evidence; CP06 registration and fresh-session authority reviewed. CP06b is outside this task.   |

### T38A

| Section                         | Requirement                                                                                                                                             |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T38A - Connect Normal Primary Login and MFA Backup UI. Status: Planned.                                                                                 |
| Objective                       | Present default discoverable passkey, explicit password/email identifier and independent TOTP/admitted backup without contact-only login.               |
| Scope                           | Existing login provider/client/routes, bounded primary/preauth UI, explicit backup-family alternative and exact expected-subject bootstrap.             |
| Explicit out of scope           | ARC as MFA, contact sign-in, lost-factor/deletion UI, automatic native/fallback, password reset-link recovery or duplicate auth provider.               |
| Dependencies                    | T18A, T21A, T28B, T39, T20.                                                                                                                             |
| Security invariants             | SEC01, SEC02, SEC03, SEC04, SEC05, SEC15.                                                                                                               |
| Authorization requirements      | Full authoritative normal admission only; preauth/partial evidence cannot mount portal. Native and code submits are explicit.                           |
| Functional acceptance           | T38A-F01: passkey default/password alternative and TOTP/backup completion match advertised policy; backup evidence is not described as TOTP.            |
| Security acceptance             | T38A-S01: contact-only/ARC/preauth/privileged downgrade and wrong-subject/key/expired response cannot bootstrap; no silent factor fallback.             |
| Unit tests                      | T38A-U01: advertised method/status/typed bilingual feedback and no automatic submit/native/bootstrap effect vectors pass.                               |
| Database/HTTP integration tests | T38A-I01: real login/MFA endpoints and strict cookie/JKT bootstrap enforce policy for password-only/passkey-only/both/required-MFA/privileged fixtures. |
| Concurrency/failure tests       | T38A-X01: duplicate/late/hidden/key-change replies, uncertain completion and locale switch never replay MFA/extend deadline/bootstrap stale subject.    |
| Browser/accessibility tests     | T38A-B01: GATE03 paste/managers/TOTP app-switch/backup exact bytes, both locales and physical prompt evidence remain separately recorded.               |
| Documentation updates           | T38A-D01: current normal/preauth/backup routes and no-contact-login terminology in frontend/localization/client.                                        |
| Completion criteria             | T38A-C01: GATE01/GATE02/GATE03 and real full-policy/no-premature-portal/explicit-action evidence.                                                       |

### T38B

| Section                         | Requirement                                                                                                                                                           |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T38B - Connect Lost-Factor and One-Repair UI. Status: Planned.                                                                                                        |
| Objective                       | Present restricted ARC+old-contact repair separately from normal login and deletion cancellation.                                                                     |
| Scope                           | Explicit ordinary repair journey, eligible/cooling/unknown contact states, one named repair, transient evidence and fresh normal-login terminal outcome.              |
| Explicit out of scope           | /recover-account reuse, promised total-loss rescue, portal/settings under repair grant, auto-repair/resend, second repair or privileged consumer recovery.            |
| Dependencies                    | T28C, T29A, T29B, T29C, T23A, T27A, T39.                                                                                                                              |
| Security invariants             | SEC04, SEC05, SEC06, SEC07, SEC08, SEC11, SEC15.                                                                                                                      |
| Authorization requirements      | Only server-admitted ordinary restricted grant, original JKT/target/ceremony deadline; TOTP replacement requires admitted pre-existing primary.                       |
| Functional acceptance           | T38B-F01: UI distinguishes ARC from backup, shows one bounded target repair and explicit fresh login; insufficient surviving factor/eligible contact remains blocked. |
| Security acceptance             | T38B-S01: recovery never mounts portal/general settings, extends ceremony, offers MFA downgrade or treats repaired primary as second-repair evidence.                 |
| Unit tests                      | T38B-U01: typed repair/unknown/cooling/barrier/category/result states, deadline caps and post-send interruption vectors pass.                                         |
| Database/HTTP integration tests | T38B-I01: real ARC/contact/grant/repair endpoints deny alternate normal/admin/deletion access; final known/unknown result paths match server.                         |
| Concurrency/failure tests       | T38B-X01: late/native/cancel/locale/key/role/contact changes and lost response clear authority without retransmission/regeneration/second repair.                     |
| Browser/accessibility tests     | T38B-B01: GATE03 explicit actions/focus/status/paste/secret masks and no private SSR; deliberate lockout explained in both locales without invented support bypass.   |
| Documentation updates           | T38B-D01: distinguish planned lost-factor route from existing /recover-account and truthful anti-chaining/total-loss/physical gates.                                  |
| Completion criteria             | T38B-C01: GATE01/GATE02/GATE03 and real restricted-route/one-repair/cooldown/barrier-denial evidence.                                                                 |

### T38C

| Section                         | Requirement                                                                                                                                                           |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T38C - Connect Factor, Contact and Code-Family Management. Status: Planned.                                                                                           |
| Objective                       | Expose only fresh authorized normal-session management and truthful independent code-family status/viewers.                                                           |
| Scope                           | Password/passkey/TOTP/contact management, last-factor/last-eligible/cooldown states, family generation/revoke and bounded explicit Copy/Download.                     |
| Explicit out of scope           | Barrier bypass, required-MFA/privileged downgrade, ARC mail/SMS, cached plaintext GET, support override, private-attribute editing or recovery as settings authority. |
| Dependencies                    | T24, T25, T26, T27A, T28A, T23A.                                                                                                                                      |
| Security invariants             | SEC01, SEC03, SEC04, SEC05, SEC07, SEC08, SEC15.                                                                                                                      |
| Authorization requirements      | Current normal session and exact fresh action/family purpose; barrier-set factor changes and gated email removal remain independently denied by backend.              |
| Functional acceptance           | T38C-F01: separate code family labels/counts, exact old/new contact steps and safe management show known/gated/cooling states without fabricated credentials.         |
| Security acceptance             | T38C-S01: buttons cannot bypass barrier/last-factor/MFA/contact gate; no auto-copy/download/regenerate or untyped-family authority reuse.                             |
| Unit tests                      | T38C-U01: advertised purposes/policy states, viewer generation/deadline and typed catalog/ARIA matrices pass.                                                         |
| Database/HTTP integration tests | T38C-I01: real management/family APIs enforce action targets and result policy regardless of hidden/disabled controls; intent/secret visibility is correct.           |
| Concurrency/failure tests       | T38C-X01: stale dialog/session/contact/role change, generation loss/late response and locale switch neither restore secrets/proofs nor reset barrier/viewer deadline. |
| Browser/accessibility tests     | T38C-B01: GATE03 destructive confirmation, separate family accessible names, exact LTR bytes, focus return and structural secret masks pass.                          |
| Documentation updates           | T38C-D01: management versus repair matrix, once-only viewer semantics and no clipboard/memory-zeroization promise in frontend/localization.                           |
| Completion criteria             | T38C-C01: GATE01/GATE02/GATE03 and alternate-management/barrier/last-contact plus once-only-viewer evidence.                                                          |

### T38D

| Section                         | Requirement                                                                                                                                                   |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T38D - Connect Private Attribute Editing. Status: Planned.                                                                                                    |
| Objective                       | Use exact private revisions and unchanged validators without mixing cosmetic display names or mutable usernames.                                              |
| Scope                           | Existing protected editor API/client, absent private fields/email, atomic birthdays/location, exact revisions and privacy clearing.                           |
| Explicit out of scope           | Security-factor management, username edit/claim, new product rules, JS-number revision, inferred old values or profile-as-authentication.                     |
| Dependencies                    | T11, T13.                                                                                                                                                     |
| Security invariants             | SEC01, SEC14, SEC15.                                                                                                                                          |
| Authorization requirements      | Live exact-subject/session/JKT private read/edit permission; normal bootstrap before private view and expected revision at save.                              |
| Functional acceptance           | T38D-F01: real edit/no-op/conflict follow T11; ordinary unsaved draft survives conflict/preference change and absent data stays absent.                       |
| Security acceptance             | T38D-S01: stale revision/wrong subject/private permission loss cannot display or save private data; username remains read-only and cosmetic name independent. |
| Unit tests                      | T38D-U01: exact large revision, birthday/calendar/no-op and typed bilingual absent/conflict message vectors pass.                                             |
| Database/HTTP integration tests | T38D-I01: real GET/PATCH validates exact same snapshot/revision and metadata-only intent without changing authentication/session lifetime.                    |
| Concurrency/failure tests       | T38D-X01: stale tabs/late reads/hide/key/session changes cannot overwrite confirmed edit or restore private state; uncertain write is not retried.            |
| Browser/accessibility tests     | T38D-B01: GATE03 both calendars/locales, names dir=auto/technical isolation, first-error focus and structural private masks pass.                             |
| Documentation updates           | T38D-D01: record actual private editor/absence/revision behavior and no legacy inference; preserve public display contract.                                   |
| Completion criteria             | T38D-C01: GATE01/GATE02/GATE03 and real exact-revision/privacy/no-op evidence; independent of code/recovery UI.                                               |

### T39

| Section                         | Requirement                                                                                                                                                                         |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T39 - Explain and Observe Authenticator Capability Truthfully. Status: Blocked by independent physical/platform evidence.                                                           |
| Objective                       | Distinguish API support, platform availability, RP credential ownership, actual UV and privileged hardware admission.                                                               |
| Scope                           | Explicit native prompts, capability/error guidance, Windows Hello/security-key/hybrid alternatives and separately observed physical acceptance.                                     |
| Explicit out of scope           | Web PIN/biometric collection, platform-check-as-credential evidence, disabling USB/hybrid on negative platform check or virtual-as-physical proof.                                  |
| Dependencies                    | None; external named device/platform/accessibility reviewers and supported physical devices.                                                                                        |
| Security invariants             | SEC02, SEC04, SEC15, SEC16.                                                                                                                                                         |
| Authorization requirements      | Capability earns no primary/UV/hardware authority; server-verified assertion/admission is decisive and native work follows explicit user action.                                    |
| Functional acceptance           | T39-F01: unsupported/unavailable/no-matching-credential/cancelled/UV-required states are distinct; alternatives remain usable without app collecting native secrets.                |
| Security acceptance             | T39-S01: page load/preferences cannot invoke native prompt; UV/AAGUID/transport/backup flags alone never advertise verified hardware.                                               |
| Unit tests                      | T39-U01: capability combinations, native errors, explicit-action call counts and no-PIN/biometric control inventory pass.                                                           |
| Database/HTTP integration tests | T39-I01: N/A for capability guidance persistence; linked T18/T25/T29B server integration proves actual UV independently.                                                            |
| Concurrency/failure tests       | T39-X01: negative capability/late native promise/hide/restart never triggers fallback/replay or changes original ceremony identity/deadline.                                        |
| Browser/accessibility tests     | T39-B01: GATE03 automated virtual tests plus separately recorded real Windows Hello, USB key, hybrid/mobile, screen reader/native-focus observations; virtual alone leaves Blocked. |
| Documentation updates           | T39-D01: source/version/device/OS/RP observations and residual limitations, no physical or hardware assurance inferred from UI label.                                               |
| Completion criteria             | T39-C01: GATE01/GATE03 and independent supported physical/platform/accessibility evidence recorded; all unobserved combinations stay explicit blockers.                             |

### T40A

| Section                         | Requirement                                                                                                                                                     |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T40A - Extend Exact Private Snapshots and Field Grants. Status: Planned.                                                                                        |
| Objective                       | Preserve the existing gRPC optional email/private snapshot contracts under actual consumer requirements.                                                        |
| Scope                           | Explicit per-field grants, exact same-snapshot private revision, minimized private values and inactive/deleted privacy behavior.                                |
| Explicit out of scope           | New audit format, protobuf email removal, fabricated identity/email, blanket profile grant, event private values or hypothetical consumers.                     |
| Dependencies                    | T11, T13, T16A, T17A.                                                                                                                                           |
| Security invariants             | SEC01, SEC04, SEC09, SEC14, SEC16.                                                                                                                              |
| Authorization requirements      | Exact admitted mTLS/service method and field grant plus live authoritative account/consumer policy; token principal type is not guessed from UUID shape.        |
| Functional acceptance           | T40A-F01: allowed fields and exact private revision come from one SQL snapshot; email present/absent wire semantics and omitted private fields remain truthful. |
| Security acceptance             | T40A-S01: unauthorized field/method/client, wrong human/workload type, inactive/deleted subject and stale privilege evidence deny disclosure.                   |
| Unit tests                      | T40A-U01: per-field/presence/privacy/status/principal matrices and large decimal revision schema/wire vectors pass.                                             |
| Database/HTTP integration tests | T40A-I01: real SQL/gRPC/mTLS consumer tests prove one-snapshot revision, optional protobuf presence and actual restricted grant denial.                         |
| Concurrency/failure tests       | T40A-X01: edit/deletion/role change during snapshot/consumer use never mixes revisions or preserves unauthorized cached fields; SQL outage denies.              |
| Browser/accessibility tests     | T40A-B01: N/A for service RPC; actual client presentation acceptance belongs to named consumer owners, not invented portal fixtures.                            |
| Documentation updates           | T40A-D01: inventory real consumers/fields/readers and contract compatibility; separate T42C assurance use-boundary prerequisite.                                |
| Completion criteria             | T40A-C01: GATE01/GATE02 with real consumer grants/one-snapshot/wire-preservation evidence; no blanket consumer readiness claim.                                 |

### T40B

| Section                         | Requirement                                                                                                                                                                          |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| ID/title                        | T40B - Define Security-Event Contracts and Compatible Readers First. Status: Planned.                                                                                                |
| Objective                       | Provide an early metadata-only event foundation before enabling new security-changing writers, avoiding notification/recovery cycles.                                                |
| Scope                           | Code family issue/revoke/use, ARC grant/repair, password/passkey/TOTP/contact/role/authority/deletion event obligations, stable IDs/revisions and immutable current formats/readers. |
| Explicit out of scope           | Private DOB/gender/location/codes/passwords/contact/secret payloads, new format solely for feature branding, writer implementation or delivery claim.                                |
| Dependencies                    | T16, T13.                                                                                                                                                                            |
| Security invariants             | SEC05, SEC10, SEC11, SEC14.                                                                                                                                                          |
| Authorization requirements      | Existing authenticated producer/consumer boundaries and caller-owned transactional intent; event receipt is information, not session/proof authority.                                |
| Functional acceptance           | T40B-F01: every required event has exact metadata/purpose/subject/revision/idempotency/intent rules and compatible current email-v1/private-profile-v2 readers.                      |
| Security acceptance             | T40B-S01: private values/secret hashes/recipient PII and event-to-authentication substitution are rejected; signed history/current readers are not rewritten.                        |
| Unit tests                      | T40B-U01: strict event schemas/allowlists, version/unknown-field handling and metadata-only redaction vectors pass.                                                                  |
| Database/HTTP integration tests | T40B-I01: existing transactional outbox plus actual reader/consumer contract tests prove compatible metadata handling before new writers activate.                                   |
| Concurrency/failure tests       | T40B-X01: duplicate/out-of-order/broker-restart/revision gap and rollback reader tests never claim delivered/chained/authorized from queued intent.                                  |
| Browser/accessibility tests     | T40B-B01: N/A for event foundation; downstream UI must consume descriptors, not private event bodies/authority.                                                                      |
| Documentation updates           | T40B-D01: API/data/client security-event inventory and reader-first rollout/rollback, separate private snapshot T40A.                                                                |
| Completion criteria             | T40B-C01: GATE01/GATE02 with actual format/reader compatibility and complete event-obligation coverage; no dependency on future repair writers.                                      |

### T41A

| Section                         | Requirement                                                                                                                                                                                           |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T41A - Build Verified-Destination Notification Foundation. Status: Planned.                                                                                                                           |
| Objective                       | Notify actual verified available email/mobile destinations with immutable work and truthful transport outcomes.                                                                                       |
| Scope                           | Event-to-template/recipient rules, selected-provider email/SMS capabilities, reader-first encrypted intent/worker, locale/template/token/deadline snapshot and least-privilege delivery.              |
| Explicit out of scope           | ARC delivery, fabricated mailbox/empty digest, queue rewrite, automatic uncertain token regeneration, provider-install authorization or exactly-once delivery.                                        |
| Dependencies                    | T40B, T13, T14, T19A; external approved selected-provider/templates/data processing.                                                                                                                  |
| Security invariants             | SEC05, SEC08, SEC10, SEC11, SEC12, SEC14, SEC15.                                                                                                                                                      |
| Authorization requirements      | Server-selected existing verified recipient policy, compatible readers before writers and committed deciding-transaction intent; delivery cannot earn normal/recovery authority.                      |
| Functional acceptance           | T41A-F01: required events select approved verified recipients, freeze each original recipient/token/locale/template/deadline and report queued/accepted/delivered/failed/unknown distinctly.          |
| Security acceptance             | T41A-S01: unverified/unknown destination, ARC content, malformed version/envelope and incompatible reader fail closed without PII/secret diagnostics.                                                 |
| Unit tests                      | T41A-U01: email/mobile/null-primary/configured-backup verified eligibility, strict v1/v2/template/locale bindings and message size/HTML isolation vectors pass.                                       |
| Database/HTTP integration tests | T41A-I01: real SQL/worker/provider sinks prove least-privilege immutable intent/readers and selected-channel notification coverage before dependent writer enablement.                                |
| Concurrency/failure tests       | T41A-X01: leases/retries/restart/rollback/provider-unknown preserve stable message bytes/token/deadline and no unauthorized new delivery/authority; contact changes do not rewrite queued recipients. |
| Browser/accessibility tests     | T41A-B01: N/A for worker; bilingual templates require independent Persian security/legal review and actual mailbox/SMS receipt, not screenshot/catalog proof.                                         |
| Documentation updates           | T41A-D01: recipient/event obligations, provider status, v1/v2-first rollback and current mailbox-only versus target mobile capabilities recorded.                                                     |
| Completion criteria             | T41A-C01: GATE01/GATE02, approved verified-recipient/templates and actual selected-channel receipt; existing nullable mailbox support alone is insufficient.                                          |

### T41B

| Section                         | Requirement                                                                                                                                                           |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T41B - Preserve Nullable Stable Audit Attribution and Security Coverage. Status: Planned.                                                                             |
| Objective                       | Cover security operations without email-dependent attribution or rewritten immutable audit/ledger history.                                                            |
| Scope                           | Existing nullable account_ref/user attribution, NULL-aware identity_blind_index, canonical formats/leaves/readers and event-to-audit coverage inventory.              |
| Explicit out of scope           | Empty-email digest, raw PII/secrets in audit, new canonical format, retention/hold changes, automatic attribution from CLIENT UUID or universal anonymity guarantee.  |
| Dependencies                    | T40B, T13, T14.                                                                                                                                                       |
| Security invariants             | SEC10, SEC12, SEC14.                                                                                                                                                  |
| Authorization requirements      | Existing recorder/worker/ledger grants, exact stable human account identity and privacy scope; attribution/disclosure requires current legal permissions.             |
| Functional acceptance           | T41B-F01: every required security event has metadata-only audit/ledger attribution with true NULL email handling; deletion leaves existing signed chain verifiable.   |
| Security acceptance             | T41B-S01: fabricated identity/empty digest/raw secret/private attribute and forbidden disclosure are rejected; nullable user FK never changes signed canonical bytes. |
| Unit tests                      | T41B-U01: present/NULL email, stable account_ref, canonical serialization/user_id exclusion and allowlist coverage vectors pass.                                      |
| Database/HTTP integration tests | T41B-I01: real signer/ledger/audit/deletion tests preserve existing v1/v2 formats, legal holds and nullable account attribution; no silent event omissions.           |
| Concurrency/failure tests       | T41B-X01: concurrent writers/signing/purge/broker loss and audit intent failure preserve atomic mutation rollback/metadata intent and truthful unavailable coverage.  |
| Browser/accessibility tests     | T41B-B01: N/A for audit pipeline; existing admin/legal GATE03 tests must preserve exact UTC/revisions/structural masks when affected.                                 |
| Documentation updates           | T41B-D01: inventory exact security-event coverage, nullable attribution and retained pseudonymized metadata without claiming new legal approval.                      |
| Completion criteria             | T41B-C01: GATE01/GATE02 and actual signer/NULL/coverage/rollback evidence; no history rewrites or invented retention approval.                                        |

### T41C

| Section                         | Requirement                                                                                                                                                                                             |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T41C - Retire T27 Gate Only after Complete Email-Absent Lifecycle. Status: Blocked by independent lifecycle/receipt approval.                                                                           |
| Objective                       | Bound activation review for present-email removal and password/mobile-only production eligibility, not implement missing dependencies.                                                                  |
| Scope                           | Independent recovery/notification/audit/deletion/cancellation/identifier/contact-cooldown acceptance and owner-approved non-destructive activation/rollback.                                            |
| Explicit out of scope           | Missing capability implementation, gate removal on fixtures alone, dataset/account cleanup, weakening cooldown/last eligible contact or changing queued bytes.                                          |
| Dependencies                    | T18A, T27A, T28C, T29A, T29B, T29C, T30A, T30B, T41A, T41B; external provider/governance/CP05 approval.                                                                                                 |
| Security invariants             | SEC01, SEC04, SEC06, SEC07, SEC08, SEC11, SEC12, SEC14.                                                                                                                                                 |
| Authorization requirements      | Explicit owner activation approval after all evidence; current gate remains enforced until verified safe lifecycle for eligible ordinary accounts, with privileged policy unchanged.                    |
| Functional acceptance           | T41C-F01: approved present-email removal retains mandatory username/verified contact/last eligible destination and every password/mobile lifecycle; safe rollback retains accepted queued/reclaim work. |
| Security acceptance             | T41C-S01: any missing recovery/receipt/reclaim/notification/reader evidence keeps gate closed; unknown provenance/last eligible loss or privilege downgrade is denied even after retirement.            |
| Unit tests                      | T41C-U01: eligibility/gate matrix covers present/NULL email, credential/MFA/category and all missing-prerequisite combinations.                                                                         |
| Database/HTTP integration tests | T41C-I01: real combined email-absent lifecycle from contact removal through notification/recovery/deletion/cancel/hold/purge proves complete compatible contracts.                                      |
| Concurrency/failure tests       | T41C-X01: activation/rollback across replicas, stale writers, contact/role change and queued reader rollback preserve gated denial or admitted complete lifecycle, never partial enablement.            |
| Browser/accessibility tests     | T41C-B01: GATE03 full email-absent primary/recovery/deletion/return flows and independent real SMS/mail receipt/physical/Persian review evidence.                                                       |
| Documentation updates           | T41C-D01: record exact approved activation source/evidence/remaining blockers and compatible rollout/rollback without claiming deployment performed.                                                    |
| Completion criteria             | T41C-C01: GATE01/GATE02/GATE03 and CP05 explicit approval; unobserved lifecycle or provider evidence remains Blocked, no implicit T31 activation.                                                       |

### T42A

| Section                         | Requirement                                                                                                                                                                                        |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T42A - Persist OAuth Grants and Authenticate Confidential Exchanges. Status: Planned.                                                                                                              |
| Objective                       | Close the bounded existing token-service authority prerequisite before final integration.                                                                                                          |
| Scope                           | Primary-SQL authorization-code/refresh-family/replay/revocation/JKT/PKCE authority and admitted confidential-client authentication at code/refresh exchange.                                       |
| Explicit out of scope           | Interactive consent T42B, new grant types, workload-to-human fabrication, Redis-earned grants, client-authentication bypass by PKCE or cookie proof claimed RFC 9449.                              |
| Dependencies                    | T16A, T17A, T40B.                                                                                                                                                                                  |
| Security invariants             | SEC04, SEC09, SEC10, SEC11, SEC16.                                                                                                                                                                 |
| Authorization requirements      | Exact admitted client/auth method/assertion/issuer/audience/key/replay, code/refresh/client/redirect/PKCE/JKT/scope/subject/version/deadline in deciding primary-SQL exchange.                     |
| Functional acceptance           | T42A-F01: code/refresh authority survives restart under SQL truth; confidential exchanges authenticate client as well as PKCE/key binding; CLIENT workload remains separate.                       |
| Security acceptance             | T42A-S01: missing/wrong confidential credential, cross-client/code/redirect/PKCE/JKT, spent/revoked/expired grant or forged Redis/CLIENT-as-human is denied.                                       |
| Unit tests                      | T42A-U01: confidential auth/assertion/replay and public-versus-confidential code/refresh/DPoP matrices match current admitted protocol profile.                                                    |
| Database/HTTP integration tests | T42A-I01: real SQL/token HTTP code/refresh one-use, breach revocation, client authentication and live account/version validation across replicas.                                                  |
| Concurrency/failure tests       | T42A-X01: simultaneous code/refresh reuse, role/revoke/Redis loss/stale replica/ambiguous commit produce no restored grant/new authority; preserve existing key-bound controls.                    |
| Browser/accessibility tests     | T42A-B01: N/A for token exchange service; T42B owns interactive browser flow and real consumers validate their token profile independently.                                                        |
| Documentation updates           | T42A-D01: scoped OAuth BCP/RFC9449/current draft distinctions, durable token facts and confidential exchange requirements with no finalized OAuth 2.1 claim.                                       |
| Completion criteria             | T42A-C01: GATE01/GATE02, CP06b token-exchange authority reviewed, and actual durable token/confidential negative evidence; missing interactive/consumer/restore work is not folded into this task. |

### T42B

| Section                         | Requirement                                                                                                                                                                            |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T42B - Complete Interactive OIDC Authorization and Consent. Status: Planned.                                                                                                           |
| Objective                       | Implement the separately bounded existing IdP interactive prerequisite with full-policy human authority.                                                                               |
| Scope                           | Existing authorization endpoint/client contracts, admitted redirect/PKCE/state/nonce/scope, fresh complete-policy session, consent/cancel/error and durable T42A code grant.           |
| Explicit out of scope           | New registration/auth service, open redirects, implicit consent, recovery/preauth as authorization, unapproved scopes or workload-to-human conversion.                                 |
| Dependencies                    | T42A, T18A, T21A, T17A.                                                                                                                                                                |
| Security invariants             | SEC01, SEC02, SEC03, SEC04, SEC09, SEC10, SEC15, SEC16.                                                                                                                                |
| Authorization requirements      | Exact registered client/redirect/request binding and live normal complete-policy human session; consent disclosure/decision is purpose-scoped, never cached authority.                 |
| Functional acceptance           | T42B-F01: approved interactive request reaches explicit consent and one bound SQL code; rejection/cancel/error discloses no private account data or grants.                            |
| Security acceptance             | T42B-S01: recovery/preauth/stale session, wrong redirect/client/PKCE/nonce/state, unauthorized scope and privileged insufficient evidence are denied.                                  |
| Unit tests                      | T42B-U01: request/redirect/PKCE/consent/state/principal validation and typed en/fa-IR messages/ARIA vectors pass.                                                                      |
| Database/HTTP integration tests | T42B-I01: real authorization/consent/token HTTP flow validates exact durable grant and client/subject/session policy without open redirects.                                           |
| Concurrency/failure tests       | T42B-X01: repeated consent, session/role/client policy change and unknown grant commit never reissue code/consent authority or silently change scope.                                  |
| Browser/accessibility tests     | T42B-B01: GATE03 real interactive login/consent/cancel/error, explicit accessible approved-client/scope names, stable locale/provider and no private SSR.                              |
| Documentation updates           | T42B-D01: mark actual mounted consent/routes versus planned, OIDC Core/BCP obligations and distinct workload clients.                                                                  |
| Completion criteria             | T42B-C01: GATE01/GATE02/GATE03, CP06b interactive OIDC authority reviewed, with real IdP flow and complete-policy/redirect/scope negative evidence; no downstream acceptance inferred. |

### T42C

| Section                         | Requirement                                                                                                                                                                                 |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T42C - Enforce Evidence-Bearing Privileged Consumer Admission. Status: Planned.                                                                                                             |
| Objective                       | Ensure actual HTTP/gRPC/OAuth consumers cannot treat roles or low-assurance tokens as verified privileged authority.                                                                        |
| Scope                           | Actual consumer inventory, exact issuer/subject/principal/evidence profile, hardware+independent-backup policy and live revocation/version/use boundaries.                                  |
| Explicit out of scope           | Hypothetical consumer implementation, offline role-only privilege, UUID-shaped CLIENT human lookup, generic assurance label or consumer recovery bypass.                                    |
| Dependencies                    | T17A, T40A, T42A, T42B; external actual consumer owners/profile agreement.                                                                                                                  |
| Security invariants             | SEC03, SEC04, SEC09, SEC14, SEC16.                                                                                                                                                          |
| Authorization requirements      | Exact admitted issuer/audience/(iss,sub)/principal/service grant plus authoritative earned hardware/independent evidence and current role/policy at privileged use.                         |
| Functional acceptance           | T42C-F01: each verified real consumer enforces its agreed evidence profile and revocation; ordinary/workload profiles cannot upgrade to privileged human.                                   |
| Security acceptance             | T42C-S01: role-only/password/contact/backup-downgrade/recovery/preauth/unknown hardware or stale account policy tokens fail privileged admission.                                           |
| Unit tests                      | T42C-U01: consumer evidence/principal/audience/issuer/version and all low-assurance deny vectors pass in actual consumers or agreed test harnesses.                                         |
| Database/HTTP integration tests | T42C-I01: real mTLS/HTTP/gRPC/token consumer boundaries validate exact profiles/live revocation and field grants, not just IdP token creation.                                              |
| Concurrency/failure tests       | T42C-X01: role/hardware/backup/trust revocation, stale caches/replicas and authority outage deny privileged use; no cached-role fallback.                                                   |
| Browser/accessibility tests     | T42C-B01: GATE03 applies to actual privileged web consumers; N/A for non-browser workloads, with owner-recorded API denial instead.                                                         |
| Documentation updates           | T42C-D01: inventory actual consumers/profiles/owners/use boundaries/residual offline risks and no unsupported AAL/FAL guarantee.                                                            |
| Completion criteria             | T42C-C01: GATE01/GATE02, CP06b privileged-consumer authority reviewed, and actual consumer-owner denial/revocation evidence; missing consumers or unobserved privileged use remain Blocked. |

### T42D

| Section                         | Requirement                                                                                                                                                                                        |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T42D - Protect Security Authority during Failover and Restore. Status: Planned.                                                                                                                    |
| Objective                       | Prevent restored snapshots/stale replicas from resurrecting spent codes, old credentials, sessions, replay or cleared repair barriers.                                                             |
| Scope                           | Primary-only authority reads, acknowledged-write durability/failover fencing, independent rollback witness or safely invalidating affected authority, quarantine and read-only reconciliation.     |
| Explicit out of scope           | Claiming deployed zero-loss/synchronous HA, restored in-database epoch as independent witness, treating session purge alone as safe restore or production failover/destructive recovery execution. |
| Dependencies                    | T16A, T19A, T21A, T23A, T28A, T42A; external approved topology/independent witness/recovery design.                                                                                                |
| Security invariants             | SEC07, SEC08, SEC09, SEC10, SEC11, SEC12, SEC16.                                                                                                                                                   |
| Authorization requirements      | Restore/failover is separately authorized operational work; authority stays closed/quarantined until independently reconciled security mutations or approved safe invalidation is proven.          |
| Functional acceptance           | T42D-F01: approved failover/restore design preserves contact history/deadlines/holds/username and never accepts rolled-back session/credential/code/replay/token/barrier authority.                |
| Security acceptance             | T42D-S01: stale primary/replica, split brain, post-backup spent/revoked state and unavailable independent witness keep issuance/use blocked.                                                       |
| Unit tests                      | T42D-U01: authority epoch/witness/quarantine and restored-state discrepancy/reconciliation matrices deny missing/unknown evidence.                                                                 |
| Database/HTTP integration tests | T42D-I01: disposable real SQL restore/failover/HTTP tests include post-backup password/key/code/TOTP/barrier/token/contact changes, not only sessions.                                             |
| Concurrency/failure tests       | T42D-X01: acknowledged-write loss, replication lag, concurrent failover/security writes and unknown reconciliation outcomes cannot reissue earned authority; measure fencing/contention.           |
| Browser/accessibility tests     | T42D-B01: N/A for operational control; affected browser requests must show unavailable/relogin without automatically retrying or restoring private state.                                          |
| Documentation updates           | T42D-D01: topology/primary-read/pooling/index/contention/rollback witness/quarantine runbooks and observed versus proposed DR evidence.                                                            |
| Completion criteria             | T42D-C01: GATE01/GATE02 and independently witnessed disposable rollback/restore-denial evidence; unobserved deployed topology remains a separate launch gate.                                      |

### T42

| Section                         | Requirement                                                                                                                                                                                                                                                                                                                                                    |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ID/title                        | T42 - Independently Integrate and Verify the Final Combined Target. Status: Blocked by all executable prerequisites and independent release gates.                                                                                                                                                                                                             |
| Objective                       | Close only observed final security/readiness evidence, never implicitly implement missing prerequisites.                                                                                                                                                                                                                                                       |
| Scope                           | Final combined integration, traceable SEC/test/control matrix, review/scan/abuse/rollback evidence and non-destructive documented rollout/rollback.                                                                                                                                                                                                            |
| Explicit out of scope           | Missing feature implementation, deployment/reset/Git mutations, silent critical/high risk acceptance, fixture-as-human/provider evidence or compliance certification.                                                                                                                                                                                          |
| Dependencies                    | T01, T02, T03, T04A, T04B, T05, T06, T07, T08, T09, T10, T11, T13, T14, T15, T16, T16A, T17, T17A, T18, T18A, T19, T19A, T20, T21, T21A, T22, T22A, T23, T23A, T24, T25, T26, T27, T27A, T28A, T28B, T28C, T29A, T29B, T29C, T30A, T30B, T31, T32, T33, T34, T35, T36, T37, T38A, T38B, T38C, T38D, T39, T40A, T40B, T41A, T41B, T41C, T42A, T42B, T42C, T42D. |
| Security invariants             | SEC01-SEC16.                                                                                                                                                                                                                                                                                                                                                   |
| Authorization requirements      | Independent CP07 review and explicit owner approval of source-bound architecture/evidence/risk decisions; documentation never grants runtime or privileged authority.                                                                                                                                                                                          |
| Functional acceptance           | T42-F01: all supported ordinary/privileged/workload registration/login/MFA/code/repair/contact/private/deletion/IdP/consumer lifecycles match one approved contract and DAG.                                                                                                                                                                                   |
| Security acceptance             | T42-S01: all matrix deny outcomes observed; no unresolved critical/high auth/recovery/authorization/credential/session issue is silently accepted; exceptions need explicit documented owner risk acceptance.                                                                                                                                                  |
| Unit tests                      | T42-U01: complete focused/unit/property/fuzz matrix, truthful evidence, exact bytes/revisions/purpose bindings and supply-chain/dependency/secret/SAST/container scan results recorded.                                                                                                                                                                        |
| Database/HTTP integration tests | T42-I01: current resolved CI real SQL/HTTP/gRPC/NATS/Redis suites and complete nullable lifecycle/token/consumer admission pass with exact expected inventories and zero mandatory skips.                                                                                                                                                                      |
| Concurrency/failure tests       | T42-X01: current 13-package race matrix plus one-winner/barrier/cooldown/SQL-Redis forgery-loss/unknown-commit/stale replica/failover/restore adversarial coverage, DAST/abuse penetration testing and independent review recorded.                                                                                                                            |
| Browser/accessibility tests     | T42-B01: GATE03 actual bilingual full journeys plus independently observed real email/SMS, Windows Hello/physical keys, screen reader/native zoom/bfcache, Persian security/legal and deployed ingress/redaction gates.                                                                                                                                        |
| Documentation updates           | T42-D01: readiness/alignment/README/API/policy/ADR/install/DR and task status evidence include exact source/toolchain/command/exits/identities, remaining blockers and approved rights/legal documents.                                                                                                                                                        |
| Completion criteria             | T42-C01: GATE01/GATE02/GATE03, CP01-CP07 and CP06b, every prerequisite criterion and independent observed release gate pass; any not-run/failed/unknown/unsupported source remains explicit Blocked, not launch authorization.                                                                                                                                 |

## Preserved Historical Definitions

This appendix is **non-executable historical evidence**, not another task list.
The original Scope and Acceptance text is reproduced unchanged below for every
defined T01-T27 record. T12 never had an executable section in the inspected
original; its excluded status is preserved. The current policy and executable
records above resolve active conflicts. No historical wording authorizes legacy
claim, contact-only login, UP-only login or a second registration contract.

| Historical ID / Original Title                       | Original Scope                                                                                                                                                                                                 | Original Acceptance                                                                                                                                                                                                                                                                                                | Resolution / Evidence                                                                                                                                               |
| ---------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T01 - Define the Existing Registration Contract      | Define the final fields, stages, and requests for the existing registration implementation. Do not implement the other features.                                                                               | One agreed contract covers names, birthday, gender, username, contact, authentication method, location, and legal acceptance. There is no second registration service or versioned registration route.                                                                                                             | H01; contract completion only; target alignment T01/T31-T33.                                                                                                        |
| T02 - Validate Given and Family Names                | Implement required Persian-script names, permitted spaces/contextual ZWNJ, and consistent Persian/Arabic Yeh/Kaf normalization.                                                                                | Invalid and missing names are rejected with focused Unicode tests. Existing public/cosmetic `display_name` validation is unchanged.                                                                                                                                                                                | H01; definition preserved, target unchanged.                                                                                                                        |
| T03 - Validate Usernames                             | Implement 7..40 canonical Unicode code points, Persian letters by default, explicit Latin mode, rejection of all numeral scripts and underscores, and the approved dot/ZWNJ rules.                             | Return validated display and canonical values with boundary, normalization, mixed-script, and Unicode rejection tests. Do not add registration endpoints in this task.                                                                                                                                             | H01; original status already superseded syntax by configured policy; current T03 and registration namespace govern.                                                 |
| T04 - Index and Reserve Usernames                    | Add a dedicated domain-separated HMAC lookup key and database uniqueness for canonical usernames. Reserve reviewed system/support names.                                                                       | Every surviving account row reserves its username through suspension and pending/soft deletion. Only hard deletion releases it. Renaming is not supported. No transparent lookup-key rotation or generic mailbox normalization is introduced.                                                                      | H01; approval/inventory still blocked, not Completed.                                                                                                               |
| T05 - Validate Date-Only Birthdays                   | Accept an explicit Gregorian/Jalali input calendar, normalize permitted numeric date digits, and use one pinned/reviewed converter.                                                                            | Validate Gregorian dates from `1900-01-01` through the current server-side Tehran civil date. Produce equivalent Gregorian/Jalali date-only values, including leap boundaries. Never parse or store DOB as a timestamp.                                                                                            | H02; definition preserved, target unchanged.                                                                                                                        |
| T06 - Require Explicit Gender                        | Accept exactly `female` and `male` without a preselected value.                                                                                                                                                | Missing or unsupported new-registration values are rejected. An unset legacy value remains unset rather than being inferred or backfilled.                                                                                                                                                                         | H02; original word legacy denotes actual absence, not an authorized legacy-account lane; definition unchanged.                                                      |
| T07 - Export IranData Safely                         | Prepare a checksummed reference-data export from local SQL Server `.` using Windows integrated authentication and database `IranData`.                                                                         | Access `dbo.CenterType` and `dbo.CityData` with SELECT-only operations. Preserve observed source IDs, labels, and hierarchy. Do not write to the source or check in its dataset without usage/redistribution permission.                                                                                           | No original explicit status; definition unchanged, separate actual source access/rights required.                                                                   |
| T08 - Import Geography into PostgreSQL               | Add reference tables and a transactional, repeatable importer that preserves source identities.                                                                                                                | Reject missing parents, cycles, duplicate IDs, and incorrect province ancestry. Preserve retired references instead of deleting places used by saved accounts. No production identity request depends on the developer SQL Server.                                                                                 | No original explicit status; definition unchanged and actual catalog source capability retained.                                                                    |
| T09 - Search Provinces and Localities                | Add bounded province/locality search using the PostgreSQL catalog and original source labels.                                                                                                                  | Support only country `IR`, require a province, allow an optional related locality, distinguish duplicate names, and resolve saved retired IDs. Do not fabricate translations or silently rename a source type as a city.                                                                                           | No original explicit status; definition unchanged, actual selector/readers retained.                                                                                |
| T10 - Store Protected Private Attributes             | Store names, the atomic birthday pair, gender, and location using authenticated account/purpose-bound encryption. The existing protected username assignment remains the sole source of username display data. | No duplicate plaintext DOB/gender/location columns are introduced. Protected values cannot be substituted across accounts or purposes. Public display names remain independent.                                                                                                                                    | No original explicit status; definition unchanged; current private-data service is not described as absent merely because signup collection is deferred.            |
| T11 - Read and Edit Private Attributes               | Add authenticated private-data GET/PATCH behavior with exact decimal revisions and optimistic concurrency.                                                                                                     | A real edit commits the data, one revision increment, and one metadata-only intent together. A no-op changes none of them. Birthday representations are updated atomically and stale edits fail safely.                                                                                                            | No original explicit status; definition unchanged, current revision/no-op/readers preserved.                                                                        |
| T12 - Excluded Username Claim                        | No original executable Scope.                                                                                                                                                                                  | Original purpose excluded one-time legacy username claim; users choose usernames during registration.                                                                                                                                                                                                              | AGENTS.md and SEC01; no executable node/dependency/endpoint.                                                                                                        |
| T13 - Represent Absent Email Truthfully              | Prepare models, adapters, bootstrap, and presentation for optional email, then remove the database's mandatory-email constraint when readers are compatible.                                                   | Absence is represented by NULL/typed absence, not a placeholder mailbox or empty string. Existing readers compile and pass present/absent tests. Phone-only registration is not enabled by this task alone.                                                                                                        | No original explicit status; preserve actual nullable support/optional protobuf, T41C still governs activation.                                                     |
| T14 - Persist Contact Verification Evidence          | Bind verification provenance to the exact canonical email/mobile destination and server verification time.                                                                                                     | Account status or a populated contact is not treated as proof of ownership. Unknown legacy provenance remains unknown. Contact changes invalidate incompatible proofs.                                                                                                                                             | No original explicit status; retain unknown-as-unknown, add T27A eligibility/cooldown.                                                                              |
| T15 - Bound Password Policy and Hashing              | Implement new-password validation and shared finite Argon2 admission.                                                                                                                                          | Require at least 15 Unicode code points and at most 1024 UTF-8 bytes, reject reviewed local compromised choices, and preserve exact bytes including spaces. Stored legacy hashes are verified without applying new creation-strength rules. Cancellation does not release a hash slot while computation continues. | No original explicit status; unchanged actual stored-hash dependency, not speculative compatibility.                                                                |
| T16 - Record Earned Session Authentication           | Extend the current session machinery with truthful authentication method, actual assertion UV, independent MFA completion, and authentication time.                                                            | Available factors do not become earned evidence. Unknown legacy evidence is not fabricated. Any actual stored-record compatibility requirement is handled within the existing implementation rather than creating a parallel registration/session system.                                                          | No original explicit status; T16A adds SQL authority and distinct backup truth.                                                                                     |
| T17 - Fence Role Changes and Session Use             | Check authoritative account/MFA/privileged policy at issuance and relevant session/token use boundaries. Invalidate old authority on actual role changes.                                                      | Promotion cannot upgrade a low-assurance session into administrative authority. No-op role changes do not revoke unnecessarily. Checks apply even when the administrative HTTP feature is disabled.                                                                                                                | No original explicit status; T17A adds verified hardware and independently enrolled backup.                                                                         |
| T18 - Implement Password Login                       | Add username identification and an explicit legacy-email identification path using the existing session and browser-proof infrastructure.                                                                      | Missing-account and wrong-password failures do not enumerate accounts. Required MFA produces only bounded preauthentication, never a premature normal session.                                                                                                                                                     | No original explicit status; legacy label superseded by intentional current verified unique primary-email identification T18A; retain independent preauth strength. |
| T19 - Implement Purpose-Isolated Contact Codes       | Add email/SMS code issuance and verification with keyed code protection, quotas, original expiry, and one-time consumption.                                                                                    | Registration, login, and sensitive-action purposes cannot exchange authority. A disabled alternate provider does not disable the selected channel. Unknown delivery or commit results do not trigger automatic unsafe retries.                                                                                     | No original explicit status; T19/T19A preserve isolation, T20 denies login authority by contact alone.                                                              |
| T20 - Sign In through Verified Contact               | Permit contact-code login for passkey-only, password-only, and dual-credential accounts through the identified account's already verified destination.                                                         | A shared mobile number cannot select an arbitrary account. Contact-only authentication cannot bypass mandatory MFA or privileged protections. Session evidence truthfully records contact-code authentication.                                                                                                     | No original explicit status; normal/contact login definition superseded by SEC02/T20 denial, not relabeled Completed.                                               |
| T21 - Complete Login MFA                             | Complete bounded password/contact-code preauthentication using the existing independent TOTP factor and shared replay protection.                                                                              | No normal cookie exists before success and final account-policy validation. Browser/account/version binding, original expiry, attempts, and single-use completion remain enforced.                                                                                                                                 | No original explicit status; contact-primary branch superseded by eligible primary only; T21A supplies durable completion/replay.                                   |
| T22 - Authorize One Sensitive Action                 | For eligible password-only accounts, combine fresh password verification and an OTP to their verified contact into a narrowly scoped action proof.                                                             | Bind account, session, JKT, earned account version, expiry, and action. Consume the proof in the action's transaction. Do not create a general password Step-up grant or permit unrelated/admin/legal use. Preserve existing WebAuthn UV and TOTP-supported scopes.                                                | No original explicit status; T22A final bindings/lock-wait recheck and T28A dedicated issuance purpose added.                                                       |
| T23 - Preserve the Last Primary Factor and Contact   | Enforce shared factor/contact invariants under the common account lock.                                                                                                                                        | An account cannot lose its final password/passkey, required verified contact, or privileged/MFA protection. OTP contact control is not a primary credential. Real security changes invalidate stale authority; cosmetic key renames do not.                                                                        | No original explicit status; T23A adds durable barrier; T27A adds last recovery-eligible contact.                                                                   |
| T24 - Manage Passwords                               | Add, change, and remove passwords using the shared hasher and an appropriate fresh authorization proof.                                                                                                        | Hash outside long-lived account transactions, recheck current authority before commit, preserve exact bytes, and invalidate prior authority on real changes. Removing a password cannot leave the account without a primary factor.                                                                                | No original explicit status; preserve current endpoint, add barrier/policy/intents.                                                                                 |
| T25 - Enroll the First Passkey on a Password Account | Authorize the first native enrollment with a specific fresh proof instead of requiring an unavailable existing passkey.                                                                                        | Require actual UV, preserve immutable identity, defer handle persistence until successful verification, and protect concurrent first enrollment. Cancelled or ambiguous results cannot replay authority automatically.                                                                                             | No original explicit status; retain source capability, add barrier/SQL final authority.                                                                             |
| T26 - Manage MFA on Password Accounts                | Start MFA enrollment and disable an existing factor using the appropriate scoped/fresh authorization.                                                                                                          | Preserve required MFA and current privileged-account policy. Pending enrollment remains session/version-bound, finite, and one-use. Do not nest conflicting account transactions.                                                                                                                                  | H03; local completion preserved, target hardware/barrier/durable replay requirements still Planned.                                                                 |
| T27 - Change or Remove Contacts                      | Keep authorization against the old verified contact separate from ownership proof of the new destination.                                                                                                      | Preserve the last required contact and a usable account identifier. Persist exact new provenance atomically and invalidate stale authority/proofs. Do not reinterpret signup authority as contact-change authority.                                                                                                | H04; original final verification was in progress; maintain current gate and add T27A/T41C.                                                                          |

## Preserved Historical Status and Evidence

H01-H04 are dated reports copied into fresh-clone documentation as evidence
references, **not rerun or independently revalidated during this task**. Exact
original extended narratives are published in the
[complete registration backlog archive](../../docs/history/registration-backlog-2026-11-23.md),
including original T01-T42 scope/acceptance and dated command/result narratives.
Local `/tmp/kilo` and `.kilo` evidence paths below are literal historical
provenance, not resolvable fresh-clone normative hyperlinks. Future implementation
must collect new source-bound results, not reuse these as target compliance.

### H00 - Root Phase Roadmap

Every original checked item in tasks.md remains checked there. Its original
Phase 1 workspace/Compose/schema scaffolding, Phase 2 cryptography/schema,
Phase 3 protocol, Phase 4 session/UP-compatible WebAuthn/contact/recovery/Step-up,
Phase 5 privacy/audit/legal, Phase 6 gRPC/lifecycle and Phase 7 CSP/forms/portal/admin
definitions are preserved rather than renamed to target T completions.
Historical migration references and seven-suite/seven-race counts are dated
records, not current commands; the
[canonical migration inventory](../../docs/devops-operations.md#canonical-packaged-migration-inventory)
and current workflow/Nx targets govern execution. Current race matrix is 13.

| Root Evidence                                       | Preserved Original Observation / Limits                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| --------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tasks 5.3-5.5, 2026-11-05                           | Local phase-5 technical closure, fresh seven-suite acceptance, Linux unit/CGO race, static/generated/binary/image/frontend/helper/browser and confirmed teardown. Numeric policy/inventory/key/backfill/provisioning/deployed grants/redaction/signer and narrative/legal-basis/retention gates remain open. Ledger external anchoring explicitly deferred; coherent privileged rewrite/rollback not independently detected.                                                                                                                                      |
| Task 6.1, 2026-10-03                                | Reusable mTLS/SPIFFE exact-method admission; backend lint/vet/tests/build/full Linux race; ten repeated security runs at 100% statements. Listener/business RPC and SPIRE deployment were separate.                                                                                                                                                                                                                                                                                                                                                               |
| Task 6.2, 2026-10-09                                | Backend lint/vet/unit/full Linux race, mandatory PostgreSQL/Redis/mTLS, sqlc/Buf/wire/image health/readiness; gRPC opt-in, deployed SPIRE/grants/cutover unobserved. Redis authority in old definition is superseded by SEC09/T16A/T42A, not deleted history.                                                                                                                                                                                                                                                                                                     |
| Task 6.3, 2026-10-22/23                             | Metadata-only lifecycle contracts, independent revisions, transaction-aware creation, acknowledged broadcast worker, broker restart/hold/rollback, clean lint/vet/build/race/generation/image. Production retention/grants/alerts/bootstrap/deployment separate. Canonical audit format preserved.                                                                                                                                                                                                                                                                |
| Task 7.1, 2026-10-18/19                             | 51 web/UI tests, 88 helpers, lint/typecheck/build/images, Chromium CSP/navigation and HMR. Fresh request nonces/private dynamic HTML; Trusted Types/deployed ingress explicitly unobserved.                                                                                                                                                                                                                                                                                                                                                                       |
| Task 7.2, 2026-10-21                                | 111 web, 17 UI, 88 helper tests, lint/format/typecheck/build/image, Chromium keyboard/contrast/reflow/paste/no-JS/CSP/navigation. English UI-only submissions disabled, no simulated authentication/reset delivery; manual screen reader outstanding. English-only active claims later superseded by actual bilingual implementation, counts remain dated.                                                                                                                                                                                                        |
| Task 7.3, 2026-10-25                                | 191 web, 17 UI, 99 helpers, clean standard/changed integration lint, unit/integration vet/generation/full Linux+fixture races, real PostgreSQL/Redis/JetStream restart, builds/images/CSP and real HTTPS two-replica portal. Once-only code viewer/lost response, TOTP, stale tabs/conflicts/revoke/six light-dark desktop-mobile/four no-JS observed. Seven pre-existing unused retention-fixture lint findings outside task remained. Native bfcache/hidden tab, manual AT/authenticator, deployed ingress/redaction and consumer-first v1/v2 rollout separate. |
| Task 7.4, 2026-10-27                                | Full backend unit/race/vet/clean lint, real PostgreSQL/Redis/JetStream/SQL, 271 web/17 UI/102 helper, images/CSP and real HTTPS deletion/reclaim/retries/cross-replica/lost responses with teardown. Strong UV-only deletion and no-session reclaim preserved; new requests default-off. Independent receipt/provider/governance/ingress/AT/native checks and dependency audit findings unchanged.                                                                                                                                                                |
| Task 7.5, accepted 2026-10-31/reconciled 2026-11-01 | Seven serial real-service suites zero skips, SQL/Buf reproduction, unit/race/fixtures/vet/lint/builds, 491 web/17 UI/143 helper/typechecks, 24 masked admin layouts and teardown. Fresh non-root Linux/AMD64 image/all nine entrypoints closed registry blocker. Literal evidence `/tmp/kilo/admin-validation-20261031T133139Z/acceptance.json`; literal old plan `.kilo/plans/1793166766163-admin-control-panel.md`. Manual AT/physical/native/production signing/retention/ingress/logging/every-replica cutover remained open.                                 |
| Task 7.6, accepted 2026-11-01/reconciled 2026-11-02 | All 25 backend gates, seven serial real-service suites zero mandatory skips, reproducible SQL/Buf, 586 web/17 UI/156 helper/lint/vet/typechecks/builds/images/CSP, real browsers with 27 legal verifications/42 masked layouts and teardown. Literal evidence `/tmp/kilo/legal-validation-20261101T115536Z/final-summary.json`. Manual AT/physical/native zoom/hidden tab/bfcache, deployed ingress/logging/governance remain open; no section 1.8 completion inherited.                                                                                          |

### H01 - Original T01-T04 Reports, 2026-11-15

| ID  | Original Recorded Status / Delivered Boundary                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T01 | Completed (repository contract audit, 2026-11-15). Authoritative contract defines all final fields, six stages and current/deferred requests for one existing implementation; contract completion, not deferred target implementation/deployment.                                                                                                                                                                                                                                                                                                                                                                                |
| T02 | Completed (standalone validator and required local gates, 2026-11-15). NormalizePersonalName has NFC/Yeh-Kaf normalization, explicit private repertoire, structural separators and independent point/byte bounds; focused table/property and 16 native fuzz seeds. Cosmetic NormalizeName unchanged. Signup endpoints did not yet accept/require/store names; no old values inferred.                                                                                                                                                                                                                                            |
| T03 | Completed under superseding configured username policy (repository audit/focused unit tests, 2026-11-15). Bounded UTF-8, full-match configured regex, NFC display/separate folded security name; historical 7..40/Latin/ZWNJ was not completed policy. Production policy review/activation/endpoint work separate.                                                                                                                                                                                                                                                                                                               |
| T04 | Partially implemented; approval-pending, not completed (implementation/required local gates, 2026-11-15). Dedicated HMAC/unconditional uniqueness/all-status reservation/immutable/hard-delete-only release implemented. Real synthetic reserved set/four folds/exact near matches/all-absent rejection/closed-stale authority via restricted login transactions tested. Real approved inventory/access/key/policy/protected reports/final artifact absent; existing-account collisions unknown. Five Persian candidates existed only in literal plan `.kilo/plans/1794725069602-complete-t02-t04.md`, none installed/activated. |

Original audit baseline: clean
`3515e8a564395e17e64b7bf0f022e347b9be496a`. Username target passed three
packages internal/username, cmd/username and internal/migrate with generation
dependencies using `npm exec -- nx run identity-api:test-username --skipNxCache`,
Node 24.18.0/npm 11.21.0/Go 1.26.10/GOTOOLCHAIN=local; explicit
verbose run passed all 18 TestUsername tests, zero skips. That **audit/status-only
pass did not run** integration/race/lint/helpers/retention/browser; its later
implementation pass below is distinct. No runtime/deployment pass is inferred
from the documentation audit.

Later T02/T04 implementation used that same clean-index baseline plus final
combined unstaged source. Acceptance source SHA-256:
`2dcc8b71c3a4a429dfe86a993ba769032585fc96bffbccadfe5d67a70a646c21`.
Generated trees were unchanged:

| Tree               | Files | Original SHA-256                                                   |
| ------------------ | ----- | ------------------------------------------------------------------ |
| Database Go        | 26    | `e158bd6709fa67c2519a95357fc6b815067bf4f5405ed5497a4c8cf53959290b` |
| Go schemas         | 4     | `da3d8a24bf7b547633784fa7b52b391f3c564093e2dec8e954e054efdb65b2cf` |
| TypeScript schemas | 3     | `71a073141ebcc4680c92cfe64933b3ab38327a6c9c6874aeef92a5915afc97d5` |

Original toolchain: Node 24.18.0, npm 11.21.0, Go 1.26.10, golangci-lint
2.12.2, GCC 13.3.0, Linux amd64/compiler-enabled CGO. Commands used verified
PATH from repository root; owned service runs sequential and no inherited
credentials. These are **historical invocations**, not this task's commands:

| Original Command                                                                                                                      | Original Final Result                                                                                                                                                             |
| ------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `npm exec -- nx run identity-api:test --skipNxCache`                                                                                  | Passed; 60 test-bearing packages/three no-test packages; 16 fuzz seeds/deterministic properties, no extended fuzz. Nonverbose output did not establish test-level skip inventory. |
| `CGO_ENABLED=1 npm exec -- nx run identity-api:test-race --skipNxCache`                                                               | Passed; same 60/three, native GCC; not integration-tagged username race evidence.                                                                                                 |
| `npm exec -- nx run identity-api:vet --skipNxCache`                                                                                   | Passed.                                                                                                                                                                           |
| `GOFLAGS=-tags=integration npm exec -- nx run identity-api:vet --skipNxCache`                                                         | Passed.                                                                                                                                                                           |
| `npm exec -- nx run identity-api:lint --skipNxCache`                                                                                  | Passed zero issues after test-label spelling fix/affected rerun.                                                                                                                  |
| `npm exec -- nx run identity-api:lint --skipNxCache --args='--build-tags=integration'`                                                | Passed zero issues.                                                                                                                                                               |
| `npm exec -- nx exec -p schemas -- node --test "$PWD"/.github/scripts/*.test.mjs`                                                     | Passed; 420 tests, zero fail/skip/cancel.                                                                                                                                         |
| `npm exec -- nx exec -p schemas -- node "$PWD/.github/scripts/portal-harness.mjs" --integration-target=test-portal-integration`       | Passed; exact 16 packages/2703 reported tests/zero fail-skip, confirmed teardown; existing registration/privacy/username immutability/concurrency/deletion fixtures included.     |
| `npm exec -- nx exec -p schemas -- node "$PWD/.github/scripts/portal-harness.mjs" --integration-race-package=./internal/registration` | Passed; one package/156 reported tests/zero fail-skip, Linux/CGO/Go/GCC proof/teardown.                                                                                           |
| `npm exec -- nx exec -p schemas -- node "$PWD/.github/scripts/portal-harness.mjs" --integration-target=test-retention-integration`    | Passed; three packages/355 reported tests/zero fail-skip/teardown.                                                                                                                |
| `npm exec -- nx run web:test-admin-browser --skipNxCache`                                                                             | Passed; fresh production dependencies, en/fa-IR, 28 checks/70 layouts per locale, unchanged worktree and teardown.                                                                |

Literal artifacts: `/tmp/kilo/t02-t04-integration`, `/tmp/kilo/t02-t04-admin`.
Browser unstaged-diff SHA-256:
`a346c9dad105d791a0d824b68bc288a16d88b5cd41fdc59db395bb17a2990b65`, no staged or
untracked changes. Evidence/status additions followed runtime verification and
changed only the local backlog; formatting/references separately checked.
All plan-required local gates passed, none final failed/unrun. Full
seven-suite/seven-race aggregation was not run locally: bounded portal/retention
and registration race were the plan. No bare dedicated username integration or
integration-tagged username-race pass claimed; no SQL/Buf source changes requiring
additional schema gates. Collision review/final policy approval remained blocked.
Deployment, actual provider receipt, physical/native zoom/AT unverified; native
hidden-tab/bfcache unobserved, real-API visibility/history probes exercised. No
production policy/list edit/install/activation/shared SQL/account repair/commit.
Other task statuses unchanged.

### H02 - Original T05/T06 Implementation, 2026-11-15

Original T05 status: **Completed (standalone validator, source review and required
local gates, 2026-11-15)**. NormalizeBirthday used explicit three-script grammar,
selected-calendar validation, MIT-attributed pinned integer converter and inclusive
Tehran-clock range. HTTP fields/storage/routing/UI were not delivered by that
task. Original T06 status: **Completed (standalone validator and required local
gates, 2026-11-15)**; exact female/male, zero Gender/static errors, no endpoints,
defaults/inference/migration/backfill/profile-read change.

Clean baseline `37dceb618cad97fb6696bf8183bdfe768d79e101`.
Final source including five new Go files and contract SHA-256:
`f8d5b0b990af08648e8e45046a29f75ffab7d73178ec7fc2c0843621e8dd91ea`.
Generated 26 database/four Go schema/three TS schema trees and hashes exactly
match H01. Original toolchain: Node 24.18.0/npm 11.21.0/Go 1.26.10
GOTOOLCHAIN=local/golangci-lint 2.12.2 built with that Go/GCC 13.3.0/Linux
amd64/CGO. Sequential fresh services, no adopted credentials.

| Original Command                                                                                                                   | Original Final Result                                                                                           |
| ---------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `npm exec -- nx run identity-api:test --skipNxCache`                                                                               | Passed 60 test-bearing/three no-test packages; no nonverbose test-level skip claim.                             |
| `CGO_ENABLED=1 npm exec -- nx run identity-api:test-race --skipNxCache`                                                            | Passed native GCC/same inventory; no integration-tagged race claim.                                             |
| `npm exec -- nx run identity-api:vet --skipNxCache`                                                                                | Passed.                                                                                                         |
| `GOFLAGS=-tags=integration npm exec -- nx run identity-api:vet --skipNxCache`                                                      | Passed.                                                                                                         |
| `npm exec -- nx run identity-api:lint --skipNxCache`                                                                               | Passed zero issues.                                                                                             |
| `npm exec -- nx run identity-api:lint --skipNxCache --args='--build-tags=integration'`                                             | Passed zero issues.                                                                                             |
| `npm exec -- nx exec -p schemas -- node --test "$PWD"/.github/scripts/*.test.mjs`                                                  | Passed 420 tests, zero fail/skip/cancel.                                                                        |
| `npm exec -- nx exec -p schemas -- node "$PWD/.github/scripts/portal-harness.mjs" --integration-target=test-retention-integration` | Passed exact three packages/355 reported tests/zero fail-skip/teardown.                                         |
| `npm exec -- nx run web:test-admin-browser --skipNxCache`                                                                          | Passed final rerun; fresh en/fa-IR real services/28 checks/70 layouts per locale, source/index freeze/teardown. |

Focused tests: three upstream vectors, 11 authority-derived/ICU anchors/leap
ends, all 46,340 days 1900-01-01..2026-11-15, all 6,561 digit-script mixtures per
calendar, grammar/size/month/leap/lower/today/next-day boundaries, Tehran
midnight/year/DST/current non-DST/location-equivalent clocks, unusable clocks,
zero/redacted error/idempotence and strict gender. Twenty birthday/11 gender fuzz
seeds ran unit/race; existing name/profile unchanged; no extended fuzz campaign.
Read-only port review compared every arithmetic expression/break table/signed
division/remainder/bounds/MIT notice to jalaali-js pin
`f592be0e06867d2752f93924fa3e338f366ce4f4`; no findings. Authority-derived/ICU pins
and astronomical limits documented, original authority PDF/official certification
not claimed.

First English browser assertions/teardown passed but identity check failed when
external staging moved identical bytes. That attempt was **not accepted**.
External staging preserved; only invalidated browser rerun. Final en/fa reports
bind staged-diff SHA-256
`4438b12cd632161b95a3f9d036906c54c5820afbfee591252a46d33b1c959617`, no unstaged or
untracked during rerun. Literal final artifacts `/tmp/kilo/t05-t06-integration`
and `/tmp/kilo/t05-t06-admin`. Later backlog evidence edits were documentation
only, separately formatting/reference checked. All nine plan-required final
gates passed; full seven-suite/seven-race release/deployment/providers/physical
authenticators/native zoom/AT not established. Native hidden-tab/bfcache not
observed; real-API event/history probes passed. No HTTP DOB/gender rejection/UI
selection/storage/migration/source SQL Server/shared database/commit delivered.
Other task evidence/statuses unchanged.

### H03 - Original T26 Final Verification, 2026-11-23

Original status: **Completed (existing implementation and required local
verification, 2026-11-23)**. Password/contact was enrollment-only; UV/TOTP
maintenance remained separate. Pending state froze session/JKT/version/method/
contact/original minimum deadline; MFA owned deciding transaction; disable
preserved then-current locked privileged/resulting-state guards. Additive
forward-only migration 00010. Local fixtures/source acceptance did not establish
deployment/policy activation/provider delivery/T38 UI.

Supplied baseline `54eb6b78bbfb7bd445d319fdddedcb9956430586`; 39-file handoff
already committed as `67ba7b7116f8f252269843f44f49dc9e09f2ffb8`, initially clean
index/worktree. Verification did not create that commit; all 39 including seven
added/four existing docs inspected. No production web/Compose/registration route
or management UI added. Final acceptance source SHA-256:
`0c7cef63b95ea86abdd3046b16bb020a373c119443a8718916cc3e3bc0127c6a`.
Existing acceptanceIdentity excluded plans/agent state and separately fingerprinted
ignored generated outputs; HEAD remained the handoff commit.

| Original Generated Tree       | Files | Original SHA-256                                                   |
| ----------------------------- | ----- | ------------------------------------------------------------------ |
| apps/identity-api/internal/db | 31    | `b2bfd798d0f5ed69a429d6184665b44088d5d2b29e95d43d7c92a467347b30e2` |
| libs/schemas/gen/go           | 4     | `75587d9200428ef0535ad7a880a20f341929b111b2be2db397629dd3118f5c2a` |
| libs/schemas/gen/ts           | 3     | `c13d5649d6d94d8a873d085c565d777ded166ae7647a5bc09c00e16f0eb90c50` |

Generators repeated uncached and full trees compared identically with diff -ru;
later fixes did not alter inputs/fingerprints, ignored outputs not staged.
Verified original environment: NVM Node 24.18.0/npm 11.21.0; cached Go
1.26.10/GOTOOLCHAIN=local satisfying go.mod 1.26.5; golangci-lint 2.12.2 built
with that Go; native GCC 13.3.0/x86_64-linux-gnu/Linux amd64/CGO; PostgreSQL
16.15 clients at /usr/lib/postgresql/16/bin; Docker Engine 29.9.3/Compose 5.7.0;
Chromium 156.0.8078.4 launched with Playwright; existing amd64 PostgreSQL16,
Redis7/NATS2.10 fixture images. Host Go1.27.3/Go1.27-built linter not selected.
Every independent command used local verified prefixes. Inherited
NODE_TLS_REJECT_UNAUTHORIZED=0 removed locally without TLS weakening/global edit.
Initial remote TS generation HTTP403 caused by omitted existing proxy; unchanged
command passed after local proxy restoration. No tools/providers/global installs.
identity-api/schemas/web resolved via Nx/current workflow. Early failed/invalidated
runs not final; affected checks rerun and six final source/inventory reports bound.

| Original Command                                                                                                                     | Original Final Result                                                                                                          |
| ------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------ |
| `npm exec -- nx run schemas:lint --skipNxCache`                                                                                      | Passed.                                                                                                                        |
| `npm exec -- nx run schemas:generate --skipNxCache`                                                                                  | Passed repeated Go/TS byte reproduction.                                                                                       |
| `npm exec -- nx run identity-api:sqlc-vet --skipNxCache`                                                                             | Passed.                                                                                                                        |
| `npm exec -- nx run identity-api:sqlc-generate --skipNxCache`                                                                        | Passed repeated database byte reproduction.                                                                                    |
| `npm exec -- nx run identity-api:test --skipNxCache`                                                                                 | Passed 68 test-bearing/three no-test packages; nonverbose no test-level skip inventory.                                        |
| `CGO_ENABLED=1 npm exec -- nx run identity-api:test-race --skipNxCache`                                                              | Passed same 68/three/native Linux GCC CGO; no nonverbose test-level skip claim.                                                |
| `npm exec -- nx run identity-api:vet --skipNxCache`                                                                                  | Passed.                                                                                                                        |
| `GOFLAGS=-tags=integration npm exec -- nx run identity-api:vet --skipNxCache`                                                        | Passed.                                                                                                                        |
| `npm exec -- nx run identity-api:lint --skipNxCache`                                                                                 | Passed zero issues.                                                                                                            |
| `npm exec -- nx run identity-api:lint --skipNxCache --args='--build-tags=integration'`                                               | Passed zero issues.                                                                                                            |
| `npm exec -- nx run identity-api:build --skipNxCache`                                                                                | Passed; browsers rebuilt production deps uncached.                                                                             |
| `npm exec -- nx run identity-api:build-migrate --skipNxCache`                                                                        | Passed.                                                                                                                        |
| `npm exec -- nx exec -p schemas -- node --test "$PWD"/.github/scripts/*.test.mjs`                                                    | Passed 482 tests/zero fail-skip-cancel.                                                                                        |
| `npm exec -- nx exec -p schemas -- node "$PWD/.github/scripts/portal-harness.mjs" --integration-target=test-security-db`             | Passed exact 22 packages/3262 reported tests/zero fail-skip/teardown; real lineage/concurrent migrators/forward dump-restore.  |
| `npm exec -- nx exec -p schemas -- node "$PWD/.github/scripts/portal-harness.mjs" --integration-target=test-portal-integration`      | Passed exact 20 packages/4173 reported tests/zero fail-skip/teardown; MFA transaction/authority/concurrency/failure.           |
| `npm exec -- nx exec -p schemas -- node "$PWD/.github/scripts/portal-harness.mjs" --integration-race-package=./internal/mfa`         | Passed one package/127 reported tests/zero fail-skip/race toolchain/teardown.                                                  |
| `npm exec -- nx exec -p schemas -- node "$PWD/.github/scripts/portal-harness.mjs" --integration-race-package=./internal/actionproof` | Passed one package/169 reported tests/zero fail-skip/race toolchain/teardown.                                                  |
| `npm exec -- nx exec -p schemas -- node "$PWD/.github/scripts/portal-harness.mjs" --integration-race-package=./internal/contactcode` | Passed one package/79 reported tests/zero fail-skip/race toolchain/teardown.                                                   |
| `npm exec -- nx exec -p schemas -- node "$PWD/.github/scripts/portal-harness.mjs" --integration-target=test-retention-integration`   | Passed three packages/355 reported tests/zero fail-skip/teardown.                                                              |
| `npm exec -- nx run web:test-admin-browser --skipNxCache`                                                                            | Passed fresh en/fa-IR dependencies/29 checks/70 layouts/12 integrated login journeys per locale/source-index freeze/teardown.  |
| `npm exec -- nx run web:test-portal-browser --skipNxCache`                                                                           | Passed final rerun/fresh en/fa-IR/18 checks/30 viewport surfaces/six no-JS per locale/assertions/source-index freeze/teardown. |

Additional original fixture target identity-api:test-portal-fixture passed one
test-bearing package, no nonverbose test-level skip claim. Focused 69-case MFA
writer-order diagnostic passed fresh teardown, supplementary not replacement.
Sequential fresh services/browser teardown confirmed; interrupted early security
run had no accepted inventory. Its three containers/network were ownership/ID
verified and retired by existing helper; unrelated stopped containers untouched.
Policy-test mock artifacts `/tmp/kilo/t26-verification/integration` were **not
acceptance evidence**.

External staging preserved. Final admin en/fa reports staged diff:
`96936f8cf020f4b3e4d8685f1e1e55881e7933c4f6b28bccf24c858a5f11bbe9`, unstaged:
`0ad32dc8ccb6ef93212c7ac3694c4aab91c051c0c0deddea4586b9dbad042018`, both
worktreeMatchesAtFinish=true plus outer freeze. Identical remaining fixture bytes
were externally staged during first otherwise successful portal run; outer
freeze failed and that attempt rejected. Final portal/service reports staged
diff:
`aee15047c81e2691ebfb63d5afd7364333ed324255081c4f09d0c94c9a3b4e43`, empty unstaged/
untracked. Same final runtime/generated bytes in both accepted browsers; no
index-changing browser run claimed.

Verification fixes were limited to eleven existing Go/test files:
cmd/portal-fixture main.go/main_test.go; internal/actionproof integration_test.go,
mfa_enrollment_integration_test.go/password_change_integration_test.go;
internal/contactcode/service.go; internal/legalhold/registration_restore_integration_test.go;
internal/mfa/service.go; internal/migrate/safety_test.go;
internal/server/mfa_integration_test.go; internal/smsotp/login.go, under
apps/identity-api. They corrected exported comments/conditionals, exact migration
10 history, distinct synthetic phone indexes, custom-role encrypted audit context,
never-assigned username fixture and finite excluded-browser TOTP deadline.
No Unicode/lint/restore/trigger/policy weakening. Combined baseline-relative
inventory was 43 files, 44 with later local ignored backlog amendment; user staging
not changed by that verification turn, eleven fix files externally staged. Later
backlog amendment separately checked formatting/references, no runtime/config/
generated/toolchain change.

Literal final artifacts `/tmp/kilo/t26-verification/final-integration`,
`/tmp/kilo/t26-verification/admin-final`, `/tmp/kilo/t26-verification/portal-final`;
commands/attempts/identities/logs under `/tmp/kilo/t26-verification`.
All **21 T26-required local gates** passed, none failed/unrun. Full
eight-suite/twelve-race release aggregation, exact-release-image signup and
full-stack Compose were not run in that bounded pass. No GitHub CI/deployment/
shared writes/production username-MFA policy/provider-template installation/reset/
commit claimed or performed. Actual email/SMS, physical authenticator, Persian
security/legal, deployed ingress/native zoom/AT remained unverified. Native
hidden-tab/bfcache unobserved; real-API visibility/history probes passed.
T27/T38 and unrelated statuses remained independently scoped.

### H04 - Original T27 Handoff, 2026-11-23

Original status: **Implemented; final combined-source verification in progress
(2026-11-23)**. Unified manager, exact action/target password/contact proofs,
frozen strong authority, separate new destination ownership, truthful current
contact read and additive forward-only 00011 implemented. Present-primary-email
removal remained operation-gated on independently verified T28 alternative
recovery identification and T41 email-absent notification/deletion/reclaim.
Already-absent/authorized absent removal supported. No T28/T41/backup-contact/
registration/T38 UI completion; actual provider/physical/deployed evidence not
claimed. No final passing source/toolchain/test inventory was recorded in that
historical T27 section; do not turn verification-in-progress into Completed.

## Documentation Handoff Status

This section records the original 2026-11-24 backlog handoff. The backlog owner
created this file alone. Historical tasks.md and local
plans remain unchanged; no application/configuration/test-source, install,
database/provider/runtime or Git mutation is part of this delivery. Full plan,
historical root and local T backlog, registration/frontend/localization contracts
and task-verification instructions were read.

| Check                                             | This Backlog Owner's Result                                                                                                                                                                                                           |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Scope and historical preservation                 | Reviewed; original T01-T27 Scope/Acceptance reproduced, H00-H04 dated boundaries/source/toolchain/results retained.                                                                                                                   |
| Active policy/criteria/graph review               | Reviewed manually; every executable record has 15 sections and stable criterion IDs, aggregate aliases excluded, primary prerequisites ordered independently of numbering. Parent owns machine validation of final combined file.     |
| Markdown formatting / paths / anchors / commands  | Not run by this child; parent integrating owner runs final combined documentation-only check after source freeze. Historical commands are evidence, not executed commands.                                                            |
| Mermaid                                           | N/A for this backlog: no Mermaid block added; text/table DAG supplied. Parent validates changed diagrams elsewhere.                                                                                                                   |
| Application/DB/browser/CI/provider/physical tests | Not run: documentation-only authorization; every target remains Planned/Blocked. Historical passes are not current acceptance.                                                                                                        |
| Unresolved gates                                  | Approved policy/reservations/data rights/legal/provider/hardware/consumer/restore evidence and separately authorized implementation, full lifecycle/T27 retirement, CP01-CP07 and readiness release gates remain open until observed. |
