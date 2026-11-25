# Security Testing and Readiness

## Evidence Boundary

Documented 2026-11-24 against source HEAD
`85abb13a27196c229efa7f59d7ef5beebb1d7e49`, initially clean. The planning source
object `f9d2119ff15927d382d860b7f62584682c5b5f31` is unavailable, so findings were
re-inspected rather than carried forward as an unchanged-source claim. Dated
acceptance in existing guides and local backlog retains its original date,
source/toolchain/count/teardown meaning; it is not this delivery's runtime evidence.

This delivery changes documentation and backlog only. Application, test source,
runtime configuration, migrations, manifests/Nx targets, database operations,
deployment and Git mutations are out of scope. No application task is completed
by this review. Target controls are Planned/Blocked pending separately authorized
implementation and independent evidence. [Policy](authentication-and-recovery-policy.md)
owns SEC01-SEC16; [assessment](security-architecture-assessment.md) owns F01-F12;
[backlog](../.github/tasks/registration-single-contract-tasks.md) owns execution;
[alignment](documentation-alignment-report.md) records this documentation pass.

## Required Test Matrix

These are mandatory **future implementation/release evidence**, not tests executed
in this documentation work. Each case needs source-bound inputs, observed results,
zero mandatory skips and completed owned-service teardown. Mocks model errors;
real primary SQL/HTTP and browser boundaries remain separately required.

| ID     | Control / Observable Required Cases                                                                                                                                                                                                                                                                                   | Evidence and Owners                                                                                                                                                                      |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| TEST01 | Mandatory immutable username on every production-human birth/admission; explicit current verified unique primary-email selection; absent email remains NULL; mobile never silently selects login; surviving reservations hold through suspend/deletion.                                                               | Unit Unicode/policy properties; real restricted SQL constraints/conflicts and HTTP identification; SEC01, T01/T03/T04/T18A/T31/T32.                                                      |
| TEST02 | Zero/one/many real-key accounts and absent accounts expose no named credential inventory by count/length/transports/response size; timing distributions measured without claiming universal constant time. Discoverable login preserved.                                                                              | Unit decoys/options; real HTTP content/length and statistical probes; SEC01/SEC02, T18A, F03.                                                                                            |
| TEST03 | Password/passkey primary required. UP without actual UV, enrollment inventory, new-device UV as old ownership and contact-code-only normal login all denied. Actual primary/UV evidence is server-earned.                                                                                                             | Unit WebAuthn vectors/PHC bounds; real HTTP UV false/true, current-policy admission and password non-owner cases; SEC02, T16A/T18/T20.                                                   |
| TEST04 | Required independent MFA after both password and UV-passkey primary; preauth cannot open portal/OAuth/admin. TOTP and backup completions record distinct evidence, no `TOTP=true` for backup, unchanged original `auth_time`.                                                                                         | Unit policy matrix; SQL one-winner preauth/backup/TOTP consumption and HTTP session issuance; SEC03, T21A/T28B.                                                                          |
| TEST05 | Privileged admission checks actual approved hardware provenance and independent backup, at role assignment and each use boundary. Reject unknown attestation, unsupported/revoked device evidence, UV/AAGUID/BE-only claims, consumer ARC/contact recovery, backup downgrade and support/admin override.              | Unit policy/evidence denial; real role/login/token/gRPC fences; physical provenance/independence review; SEC04, T17A/T42C.                                                               |
| TEST06 | Negative account, purpose, factor, family/generation, JKT, session, destination-association and policy/security-version substitution at every earning and consuming endpoint. Invalid probes cannot burn another account's authority.                                                                                 | Unit bindings/vectors plus real SQL/HTTP cross-account tests; SEC05/SEC06/SEC10, T22A/T28/T29.                                                                                           |
| TEST07 | At least 128 random bits, distinct HMAC family domains/account/generation, unknown key/version denial, no low-entropy password-KDF reinterpretation. ARC never appears in email/SMS/logs/cache/browser storage. Existing untyped artifacts are inventoried and approved handling observed.                            | Unit CSPRNG/domain vectors; SQL unique one-use/gen revocation; transient viewer/browser artifact inspection; SEC05/SEC14/SEC15, T28A/T38.                                                |
| TEST08 | Fresh password-and-eligible-old-contact ARC issuance purpose for password-only account; required full MFA preserved elsewhere. Stale session, generic deletion/enrollment proof, repair grant, result receipt and contact-only issuance denied. Regeneration invalidates derived grants without clearing barrier.     | Real SQL/HTTP issuance/uncertainty/regeneration races and one-use viewer; SEC05/SEC07, T28A.                                                                                             |
| TEST09 | ARC plus fresh eligible old-current contact earns one factor-bound repair only. ARC alone/OTP alone/expired-spent-revoked-cancelled-unknown evidence fails. No normal/OAuth/admin/legal/contact/deletion/general-Step-up authority.                                                                                   | Unit complete admission matrix; real SQL grant consume and HTTP all forbidden routes; SEC06, T28C/T29.                                                                                   |
| TEST10 | Password and one-passkey repair preserve unrelated uncompromised credentials; new passkey UV mandatory. TOTP repair also requires pre-existing primary; old TOTP remains until verified atomic replacement, including cancelled/expired/failed/lost-result staging.                                                   | SQL/HTTP per-factor success/deny, rollback and current-factor login; SEC06/SEC10, T29A-T29C.                                                                                             |
| TEST11 | Repair commits barrier durably; new ARC/challenge/pool/time/contact/refresh/pre-repair session cannot clear it. All alternate password/passkey/MFA endpoints reject factor-changing bypass across replicas/restarts. Repaired password-only fresh login clears; MFA-required repaired password only preauth does not. | Real multi-session/replica restart integration, property state machine and conflicting management races; SEC07, T16A/T21A/T23A/T24-T26/T29A-T29C.                                        |
| TEST12 | Contact cooldown boundary immediately before/at/after 24h, trusted initial exemption, unknown provenance denial, replacement/re-add/reverification without bypass, last eligible contact protection and in-flight association fencing. Display zone/locale never changes UTC eligibility.                             | Unit trusted clocks/history properties; real SQL/HTTP concurrent contact/repair and bilingual boundary display; SEC08/SEC15, T27A/T28C/T41C.                                             |
| TEST13 | Redis forged session/preauth/factor/replay records grant nothing; loss/flush/failover cannot make TOTP unseen or reset critical budgets. SQL errors deny authority; caches cannot provide fallback earning.                                                                                                           | Fault-injected real SQL/Redis/HTTP cross-replica tests, durable budget/replay inventories; SEC09, T16A/T19A/T21A/T42A.                                                                   |
| TEST14 | After slow hash/native verification/lock waits, exact live session/proof/grant/JKT/status/versions/deadline/policy are finally checked in the deciding transaction. Expiry/revocation/role/contact changes win safely against repair/deletion/enrollment.                                                             | Deterministic SQL barriers/locks, Linux CGO races, one-winner consume/conflicting mutation; global lock-order/deadlock tests; SEC10, T22A/T28-T33, F02/F08.                              |
| TEST15 | Unknown commit/provider send produces bounded uncertainty, never automatic retry/new session/proof refund/new account. Read-only reconciliation reports committed/absent/unknown without secret or authority. Known noncommit does not relax new evidence requirements.                                               | SQL commit/network loss and provider ambiguity injection; same-key HTTP receipts/browser interruptions; SEC11/SEC13, T19A/T28-T33/T41A.                                                  |
| TEST16 | Deletion's existing stronger authorization joins exact grant/session/deadline to transaction; grace remains 30 days; holds/reservations/retained factors persist. Password/mobile reclaim has independent verified notifications and factor proof, no ARC/backup/repair reuse or normal session.                      | Real SQL/HTTP hold/purge/reclaim conflicts, exact deadlines and absent-email/password/mobile lifecycle; SEC12, T30/T41C.                                                                 |
| TEST17 | One registration service and atomic birth: required names/birthday/gender/username/contact/credential choice/location/legal evidence; no code-only account or automatic `both` downgrade. Known fresh birth alone issues expected subject/same-key session; receipt/replay/lookup never authenticates.                | Unit final validators/keyed password fingerprints; SQL duplicate/constraint/uncertain commit; HTTP/browser once-only bootstrap and failed-delivery ordinary login; SEC13/SEC15, T31-T37. |
| TEST18 | Exact same-snapshot private revisions, decimal-string precision, authorized grants/no-ops/statuses and encryption bindings. Current optional email presence, nullable account attribution, signed formats and metadata-only readers remain compatible.                                                                | Protobuf generation/wire tests; real SQL/gRPC/RBAC snapshot/conflict tests; event privacy assertions; SEC14, T15/T40/T41B.                                                               |
| TEST19 | Notification contracts/readers precede writers; exact recipient/token/locale/template/deadline survive retries/rollback; queued/accepted/delivered/unknown distinct. Absent-email/mobile support never uses empty digest or fabricated email.                                                                         | Unit v1/v2 readers; real SQL/worker/provider failure; observed independent receipt and redaction; SEC11/SEC12/SEC14, T40B/T41A.                                                          |
| TEST20 | En/fa-IR desktop/tablet/mobile light/dark login/preauth/backup/lost-factor/repair/viewer/management/deletion journeys preserve stable key/provider/ceremony and absolute deadlines. Native operations explicit; preference changes replay no API work; screenshots structurally mask secrets/private fields.          | Fresh production real-API browsers, keyboard/accessible-name/focus/reflow/contrast assertions, manual AT/native device gates; SEC15, T34-T39.                                            |
| TEST21 | Durable OAuth grant/code/refresh/client-assertion/replay and original auth evidence; confidential clients authenticate on applicable exchanges; complete interactive authorization/consent with exact redirect/PKCE/issuer/nonce/scope. Recovery/preauth/CLIENT cannot become normal user authority.                  | Real SQL/HTTP token/consent/client cases; external consumer `(iss, sub)` and privileged evidence fences; SEC16, T42A-T42C.                                                               |
| TEST22 | Stale replicas, acknowledged-write loss, failover split-brain and restored snapshots never resurrect credentials/spent codes/replay/barriers/policy. Primary-only authority reads/fencing and independent rollback evidence or safe affected-authority invalidation observed before quarantine opens.                 | Controlled failover/backup-restore tests with post-backup security mutations and independent witness; security ops review; SEC09/SEC16, T42D.                                            |
| TEST23 | Stuffing/spraying/enumeration, phishing, mailbox/SIM/code theft and correlated vault compromise, browser-key/session theft, substitution/replay/stale evidence, concurrent roles/repairs/MFA downgrade, SQL/Redis insider/rollback, privacy/audit and recovery DoS addressed.                                         | Threat-linked abuse/property/fuzz campaigns, SAST/DAST/dependency/secret/supply-chain/container scans and penetration testing; all SEC IDs, T42, threat model.                           |

## Release Gates

All gates below are **Blocked or Not Run** for the planned target. Local historical
passes remain independently scoped historical evidence, not target completion.
No prerequisite is complete because documentation or test source exists.

| Gate                          | Required Decision / Observation                                                                                                                                                       | Status and Owner Boundary                                                              |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| G01 Policy/ADR                | Owner approves delivered policy, full architecture, documents and revised backlog; separately authorizes bounded implementation.                                                      | Approval pending; product/security owner, not implicitly assigned by this review.      |
| G02 SQL ownership             | Persisted evidence/consumption/replay/limit inventory, common final-check protocol/global lock order, custody and rollback design accepted.                                           | Planned/Blocked, security and database owners.                                         |
| G03 MFA/privileged/recovery   | TEST03-TEST11 complete with truthful evidence, hardware/backup admission, restricted authority and deliberate total-loss denial.                                                      | Planned/Blocked, authentication/security owners plus physical-device reviewer.         |
| G04 Contact/barrier           | TEST11-TEST14 prove durable alternate-endpoint barrier, 24h provenance/cooldown and last eligible destination under conflicting mutations.                                            | Planned/Blocked, authentication/contact owners.                                        |
| G05 Password/mobile lifecycle | Independent recovery, verified-destination readers/notifications, exact deletion/reclaim, receipt and audit coverage; only then T27 email-removal retirement/mobile-only activation.  | Planned/Blocked; keep current safety gate and defaults disabled.                       |
| G06 Registration/consumer     | Single atomic birth/fresh-only session, complete validators/legal versions and durable IdP/client/consumer admission; no receipt login.                                               | Planned/Blocked, registration/IdP/consumer owners.                                     |
| G07 Security restore          | Primary reads/replication/failover fencing and post-backup security-state rollback prevention or safe invalidation, not session flush alone.                                          | Planned/Blocked, database/security operator and independent reviewer.                  |
| G08 Independent review        | Independent architecture and authentication/authorization/recovery abuse penetration review; privileged categories explicitly tested; no unresolved critical/high authority findings. | Not Run; reviewer independent of implementation, not assigned by test execution.       |
| G09 Scanning                  | SAST/DAST, dependencies/secrets/supply-chain/container/image provenance; triaged results bound to final source/image.                                                                 | Not Run in this scope; CI/security/release owner.                                      |
| G10 Source/legal rights       | Approved geography-source rights, legal versions/links, retention/basis/vendor/transfer inventory and sign-off.                                                                       | Not established by repository inspection; governance/data/legal owners.                |
| G11 Provider/platform         | Real email/SMS independently received, correct selected-provider failure behavior; physical Windows Hello/security keys/USB/hybrid/native prompts verified.                           | Not Run; provider/device owners. Virtual authenticators/accepted sends do not pass it. |
| G12 Persian/accessibility     | Independent professional Persian security/legal wording and native AT/keyboard/browser zoom/platform interruption review.                                                             | Not Run; qualified reviewers. CSS/headless approximations are not native evidence.     |
| G13 Deployed ingress          | HTTPS nonce/SSR/CSP/Server Actions/strict cookies/font/Origin/proxy/redaction and every-replica rollout/compatible queued-reader rollback.                                            | Not Run; deployment/security operators. Local containers are not deployed evidence.    |

Exceptional risk acceptance must name the finding/threat/invariant, exact source
and exposure, severity and affected populations, compensating controls, accountable
owner, expiration/review date and explicit owner approval. It cannot be implied by
a task checkbox or green CI. Unresolved critical/high authentication, recovery,
authorization, credential or session findings block normal launch; exceptional
handling requires the explicit recorded process, never silent acceptance. No
support override or higher-assurance recovery procedure is approved by that text.

## Future CI Authority

The current `.github/workflows/identity-api.yml` and resolved Nx projects remain
the command/toolchain authority. Node 24 / `.nvmrc` 24.18.0, npm 11.21.0, Go
1.26.x and golangci-lint 2.12.2 are the current requirements. Every independent
agent command must use its verified installed environment prefix; do not install
workspace tools or change global/startup files to repair PATH. Go/linter versions
were not executed for this documentation-only pass, so no matching Go gate is claimed.

Current required real-service inventory: eight integration suites and thirteen
race packages, enumerated in [operations](devops-operations.md#automated-portal-acceptance).
The resolved `schemas`, `identity-api` and `web` projects were inspected using
`npm exec -- nx show project <name> --json`. No runtime target was executed here.
Application implementation must load `task-verification` and run its final combined
required local gates, plus affected CI targets. Use uncached tests and owned
services; skipped tests, cached browser evidence, incomplete teardown and a
different source identity are not passes. The integrating agent owns that pass,
not one full-suite duplicate per child.

For future code work, required local classes remain standard/integration-tag Go
lint, CI release/container policy tests, real retention integration and real
admin browser acceptance. The workflow additionally supplies SQL/schema/generated
reproducibility, Go tests/race/vet/build, integration/race inventories, frontend
lint/test/typecheck/build, image/CSP, portal/admin/geography/registration browsers
and Compose acceptance. T42 adds missing property/fuzz/abuse/failover/security
review evidence; it must not silently implement those prerequisites or weaken CI.

## Standards Evidence

Official retrieval date 2026-11-24. [Policy standards applicability](authentication-and-recovery-policy.md#standards-applicability)
is canonical; this table records observed status/errata limitations, not blanket
conformity or adoption of every reported erratum.

| Reference                                                                                                                                                                                                                                                                                                                                    | Official Status Evidence / Limit                                                                                                                                                                 |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [NIST B-4](https://csrc.nist.gov/pubs/sp/800/63/b/4/final) / [C-4](https://csrc.nist.gov/pubs/sp/800/63/c/4/final)                                                                                                                                                                                                                           | Final 31 July 2025; official CSRC and published sections inspected. Separate complete NIST errata inventory not verified.                                                                        |
| [WebAuthn 3 dated version](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/)                                                                                                                                                                                                                                                              | Directly retrieved W3C Recommendation dated 25 August 2026; older 26 May CR snapshot is not the selected status. Errata route exists but complete issue dispositions not independently reviewed. |
| [ASVS 5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en)                                                                                                                                                                                                                                                                               | Pinned stable release 30 May 2025, official overview/authentication chapter reviewed; L1-L3 only. No Level 4 or whole-profile pass.                                                              |
| [OAuth 2.1 draft-17](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/17/)                                                                                                                                                                                                                                                             | Active draft, Datatracker update 30 October and draft header 31 October 2026; expires 4 May 2027. Not an RFC.                                                                                    |
| [RFC 9700](https://www.rfc-editor.org/info/rfc9700) / [errata](https://errata.rfc-editor.org/search/?rfc_number=9700)                                                                                                                                                                                                                        | BCP 240 January 2025; official search returned no matching errata.                                                                                                                               |
| [RFC 9449](https://www.rfc-editor.org/info/rfc9449) / [errata](https://errata.rfc-editor.org/search/?rfc_number=9449)                                                                                                                                                                                                                        | Proposed Standard September 2023; verified editorial 7646 reported by official search.                                                                                                           |
| [RFC 6238](https://www.rfc-editor.org/info/rfc6238) / [errata](https://errata.rfc-editor.org/search/?rfc_number=6238)                                                                                                                                                                                                                        | Informational May 2011; verified 2866 and 4678; SHA-specific Appendix B secrets require proper vectors.                                                                                          |
| [RFC 4226](https://www.rfc-editor.org/info/rfc4226) / [errata](https://errata.rfc-editor.org/search/?rfc_number=4226)                                                                                                                                                                                                                        | Informational December 2005; verified 163/4994/5130/5723; reported/held/rejected entries are not silently treated as approved corrections.                                                       |
| [RFC 10017](https://www.rfc-editor.org/info/rfc10017) / [errata](https://errata.rfc-editor.org/search/?rfc_number=10017)                                                                                                                                                                                                                     | BCP 212 August 2026; official search returned no matching errata. Same-domain cookie profile has scoped applicability.                                                                           |
| [OIDC Core errata 2](https://openid.net/specs/openid-connect-core-1_0-errata2.html)                                                                                                                                                                                                                                                          | Approved errata set 2, 15 December 2023, selected published version. Full independent OIDC certification not performed.                                                                          |
| [FIDO recovery](https://fidoalliance.org/recommended-account-recovery-practices/) / [multiple authenticators](https://fidoalliance.org/white-paper-multiple-authenticators-for-reducing-account-recovery-needs-for-fido-enabled-consumer-accounts/) / [passkey types](https://www.passkeycentral.org/introduction-to-passkeys/passkey-types) | Official landing pages/living type guidance inspected. Binary PDFs' detailed internal sections were not extracted/verified; no invented section citations.                                       |
| [OWASP cheat sheets](https://cheatsheetseries.owasp.org/)                                                                                                                                                                                                                                                                                    | Official authentication/MFA/forgot-password/session/password-storage/CSRF/passkey guidance retrieved; unversioned nonbinding guidance, not certification.                                        |

Open applicability gaps include online password-only ARC/lookup issuance at AAL2,
at-least-two recovery/notification address support, ASVS MFA/identity-proofing/TOTP
windows, and NIST Unicode NFC SHOULD versus ASVS exact-byte password verification.
At least 128 bits/HMAC, independent MFA after UV, one-repair barrier, 24h cooldown
and privileged recovery denial are Hatef choices. No target-policy expansion or
certification is inferred from citing a standard.

## Reproducible Documentation Checks

A fresh checkout needs only the repository-required Node/npm versions and
`npm ci` for structural checks. Run from the workspace root; `$PWD` is expanded
before `nx exec -p schemas` changes its working directory:

```sh
npm exec -- nx exec -p schemas -- node "$PWD/.github/scripts/check-documentation.mjs" --references-only
npm exec -- nx exec -p schemas -- node --test "$PWD/.github/scripts/check-documentation.test.mjs"
npm exec -- nx exec -p schemas -- prettier --check "$PWD/README.md" "$PWD/.github/tasks/registration-single-contract-tasks.md" "$PWD/docs/**/*.md" "$PWD/.github/scripts/check-documentation*.mjs"
```

References-only mode explicitly reports diagram validation as **Not Run**. A full
check requires pinned Mermaid/jsdom in an explicitly selected isolated directory
outside the checkout; no repository dependency, private agent folder, database or
browser service is required:

```sh
export MERMAID_TOOLS_DIR="<isolated-directory-outside-the-checkout>"
npm install --prefix "$MERMAID_TOOLS_DIR" --no-audit --no-fund --package-lock=false --ignore-scripts mermaid@11.17.2 jsdom@27.4.0
npm exec -- nx exec -p schemas -- node "$PWD/.github/scripts/check-documentation.mjs" --mermaid-tools "$MERMAID_TOOLS_DIR"
```

The directory is an explicit local tooling choice, not a documentation dependency
on one machine's path. Missing tooling, wrong versions or invalid diagrams fail
the full gate; they do not silently become a pass. The CLI resolves its repository
root from its own tracked location and queries only installed Nx project metadata.
It does not execute referenced examples or read private agent configuration.

Output is JSON on stdout. Optional `--output "<new-json-report-path>"` writes a
sanitized source-bound record without overwriting an existing file. The
[published 2026-11-24 record](history/documentation-validation-2026-11-24.json)
contains only counts, statuses, versions and fingerprints. It is documentation
evidence, not runtime, penetration, provider, physical-device or launch acceptance.
Historical raw artifacts are not prerequisites and their original absence is
not hidden by publishing summaries. Any later changes invalidate affected checks.

## This Documentation Pass

The table below preserves the original local documentation pass. The
[portable follow-up](documentation-alignment-report.md#portable-documentation-follow-up)
supersedes its temporary entry point and does not convert historical observations
into current application acceptance.

### Original Local Pass (2026-11-24)

| Gate                                      | Current Observation                                                                                                                                                                                                                                                                                         |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Scope/source                              | Passed documentation-only combined scope at unchanged HEAD: 16 modified and 6 new files. External staging preserved. Final document fingerprint/counts retained in `/tmp/kilo/identity-doc-validation.json` and described in alignment.                                                                     |
| Node/npm/Nx                               | Verified Node v24.18.0/npm 11.21.0 with local NVM prefix; resolved projects and `nx exec --help`. Nx MCP documentation request returned HTTP 500, so local resolved CLI evidence was used.                                                                                                                  |
| Markdown formatting                       | Passed all 22 files using actual Prettier 3.9.5 and absolute root paths through Nx; evidence-report edits rechecked. Planning's relative-path command/project-CWD error was corrected, not counted as a pass.                                                                                               |
| Paths/anchors/tasks/invariants/commands   | Passed temporary Markdown-parser/current-target/source-range checker: no failures, 71 IDs/64 executable records/960 sections/512 criteria, 280 acyclic dependencies, complete index and local references. Manual documentation consistency completed; historical commands are not current runtime evidence. |
| Mermaid                                   | Passed all three changed/new diagrams using owner-authorized isolated Mermaid 11.17.2/jsdom 27.4.0. No repository dependency or browser/database startup; syntax is not browser/physical/runtime acceptance.                                                                                                |
| Runtime/local CI/security/manual/deployed | **Not Run**, intentionally outside documentation-only scope. No runtime, exploit, provider receipt, physical device, independent review or launch pass claimed.                                                                                                                                             |
