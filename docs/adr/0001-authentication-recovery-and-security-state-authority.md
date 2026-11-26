# ADR 0001: Authentication, Recovery and Security-State Authority

## Status

**Accepted**, 2026-11-26. The project owner approved the delivered
[authentication and recovery policy](../authentication-and-recovery-policy.md),
this ADR, the architecture and supporting documents, and the revised backlog
under CP01. The [decision record](../../.github/tasks/registration-single-contract-tasks.md#t01)
records the owner's explicit confirmation. Implementation remains subject to
separate task authorization and acceptance gates.

## Context

Identity is pre-launch. One registration/authentication implementation exists;
historical plans do not establish a production population needing a compatibility
lane. Current source has useful independent-TOTP preauthentication, verified
assertion UV recording, transactional locks/actionproof consumption, private
attribute encryption, exact revisions, strict browser protections, PKCE,
key-bound refresh and immutable metadata/audit/notification contracts. It also
allows code-only restricted passkey enrollment, UP-only ordinary passkey login,
contact-code normal login, Redis-earned authority/replay and incomplete
password/mobile lifecycles. Exact findings and limitations are in the
[current-source assessment](../security-architecture-assessment.md).

The audit's historical source object is unavailable in this checkout. The
[published registration backlog snapshot](../history/registration-backlog-2026-11-23.md)
preserves the complete original T01-T42 definitions and dated evidence; the
[archived architecture plan](../history/security-architecture-plan-2026-11-24.md)
preserves the original static planning scope and findings. Both are superseded,
non-executable history, not policy or implementation authorization. The
[current canonical backlog](../../.github/tasks/registration-single-contract-tasks.md)
owns executable task definitions; the local originals remain unchanged.
The refresh is tied to
`85abb13a27196c229efa7f59d7ef5beebb1d7e49`, not presumed identical to that audit.
Historical `tasks.md`, dated acceptance, real stored artifacts, signed history
and queued recipients/tokens/locales/deadlines are preserved. T12 is out of scope.

## Decision

1. Keep mandatory immutable username ownership, intentional current verified unique
   primary-email identification and at least one verified contact per production
   human. Email/mobile are individually optional only after complete lifecycle
   dependencies pass; no fabricated mailbox or mobile-login fallback (SEC01/SEC12).
2. Require eligible password or actual-UV passkey for normal authentication. Complete
   independent MFA through actual TOTP or an admitted backup after primary-bound
   preauthentication. Record evidence truthfully and preserve original `auth_time`
   (SEC02/SEC03).
3. Separate MFA Backup Codes from Account Recovery Codes. ARCs plus eligible old
   contact proof authorize one restricted factor repair; TOTP replacement also
   needs a pre-existing primary. ARCs are shown only in an explicitly authorized
   transient viewer/download, never email/SMS (SEC05/SEC06).
4. Set a durable SQL repair barrier after one successful repair. Only subsequent
   genuinely fresh full-policy normal login clears it; repaired-password login may
   clear it for an ordinary password-only account, but not where required MFA
   remains incomplete. Credential/MFA management, refresh, new codes and contacts
   cannot downgrade or bypass it (SEC07).
5. Record contact provenance and a mandatory 24-hour recovery cooldown for verified
   additions/replacements; initial registration is exempt. Preserve the last
   recovery-eligible destination and fence in-flight authority on relevant changes
   (SEC08).
6. Privileged admission requires policy-verified hardware-backed phishing-resistant
   UV and separately enrolled independent backup. Consumer ARC recovery, backup-code
   downgrade, support/admin override and total-loss bypass remain denied. No new
   higher-assurance recovery procedure is designed here (SEC04).
7. Make primary PostgreSQL authoritative for earned session/preauthentication,
   replay, proof consumption, policy/version/credential and barrier facts. Redis
   is non-authoritative acceleration/coordination/rate limiting. Its corruption or
   loss must not grant authority or silently disable critical limits (SEC09).
8. Join applicable consumption, mutation, security versions/barrier and metadata
   audit/notification intents in one deciding SQL transaction. Apply final checks
   after lock waits. Adopt the global lock order in the policy/data design;
   expensive hash/native/provider work stays outside long-held locks (SEC10).
9. Unknown results permit read-only reconciliation, not replay/restored proofs/new
   sessions. Use one absolute recovery ceremony of at most ten minutes and a grant
   capped at five minutes and the remaining ceremony deadline, preserving tighter
   existing limits. New families use at least 128 random bits and purpose/account/
   generation-bound HMAC-SHA-256 with separate domains and custody (SEC05/SEC11).
10. Preserve one [registration service and contract](../registration-contract.md) at
    `/register` with atomic account birth. Issue a session only from a known fresh
    success to the expected subject and original browser key.
    Receipt/replay/result lookup never authenticates. `/recover-account` stays
    deletion-exclusive. Keep 30-day grace, holds, username ownership, required
    reclaim factors, exact revisions, optional email and real readers (SEC12-SEC15).
11. Treat durable token/IdP/consumer/restore controls and independent/manual release
    evidence as separately bounded prerequisites, not implicit T42 implementation
    or proof of AAL/FAL/ASVS conformity (SEC16).

## Alternatives and Trade-offs

| Alternative                                                  | Decision and Consequences                                                                                                                                                                             |
| ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Recovery code alone enrolls a new UV passkey                 | Rejected: new-device UV proves new-key control, not old-account ownership; it permits a stolen live-code takeover path.                                                                               |
| Contact OTP alone issues normal authority                    | Rejected: mailbox/SIM compromise would replace the primary policy. Contact ownership is an explicit verification/recovery capability only.                                                            |
| Treat UV as automatically satisfying independent MFA         | Rejected: loses independent factor policy and truthful TOTP/backup evidence.                                                                                                                          |
| One untyped saved code pool for login and recovery           | Rejected for new target writers: cross-purpose confusion and authority substitution. Concrete stored artifacts require approved handling, not transparent dual-purpose reinterpretation.              |
| Privileged consumer recovery/support bypass                  | Rejected: weakens hardware/independent-backup admission. Total-loss lockout is intentional pending an independently approved procedure.                                                               |
| Redis authoritative plus SQL account-version checks          | Rejected: version checks do not authenticate Redis-earned evidence; lost replay/admission state can weaken limits. Primary SQL adds load and availability coupling but provides one durable decision. |
| Time-based repair cooldown only                              | Rejected: time or restarted/new ceremonies allow chaining after several factor losses. Durable barrier makes complete-policy evidence the reset condition.                                            |
| Immediate new-contact recovery eligibility                   | Rejected: an attacker can install a destination then repair factors. A provenance-based 24-hour cooldown introduces user delay and last-destination protection.                                       |
| Duplicate register-v2 or speculative legacy lane             | Rejected: no verified production dependency. Extend one service; preserve actual data/readers without designing fictitious users.                                                                     |
| Blanket code/credential destruction on every ordinary change | Rejected: retain unrelated uncompromised artifacts under explicit family policy, while fencing all stale derived authority. Confirmed compromise has scoped stronger revocation.                      |
| Claim SQL+Redis/provider exactly-once atomicity              | Rejected: unknown outcomes and separate external delivery require bounded reconciliation and immutable intents.                                                                                       |
| Restore database and clear sessions only                     | Rejected: old credentials/spent codes/policy can resurrect. Primary/failover fencing and an independent rollback witness or safe affected-authority invalidation are release prerequisites.           |

## Consequences and Rollout

SQL admission must be designed for primary-only reads, pooling/indexes, contention,
acknowledged-write durability and failover fencing. Availability is deliberately
traded for fail-closed security on unknown/unavailable authority. A global lock
inventory and failure/race evidence are mandatory before security-changing writers.
The dedicated HMAC key reduces database-read exposure, but increases custody,
rotation and disaster-recovery obligations; it does not protect against a fully
compromised authority writer/application.

Define evidence/event contracts and compatible notification readers before writers
to break recovery/notification cycles. Implement SQL/admission foundations before
code issuance/completion/repair; integrate individual repair and barrier tests
before UI. Password/mobile-only and email-removal activation wait for notification,
deletion, reclaim and recovery acceptance. Complete token/IdP/consumer/restore
prerequisites before independent T42 release review. UI work consumes fixed
contracts and preserves existing stable ceremony/preferences/security boundaries.

Inventory existing untyped saved codes, real consumers and queued work; obtain
owner-approved treatment and compatible-reader rollout before new families.
Do not delete migration history, real artifacts, signed formats or accepted queued
work, and do not introduce compatibility mechanisms for hypothetical accounts.
Disabling new writers does not authorize discarding live work. Full-policy/session
cutovers and rollback admission need an explicit operator design, not a cache flush.

## Supersession and Evidence

Supersedes active recovery-as-bypass, contact-only normal authentication, UP-only
target authentication, Redis-authority/disposable-cache equivalence, assumed
username-claim migration, unsupported finalized OAuth 2.1/ASVS Level 4/XSS-immunity
and deployed-HA/conformity claims. Dated historical acceptance is not rewritten or
counted as proof of the target. Existing schemas/formats are current contracts
until separately authorized implementation, not silently superseded wire behavior.

The [dependency backlog](../../.github/tasks/registration-single-contract-tasks.md),
[readiness matrix](../security-testing-and-readiness.md) and
[alignment report](../documentation-alignment-report.md) record owners, acceptance,
remaining gates and exact documentation-only validation. Standards citations and
Hatef-specific stronger choices are consolidated in the policy. No application
task becomes completed because this ADR exists.
