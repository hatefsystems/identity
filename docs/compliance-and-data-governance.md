# Hatef Identity Platform - Compliance & Data Governance

This document records engineering data inventories, current retention constraints
and proposed governance obligations. It is not legal advice, evidence of approved
processing, delivered data-subject rights or compliance certification. Target
authority belongs to the [authentication policy](authentication-and-recovery-policy.md);
source findings and release blockers belong to the
[assessment](security-architecture-assessment.md) and
[security readiness](security-testing-and-readiness.md).

The intended initial market is Iran; applicable jurisdiction, controller duties,
lawful bases and disclosure restrictions require qualified legal approval before
launch. GDPR and other statutory references are applicability examples, not
universal authority or proof that an exemption is available. Engineering policy
cannot guarantee identical legal outcomes across jurisdictions.

---

## 1. Purpose & Scope

- **Purpose:** Support purpose-limited privacy/deletion and lawful security investigations while documenting conflicts, retention gaps and independently required legal decisions; no guaranteed compliance or complete attribution is claimed.
- **Scope:** Applies to all identity data processed by `apps/identity-api` (the Go IdP) and the identity records propagated to downstream services (e.g., Email Service, Search Core). It does not govern the _content_ handled by those downstream services (e.g., email bodies); each service owns its own content-retention policy and must respect the identity-level signals defined here.

---

## 2. Data Classification

All data handled by the IdP falls into exactly one of three classes. The class determines its lifecycle.

### 2.1 Class A - Deletable PII (User-Owned)

Personal data that exists to serve the user and is erased when the user is deleted.

- Primary email, name/display name, avatar.
- Phone number, backup email, MFA/TOTP secrets (stored envelope-encrypted).
- Password hash, WebAuthn credentials and current untyped recovery codes. Planned
  separate MFA Backup Codes/ARCs and their verifiers remain credential data; never
  put plaintext codes or TOTP secrets in notifications/audit/lifecycle events.
- Active sessions and refresh tokens.
- Durable registration attempts: encrypted frozen email/phone/handle/ceremony,
  capability/token hashes, original browser JKT and bounded proof/outcome metadata.
  Pending state is not an account or login; possession proofs do not identify a
  legal person or confer any privileged role.

**Lifecycle:** Removed during hard-delete (see Section 5). Erasure is the default.
Pending signup has no user subject and expires via its separate bounded cleanup;
completed receipt retains the original-subject FK cascade and hold-aware policy.

### 2.2 Class B - Minimal Security Metadata (Platform-Owned), Pseudonymized Personal Data

Non-content, minimized metadata retained to attribute abusive or security-relevant actions even after an account is deleted. This is the class that answers "who did this, and when" after the fact.

- Stable account reference (`account_ref`). Stable, but **not** anonymous: it is the join key that makes post-deletion attribution work.
- Optional identity **blind index** (keyed HMAC-SHA-256 over declared canonical
  email input), never raw email, plus recorded `blind_index_version`. NULL
  attribution is legitimate absence, not an empty-email digest, mobile index
  or fabricated mailbox; stable `account_ref` remains the event subject.
- Event type, timestamp, source IP / subnet, user-agent / device fingerprint.
- Token/authorization issuance metadata (client_id, scope, issued-at).
- Security signals (RTR breach, suspicious login, risk-based lockout).

**Lifecycle:** Independent retention (see Section 7). **Not** deleted when the
account is hard-deleted. It excludes raw email/contact and action content but
retains personal network/device metadata; it is not free of personal data.

**Classification:** This is **pseudonymized personal data**, not non-PII - see Section 7.0 for why the distinction is load-bearing and what it obliges. Retaining it past an erasure request relies on an Art. 17(3) exemption that must be documented and disclosed.

### 2.3 Class C - Immutable Audit Logs

Tamper-evident administrative and system audit trail.

- Append-only, cryptographically chained. Under canonical format v2 the chain lives in `audit_log_chain` (leaf digest + chain digest, one row per event), separate from the `mvp_audit_logs` payload.
- No runtime role holds chain `UPDATE`/`DELETE`/`TRUNCATE`; signer INSERT is separate, with no maintenance exemption. Class C payload mutation permits only its existing `user_id` FK nulling, not narrative rewriting.

**Lifecycle:** Retained per the audit-retention policy; integrity verified periodically. Never rewritten.

**Note on Class C retention.** Class C payload rows also carry `client_ip` and
`user_agent`, which are personal data, and there is currently no Class C purge
worker - so that retention policy has no implementation, and the data is retained
indefinitely. The v2 split makes a purge _possible_ for the first time (erasing a
payload no longer breaks the chain, and `DELETE` on `mvp_audit_logs` can be
granted to a dedicated role), but the worker and its retention number remain
outstanding. Until they exist, Class C indefinite retention is a known
storage-limitation gap under Art. 5(1)(e), not a settled position.

---

## 3. Data Retention Schedule

Retention must be purpose-bound and approved. Some current minimized metadata
has `no_expiry` and Class C has no finite purge implementation; those are explicit
governance gaps, not time-boxed controls. Expiry purges require operational
approval and hold checks. Class C is not purged by the Class B worker.

| Data Category                    | Class | Default Retention                                                   | Basis                                                                               | Purge Mechanism                                                                   |
| :------------------------------- | :---- | :------------------------------------------------------------------ | :---------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------- |
| Active account PII & credentials | A     | Life of account                                                     | Contract / consent                                                                  | Hard-delete on erasure                                                            |
| Sessions & refresh tokens        | A     | Until logout / expiry                                               | Contract                                                                            | TTL + revocation                                                                  |
| Pending registration             | A     | 15m; email proof <=10m, passkey <=5m, capped by original deadline   | Account enrollment / abuse prevention, subject to approved notices and lawful basis | Dedicated bounded cleanup; expiry checks alone are not physical erasure           |
| Registration completion receipt  | A     | 1h after completion, subject to current original-subject holds      | Bounded outcome reconciliation                                                      | Dedicated hold-aware cleanup; user FK cascade cannot prevent lawful account purge |
| Deletion grace record            | A     | 30 days                                                             | Contract / user recovery                                                            | Cron after grace window                                                           |
| Security event ledger            | B     | 365 days (`8760h`; validated `4320h..13140h` range)                 | Legitimate interest / legal obligation                                              | Separately credentialed hourly worker after rollout gates                         |
| Admin/system audit logs          | C     | Currently indefinite; numeric policy and purge remain unimplemented | Proposed legal obligation / accountability, subject to approval                     | Immutable chains; no Class C purge worker                                         |
| Backups (PostgreSQL)             | Mixed | Per backup retention (e.g., 14-30 days)                             | Operational continuity                                                              | Backup rotation                                                                   |

The configured security-ledger default is `SECURITY_LEDGER_RETENTION=8760h`
(365 days), not legal approval. Changes within the validated range require a
documented decision. The signer derives expiry from occurrence, not ingestion;
the worker honors persisted `retain_until` without rewriting signed timestamps or
restarting retention after hold release. This finite Class B payload default does
not remove current `no_expiry` metadata or Class C's storage-limitation gap.

Registration/SMS default disabled. Transient windows and finite admission/send
ceilings are not production budget/legal-basis approval. Complete ROPA/DPIA/notices,
vendor terms, country-routing/spend approval and supervised cleanup before
enablement. Completed attempts clear transient contact/token/ceremony payloads;
retained receipts need only bounded capability/JKT-bound outcome metadata. Current
holds can retain a completed receipt, never extend an expired proof or capability.
Pending/failed attempts have no user subject; expiry alone does not erase stored
PII, and protected backups retain their independent rotation/recovery obligations.

---

## 4. Right to Erasure & Its Limits

Users may request deletion of their data ("Right to be Forgotten"). Erasure is the default outcome. It is limited only in narrow, documented cases:

- **Legal obligation:** A law requires the data to be retained (supporting reference: GDPR Art. 17(3)(b); local retention duties such as those under Iran's Computer Crimes Law for service providers).
- **Legal claims:** The data is needed for the establishment, exercise, or defense of legal claims, or an active investigation (supporting reference: GDPR Art. 17(3)(e)).

When a limit applies, the corresponding data is placed under Legal Hold (Section 6) or retained as Class B metadata; the rest is still erased. The user is informed that deletion is partially deferred where lawful to do so.

---

## 5. Deletion Flow & 30-Day Grace / Recovery Window

Deletion is a staged, reversible-then-permanent process:

1. **Current request:** Fresh WebAuthn UV step-up is required; TOTP cannot authorize deletion. Middleware validates the grant before the service transaction, which rechecks captured account version, sets `pending_deletion` and persists reclaim plus per-recipient notice intent. Exact earned session/grant/deadline/JKT binding is not yet joined to the deciding transaction; T30/SEC10 must close that gap without weakening the stronger route. Old linked authority is revoked; SMTP retries retain original notice tokens/deadlines.
2. **Grace window (30 days):** Pending accounts cannot log in. Cancellation uses the separate anonymous email-token plus WebAuthn UV/TOTP ceremony, followed by fresh normal login. Production uses exactly 720 hours from the original request. Retries and holds do not extend recovery access. Neither relay acknowledgement nor HTTP `204` proves inbox delivery.
3. **Hard-delete:** After the window, the existing worker checks current eligibility and holds before erasing Class A data in a per-subject ACID transaction and committing the terminal lifecycle event. Downstream consumers apply their own data policies; this is not a promise that every service's content or backup disappears at the deadline.

The notification outbox is operational Class A data, separate from lifecycle
metadata/security ledger. Recipient/token payloads are encrypted and identity-bound,
with real v1 English/template-1 and v2 frozen-locale readers. Cleanup follows relay
acceptance, invalidation or expiry, retaining held/undecidable subjects without
extending token validity; hard deletion cascades rows. Current selection accepts
nullable primary and configured backup mailboxes, but is mailbox-only and does not
establish a verified-destination notification foundation. Approve retention/provider/
escalation rules and independent mailbox access before enablement; do not claim
mobile-only lifecycle completeness.

Planned T40/T41 writers select eligible verified destinations and transactionally
record metadata-only security intent before changing factors/contacts. Retain
v1/v2 readers before writers and throughout rollback; preserve queued bytes,
recipients, locale/template, token and deadline. Report queued, accepted, observed
delivered and unknown distinctly. Optional email/grpc fields and current signed
audit formats remain intact (SEC14). T27 primary-email removal and password/mobile
activation stay blocked until complete recovery/notification/deletion/reclaim is
independently verified (SEC12).

The 30-day window is a **user-recovery** mechanism only. It is **not** a legal-retention period and is **independent** of Legal Hold (Section 6) and security-ledger retention (Section 7).

---

## 6. Legal Hold

A Legal Hold is a **precedence lock**, not a timer.

- **Precedence rule:** Active holds defer physical erasure/cleanup. They never
  extend the 30-day cancellation deadline, restore authentication, reset code/grant
  expiry or turn advisory review dates into authority. Holds > erasure, not holds
  > authentication deadlines.
- **No time cap:** A hold has no predefined duration. It stays until explicitly released (e.g., case closed, order satisfied).
- **Activation:** Applied by an authorized role (e.g., DPO / Legal). Each hold records: subject reference, reason, requesting authority / case reference, legal basis, start time, and optional expected review date.
- **Enforcement:** The hard-delete Cron **must** check for an active hold before purging any record. If a hold covers the subject, the purge is skipped entirely and logged.
- **Release:** Releasing a hold re-subjects the data to the normal retention timers (data past its window is then purged on the next cycle).

**Important limitation:** A Legal Hold only helps if it is applied **before** the data is purged. It cannot resurrect already-deleted data. For requests that arrive _after_ deletion, the answer comes from the minimal security ledger (Section 7), not from the hold.

---

## 7. Minimal Security Event Ledger

The ledger is the mechanism that answers a lawful request that arrives **after** an account has been deleted (e.g., a court inquiry at day 60 about an action taken before a day-30 deletion).

- **Decoupled lifecycle:** Ledger rows survive account hard-delete. Their lifetime is tied to the ledger's own retention (Section 3), not to the account.
- **Pseudonymized, not anonymous:** Rows carry stable `account_ref`, optional
  canonical-email blind index/generation, network/device metadata, event type and
  timestamp. No raw email/contact or action content is stored, but IP/user-agent
  and linkable references remain personal data.
- **Conditional attribution:** Current gated inquiry accepts email only and
  matches available eligible indexed records. NULL-email rows preserve stable
  attribution without an email digest; phone attribution/multi-generation lookup
  are not implemented. Matches do not verify a real-world person or complete history.
- **Legal basis:** Art. 17(3)(e) (establishment, exercise or defence of legal claims) and/or Art. 17(3)(b) (legal obligation), supported by legitimate interest in abuse prevention and security - never user consent.

This is the load-bearing difference from a design that only masks and nulls audit rows on deletion: the ledger is intentionally kept attributable (via blind index and stable ref) within a bounded, documented window.

### 7.0 Class B is pseudonymized personal data, not non-PII

This must be stated plainly, because an earlier framing of this table as
"non-PII" was wrong and would not survive a DPA review:

- A **keyed hash of an identifier is pseudonymization, not anonymization**
  (Recital 26). It remains personal data for as long as the controller can
  re-derive it - which is precisely the design goal, since re-deriving it is how
  a lawful post-deletion inquiry is answered.
- **IP addresses are personal data**, including dynamic ones (CJEU _Breyer_,
  C-582/14). `client_ip` and `ip_subnet` are therefore personal data, not
  metadata.
- **`device_fingerprint` and `user_agent` are online identifiers** under
  Art. 4(1).

The consequence is a constraint, not a caveat: **if post-deletion attribution
works, the data is still personal data.** A design cannot claim both. Class B
retention after an erasure request is therefore an Art. 17(3) exemption that
must be justified, documented in the DPIA, and disclosed - not an absence of
personal data that needs no justification.

Required disclosures, which are controller obligations rather than engineering
ones:

- The privacy notice must state that an erasure request does not remove Class B,
  and must state the retention period.
- The ROPA entry must record the Art. 17(3) basis and the balancing test.
- A DSAR response must account for Class B rather than reporting the subject as
  fully erased.

**Open governance items.** Two decisions remain outstanding and are deliberately
not settled in code:

1. **Retention length.** `SECURITY_LEDGER_RETENTION` is 8760h (365 days), between
   the implementation bounds 4320h (180 days) and 13140h (547.5 days), not the top
   of that range. Bounds are not legal approval. If the purpose is RTR-breach and
   credential-stuffing correlation, evidentiary value decays in weeks; 90-180
   days is materially easier to defend. 365 days needs a written justification
   tied to a concrete limitation period.
2. **`client_ip` alongside `ip_subnet`.** The subnet is derivable from the
   address, so storing both is redundant and weakens the minimization claim this
   very section makes. Keeping only the subnet - or dropping the full address
   after a short window - would be more minimal and still serve abuse
   correlation.

**Pepper compromise.** The blind index resists offline brute force while the
pepper is secret, but email addresses and E.164 numbers are an enumerable input
space: a leaked pepper re-identifies every indexed row. `blind_index_version`
(included in the fresh baseline) exists so a compromised pepper can be retired - historical
rows keep their recorded generation, so a lookup can compute one candidate digest
per retained generation instead of losing the lookup path entirely. Multi-pepper
lookup is the required follow-up; the column is the part that could not be added
later, because the index sits inside a signed, UPDATE-forbidden row.

### 7.1 Authorized Retention and Proof Minimization

The independent `security-ledger-purge` command removes only rows whose stored
`retain_until` is strictly before the run's database cutoff and for which no
independent active hold remains on the original account reference. Account
hard-delete does not remove that protection. Advisory dates are not releases;
applying a hold after erasure cannot restore evidence. The Class A deletion
worker and Class C audit history remain untouched.

Minimal proof metadata outlives erased events, and under canonical format v2
(included in the fresh baseline) it is simply the chain itself. Tamper-evidence lives in
`security_ledger_chain`, one row per event holding a leaf digest and a chain
digest, and that table is never deleted. Erasure removes the payload row and
nothing else, so the chain stays complete and verifiable from genesis across an
erased span.

An erased span is additionally annotated in `security_ledger_erasures`
(`first_seq`, `last_seq`, `operation_id`, `erased_at`). DELETE, exact spans and
durable receipt intent commit together; chaining happens later through publisher
and signer. Structural verification requires an annotation for an absent ledger
payload, not proof of receipt chaining or legal authorization. The trusted Go
worker rechecks canonical leaves, expiry and holds under ordered locks; ordinary
table DELETE permits arbitrary DELETE by that credential, so neither SQL grants,
annotations nor receipts prove a compromised worker honored policy. Chains retain
`seq`, unique `event_id`, `leaf_hash`, `chain_hash`; erasures retain operation/time
coordinates. They omit body/account/network fields but can remain correlated to
internal/external records and are not anonymous or constant-size proof state.

v1 instead stored each event's digest on its own row, so erasing a row removed a
chain link and had to be bridged by checkpoints recording the removed span's
predecessor and terminal digests, compacted whenever adjacent spans met. All of
that machinery is gone, along with the duplicate PL/pgSQL copy of the canonical
serializer it required. The purpose is validating surviving segments and future
appends, not preserving erased evidence under a different name.

Sanitized `legal.ledger.purged` / `legal.ledger.purge_skipped` Class C receipts
contain a system actor/event UUID/time, opaque operation ID, cutoff, aggregate
deleted/held counts, dry-run/outcome and high-water, plus new
`span_manifest_version=1` / `span_manifest_sha256` committing the exact ordered
inclusive spans. They omit account refs, source event IDs, blind indexes,
network/device data and narratives, but are still operation/time/digest-correlatable
metadata. An actually inspected held-only batch commits the empty manifest with no
erasure rows; prefiltered holds are not individually inspected skips. Dry-run
commits neither DELETE, erasure annotations nor receipt intent.

Separately scoped read-only `admin-legal --operation=ledger-receipts` correlates
erasure, retained outbox, receipt body/leaf and bounded Class C linkage coverage.
Unrelated audit narrative bodies are not read for the linkage proof. It reports
recorded-pending, chained, legacy/unbound, missing/unavailable, invalid and incomplete
states, bounded pagination and proof coverage, never a global pass. PubAck or
`published_at` is not chaining, a partial prefix is not a full-chain pass, and
missing retained material is unavailable assurance. Legitimate pending receipts
must not block signer restart. Legacy receipts without a manifest remain unbound;
signed bytes/hashes are not rewritten or retroactively certified. Receipt/outbox
finite retention is not implemented here; Class C's existing policy gap remains.

Verification is explicitly database-relative. Chains, annotations and Class C receipts
are not external anchors and do not independently defeat a privileged coherent
rewrite or backup rollback. External anchoring is a deferred follow-up, not a
completed Task 5.4 control. Enablement requires the [operator gates](admin-operations.md#security-ledger-retention-task-54),
including history assessment, explicit bootstrap, real-role denial tests and
successful dry-run/audit delivery. Task 5.3 deployment closure and Task 5.5
restricted-narrative retention approval/cleanup remain independent and open.

### 7.2 Surviving Metadata and Lifetimes

The [retained metadata inventory](data-architecture.md#retained-metadata-inventory)
enumerates exact fields and current lifetimes, including more than the approved
five-field erased workflow replay stub. Contracted hold tombstones retain original
account/actor/kind/time/key metadata with `no_expiry`. Erased hold-review replay
`scope`/`result_id` still joins those tombstones. Case stubs join an erased
`legal_cases` ID/sentinel even after narratives/associations/clocks are removed.
These are minimized but not unconditionally anonymous.

Reports retain preparer/approver/auth-version/time/policy/digest/source-version
provenance; transparency replay prepare/approve results retain actor/report/policy
references and exact snapshot bytes. Immutable governance records retain operator,
action, installation time/environment and external approval/inventory references.
Both chains retain one event UUID/digest node per event; erasures, receipt material,
settings, aggregate reporting state and Class C payloads have no implemented finite
expiry here. The literal supported replay lifetime remains `no_expiry`; it does
not legally approve all these permanent tables or supply a Class C purge policy.

Numeric narrative/context periods do not reset on review/release/retry. Baseline
context/released-hold cleanup is strict-before; workflow cleanup is at-or-after
expiry, with closed expiry the minimum of original max age and closure-relative
retention. Active independent holds defer cleanup, not account recovery expiry.
Approve actual purposes, legal basis, linkability, notices and retained inventories
before production processing; finite replay and identifier/pepper lifecycle remain
separate work. Local automated acceptance is not governance/deployment approval.

---

## 8. Law Enforcement Response & Preservation Requests

- **Intake & review:** Lawful requests are received through a defined channel, validated for legal sufficiency, and scoped narrowly (minimum necessary data).
- **Preservation (freeze-before-order):** On a valid preservation request, the relevant records are placed under Legal Hold immediately - freezing them before a full order arrives (supporting reference: 18 U.S.C. § 2703(f) for U.S. requests; equivalent local mechanisms elsewhere).
- **Response:** Only the minimum necessary data is disclosed, logged as a Class C audit event (who requested, what was disclosed, under what authority).
- **Transparency:** Aggregate statistics on requests received and answered are tracked for a future transparency report.

### 8.1 Operational Workflow and Approval Gate

One restricted case represents one actual request, including a rejected/no-match
request, not one account, lookup or hold. Intake is disabled until governance
approves a versioned numeric narrative-retention policy and the actual replay
metadata inventory/lifetime. Positive configuration alone is insufficient.
Existing hold tombstones retain linkable account/actor/time metadata; they are not
anonymous. Finite replay-token expiry is separately scoped, and rejection of the
supported lifetime keeps intake disabled.

Restricted legal narratives and subject associations are purpose-bound legal
administration records, not immutable Class C narrative archives. They use the
documented legal-obligation/claims exception to ordinary Class A erasure while
required, without extending Class B evidence retention. Intake fixes a maximum
case lifetime; closure may shorten it. Any active hold on any historically linked
subject takes precedence; release resumes the original clock. An abandoned open
case is not an indefinite-retention exemption. Exact policy numbers remain
unapproved until an external governance decision is installed.

Data-bearing response plans require an accepted content revision and approval by
a different active DPO account. This means distinct authorized accounts, not
verification that they represent different humans. This is distinct from investigative access and
does not automatically transfer data. Document handling and delivery use the
approved external system with its own retention/access controls. Case review or
closure never releases Task 5.3 holds. The first release supports one final
response, no reopening/supplements, and no automatic publication.

Case-free monthly counters survive narrative erasure for the transparency
purpose. Received and answered use their own timestamps/cohorts; an uncommunicated
rejection is not an answer. Annual reviewed artifacts omit identifiers and
fine-grained dimensions, suppress nonzero counts below 5, and suppress a whole
outcome breakdown when any cell is small. They are aggregate reporting records,
not a substitute for retained evidence or an anonymity guarantee. Restricted
approval provenance remains access-controlled; Class C action receipts retain
only minimized accountability data under the existing audit policy. No per-case
archive is reconstructed from statistics. Public publication remains a separate
manual governance decision.

---

## 9. Backup Deletion Policy

- Deleted data does not vanish from backups instantly. It persists until the relevant backup rotates out (e.g., 14-30 days per Section 3).
- Backups are encrypted and access-controlled. They are not used to circumvent erasure; they are a disaster-recovery mechanism only.
- A restore that would reintroduce erased data must re-apply pending deletions and active holds after recovery.
- Restore both payload/chain/head tables and sequence state, erasures, holds, governance/workflow, settings and outbox from one consistent recovery point. Verify before reopening ingestion/purge; separately reconcile pending/chained/legacy/unavailable receipt coverage and authoritative holds/deletions, then resume original eligible expiry. Backup rotation remains independent; no automatic genesis, hold bypass or guarantee of recovering erased payloads. See [disaster recovery](disaster-recovery.md#33-security-ledger-retention-recovery).

---

## 10. Data Subject Rights

Applicable rights and fulfillment procedures require legal review; they are not
all delivered through endpoints/dashboard controls. Current profile editing,
private-attribute API primitives and conditional deletion are narrower capabilities.
General archives, portability, objection/restriction workflows and approved
complete notices/DSAR handling are not established here.

| Proposed right/obligation       | Current evidence boundary                                                                                                     |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Access / portability            | No complete archive/export journey or downstream fulfillment is demonstrated.                                                 |
| Rectification                   | Current bounded profile/private-attribute edits are not complete rights fulfillment; preserve exact revisions/privacy grants. |
| Erasure                         | Conditional 30-day deletion/holds pipeline; downstream content, backups and retained metadata remain separate obligations.    |
| Object / restrict / be informed | Approved procedures/notices and receipt/response evidence remain legal/operator gates.                                        |

Never report complete erasure or rights fulfillment from `204`, missing profile
or NULL email. Account for retained Class B/Class C/backup/hold data in responses.

---

## 11. Consent Management

- Planned registration records exact approved legal versions and separate
  acceptance evidence in account birth. Current registration does not collect
  final legal evidence; no delivered withdrawal workflow is claimed.
- Approval/withdrawal behavior and prospective effects need defined legal
  contracts and observable implementation, not inferred consent from a checkbox.
- Processing that relies on a basis other than consent (legitimate interest / legal obligation, e.g., the security ledger) is documented as such and is not gated on consent.

---

## 12. Breach Notification & Incident Response

- **Detection & classification:** Incidents are triaged by severity with a defined escalation path.
- **Regulator notification:** Define applicable notification decisions, incident
  ownership and observed delivery procedures before launch. Where GDPR applies,
  Article 33's 72-hour rule has conditions; user notice under Article 34 is distinct.
  No actual response capability or timely delivery is certified here.
- **Post-incident:** Root-cause analysis and remediation are documented; audit trail integrity is verified.

---

## 13. Records of Processing & Impact Assessments

- **Records of Processing Activities (RoPA):** Required approved inventory of
  processing, purposes, categories and recipients where applicable (GDPR Art. 30);
  maintained approved records are not evidenced here.
- **Data Protection Impact Assessment (DPIA):** Required applicability/risk decision
  and completed review before high-risk launch where applicable (GDPR Art. 35);
  this technical guide is not a completed DPIA.

---

## 14. Roles & Accountability

- **Data Protection Officer (DPO):** Current seeded grants include gated audit,
  verification, holds/preservation/attribution and optional legal workflows,
  not a globally read-only role or delivered general export capability. Every use
  requires live permissions and its audit/assurance prerequisites.
- **Least privilege & segregation of duties:** No admin can perform a manual hard-delete of a user. Hard-delete is triggered only by the user's self-service erasure flow and executed by the scheduled job. Moderators can suspend/ban but not erase.
- **Documentation as accountability:** Every policy here is written, versioned, and auditable - this is what an investor or auditor reviews.

---

## 15. Vendor / Sub-processor Management

- Inventory proposed/enabled SMS.ir and SMTP processors and operator secret-delivery
  tools. Current crypto loads environment-injected local keys; it does not fetch
  live Infisical material or supply cached/offline/hot-rotation guarantees.
- Required DPAs/terms, processing/transfer inventory and security review are launch
  gates; signed agreements or completed reviews are not evidenced in this repository.
- Assign processor review and periodic reassessment owners before onboarding;
  proposed providers/environment-injected secret tools are not approved vendors.

SMS.ir VERIFY sends only to the supported Iranian mobile policy with explicit
key/template/parameter and budget approval. Sandbox shares the endpoint and
success-shaped responses but sends nothing; ID/cost/ACK does not prove live key
provenance or handset delivery. A live received-message test needs separate
billing/target authorization. SMTP must use verified authenticated TLS and strict
post-TLS SMTPUTF8 before EAI AUTH/envelope/DATA; no ASCII mailbox downgrade. Relay
acceptance and durable send intent are not inbox receipt or exactly-once delivery.

New account email is an existing owned mailbox, not a mailbox supplied by the IdP.
NFC/local lowercase/NFC plus strict IDNA is the declared identity profile; verify,
store, deliver and lookup exact canonical bytes. Persian/Arabic letters, dot/plus
variants and NFKC-distinct addresses stay distinct. Generic BlindIndex's NFKC
construction is unchanged; email capture/fallback/attribution shares its explicit
canonical input and pepper generation, without rehashing signed history or adding
historical dual-normalization lookup. Private retired-key backup/recovery and
coordinated rotation remain operator obligations, not primitive-test assurance.

---

## 16. Standards & Certifications Posture

SOC 2 Type II and ISO/IEC 27001/27701 are organizational aspirations, not observed
certifications. Technical mapping uses NIST SP 800-63B-4/C-4, ASVS 5.0.0 (L1-L3
only), WebAuthn Level 3 and applicable OAuth/OIDC RFCs; OAuth 2.1 remains a draft.
There is no ASVS Level 4, blanket NIST AAL/FAL, OAuth conformance, identity-proofing
or XSS-immunity claim. See the policy's standards applicability and readiness matrix.

Password-only consumer authentication, online saved-code issuance at lower assurance,
one-contact recovery/notification, lost-MFA identity-proofing and TOTP windows need
explicit standards-gap assessment. Independent MFA after UV, >=128-bit purpose-bound
HMAC codes and privileged hardware/backup are Hatef choices; documentation does
not prove implementation or legal approval. Exact-byte passwords align with ASVS
but diverge from NIST's NFC recommendation. Preserve high-entropy SHA-256 code
artifacts; HMAC is a proposed stronger choice, not proof existing verifiers are insecure.

---

## 17. Cross-References

- Physical schema for the security ledger and legal-hold tables: `data-architecture.md`.
- Deletion Cron behavior and hold precedence: `architecture.md`.
- Threat analysis (including deletion-to-evade-attribution): `threat-modeling.md`.
- Admin endpoints for holds and preservation: `api-design.md`.

### Task 5.3 implementation boundary

Legal requests are independent encrypted rows, unique by account, kind and opaque idempotency key. The original account reference survives deletion. Restricted narratives are encrypted under the durable action ID; general audit excludes raw lookup identifiers, blind indexes and legal narratives but remains personal data. Review dates are advisory. Approved retention and hold-aware cleanup retain replay tombstones without reapplying cleaned holds. Fresh storage has no plaintext narratives; obsolete legal Backfill/plaintext compatibility is removed. See [admin operations](admin-operations.md#migration-and-contraction).

Task 5.4 owns separately credentialed payload retention, structural verification
and read-only receipt reconciliation, not erasure certification or Task 5.5 approval.
External anchors, phone attribution and pepper rotation remain separate. API must
not receive ledger DELETE, head EXECUTE or trigger bypass. Installation follows
the [canonical inventory](devops-operations.md#canonical-packaged-migration-inventory)
under `public.identity_schema_version`; retired/untracked/contradictory histories
refuse without adoption. Stop incompatible writers and isolate matching resources;
baseline Down/reset refuse. Any existing-environment reset needs explicit scoped
authorization and never waives retention/hold/backup obligations. Historical evidence
remains unchanged, not current acceptance. Fresh final-source and
[production/manual gates](admin-operations.md#production-checklist) remain required.
