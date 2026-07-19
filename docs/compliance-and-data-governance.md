# Hatef Identity Platform - Compliance & Data Governance

This document is the single authoritative reference for the legal, privacy, and data-governance posture of the Hatef Identity Platform (IdP). It defines what data we retain, for how long, on what basis, and how we respond to lawful requests, account-deletion requests, and abuse investigations.

Principles in this document are written to be **law-agnostic** (they hold regardless of jurisdiction). Where a specific statute reinforces a principle, it is cited inline as a supporting reference (e.g., GDPR Article 17, Iran Computer Crimes Law). The platform launches first in Iran and expands to other jurisdictions afterward; the governance model is designed so that entering a new jurisdiction adds obligations without rewriting these principles.

---

## 1. Purpose & Scope

- **Purpose:** Guarantee that the IdP can simultaneously (a) honor user privacy and deletion rights, and (b) remain able to answer legitimate abuse and law-enforcement inquiries, without either goal defeating the other.
- **Scope:** Applies to all identity data processed by `apps/identity-api` (the Go IdP) and the identity records propagated to downstream services (e.g., Email Service, Search Core). It does not govern the *content* handled by those downstream services (e.g., email bodies); each service owns its own content-retention policy and must respect the identity-level signals defined here.

---

## 2. Data Classification

All data handled by the IdP falls into exactly one of three classes. The class determines its lifecycle.

### 2.1 Class A - Deletable PII (User-Owned)
Personal data that exists to serve the user and is erased when the user is deleted.
- Primary email, name/display name, avatar.
- Phone number, backup email, MFA/TOTP secrets (stored envelope-encrypted).
- Password hash, WebAuthn credentials, recovery codes.
- Active sessions and refresh tokens.

**Lifecycle:** Removed during hard-delete (see Section 5). Erasure is the default.

### 2.2 Class B - Minimal Security Metadata (Platform-Owned)
Non-content, minimized metadata retained to attribute abusive or security-relevant actions even after an account is deleted. This is the class that answers "who did this, and when" after the fact.
- Stable, non-reversible account reference (`account_ref`).
- Identity **blind index** only (e.g., `SHA-256(email + pepper)`), never raw PII.
- Event type, timestamp, source IP / subnet, user-agent / device fingerprint.
- Token/authorization issuance metadata (client_id, scope, issued-at).
- Security signals (RTR breach, suspicious login, risk-based lockout).

**Lifecycle:** Independent retention (see Section 7). **Not** deleted when the account is hard-deleted. Contains no raw PII and no action content.

### 2.3 Class C - Immutable Audit Logs
Tamper-evident administrative and system audit trail.
- Append-only, cryptographically chained (`chain_hash`).
- Administrative DB roles hold no `UPDATE`/`DELETE` rights.

**Lifecycle:** Retained per the audit-retention policy; integrity verified periodically. Never rewritten.

---

## 3. Data Retention Schedule

Retention is purpose-bound and time-boxed. Every category auto-purges when its window expires, unless a Legal Hold (Section 6) is active.

| Data Category | Class | Default Retention | Basis | Purge Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| Active account PII & credentials | A | Life of account | Contract / consent | Hard-delete on erasure |
| Sessions & refresh tokens | A | Until logout / expiry | Contract | TTL + revocation |
| Deletion grace record | A | 30 days | Contract / user recovery | Cron after grace window |
| Security event ledger | B | 6-18 months (configurable) | Legitimate interest / legal obligation | Scheduled purge job |
| Admin/system audit logs | C | Long-term (policy-defined) | Legal obligation / accountability | Append-only; no ad-hoc delete |
| Backups (PostgreSQL) | Mixed | Per backup retention (e.g., 14-30 days) | Operational continuity | Backup rotation |

The exact security-ledger retention value is a configuration decision. A shorter window is more privacy-protective; a longer window reduces the risk of being unable to answer a late-arriving lawful request. It must be a single, documented, enforced value - never "keep everything indefinitely."

---

## 4. Right to Erasure & Its Limits

Users may request deletion of their data ("Right to be Forgotten"). Erasure is the default outcome. It is limited only in narrow, documented cases:
- **Legal obligation:** A law requires the data to be retained (supporting reference: GDPR Art. 17(3)(b); local retention duties such as those under Iran's Computer Crimes Law for service providers).
- **Legal claims:** The data is needed for the establishment, exercise, or defense of legal claims, or an active investigation (supporting reference: GDPR Art. 17(3)(e)).

When a limit applies, the corresponding data is placed under Legal Hold (Section 6) or retained as Class B metadata; the rest is still erased. The user is informed that deletion is partially deferred where lawful to do so.

---

## 5. Deletion Flow & 30-Day Grace / Recovery Window

Deletion is a staged, reversible-then-permanent process:

1. **Request:** User initiates deletion (requires step-up authentication). Account status becomes `pending_deletion`; all sessions and refresh tokens are revoked immediately. An alert is sent to primary and backup email.
2. **Grace window (30 days):** A user-facing recovery period. The legitimate user can log in (with MFA/WebAuthn + step-up) and cancel the deletion. This window exists to defend against accidental or attacker-triggered (ATO) deletion.
3. **Hard-delete:** After 30 days, a Cron job permanently purges Class A data for that account across all tables in an ACID transaction, and emits the deletion event so downstream services scrub their PII.

The 30-day window is a **user-recovery** mechanism only. It is **not** a legal-retention period and is **independent** of Legal Hold (Section 6) and security-ledger retention (Section 7).

---

## 6. Legal Hold

A Legal Hold is a **precedence lock**, not a timer.

- **Precedence rule:** An active hold overrides every retention timer, including the 30-day grace window and the security-ledger retention. Holds > retention.
- **No time cap:** A hold has no predefined duration. It stays until explicitly released (e.g., case closed, order satisfied).
- **Activation:** Applied by an authorized role (e.g., DPO / Legal). Each hold records: subject reference, reason, requesting authority / case reference, legal basis, start time, and optional expected review date.
- **Enforcement:** The hard-delete Cron **must** check for an active hold before purging any record. If a hold covers the subject, the purge is skipped entirely and logged.
- **Release:** Releasing a hold re-subjects the data to the normal retention timers (data past its window is then purged on the next cycle).

**Important limitation:** A Legal Hold only helps if it is applied **before** the data is purged. It cannot resurrect already-deleted data. For requests that arrive *after* deletion, the answer comes from the minimal security ledger (Section 7), not from the hold.

---

## 7. Minimal Security Event Ledger

The ledger is the mechanism that answers a lawful request that arrives **after** an account has been deleted (e.g., a court inquiry at day 60 about an action taken before a day-30 deletion).

- **Decoupled lifecycle:** Ledger rows survive account hard-delete. Their lifetime is tied to the ledger's own retention (Section 3), not to the account.
- **Minimal & non-PII:** Rows carry a stable `account_ref`, an identity **blind index** (not raw email/phone), network/device metadata, event type, and timestamp - never action content and never raw PII.
- **Attribution on request:** When an authority provides a person's identifier, we compute the blind index and match it against the ledger. This attributes an action to an identity without us having retained raw PII.
- **Legal basis:** Legitimate interest (abuse prevention, security) and/or legal obligation - not user consent.

This is the load-bearing difference from a design that only masks and nulls audit rows on deletion: the ledger is intentionally kept attributable (via blind index and stable ref) within a bounded, documented window.

---

## 8. Law Enforcement Response & Preservation Requests

- **Intake & review:** Lawful requests are received through a defined channel, validated for legal sufficiency, and scoped narrowly (minimum necessary data).
- **Preservation (freeze-before-order):** On a valid preservation request, the relevant records are placed under Legal Hold immediately - freezing them before a full order arrives (supporting reference: 18 U.S.C. § 2703(f) for U.S. requests; equivalent local mechanisms elsewhere).
- **Response:** Only the minimum necessary data is disclosed, logged as a Class C audit event (who requested, what was disclosed, under what authority).
- **Transparency:** Aggregate statistics on requests received and answered are tracked for a future transparency report.

---

## 9. Backup Deletion Policy

- Deleted data does not vanish from backups instantly. It persists until the relevant backup rotates out (e.g., 14-30 days per Section 3).
- Backups are encrypted and access-controlled. They are not used to circumvent erasure; they are a disaster-recovery mechanism only.
- A restore that would reintroduce erased data must re-apply pending deletions and active holds after recovery.

---

## 10. Data Subject Rights

The platform supports the standard data-subject rights:
- **Access:** Obtain a copy of one's data (downloadable archive).
- **Rectification:** Correct inaccurate profile data.
- **Portability:** Machine-readable export.
- **Erasure:** Section 4-5.
- **Object / Restrict:** Object to or restrict certain processing.
- **Be informed:** Clear notice of what is collected, why, and for how long.

Each right is exposed through user-facing endpoints and dashboard controls, and each fulfillment is audit-logged.

---

## 11. Consent Management

- Consent is recorded with its **version** and **timestamp**, tied to the policy text in force at the time.
- Consent can be withdrawn; withdrawal is recorded and honored going forward.
- Processing that relies on a basis other than consent (legitimate interest / legal obligation, e.g., the security ledger) is documented as such and is not gated on consent.

---

## 12. Breach Notification & Incident Response

- **Detection & classification:** Incidents are triaged by severity with a defined escalation path.
- **Regulator notification:** Where required, the supervisory authority is notified without undue delay (supporting reference: GDPR's 72-hour expectation); affected users are notified when the risk warrants.
- **Post-incident:** Root-cause analysis and remediation are documented; audit trail integrity is verified.

---

## 13. Records of Processing & Impact Assessments

- **Records of Processing Activities (RoPA):** A maintained inventory of processing activities, purposes, categories of data, and recipients (supporting reference: GDPR Art. 30).
- **Data Protection Impact Assessment (DPIA):** Conducted for high-risk processing before launch (supporting reference: GDPR Art. 35).

---

## 14. Roles & Accountability

- **Data Protection Officer (DPO):** Read-only access to audit logs; oversees deletion pipelines, data-export requests, and Legal Holds.
- **Least privilege & segregation of duties:** No admin can perform a manual hard-delete of a user. Hard-delete is triggered only by the user's self-service erasure flow and executed by the scheduled job. Moderators can suspend/ban but not erase.
- **Documentation as accountability:** Every policy here is written, versioned, and auditable - this is what an investor or auditor reviews.

---

## 15. Vendor / Sub-processor Management

- Third-party processors (e.g., SMS gateway, Infisical KMS) are inventoried.
- Each has a data-processing agreement (DPA) defining scope, security obligations, and data handling.
- Sub-processors are reviewed before onboarding and periodically thereafter.

---

## 16. Standards & Certifications Posture

The platform is engineered toward, and documents its posture against, recognized standards:
- **SOC 2 Type II** - operational security controls (target).
- **ISO/IEC 27001** (information security) and **ISO/IEC 27701** (privacy information management) - target.
- **NIST SP 800-63B** and **OWASP ASVS Level 4** - implemented and auditable in the IdP's authentication design.

These are stated as posture and targets; formal certification is pursued as the platform matures.

---

## 17. Cross-References

- Physical schema for the security ledger and legal-hold tables: `data-architecture.md`.
- Deletion Cron behavior and hold precedence: `architecture.md`.
- Threat analysis (including deletion-to-evade-attribution): `threat-modeling.md`.
- Admin endpoints for holds and preservation: `api-design.md`.
