# Hatef Identity Platform - Threat Modeling & Risk Mitigation

This document formalizes the threat model for the Hatef Identity Platform using the industry-standard STRIDE framework, mapping potential security risks to corresponding cryptographic and protocol mitigations. It establishes the security assets, trust boundaries, and specific threat analyses to serve as an auditing and development blueprint.

---

## 1. Security Assets & Boundaries

### 1.1 Critical Assets

The platform manages several categories of sensitive assets. Compromise of any of these assets would result in significant privacy breaches or operational failure.

| Asset | Storage Medium | Protection Mechanisms | Impact of Compromise |
| :--- | :--- | :--- | :--- |
| **Password Hashes** | PostgreSQL | Argon2id ($m=64\text{MB}$, $t=3$, $p=4$) with a cryptographically secure salt per user. | High: Offline brute-force risk if weak hashing was used; neutralized by Argon2id parameters. |
| **Recovery Codes** | PostgreSQL | SHA-256 hashes ($O(1)$ fast indexed database lookup), high entropy (minimum 128-bit random value), atomic single-use destruction. | High: Account takeover. Implemented SHA-256 database index lookup to eliminate Argon2id CPU DoS vectors. |
| **PII (Phone, Backup Email, MFA secrets)** | PostgreSQL | Envelope Encryption: AES-GCM-256 with dynamic Data Encryption Keys (DEKs) wrapped by a Master Key Encryption Key (KEK) managed in Infisical. | High: Privacy violation (GDPR/compliance audit failure). Protected via application-layer envelope encryption. |
| **DPoP Private Keys** | Browser (IndexedDB) | WebCrypto API with `extractable: false` constraint. Strict Content Security Policy (CSP) with Strict-Nonce to prevent XSS-based extraction. | Medium: Request spoofing. Mitigated by sender-constrained tokens and non-extractable client-side storage. |
| **Session & Refresh Tokens** | Redis / Client Cookie | Next.js and Go session cookies with `__Host-` secure prefix, `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`. Refresh Token Rotation (RTR). | High: Active session hijacking. |
| **Step-up Replay HMAC Key** | Infisical / process memory | Base64-encoded key of at least 32 decoded bytes, identical on every replica, used to derive opaque Redis replay keys. | High: Inconsistent or exposed key material can split the replay domain or reveal replay-key inputs. |
| **Class B Security Ledger** | PostgreSQL retained payload/chain | Pseudonymized personal data with original account references, keyed identity index and minimized security metadata; live legal permissions, per-page step-up/audit and hold-aware retention. | High: Identity linkage and disclosure of network/device/activity metadata. Absence of raw email/phone is not anonymity. |
| **Baseline Administrative Audit and Legal Context** | PostgreSQL / durable audit pipeline | Restricted narratives encrypted separately; baseline audit minimizes content but retains actor/network metadata, action/hold references, timestamps and response digests. | High: Personal-data linkage and purpose/retention violations. Nulling a subject FK or masking a payload does not anonymize the audit. |

### 1.2 Trust Boundaries

The system is segmented into distinct trust boundaries to prevent lateral movement and contain potential security breaches:

```
[ External User / Untrusted Client ]
                |
     ============================= (Boundary 1: Ingress Insecure - HTTP Port 80) -- Auto-redirected to HTTPS
                |
[ Secure Ingress (Nginx MVP / Traefik target) - TLS Termination ]
                |
     ============================= (Boundary 2: Ingress Secure - HTTPS Port 443)
                |
     +----------+----------+
     |                     |
     v                     v
[Next.js UI (Nx)]     [Go IdP Core]
     |                     |
     |                     v
     |       ============================= (Boundary 3: Go IdP Trust Boundary)
     |                     |
     |                     +-----------------------+-----------------------+
     |                     | (PostgreSQL TCP)      | (Redis TCP)           | (ClickHouse TCP)
     |                     v                       v                       v
     |               [PostgreSQL]               [Redis]              [ClickHouse]
     |
     v
============================= (Boundary 4: Internal mTLS gRPC Mesh with SPIFFE/SPIRE)
     |
     +-----> [Search Core] (C++)
     |
     +-----> [Email Service] (Go)
```

1. **Client Boundary (Browser / Next.js SPA):** Regarded as untrusted. Host-level cookies are sealed using cryptographic flags. All script executions are limited by Strict-Nonce Content Security Policy (CSP).
2. **Ingress Insecure Boundary (HTTP):** Completely untrusted. Automatically redirected to HTTPS by the active edge ingress (Nginx in the MVP, Traefik in the post-MVP target).
3. **Ingress Secure Boundary (HTTPS):** Semi-trusted edge terminating public TLS. Routes path-based requests directly to Next.js or Go IdP. Only explicitly configured immediate proxy CIDRs may assert `X-Forwarded-For`; the edge overwrites inbound forwarding headers and the backend is not exposed directly.
4. **Go IdP Core Boundary:** High-trust internal backend. Houses local cryptographic keys (retrieved from Infisical) and performs identity verification.
5. **Internal gRPC Mesh Boundary:** Zero-Trust boundary. Every microservice within the Hatef ecosystem (e.g., Go Email Service, C++ Search Core) must authenticate via mutual TLS (mTLS) with dynamically rotated SPIFFE SVIDs issued by SPIRE.

---

## 2. STRIDE Threat Analysis Matrix

### 2.1 Spoofing (Identity Spoofing)

* **Threat S1: Phishing and Man-in-the-Middle (MitM) Auth Interception**
  * *Description:* Attackers set up dummy domains (e.g., `hatef-login.ir`) to trick users into submitting credentials or intercepting sessions.
  * *Mitigation:* Phishing-resistant WebAuthn (FIDO2) is utilized. The browser strictly binds registration and login assertions to the Relying Party ID (RP ID) origin. Any spoofed domain fails origin verification at the browser level.
* **Threat S2: Impersonation of Internal Microservices**
  * *Description:* A compromised internal container attempts to make gRPC calls to the IdP to validate fake user tokens or query identities.
  * *Mitigation:* Dynamic mTLS with SPIFFE/SPIRE SVIDs. Go gRPC interceptors inspect the client's cert SAN to verify the SPIFFE ID (e.g., `spiffe://hatef.ir/ns/identity/sa/email-service`) and strictly enforce method-level RBAC.
* **Threat S3: Client-IP Spoofing Through Forwarding Headers**
  * *Description:* A direct client supplies forged forwarding headers to evade subnet rate limits or poison audit attribution.
  * *Mitigation:* With an empty trusted-proxy list, the API ignores all forwarding headers and uses the socket peer. In deployment, only exact immediate-proxy CIDRs are allowed; `X-Forwarded-For` is accepted only from such a peer and resolved right-to-left to the first untrusted address. The Nginx edge overwrites, rather than appends to, the inbound header. `X-Real-IP` and `True-Client-IP` are not authority sources.

### 2.2 Tampering (Data Modification)

* **Threat T1: Relational Database Compromise (Direct SQL Modification)**
  * *Description:* An attacker gains read/write access to PostgreSQL and attempts to edit PII, inject arbitrary backup codes, or change user roles.
  * *Mitigation:* Sensitive PII is encrypted in the application layer using AES-GCM-256 envelope encryption. User roles and permissions are validated against signed, immutable gRPC SVID scopes. Backup codes have at least 128 bits of entropy and are stored under a deterministic SHA-256 digest (or HMAC-SHA-256 when the optional service-wide pepper is configured), preserving indexed lookup without storing plaintext. Verification and physical deletion occur in one ACID transaction.
* **Threat T2: Audit Log Alteration (Repudiation & Cover-up)**
  * *Description:* A malicious administrator or attacker gains access to logs and tries to delete trace events to cover their tracks.
   * *Mitigation:* The MVP uses PostgreSQL canonical-v2 append-only `audit_log_chain` / `security_ledger_chain`, separate retained payloads and both durable heads; ClickHouse is deferred. Checks validate links, retained leaves and absent-ledger-payload annotations against current heads/genesis. Armed guards and effective non-owner ACLs restrict ordinary mutation, but annotations do not prove lawful erasure and a coherent privileged rewrite/rollback is not independently detected. External anchoring and deployed monitoring remain separate gates.
* **Threat T3: Malicious Account Deletion (Account Takeover / ATO)**
  * *Description:* An attacker gains access to a user's active session or credentials and initiates immediate account deletion to destroy their data or lock them out permanently.
  * *Mitigation:* Deletion requires fresh WebAuthn UV, with active status/auth-version rechecked under the deciding account lock. The 30-day pending window, hashed reclaim request and encrypted email intents commit together. A separate SMTP worker retries primary/configured-backup notices. Pending users cancel through anonymous emailed-token plus UV/TOTP verification, not login. Recovery rechecks retirement, expiry and attempt limits at commit and never revives old sessions. Deployment requires a mailbox independently accessible after deactivation. This mitigates accidental/attacker deletion without claiming guaranteed delivery or recovery after mailbox/factor loss.
* **Threat T4: Cross-Session Ceremony or Enrollment Transplant**
  * *Description:* An attacker tries to finish another browser session's WebAuthn challenge, TOTP enrollment, phone verification, or Step-up ceremony, potentially burning the victim's pending state while probing it.
  * *Mitigation:* Pending challenges and opaque enrollment identifiers are bound to the exact user, initiating session, purpose, and ceremony flow. Matching and consumption are atomic; a foreign-session mismatch is rejected without consuming the legitimate state. TOTP enrollment returns an `enrollment_id`, phone send returns a 256-bit `verification_id`, and neither completion endpoint accepts client-supplied replacement identity data. The general enabled-TOTP `/auth/mfa/verify-code` oracle is not exposed.
* **Threat T5: Concurrent Removal of the Last Login Factor**
  * *Description:* Concurrent passkey deletion and TOTP-disable requests race their independent factor counts and leave an account without a browser login credential.
  * *Mitigation:* Both mutations begin a database transaction and lock the user row first. Passkey deletion then locks that user's credentials in stable credential-ID order before counting and deleting. The final passkey is always retained because WebAuthn is currently the only session-issuing browser login surface; TOTP disablement likewise refuses to remove the last factor when no passkey remains.

### 2.3 Repudiation (Denying Actions)

* **Threat R1: Admin Denies Performing Unauthorized Account Ban or Deletion**
  * *Description:* An admin performs a sensitive action (e.g., banning a user, changing roles) and claims they did not initiate it.
   * *Mitigation:* Privileged acceptance commits minimized durable outbox intent with the business transaction, then the separately credentialed publisher and signer deliver/chain it in PostgreSQL. Actor/network/action/time metadata remains personal data. HTTP operator identity is authenticated by the session; CLI actor/SPIFFE environment strings are launcher attribution, not independently verified SVID authentication. Hash chains are tamper-evidence, not cryptographic signatures by an operator or complete-ingestion/legal-authorization proof. PubAck or pending intent is not a chained receipt.
* **Threat R2: Deletion-to-Evade-Attribution (User Destroys Trail to Escape Accountability)**
  * *Description:* A user requests account deletion after a security-relevant action, and a lawful inquiry may arrive after hard deletion, for example at day 60 about an action before a day-30 deletion. A nulled Class C `user_id` FK is not a reliable identity-attribution mechanism. It also does **not** imply that no attributable trace remains: baseline administrative audit still contains personal data, including actor/network metadata and linkable references despite payload minimization.
  * *Mitigation:* The **`security_event_ledger`** (Class B) retains minimal **pseudonymized personal data**, not anonymous or non-PII data, for supported security events. Its original `account_ref` and keyed identity blind index survive account deletion subject to the existing independent retention policy and holds; it stores no raw email/phone, but network/device metadata remains personal data. Lookup is bounded to matching indexed, currently eligible records and does not prove complete activity, live-account existence or verified real-world identity. Independent holds protect still-retained data until explicit release; advisory review/expiry dates never release them. Release resumes original clocks and cannot restore erased data, extend account recovery or create an immutable snapshot. Preservation does not require a completed disclosure order/case workflow, and investigative access is not authority to transfer data externally. The documented retention bases remain legitimate interest / legal obligation, not consent; applicability and production approval remain separate governance requirements in `compliance-and-data-governance.md` and [admin operations](admin-operations.md). This panel does not supply approval.

### 2.4 Information Disclosure (Exposing Secrets)

* **Threat I1: XSS Extraction of Sender-Constrained Tokens**
  * *Description:* An attacker injects malicious JavaScript via an XSS vulnerability to read session tokens or OAuth keys.
  * *Mitigation:* Access tokens and refresh tokens are protected via DPoP (RFC 9449), sender-constraining them to client-side asymmetric ECDSA P-256 keypairs stored in IndexedDB. These keys are created with `extractable: false`, preventing scripts from extracting the private key. Frontend and backend enforce a Strict-Nonce CSP to block XSS execution vectors.
* **Threat I2: Session Hijacking via Cookie Stealing**
  * *Description:* Intercepted network traffic or script access allows attackers to copy session cookies.
  * *Mitigation:* All session cookies enforce the `__Host-` prefix with flags: `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`. This blocks cross-site script access and prevents cookies from being sent over insecure (HTTP) channels.

### 2.5 Denial of Service (DoS)

* **Threat D1: CPU Exhaustion via Backup Code Verification Attacks**
  * *Description:* Attackers spam the MFA recovery endpoint with continuous guesses. If the server utilizes memory-hard Argon2id to hash backup codes, sequential database checks will exhaust CPU resources instantly.
  * *Mitigation:* High-entropy backup codes ($128$-bit minimum) are immune to dictionary attacks and are stored as SHA-256 hashes instead of Argon2id. This allows direct indexed database lookups ($O(1)$ lookup time) and prevents CPU exhaustion DoS.
* **Threat D2: SMS OTP Gateway Toll Fraud and Bombing**
  * *Description:* Attackers execute a script to trigger thousands of SMS OTP requests, causing massive financial costs and service degradation.
  * *Mitigation:* Independent rate limiting in Redis. SMS triggers are limited independently per phone number (e.g., max 1/minute and 5/hour) and per IP subnet range (e.g., max 10/hour). Failed OTP verification is capped at 3 attempts; on the 3rd fail, the OTP is purged and the number is locked out for 15 minutes.

### 2.6 Elevation of Privilege (Privilege Escalation)

* **Threat E1: Bypassing Role Restrictions on gRPC Endpoints**
  * *Description:* An internal microservice with low privileges (e.g., email-service) attempts to execute admin operations such as role assignment.
  * *Mitigation:* Rigid RBAC scopes and SAN-based gRPC interceptor validation. The identity platform checks the client SPIFFE SVID in the SAN field of the TLS handshake, ensuring only authorized SPIFFE IDs can call privileged RPC endpoints.
* **Threat E2: Admin Privilege Abuse**
  * *Description:* A Moderator admin attempts to perform super-admin tasks such as modifying system-wide configurations or role allocations.
  * *Mitigation:* strict decoupling of administrative capabilities. The platform uses specific RBAC scopes (`System Administrator`, `Trust & Safety / Moderator`, `Data Protection Officer`, `Support`). Go APIs strictly authorize endpoints using these scope maps.
* **Threat E3: Recovery-Code Escalation Into a Full Session**
  * *Description:* A stolen backup code is used to obtain ordinary account, contact, TOTP, or Step-up authority before the legitimate owner can respond.
  * *Mitigation:* Recovery start is account-enumeration resistant and produces a one-time, ten-minute transaction. Successful code verification consumes the transaction and physically deletes the code atomically, then issues a distinct `recovery_enrollment` session. That restricted session can claim at most one UV-required replacement-passkey enrollment and cannot reach ordinary authenticated or Step-up-gated routes; completion revokes it and requires a normal login.
* **Threat E4: Replay of Step-up Grants or TOTP Proofs**
  * *Description:* A valid short-lived grant or still-valid TOTP code is replayed against multiple high-risk operations or replicas.
  * *Mitigation:* Grants are signed, session-bound, short-lived, and single-use. Production replicas share a Redis replay guard that performs atomic `SET NX` for the remaining lifetime under an HMAC-SHA-256-derived opaque key. TOTP-to-grant exchanges use the same guard for their validity window. Redis errors fail closed, and all replicas use the same `STEPUP_REPLAY_HMAC_KEY`; mixed-key rolling rotation is prohibited because it would create disjoint replay domains.

### 2.7 DPO/Legal Browser Boundary (Task 7.6)

| Risk | Required boundary / residual risk |
|---|---|
| Stale capability or overbroad role access | Five section 1.7 legal flags combine current permissions with actual mounts; every operation rechecks backend authority. No Super Admin bypass or DPO profile-browsing permission is added. Legal denial clears privileged state without signing out an otherwise valid ordinary session. UV or advertised TOTP is required per create/release/lookup page; absent step-up leaves only eligible reads. |
| Excessive or misattributed disclosure | Explicit bounded email POST only, core metadata by default and six purpose-specific unchecked opt-ins. No browser hashing/provider-specific normalization, blind-index/version disclosure, full payload, export, bulk copy or transfer. Keep multiple original references separate; no first-match selection or verified-person claim. Current retention/holds are rechecked per cursor page, with a fixed high-water and full coverage note, not complete history or inclusion proof. |
| Accidental scope widening / precision loss | Strict raw-query parsing rejects malformed/duplicate/unknown keys and empty supplied account filters; all-subject reads are explicit. Query/fields/page size remain fixed during continuation. Sequence/high-water strings preserve exact signed-64-bit coordinates, with no numeric fallback. A rejected cursor never silently becomes a fresh broader run; the server has no cursor age TTL or session binding, so the browser must clear it on scope/session change. |
| Replay, target substitution or false rollback | Create keys are scoped to `(account_ref, request_kind, key)`, not actor or globally unique. External intake retains exact normalized inputs; immutable confirmation and fresh grants guard explicit retries. Changed-input/cleaned-tombstone conflict never causes a new key or reactivation. A commit can precede session-renewal failure/lost response; uncertain writes are not automatically retried, and list state or later `401` cannot establish which request committed. |
| Browser / observability leakage | Neutral SSR/Flight/no-JavaScript shell; one fixed `/admin/legal` page, no legal data in navigation/history, storage, analytics or cross-tab messages. Abort, synchronously clear detached controls/hide sensitive regions and ignore late replies on section/cancel/hide/navigation/session/permission changes; pending forms clear at grant expiry. Only exact authorized API account-filter/hold-path/key-header exceptions are allowed, with template/redacted diagnostics. Mask narratives/results in artifacts. CSP and inert text reduce XSS risk but do not prevent authorized screenshots or guarantee memory zeroization. |
| False-negative signer setup / incompatible rollout | Require the real `admin-legal --operation=lookup-probe` against the actual canonical-v2 schema and keys before exposing attribution, including the post-synthetic-deletion check. Fixture omission keeps lookup unavailable; wrong supplied fixtures/keys fail rather than yield no match. Fake verified wiring is not acceptance evidence. Close/drain affected old admin ingress and retire incompatible callers/forms before every-replica API/UI cutover or rollback; preserve holds, intent, clocks and signed data. |

These controls do not close existing governance or deployment risks. Baseline admin audit remains personal data; approved narrative/replay/ledger retention, Class C policy, effective DB grants, actual signer/publisher delivery, exact-origin/APM redaction, privacy notices and ROPA/DPIA/DSAR duties remain separate. External anchoring and historical multi-pepper coverage remain deferred. Automated/source changes are not validation results or production approval; unobserved manual screen-reader, physical-authenticator, native zoom, hidden-tab/bfcache and deployed-ingress checks, and Task 5.3/5.4/5.5 statuses, remain open/unchanged as applicable.

### 2.8 Trusted Maintenance and Retained Metadata

The v2 purge login has ordinary Class B payload DELETE and erasure/outbox INSERT
plus required SELECT, not a SQL policy-enforcing purge routine. Trusted Go code
rechecks canonical candidates and retention/holds under ordered locks; a compromised
credential can issue arbitrary DELETE within its table authority. Structural chain/
leaf/annotation checks and separate bounded SELECT-only receipt reconciliation do
not independently prove policy compliance, receipt ingestion completeness or legal
authorization. Signer restart must tolerate legitimate pending receipt intent.

`no_expiry` metadata includes joinable hold tombstones/review replay, erased case
sentinels, report/transparency replay and governance provenance, chain event UUIDs/
digests and erasure/receipt material. Minimization is not unconditional anonymity
or blanket approval of permanent retention. See the [exact retained inventory](data-architecture.md#retained-metadata-inventory)
and unchecked [production checklist](admin-operations.md#production-checklist).
Forward `00019`/`00020` cutover stops affected intake/writers and verifies bounded
backfill before physical plaintext contraction; populated v1 or initialized proof
state refuses pending `00015`, never permitting a development-data wipe or genesis
reset. In-flight work must stop before emergency revocation is declared effective.
