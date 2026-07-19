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

### 1.2 Trust Boundaries

The system is segmented into distinct trust boundaries to prevent lateral movement and contain potential security breaches:

```
[ External User / Untrusted Client ]
                |
     ============================= (Boundary 1: Ingress Insecure - HTTP Port 80) -- Auto-redirected to HTTPS
                |
[ Secure Ingress (Traefik) - TLS Termination ]
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
2. **Ingress Insecure Boundary (HTTP):** Completely untrusted. Automatically redirected to HTTPS by Traefik.
3. **Ingress Secure Boundary (HTTPS):** Semi-trusted edge terminating public TLS. Routes path-based requests directly to Next.js or Go IdP.
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

### 2.2 Tampering (Data Modification)

* **Threat T1: Relational Database Compromise (Direct SQL Modification)**
  * *Description:* An attacker gains read/write access to PostgreSQL and attempts to edit PII, inject arbitrary backup codes, or change user roles.
  * *Mitigation:* Sensitive PII is encrypted in the application layer using AES-GCM-256 envelope encryption. User roles and permissions are validated against signed, immutable gRPC SVID scopes. Backup codes are stored as salted SHA-256 hashes, preventing bulk decryption even in the event of database exfiltration.
* **Threat T2: Audit Log Alteration (Repudiation & Cover-up)**
  * *Description:* A malicious administrator or attacker gains access to logs and tries to delete trace events to cover their tracks.
  * *Mitigation:* Logs are stored in ClickHouse which is configured to be strictly Append-Only (administrative DB roles lack `ALTER...DELETE` privileges). Every audit log row's cryptographic hash is chained to the preceding row's hash. Any tampering breaks the chain and triggers immediate system alerts.
* **Threat T3: Malicious Account Deletion (Account Takeover / ATO)**
  * *Description:* An attacker gains access to a user's active session or credentials and initiates immediate account deletion to destroy their data or lock them out permanently.
  * *Mitigation:* Deleting an account requires high-risk Step-Up authentication (WebAuthn User Verification). Furthermore, deletion requests are queued under a **30-day Grace Period (`pending_deletion` status)**. Legitimate users are notified immediately via primary and backup emails, and can log in with multi-factor authentication within 30 days to cancel the request and recover their account, neutralizing the threat of irreversible malicious deletion.

### 2.3 Repudiation (Denying Actions)

* **Threat R1: Admin Denies Performing Unauthorized Account Ban or Deletion**
  * *Description:* An admin performs a sensitive action (e.g., banning a user, changing roles) and claims they did not initiate it.
  * *Mitigation:* ClickHouse immutable append-only logs record every single state change initiated by an administrator. Every row contains the admin's verified user ID, SPIFFE SVID details, IP address, and a cryptographic signature. This immutable log is checked during periodic compliance audits.
* **Threat R2: Deletion-to-Evade-Attribution (User Destroys Trail to Escape Accountability)**
  * *Description:* A user performs a harmful, security-relevant action (e.g., sends a malicious/abusive email through the ecosystem), then requests account deletion to erase attribution. A lawful inquiry (e.g., a court order) may arrive *after* the account has been hard-deleted - for example, at day 60 about an action taken before a day-30 deletion. With only the standard audit table (`user_id ON DELETE SET NULL`, PII-masked `payload`), no attributable trace would remain.
  * *Mitigation:* A minimal, non-PII **`security_event_ledger`** (Class B) is written at the time of security-relevant actions and is **decoupled from the account lifecycle** - it survives hard-delete and purges only on its own independent retention schedule (e.g., 6-18 months). It stores a stable `account_ref` and an identity **blind index** (never raw PII), so an action stays attributable to an identity within a bounded, documented window. For inquiries known *before* deletion, a **Legal Hold** (precedence lock, holds > retention) freezes the subject's data ahead of any purge. Legal basis for retention is legitimate interest / legal obligation, not consent. Full policy and schema: `compliance-and-data-governance.md` and `data-architecture.md`.

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
