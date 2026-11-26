# Hatef Identity Platform - Threat Modeling & Risk Mitigation

This document formalizes the threat model for the Hatef Identity Platform using the industry-standard STRIDE framework, mapping potential security risks to corresponding cryptographic and protocol mitigations. It establishes the security assets, trust boundaries, and specific threat analyses to serve as an auditing and development blueprint.

Source baseline: `85abb13a27196c229efa7f59d7ef5beebb1d7e49`, inspected 2026-11-24.
This is static analysis, not exploitation, deployed-control acceptance or certification.
[Policy](authentication-and-recovery-policy.md) owns SEC01-SEC16;
[assessment](security-architecture-assessment.md) owns F01-F12 exact source evidence;
[ADR](adr/0001-authentication-recovery-and-security-state-authority.md) records CP01 acceptance;
[readiness](security-testing-and-readiness.md) and
[backlog](../.github/tasks/registration-single-contract-tasks.md) own future
acceptance. Planned mitigations are not current controls. Supplemental inventories
below do not override the authoritative matrix.

---

## 1. Security Assets & Boundaries

### 1.1 Critical Assets

The platform manages several categories of sensitive assets. Compromise of any of these assets would result in significant privacy breaches or operational failure.

| Asset                                                      | Storage Medium                      | Protection Mechanisms                                                                                                                                                                        | Impact of Compromise                                                                                                                                                            |
| :--------------------------------------------------------- | :---------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Password Hashes**                                        | PostgreSQL                          | Exact-byte Argon2id (64 MiB, three iterations, four lanes), random salts and bounded computation/PHC admission.                                                                              | High: Weak passwords/offline guessing remain possible; hashing raises cost, not immunity.                                                                                       |
| **Saved Recovery Codes**                                   | PostgreSQL                          | Current untyped >=128-bit pool, SHA-256 or configured HMAC indexed verification and atomic destruction. Planned ARC/MFA Backup families.                                                     | High: Stolen live code can authorize factor mutation (F01); indexed lookup is not DoS or SQL-write immunity.                                                                    |
| **PII (Phone, Backup Email, MFA secrets, pending signup)** | PostgreSQL                          | Real AES-GCM-256, random per-record DEKs and one environment-injected KEK/version in process-local custody.                                                                                  | High: Privacy violation; no live Infisical fetch/cache/fallback/hot rotation or automatic retired-key retrieval. Protected backup/key inventory remains an operator obligation. |
| **Browser Proof Keys**                                     | Browser (IndexedDB)                 | Non-exportable keys and request-time Strict-Nonce CSP reduce extraction/injection.                                                                                                           | High: XSS/browser compromise can use keys without exporting; cookie+proof is a Hatef profile, not automatically RFC 9449 resource-token DPoP.                                   |
| **Session & Refresh Tokens**                               | Redis / Client Cookie               | Next.js and Go session cookies with `__Host-` secure prefix, `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`. Refresh Token Rotation (RTR).                                                | High: Active session hijacking.                                                                                                                                                 |
| **Replay/Encryption Keys**                                 | Operator delivery / process memory  | Separately injected bounded keys, common admitted replay domain; Infisical is an option, not verified runtime KMS.                                                                           | High: Custody/rotation failure can split replay domains; backup/key recovery needs independent evidence.                                                                        |
| **Class B Security Ledger**                                | PostgreSQL retained payload/chain   | Pseudonymized personal data with original account references, keyed identity index and minimized security metadata; live legal permissions, per-page step-up/audit and hold-aware retention. | High: Identity linkage and disclosure of network/device/activity metadata. Absence of raw email/phone is not anonymity.                                                         |
| **Baseline Administrative Audit and Legal Context**        | PostgreSQL / durable audit pipeline | Restricted narratives encrypted separately; baseline audit minimizes content but retains actor/network metadata, action/hold references, timestamps and response digests.                    | High: Personal-data linkage and purpose/retention violations. Nulling a subject FK or masking a payload does not anonymize the audit.                                           |

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

1. **Client Boundary:** Untrusted browser; cookie flags and CSP are hardening, not cryptographic seals or XSS immunity.
2. **HTTP Boundary:** Untrusted. HTTPS redirect/enforcement belongs to the documented Nginx MVP profile and deployed-ingress gate; Traefik is planned.
3. **Ingress Secure Boundary (HTTPS):** Semi-trusted edge terminating public TLS. Routes path-based requests directly to Next.js or Go IdP. Only explicitly configured immediate proxy CIDRs may assert `X-Forwarded-For`; the edge overwrites inbound forwarding headers and the backend is not exposed directly.
4. **Go IdP Core Boundary:** Holds operator-injected local cryptographic keys and performs bounded proofs. Infisical/SOPS/Sealed Secrets are provisioning options, not a live runtime KMS integration. Exact `APP_ENV=development|test|production` is mandatory; test is not a development exemption.
5. **Internal gRPC Boundary:** Opt-in private listener requires verified SPIFFE SVID/mTLS and exact method grants. Actual SPIRE/consumer deployment is not established; workload permission is not human delegation/assurance.

---

## Authoritative STRIDE Matrix

S = spoofing, T = tampering, R = repudiation, I = information disclosure,
D = denial of service, E = elevation. Tags are threat classes, not proof that an
attacker has the necessary access. F references resolve to exact current-source
ranges in the assessment. Required evidence below is future acceptance, not a
passing run. Planned controls do not erase current gaps.

| Threat / STRIDE                                              | Preconditions and assets                                                                        | Inspected controls and gap                                                                                                                  | Planned mitigation                                                                                                                                         | Residual risk                                                                                                       | Invariant / task                                       | Required evidence                                                                                                                    |
| ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| Credential stuffing / spraying (S/D/E)                       | Known identifier, reused/guessable password and enabled login; account/compute                  | Exact-byte Argon2id/PHC bounds and username admission; distributed attack/Redis critical-limit loss remains                                 | Eligible primary plus required independent MFA, durable subnet/account/global budgets                                                                      | Weak passwords/correlated compromise and targeted lockout remain                                                    | SEC02/SEC03/SEC09; T15/T18/T19A/T21A                   | F04/F06; `apps/identity-api/internal/crypto/password/password.go:32-50,89-125,163-205`; spray/saturation/limit-loss tests            |
| Enumeration / key inventory (I)                              | Anonymous named probes; account existence, credential IDs/counts                                | Stable decoy/floor; all real descriptors versus one 32-byte decoy exposes multi-key subset                                                  | Explicit eligible identification without inventories; retain discoverable login and opaque failures                                                        | Browser-local timing/username availability need bounded product analysis                                            | SEC01/SEC02; T18A/T03                                  | F03; real multi-key count/length/transport/repeated-probe distributions, not one-key-only fixture                                    |
| Phishing / interception (S/I/E)                              | Fake origin persuades victim to submit password/TOTP/contact/code; credentials                  | RP/origin/signature checks; password/TOTP/contact remain phishable and ordinary UP-only admitted                                            | Actual UV for all passkeys; privileged verified hardware plus independent backup; no contact-only primary                                                  | Compromised browser/RP/synced vault/social engineering remain                                                       | SEC02-SEC06; T17A/T18A/T28/T29                         | F01/F04/F05; wrong-origin/RP, physical hardware and abuse-review evidence                                                            |
| Mailbox / SIM takeover (S/E)                                 | Control of old mailbox/SIM, optionally leaked saved code; account/factor                        | Exact contact evidence; current contact normal login and code-only repair conflict with target                                              | Contact never primary; ARC+fresh eligible old contact for one ordinary repair; TOTP also pre-existing primary; privileged deny                             | Combined mailbox/SIM/saved-secret loss and one-contact availability risk                                            | SEC01/SEC02/SEC06/SEC08; T20/T27A/T28C/T29             | F01/F04/F09; channel takeover, unknown provenance/cooldown and no-fallback negatives                                                 |
| Saved-code theft / correlated vault-channel compromise (S/E) | Live ARC/backup theft, vault also owns password/TOTP/mail key; independent evidence             | High entropy and atomic destruction; current untyped purpose/issuance lacks independence model                                              | Separate family domains/generations/issuance; primary-bound backup or ARC+old-contact restricted repair; transient viewer/offline storage, no ARC delivery | Custody independence is an assumption; combined compromise may satisfy ordinary policy                              | SEC03-SEC07; T28A/T28B/T28C                            | F01/F07; stolen-only/correlated factors, cross-family rejection and viewer/issuance review                                           |
| Browser-key/session theft / XSS (S/I/E)                      | Stolen cookie+key or same-origin script; sessions/private data                                  | Strict cookies/Origin/CSP/JKT/intent; non-exportable key still script-usable                                                                | Preserve browser controls; SQL-earned session facts/revocation/deadlines and short explicit action authority                                               | Browser/extension/device compromise and screenshots remain                                                          | SEC09/SEC10/SEC14/SEC15; T16A/T22A/T34-T39             | F06/F08; wrong key/kind/intent, XSS-key-use review, deployed CSP/cookie/Origin observations                                          |
| Cross-account/purpose/destination/JKT substitution (S/T/E)   | Legitimate other proof/capability; unauthorized mutation                                        | Flow/session/key and complete contact bindings; new families/SQL continuity missing                                                         | Bind account/purpose/target/JKT/security/policy/family/contact association and final earned evidence; no fallback                                          | Compromised authority/application keys can still forge facts                                                        | SEC05/SEC06/SEC10/SEC14; T22A/T28-T33                  | F02/F06/F08; all negative bindings before legitimate consumption                                                                     |
| Replay / concurrent consumption (T/E)                        | Captured TOTP/grant/code/native response or lost marker; factors/sessions                       | Saved-code SQL destruction and Redis atomic claims; replay loss means unseen                                                                | Durable matched-step/factor-generation replay and proof/code spending in deciding SQL; original deadlines                                                  | Clock skew, matched-step ambiguity and restore rollback remain                                                      | SEC05/SEC09/SEC10/SEC16; T19A/T21A/T22A/T28/T42D       | F02/F06; real separate-connection one-winner, expiry/skew and flush/restore tests                                                    |
| Stale evidence during lock wait (T/E)                        | Admitted finish then session/grant expiry/revoke while waiting; credential/deletion             | Account/version locks and stronger T25/T26/T27 checks; recovery/deletion exact freshness omitted                                            | Fresh primary SQL live evidence/deadline checks after waits and immediately before mutation/consumption                                                    | Already-committed or admitted external effects not retroactively cancelled                                          | SEC09/SEC10; T16A/T22A/T29/T30                         | F02/F08; session-only revocation, original grant expiry and lock-wait races                                                          |
| Concurrent repairs/role/contact/factor changes (T/E)         | Competing valid attempts/operator role mutation; policy/primary/MFA/contact                     | Shared account/policy/user and deterministic credential locks; no target barrier/family model                                               | Global guards/ledger/account/operation-row order; final current category/policy/contact/family checks                                                      | Contention/deadlock/trigger effects need measured validation                                                        | SEC04/SEC07/SEC08/SEC10; T17A/T27A/T28/T29             | F02/F05/F09; repair versus promotion/removal/regen and failure injection                                                             |
| Recovery chaining / alternate management bypass (T/E)        | First repair then new session/challenge/code pool/settings mutation; other factors              | Restricted one-claim and version cutoff; no durable barrier                                                                                 | SQL account barrier consulted across all endpoints/replicas/restarts; fresh full-policy login only clears                                                  | Intentional multi-factor-loss lockout; repaired ordinary password qualifies only for unchanged password-only policy | SEC06/SEC07; T16A/T21A/T23A/T24/T25/T26/T29A/T29B/T29C | F01/F02; alternate endpoints, regen, replica/restart and barrier-clear matrix                                                        |
| MFA downgrade / untruthful backup (T/E)                      | Primary/repaired primary control, disable/reclassify request; MFA/assurance                     | Independent TOTP login gate exists; TOTP-only booleans and privileged passkey-or-TOTP weaker                                                | Record actual TOTP/backup separately, preserve required MFA during repair, no privileged backup downgrade                                                  | Total privileged factor loss remains blocked, no new support procedure                                              | SEC03/SEC04/SEC07; T17A/T21A/T28B/T29                  | F05; UV-only normal denial, backup not TOTP, management downgrade and privileged rejection                                           |
| Cooldown / provenance laundering (T/E)                       | Add/replace/re-add/reverify contact then recover; old eligibility                               | Protected evidence/invalidation and T27 gate; no explicit 24h association history                                                           | SQL absolute verification+24h eligibility, registration-only exemption, last-eligible protection and stale-proof fences                                    | Last destination loss can block recovery; clock/restore trust matters                                               | SEC08/SEC12; T27A/T28C/T41C                            | F09; before/equality/after24h, re-add/reverify/unknown history and last-contact races                                                |
| SQL read compromise (I)                                      | Snapshot/SELECT without app key; PII/hash/relationships                                         | Envelope encryption/keyed indexes/private fields; plaintext primary email/linkage remain                                                    | Dedicated external family HMAC keys, scoped grants and approved minimization/retention                                                                     | Equality/linkage/primary email/password guesses remain; HMAC is not writer defense                                  | SEC05/SEC14/SEC16; T28A/T40/T41/T42                    | F06/F07; DB/key separation, exact inventory and no-secret artifacts                                                                  |
| SQL writer/application/key compromise (T/R/E)                | Privileged write/process/key access; roles/evidence/credentials/audit                           | Guards/non-owner ACL/AEAD/chains; coherent privileged rewrite not independently detected                                                    | Least privilege, immutable facts/consumption where applicable, incident fencing/independent rollback witness                                               | Fully compromised authority/key operator may forge facts; SQL authority is not immunity                             | SEC09/SEC10/SEC16; T16A/T17A/T42D/T42                  | F06; deployed grants, forgery/rollback simulation, custody/independent review                                                        |
| Redis forged earned records (T/E)                            | Redis write/corruption; primary/UV/TOTP/JKT/session claims                                      | Structural validation/TTL and SQL status/version; no independent SQL fact proving earned evidence                                           | Redis non-authoritative; primary SQL backs all earned normal/preauth/repair authority                                                                      | Redis still causes outages/cost pressure                                                                            | SEC09; T16A/T19A/T21A/T42A                             | F06; structurally valid forged rows, corrupt indexes and no-minting acceptance                                                       |
| Redis loss/outage / critical-limit reset (D/T/E)             | Flush/eviction/partition/stale failover; replay and abuse budgets                               | Errors refuse without fallback, but lost markers/budgets appear fresh                                                                       | Durable replay/critical floors or closed admission; preserve stricter budgets                                                                              | Availability loss and distributed abuse remain                                                                      | SEC09/SEC16; T19A/T21A/T42A/T42D                       | F06; flush/eviction/partition/stale snapshot/failover and critical-limit survival                                                    |
| Stale SQL replicas/failover/restore (T/R/E)                  | Lagging authority read or pre-mutation snapshot restore; spent codes/credentials/grants/barrier | Current primary account/version checks; no independent observed rollback witness/zero-loss HA                                               | Primary-only admission, acknowledged-write/fencing gates and restore quarantine/reconciliation or safe invalidation                                        | Same-backup epoch cannot witness rollback; unobserved loss windows block release                                    | SEC09/SEC16; T42D/T42                                  | F06; stale-positive replicas/ambiguous failover/resurrected-code/credential/barrier and operator evidence                            |
| Unknown-result laundering (R/T/E)                            | Commit/send succeeded but output lost; proofs/accounts/secrets                                  | Bounded unknown/no-refund handling and narrow signup receipts; not universal reconciliation                                                 | Known fresh commit only for authority; task-defined read-only facts never refund/reissue/recreate/replay                                                   | Legitimate duplicate delivery or spent-secret loss can need fresh independent ceremony                              | SEC11/SEC13/SEC16; T19A/T28-T33/T41A                   | F02/F08/F10; every response-loss boundary, replay/result cannot bootstrap, provider ACK ambiguity                                    |
| Deletion abuse / reclaim-factor loss (T/D/E)                 | Stolen normal evidence/stale grant, pending deletion; data/username                             | UV-only deletion,30d,holds,reservations/exact reclaim checks; password/mobile/verified destination incomplete                               | Join exact grant/SID/JKT/deadline to deciding SQL; retain required reclaim factors; complete notifications before T27/mobile-only activation               | Mail/factor loss blocks reclaim; holds never renew expiry or restore purge                                          | SEC10/SEC12/SEC14; T30/T41/T27A                        | F08/F09; stale deletion, retained password/UV/TOTP,30d boundaries,hold/purge/reclaim races and real receipt                          |
| Partial/duplicate birth or receipt session (T/E)             | Collision, concurrent signup/lost response/replay; identity/private/legal/credentials           | One existing email/mobile/username/UV birth atomic, no session; selected/private/legal target missing                                       | Extend one service: all mandatory facts atomic, only known fresh birth issues same-JKT expected-subject session                                            | Post-birth delivery failure requires ordinary login, never attachment/recreation                                    | SEC01/SEC13/SEC14; T31-T37                             | F10/F11; all credential choices, rollback/collision,keyed password fingerprint,replay/result no-session                              |
| Privileged/consumer/workload confusion (S/E)                 | Valid user/client token or service query for privileged action; subject/role                    | SVID/method ACL, USER/CLIENT/live grant/PKCE; interactive/confidential/hardware admission incomplete                                        | Durable token/interactive flow and confidential auth; `(iss,sub)`,proof/scopes/current earned assurance/freshness at consumer action                       | Offline token residual lifetime and already-open streams/admitted work remain                                       | SEC03/SEC04/SEC16; T17A/T42A-T42C                      | F12; complete consent, client-auth negatives, UUID CLIENT separation and actual downstream admission                                 |
| Insider/audit repudiation/privacy leak (R/I/T)               | Operator/legal read or privileged rewrite; private/legal/audit records                          | Minimized intent,encrypted context,NULL-aware stable refs,chains/heads/holds; no independent authenticity/full-ingestion/retention approval | Preserve exact revisions/privacy grants/readers,least privilege,approved rights/retention and independent anchors                                          | Audit remains personal data; screenshots/coherent rewrite possible                                                  | SEC14/SEC16; T40/T41/T42                               | Assessment strengths and scoped legal controls below; disclosure/ACL/NULL-email audit/immutable-byte acceptance                      |
| Recovery/OTP/compute DoS/toll fraud (D)                      | Automated starts/guesses/provider abuse; availability/budgets/cost                              | Entropy/indexed pool,bounded Argon2,quotas/capacity/decoys; critical-limit loss and pool issuance gaps                                      | Durable budgets,absolute ceremonies,bounded cleanup/provider work,no billed auto-retry                                                                     | Targeted budget poisoning/provider outage/pool loss remain                                                          | SEC05/SEC08/SEC09/SEC11; T19A/T28/T41                  | F06/F07; saturation/cleanup/provider failures,unknown ACK,target-budget pressure and approved spend                                  |
| Preferences/navigation/native replay (T/E/I)                 | Locale/calendar/zone/theme/back/cancel; ceremony/private state                                  | Stable localized providers/exact wire bytes; new repair/code UI not implemented                                                             | Preserve key/subject/provider/ceremony/deadline,explicit send/native work,typed whole bilingual feedback                                                   | Browser prompts/manual Persian/accessibility/physical acceptance stay separate                                      | SEC15; T34-T39                                         | `docs/localization.md`; both locales desktop/tablet/mobile/light/dark,cross-tab/cancel,no replay/deadline extension,structural masks |
| Supply chain/CI/image/key injection (T/I/E/D)                | Upstream/build/operator compromise; entire system                                               | Pinned/toolchain/source contracts; no scans or deployed acceptance in doc work                                                              | T42 SAST/DAST/dependency/secret/container/provenance scans,reproducible image,least privilege,independent review                                           | Upstream/CI/operator trust and scan blind spots remain                                                              | SEC16; T42                                             | Actual source/toolchain fingerprints,scans,abuse penetration and physical/deployed gates                                             |

No critical/high authentication, recovery or authorization risk is silently accepted.
Evidence stays Planned/Blocked/Not Run until observed; exceptional risk acceptance
needs explicit documented owner approval. Existing strengths are preserved, not
claimed to close target prerequisites. No row licenses support override, duplicate
registration or lost-factor reuse of `/recover-account`.

## 2. Supplemental Current Controls

### 2.1 Spoofing (Identity Spoofing)

- **Threat S1: Phishing and Man-in-the-Middle (MitM) Auth Interception**
  - _Description:_ Attackers set up dummy domains (e.g., `hatef-login.ir`) to trick users into submitting credentials or intercepting sessions.
  - _Mitigation:_ Phishing-resistant WebAuthn (FIDO2) is utilized. The browser strictly binds registration and login assertions to the Relying Party ID (RP ID) origin. Any spoofed domain fails origin verification at the browser level.
- **Threat S2: Impersonation of Internal Microservices**
  - _Description:_ A compromised internal container attempts to make gRPC calls to the IdP to validate fake user tokens or query identities.
  - _Mitigation:_ Dynamic mTLS with SPIFFE/SPIRE SVIDs. Go gRPC interceptors inspect the client's cert SAN to verify the SPIFFE ID (e.g., `spiffe://hatef.ir/ns/identity/sa/email-service`) and strictly enforce method-level RBAC.
- **Threat S3: Client-IP Spoofing Through Forwarding Headers**
  - _Description:_ A direct client supplies forged forwarding headers to evade subnet rate limits or poison audit attribution.
  - _Mitigation:_ With an empty trusted-proxy list, the API ignores all forwarding headers and uses the socket peer. In deployment, only exact immediate-proxy CIDRs are allowed; `X-Forwarded-For` is accepted only from such a peer and resolved right-to-left to the first untrusted address. The Nginx edge overwrites, rather than appends to, the inbound header. `X-Real-IP` and `True-Client-IP` are not authority sources.

### 2.2 Tampering (Data Modification)

- **Threat T1: Relational Database Compromise (Direct SQL Modification)**
  - _Description:_ An attacker gains read/write access to PostgreSQL and attempts to edit PII, inject arbitrary backup codes, or change user roles.
  - _Current control and gap:_ Envelope encryption protects selected private values, not plaintext roles/all metadata. gRPC SVID method admission is separate from human roles. Current saved SHA-256/optional HMAC and atomic destruction do not prevent a SQL writer/application compromise from inventing authority. Planned SQL-earned facts need least privilege and independent rollback evidence, not database-compromise immunity.
- **Threat T2: Audit Log Alteration (Repudiation & Cover-up)**
  - _Description:_ A malicious administrator or attacker gains access to logs and tries to delete trace events to cover their tracks.
  - _Mitigation:_ The MVP uses PostgreSQL canonical-v2 append-only `audit_log_chain` / `security_ledger_chain`, separate retained payloads and both durable heads; ClickHouse is deferred. Checks validate links, retained leaves and absent-ledger-payload annotations against current heads/genesis. Armed guards and effective non-owner ACLs restrict ordinary mutation, but annotations do not prove lawful erasure and a coherent privileged rewrite/rollback is not independently detected. External anchoring and deployed monitoring remain separate gates.
- **Threat T3: Malicious Account Deletion (Account Takeover / ATO)**
  - _Description:_ An attacker gains access to a user's active session or credentials and initiates immediate account deletion to destroy their data or lock them out permanently.
  - _Mitigation:_ Deletion requires fresh WebAuthn UV, with active status/auth-version rechecked under the deciding account lock. The 30-day pending window, hashed reclaim request and encrypted email intents commit together. A separate SMTP worker retries primary/configured-backup notices. Pending users cancel through anonymous emailed-token plus UV/TOTP verification, not login. Recovery rechecks retirement, expiry and attempt limits at commit and never revives old sessions. Deployment requires a mailbox independently accessible after deactivation. This mitigates accidental/attacker deletion without claiming guaranteed delivery or recovery after mailbox/factor loss.
- **Threat T4: Cross-Session Ceremony or Enrollment Transplant**
  - _Description:_ An attacker tries to finish another browser session's WebAuthn challenge, TOTP enrollment, phone verification, or Step-up ceremony, potentially burning the victim's pending state while probing it.
  - _Mitigation:_ Pending challenges and opaque enrollment identifiers are bound to the exact user, initiating session, purpose, and ceremony flow. Matching and consumption are atomic; a foreign-session mismatch is rejected without consuming the legitimate state. TOTP enrollment returns an `enrollment_id`, phone send returns a 256-bit `verification_id`, and neither completion endpoint accepts client-supplied replacement identity data. The general enabled-TOTP `/auth/mfa/verify-code` oracle is not exposed.

T26 additionally freezes pending TOTP `auth_version`, DPoP JKT, authorizing method
and, for password/contact mode, channel and keyed complete current contact evidence.
The fixed `mfa_enrollment` proof is consumed once in the MFA-owned start transaction;
confirmation read-only revalidates the stored authorization, not the spent proof,
and accepts no additional grant/proof header. Its deadline is the earliest configured
enrollment, original fresh authorization, initiating-session idle and absolute
expiry, frozen at start; renewal, retry and same-authorization replacement cannot
extend it. Binding, live authority, budget and expiry are checked before decryption
and at the deciding write after slow work/lock waits. Foreign session/JKT requests
do not spend legitimate attempts; wrong-code counters and expired/exhausted-row
deletion commit as domain outcomes, while infrastructure/authorization faults roll
back. Packaged migration `00010_mfa_enrollment_authorization.sql` preserves entirely
missing metadata without fabricating authority, but new readers reject those rows
before decrypting secrets; partial bindings fail constraints. No backfill or mixed
old/new MFA maintenance writers may bypass the frozen checks.

- **Threat T5: Concurrent Removal of the Last Login Factor**
  - _Description:_ Concurrent passkey deletion, TOTP disablement or role provisioning races independent credential checks and leaves an account without a usable primary login or a privileged account without its required strong factor.
  - _Mitigation:_ The shared resulting-state policy is evaluated in caller-owned READ COMMITTED transactions. When password fallback is enabled, admitted username authority is locked before the shared account mutex and user row; credentials are locked in stable credential-ID order. The final passkey may be removed only if enabled username/password login has a supported usable verifier and a retained admitted username. Any privileged role additionally requires a surviving passkey or enabled TOTP backed by secret material. TOTP, contacts, backup codes and sessions are not primary credentials. Role admission uses the same policy; revocation remains possible without demanding stronger protection. `can_remove` is a per-entry locked-snapshot hint, not authority: stale DELETE is refused with `last_credential` or `last_factor` and remains localized in both portal languages.

T26 disable requires fresh Step-up earned through enrolled TOTP (`otp`) or actual
WebAuthn UV (`hwk` AND `user`), never password/contact control. Under those same
locks, evaluate authoritative `TOTP=false` resulting-state policy: zero-passkey
removal needs a nonprivileged account, enabled usable supported password login and
an admitted protected username. Any role membership, including custom roles with
administrative HTTP disabled, requires a surviving passkey after TOTP removal.
Unavailable policy/session evidence fails closed. Enabled `is_mfa_enabled`
continues to require independently earned TOTP at normal-session boundaries even
after UV-passkey login; there is no separate optional/required flag or exemption.

- **Threat T6: Credential Mutation After Session Revocation**
  - _Current control and gap:_ Captured account version/status is checked under account/user locks; real changes revoke authority and committed success bypasses renewal. No-ops/cosmetic renames do not revoke. This is not final live-session/grant/expiry continuity for recovery/deletion: F02/F08 remain. Email value changes also advance lifecycle revision; factor changes do not. The portal decodes self-invalidating success before clearing state, never replays after a later `401`, and keeps unknown responses unknown. Restricted enrollment returns to login without direct normal authority.

Known T26 setup/no-op commits use `session.OutcomeCommitted` so renewal faults cannot
replace a decided success. Enable/removal use committed-security-change handling,
never renew old authority or mark the initiating session MFA-authenticated. Only
real changes emit existing MFA enabled/disabled events; already-absent/pending-only
disable has no auth-version bump, disabled-factor audit or invalidation header.
Unknown commit acknowledgement returns bounded `503 outcome_unknown` without
tentative setup secret, success or success audit, and never refunds/retries spent
strong grants. SQL rollback restores SQL state, not consumed Redis authority. Lost
setup output needs an explicit fresh ceremony; uncertain enable/disable needs fresh
ordinary login/current-state inspection, not automatic replay or reconciliation.

- **Threat T7: Loss Or Fabrication Of Verified Contact Evidence**
  - _Description:_ A security change removes the only proven contact or treats a populated email/phone/backup field as verified without actual provenance.
  - _Mitigation:_ Phone replacement/removal validates encrypted evidence against the exact account, contact kind and current canonical contact under the shared account lock. An evidenced phone may be removed only when matching verified primary-email evidence survives; otherwise `last_verified_contact`. A populated backup address, verification-looking timestamp or legacy payload without matching evidence is not proof. Corrupt/misbound evidence fails closed rather than becoming absence. Phone ciphertext, blind index and evidence change together, with one auth-version increment for actual changes and none for absent-phone no-ops. This contact-preservation rule is separate from primary-login/factor policy and does not enable SMS/email sign-in.

T27 separates old-contact authorization from new-destination ownership. Eligible
password-only fallback needs usable admitted username/password login, no enabled
or configured independent MFA and no role membership. Its fresh password plus OTP
to an exactly evidenced server-selected contact yields only change/removal and
email/phone-target authority. New ownership, signup/login/recovery and other action
proofs cannot cross this boundary. Strong grants retain their existing shared
single-use contract; only genuinely earned UV or enrolled TOTP is admitted.

One contact manager freezes account/SID/JKT/version, original target evidence and
the earliest original authorization/channel/session deadline in encrypted pending
state. Prepared code and SQL pending state share one digest handle. Shared quota
reservation precedes the final pending/live-authority check immediately before
provider submission; no SQL lock spans transport I/O. Replacement/revocation
detected at that check sends nothing. Already-admitted external sends can race a
later change, but final locked validation rejects stale ownership. Redis holds a
keyed destination binding, not the plaintext new pending destination. Foreign
bindings are rejected before legitimate attempt consumption.

Finish spends ownership once and revalidates frozen authority read-only. Contact
write, exact `email_otp`/`sms_otp` evidence, pending consumption and one auth-version
cutoff commit atomically; an actual email value change adds one metadata-only
email lifecycle update. Same-value fresh provenance is a security change. Missing
evidence stays unknown, corrupt evidence cannot authorize or survive, and deliberate
repair needs independent valid authority plus new exact ownership. Known committed
outcomes survive renewal failure; unknown SQL/Redis/provider acknowledgement
exposes no tentative handle/success and never refunds or automatically retries.

Present-email removal is temporarily refused at the operation boundary until T28
alternative recovery identification and T41 email-absent notification/deletion/reclaim
are independently implemented and verified. Backup recipients or raw username bytes
do not bypass it. Already-absent email remains valid; no schema mandatory-email
rule or operator bypass is added. Disabled issuance retains finite code/proof readers,
keys and frozen budgets through original deadlines, and durable `email_otp` evidence
readers/envelope keys remain necessary for as long as stored evidence needs them.

### 2.3 Repudiation (Denying Actions)

- **Threat R1: Admin Denies Performing Unauthorized Account Ban or Deletion**
  - _Description:_ An admin performs a sensitive action (e.g., banning a user, changing roles) and claims they did not initiate it.
  - _Mitigation:_ Privileged acceptance commits minimized durable outbox intent with the business transaction, then the separately credentialed publisher and signer deliver/chain it in PostgreSQL. Actor/network/action/time metadata remains personal data. HTTP operator identity is authenticated by the session; CLI actor/SPIFFE environment strings are launcher attribution, not independently verified SVID authentication. Hash chains are tamper-evidence, not cryptographic signatures by an operator or complete-ingestion/legal-authorization proof. PubAck or pending intent is not a chained receipt.
- **Threat R2: Deletion-to-Evade-Attribution (User Destroys Trail to Escape Accountability)**
  - _Description:_ A user requests account deletion after a security-relevant action, and a lawful inquiry may arrive after hard deletion, for example at day 60 about an action before a day-30 deletion. A nulled Class C `user_id` FK is not a reliable identity-attribution mechanism. It also does **not** imply that no attributable trace remains: baseline administrative audit still contains personal data, including actor/network metadata and linkable references despite payload minimization.
  - _Mitigation:_ The **`security_event_ledger`** (Class B) retains minimal **pseudonymized personal data**, not anonymous or non-PII data, for supported security events. Its original `account_ref` and keyed identity blind index survive account deletion subject to the existing independent retention policy and holds; it stores no raw email/phone, but network/device metadata remains personal data. Lookup is bounded to matching indexed, currently eligible records and does not prove complete activity, live-account existence or verified real-world identity. Independent holds protect still-retained data until explicit release; advisory review/expiry dates never release them. Release resumes original clocks and cannot restore erased data, extend account recovery or create an immutable snapshot. Preservation does not require a completed disclosure order/case workflow, and investigative access is not authority to transfer data externally. The documented retention bases remain legitimate interest / legal obligation, not consent; applicability and production approval remain separate governance requirements in `compliance-and-data-governance.md` and [admin operations](admin-operations.md). This panel does not supply approval.

### 2.4 Information Disclosure (Exposing Secrets)

- **Threat I1: XSS Extraction of Sender-Constrained Tokens**
  - _Description:_ An attacker injects malicious JavaScript via an XSS vulnerability to read session tokens or OAuth keys.
  - _Current control and residual:_ Non-exportable browser keys, strict cookies and CSP reduce theft/injection; malicious same-origin script can still use the key. Cookie proof is separate from applicable RFC 9449 access-token DPoP. No XSS immunity is claimed.
- **Threat I2: Session Hijacking via Cookie Stealing**
  - _Description:_ Intercepted network traffic or script access allows attackers to copy session cookies.
  - _Mitigation:_ All session cookies enforce the `__Host-` prefix with flags: `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`. This blocks cross-site script access and prevents cookies from being sent over insecure (HTTP) channels.

### 2.5 Denial of Service (DoS)

- **Threat D1: CPU Exhaustion via Backup Code Verification Attacks**
  - _Description:_ Attackers spam the MFA recovery endpoint with continuous guesses. If the server utilizes memory-hard Argon2id to hash backup codes, sequential database checks will exhaust CPU resources instantly.
  - _Current control and residual:_ >=128-bit saved-code entropy and indexed SHA-256/optional HMAC avoid sequential memory-hard work. SQL/connection/provider capacity and quotas still require testing; no O(1) or DoS immunity. Planned family/account/generation HMAC is a stronger Hatef choice, not proof current high-entropy SHA is inherently unsafe.
- **Threat D2: SMS OTP Gateway Toll Fraud and Bombing**
  - _Description:_ Attackers execute a script to trigger thousands of SMS OTP requests, causing massive financial costs and service degradation.
  - _Mitigation:_ Enabled SMS uses shared atomic phone/subnet/global limits and finite outstanding-signup capacity, plus bounded attempts/expiry/lockout. Disabled mode needs no provider key and retains DB-only removal. SMS.ir VERIFY is fixed HTTPS POST, Iranian-only destination policy and explicit live/sandbox mode; production live-only. Six-digit string codes preserve zeros. Provider throttle is a failed send, not falsely reported local throttling. Sandbox success sends nothing; approved spend/egress/key/template/handset receipt remain operational gates, not guarantees from engineering ceilings.

### 2.6 Elevation of Privilege (Privilege Escalation)

- **Threat E1: Bypassing Role Restrictions on gRPC Endpoints**
  - _Description:_ An internal microservice with low privileges (e.g., email-service) attempts to execute admin operations such as role assignment.
  - _Mitigation:_ Rigid RBAC scopes and SAN-based gRPC interceptor validation. The identity platform checks the client SPIFFE SVID in the SAN field of the TLS handshake, ensuring only authorized SPIFFE IDs can call privileged RPC endpoints.
- **Threat E2: Admin Privilege Abuse**
  - _Description:_ A Moderator admin attempts to perform super-admin tasks such as modifying system-wide configurations or role allocations.
  - _Mitigation:_ strict decoupling of administrative capabilities. The platform uses specific RBAC scopes (`System Administrator`, `Trust & Safety / Moderator`, `Data Protection Officer`, `Support`). Go APIs strictly authorize endpoints using these scope maps.
- **Threat E3: Recovery-Code Escalation Into a Full Session**
  - _Description:_ A stolen backup code is used to obtain ordinary account, contact, TOTP, or Step-up authority before the legitimate owner can respond.
  - _Current control and gap:_ Restricted enrollment cannot directly reach normal/Step-up routes and consumes a saved code before UV-passkey enrollment. But current code plus known email can enroll the attacker's key without old-contact/privileged denial; it can then satisfy normal login for MFA-disabled accounts. Enabled TOTP still needs independent completion. Final expiry/anti-chaining are missing; F01/F02 are static conditional findings, not dynamically demonstrated anonymous exploits.
- **Threat E4: Replay of Step-up Grants or TOTP Proofs**
  - _Description:_ A valid short-lived grant or still-valid TOTP code is replayed against multiple high-risk operations or replicas.
  - _Mitigation:_ Grants are signed, session/version/JKT-bound, short-lived, and single-use, not action-scoped; each consumer checks its required actually earned factor. Production replicas share a Redis replay guard that performs atomic `SET NX` for the remaining lifetime under an HMAC-SHA-256-derived opaque key. TOTP-to-grant exchanges use the same guard for their validity window. Redis errors fail closed, and all replicas use the same `STEPUP_REPLAY_HMAC_KEY`; mixed-key rolling rotation is prohibited because it would create disjoint replay domains.

The T26 password/contact proof is purpose-specific `mfa_enrollment`. Fresh
password verification and exact protected canonical-contact evidence are required
before delivery and rechecked at issuance/start/confirmation; populated contacts,
available factors or an old login do not confer fresh authority. Eligibility is
active nondeleted nonprivileged password-only, zero passkeys, no enabled/configured
active TOTP and usable enabled admitted password sign-in. Enrollment start accepts
exactly one UV strong Step-up OR its purpose proof, with malformed/mixed/misplaced
headers rejected before consumption. Codes/proofs cannot cross signup, login,
deletion, password-change, first-passkey, recovery or disable boundaries; no general
password Step-up grant is created. Default-off independent issuance/channel switches,
a dedicated binding key, shared bounded contact-code quotas and a distinct SMS
template prevent silent activation or authority/template reuse. Delivery/password
verification happen outside long-held SQL locks, with no automatic billed retries.
Provider acceptance is not receipt; reader/key availability is retained for bounded
pending work after issuance is disabled, without requiring a delivery provider at
final confirmation. See [rollout and rollback](devops-operations.md#first-passkey-proofs-t25).

### 2.7 DPO/Legal Browser Boundary (Task 7.6)

| Risk                                               | Required boundary / residual risk                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Stale capability or overbroad role access          | Five section 1.7 legal flags combine current permissions with actual mounts; every operation rechecks backend authority. No Super Admin bypass or DPO profile-browsing permission is added. Legal denial clears privileged state without signing out an otherwise valid ordinary session. UV or advertised TOTP is required per create/release/lookup page; absent step-up leaves only eligible reads.                                                                                                                                                                                                                             |
| Excessive or misattributed disclosure              | Explicit bounded email POST only, core metadata by default and six purpose-specific unchecked opt-ins. No browser hashing/provider-specific normalization, blind-index/version disclosure, full payload, export, bulk copy or transfer. Keep multiple original references separate; no first-match selection or verified-person claim. Current retention/holds are rechecked per cursor page, with a fixed high-water and full coverage note, not complete history or inclusion proof.                                                                                                                                             |
| Accidental scope widening / precision loss         | Strict raw-query parsing rejects malformed/duplicate/unknown keys and empty supplied account filters; all-subject reads are explicit. Query/fields/page size remain fixed during continuation. Sequence/high-water strings preserve exact signed-64-bit coordinates, with no numeric fallback. A rejected cursor never silently becomes a fresh broader run; the server has no cursor age TTL or session binding, so the browser must clear it on scope/session change.                                                                                                                                                            |
| Replay, target substitution or false rollback      | Create keys are scoped to `(account_ref, request_kind, key)`, not actor or globally unique. External intake retains exact normalized inputs; immutable confirmation and fresh grants guard explicit retries. Changed-input/cleaned-tombstone conflict never causes a new key or reactivation. A commit can precede session-renewal failure/lost response; uncertain writes are not automatically retried, and list state or later `401` cannot establish which request committed.                                                                                                                                                  |
| Browser / observability leakage                    | Neutral SSR/Flight/no-JavaScript shell; one fixed `/admin/legal` page, no legal data in navigation/history, storage, analytics or cross-tab messages. Abort, synchronously clear detached controls/hide sensitive regions and ignore late replies on section/cancel/hide/navigation/session/permission changes; pending forms clear at grant expiry. Only exact authorized API account-filter/hold-path/key-header exceptions are allowed, with template/redacted diagnostics. Mask narratives/results in artifacts. CSP and inert text reduce XSS risk but do not prevent authorized screenshots or guarantee memory zeroization. |
| False-negative signer setup / incompatible rollout | Require the real `admin-legal --operation=lookup-probe` against the actual canonical-v2 schema and keys before exposing attribution, including the post-synthetic-deletion check. Fixture omission keeps lookup unavailable; wrong supplied fixtures/keys fail rather than yield no match. Fake verified wiring is not acceptance evidence. Close/drain affected old admin ingress and retire incompatible callers/forms before every-replica API/UI cutover or rollback; preserve holds, intent, clocks and signed data.                                                                                                          |

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
Fresh installation uses the complete packaged `00001` through `00011` inventory
in [operations](devops-operations.md#canonical-packaged-migration-inventory), tracked in
`public.identity_schema_version`. All legacy `public.goose_db_version`, untracked
nonempty application schemas and contradictory histories refuse without mutation,
even if old storage appears equivalent. There is no old-lineage upgrade/adoption,
automatic history stamping or genesis reset. Stop all old writers and pair the
explicitly scoped fresh PostgreSQL target with matching isolated Redis/NATS state
so stale authority, queued events and checkpoints cannot enter the new database.
Baseline Down/reset refuse; disposable-data confirmation does not authorize an
existing-environment reset, which needs separately explicit scoped targets.
Obsolete legal Backfill/plaintext compatibility is removed, not a new-lineage
upgrade path. Operator
genesis/provisioning, legal retention, approval and production/manual gates remain
unchanged; historical evidence does not certify fresh-baseline acceptance.
In-flight work must stop before emergency revocation is declared effective.

### 2.9 Conditional Signup, Unicode and Delivery

| Risk                                               | Required boundary / residual risk                                                                                                                                                                                                                                                                                                                                                                  |
| -------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Identity aliases or misdelivery                    | Canonical NFC/local lowercase/NFC plus strict non-transitional IDNA; exact canonical verify/store/deliver/lookup and email HMAC input. Generic BlindIndex NFKC remains unchanged. NFC equivalents converge; Persian/Arabic, dot/plus and NFKC-distinct mailboxes remain distinct. Reject malformed/invisible inputs instead of stripping them; no signed-history rehash or fallback normalization. |
| EAI downgrade / secret leakage                     | Strict post-TLS EHLO must advertise SMTPUTF8 before EAI AUTH/envelope/DATA. System sender/auth stays ASCII; no transliteration/address rerouting. Message-free readiness probes do not prove independent mailbox access or actual inbox delivery.                                                                                                                                                  |
| Stolen/transplanted enrollment                     | Attempt capability hash, original verified DPoP JKT, distinct email token, signup-purpose phone reference and frozen resident UV ceremony. Email link fragment is scrubbed before explicit verification; it cannot mint a capability/session/role. Capability cannot authorize account, recovery, Step-up, OAuth or admin operations.                                                              |
| Unbounded PII or delivery costs                    | Explicit finite admission/send/pending budgets; 15m pending, 10m email, <=5m passkey and 1h receipt; separate actual-login bounded cleanup with holds/subject locks. Holds retain expired evidence, not renewed authority. Cleanup outage cannot bypass pending capacity; ceilings are not operator budget approval.                                                                               |
| Duplicate account birth / lost completion response | Final user/credential/encrypted-phone/created-event/receipt commit together. DB uniqueness protects active/pending-deletion identifiers and credentials. Same-capability/JKT result reconciliation uses a fresh proof; no existing-account attachment, email-only capability recovery or speculative duplicate creation. External mail/SMS acceptance remains ambiguous and not exactly once.      |
| Fake provider or production development mode       | Exact mode allowlist, positive development-only conveniences and no fallback on errors. SMS.ir fixed VERIFY POST/verified TLS/Iranian-only policy; production live-only, no runtime fake-provider switch. Controlled internal DNS/trust fixtures exercise the immutable image without external egress and are not real sandbox/handset evidence.                                                   |
| Audit or lookup mismatch                           | Capture preserves canonical-email digest+generation; storage admission rejects invalid actor/time/shape/index metadata before hashing with fixed redacted quarantine reasons. Moderator lookup requires mandatory returned `canonical_email` bound to its selected row; no raw-input/ASCII-only fallback. Neither metadata field grants additional disclosure authority.                           |

Registration/SMS default disabled. These contracts do not certify final service,
race, immutable-image browser or cleanup acceptance. Live provider/billing/egress,
mailbox access, private key custody/recovery, approved retention/budgets, effective
deployed logins and supervision remain separate enablement gates. No mailbox,
password, role or session bootstrap, laboratory reset/adoption or live-target
permission is supplied.
