# Hatef Identity Platform - API Design

This document describes the platform's gRPC/protobuf, REST/OIDC and strict first-party JSON contracts. Browser enrollment shapes below are not new protobuf/event versions. Enabled-feature descriptions are conditional contracts, not acceptance results or deployed capability claims.

Source baseline: `85abb13a27196c229efa7f59d7ef5beebb1d7e49`, inspected 2026-11-24.
[Policy](authentication-and-recovery-policy.md) owns SEC01-SEC16 and proposed
authority; [assessment](security-architecture-assessment.md) owns exact findings.
[ADR](adr/0001-authentication-recovery-and-security-state-authority.md),
[readiness](security-testing-and-readiness.md) and
[backlog](../.github/tasks/registration-single-contract-tasks.md) do not activate
routes. Current shapes below stay current until separately authorized implementation;
planned shapes are not client-compatible promises or already mounted interfaces.

## 1. External APIs (REST & OIDC)

These endpoints use the canonical ingress (host Nginx for MVP; Traefik is a later target) and are consumed by the Next.js frontend and authorized OIDC clients.

### 1.1 Standard OIDC/OAuth2 Endpoints

Scoped current protocol support, not complete OIDC/OAuth conformity. OAuth 2.1 is
an active draft. Interactive login/consent/code issuance is incomplete
(`apps/identity-api/internal/server/authorize.go:34-65`).

- `GET /.well-known/openid-configuration`: Discovery endpoint. Indicates mandatory PKCE support (`code_challenge_methods_supported: ["S256"]`), DPoP support, and supported client authentication methods (`token_endpoint_auth_methods_supported: ["private_key_jwt", "none"]`).
- `GET /oauth2/jwks`: Returns the JSON Web Key Set containing only asymmetric public keys (**RS256** and **ES256**) mapped across a graceful 3-key rotation cycle: `active` (currently signing new tokens), `next` (pre-generated and published key), and `previous` (recently expired key, kept to verify outstanding unexpired tokens).
- `GET /oauth2/auth`: Authorization endpoint (redirects to login/consent UI). Requires `code_challenge` (S256) and `code_challenge_method=S256` for public clients.
- `POST /oauth2/token`: Token exchange endpoint (Auth Code, Refresh Token, Client Credentials).
  - **PKCE Verification:** Rejects exchange requests using the `plain` method; strictly validates `code_verifier` with SHA-256 (`S256`).
  - **Refresh Token Rotation (RTR):** One-use grant/session/version/key-bound rotation retains spent metadata. Recognized reuse invokes account-wide breach handling only after required original proof-key validation; a stolen sender-constrained secret alone cannot trigger revocation. Already-admitted work/offline JWT lifetime remains residual.
  - **DPoP Binding (RFC 9449):** Validated proofs use bounded nonce/JTI replay and produce the bound JKT. The token service selects bearer if no validated proof is supplied (`apps/identity-api/internal/oidc/token/service.go:670-679`); actual client/handler admission determines whether that profile is reachable. Do not claim every token is sender-constrained. Applicable resource-token DPoP and cookie+proof are distinct profiles.
  - **Client Authentication (`private_key_jwt`):** Current client-credentials exchange invokes client authentication; authorization-code/refresh exchange does not (`apps/identity-api/internal/oidc/token/service.go:283-483,521-525`). **Planned SEC16:** every applicable confidential exchange authenticates a registered asymmetric assertion with bound audience, bounded expiry and durable one-use JTI. Discovery metadata is not proof that every exchange implements its advertised method.

### 1.2 Authentication Flow (Frontend API)

Discoverable-passkey sign-in issues normal browser sessions. Separately enabled new-account registration verifies an existing owned email/phone and resident UV passkey; it never authenticates the browser or allocates a mailbox. See [registration](#15-new-account-registration).

- `POST /api/v1/auth/login`: Current `{username,password}` sign-in when `LOGIN_ENABLED` and admitted username authority are configured. Supported password and admitted immutable username are required; populated fields alone are not authority. Returns normal `204` cookie only when full current policy permits, otherwise `{status:"mfa_required",preauthentication,expires_at}` without normal cookie.
- `POST /api/v1/auth/login/code/request`: Current `{username,channel}` (`email`/`sms`) conditional contact-code request; returns opaque `202 {status:"code_requested",challenge,expires_at}`. Server selects the protected current contact; acceptance is not receipt.
- `POST /api/v1/auth/login/code/verify`: Current `{challenge,code}` may issue normal contact-code authority if MFA is disabled, otherwise only preauth. This conflicts with planned SEC02: contacts are never eligible normal primaries.
- `POST /api/v1/auth/login/mfa`: Current `{preauthentication,code}` with original JKT completes enabled TOTP, not a normal session/grant lookup or MFA Backup Code. Fixed-lifetime three-attempt Redis preauth is current; SQL preauth/replay and truthful backup evidence are planned SEC03/SEC09. Source: `apps/identity-api/internal/server/login.go:18-48,82-141`.
- `POST /api/v1/auth/logout`: Revokes the current live bound session and clears its cookie. Requires browser proof and matching session intent while a live session exists. Missing/expired-cookie logout remains an idempotent `204`, with exact Origin still required. Dependency failure is not successful revocation.

#### First-Party Browser Boundary (Task 7.3)

Pages/assets go to Next.js and `/api` goes directly to Go through one HTTPS origin. There is no BFF, CORS workaround, bearer token in browser storage, or cookie-only fallback. `PORTAL_ORIGIN` is a canonical origin, matching the `OIDC_ISSUER` origin and one `WEBAUTHN_RP_ORIGINS` entry. HTTP is permitted only for explicit loopback development. Proof target URIs use this trusted origin plus the escaped request path, never caller-controlled Host or forwarding headers.

`APP_ENV` is mandatory and exactly `development`, `test`, or `production`; test
is not a development exemption. Issuers reject query/fragment markers including
bare `?`/`#`; configured callbacks are structural HTTPS URLs without userinfo,
opaque forms, fragments or invalid hosts/ports. Only explicitly selected
development allows canonical localhost/loopback HTTP callbacks. Request callback
matching remains exact; no prefix/provider aliases or custom schemes are added.

Mailbox identity is valid UTF-8 with bounded raw input, outer whitespace trim,
NFC/local lowercase/NFC, and non-transitional strict IDNA lowercase ASCII domain.
The canonical local part is at most 64 UTF-8 bytes and address at most 254 bytes.
Malformed dots, lists/quoted forms, literals, invalid/control/bidi/default-ignorable
characters and embedded whitespace are rejected, not silently stripped. Verify,
store, deliver and look up the exact canonical address. NFC equivalents converge;
Persian/Arabic letters, dot/plus variants and NFKC-distinct local parts remain
distinct. Email-specific HMAC input uses exact canonical bytes; generic BlindIndex
NFKC behavior remains unchanged. Do not rehash signed history or add fallback
identity algorithms. Stored notification recipient bindings must already match;
SMTPUTF8 requires strict post-TLS EHLO before EAI AUTH/envelope/DATA, with no
transliteration or ASCII downgrade. Sender/auth values remain ASCII.

- Normal authenticated routes require a live `__Host-` Secure/HttpOnly/SameSite=Strict cookie, an active account and a DPoP proof using the session's originally bound key. Restricted recovery-enrollment and old unbound cookies cannot bootstrap the portal. A missing browser key requires fresh passkey authentication, not attaching a replacement key to an old cookie.
- Every unsafe first-party request, including login/logout, requires one exact `Origin`. Missing, `null`, multiple, sibling and noncanonical origins are rejected. JSON bodies are bounded UTF-8 objects with valid media types; duplicate fields/trailing documents are rejected, and endpoint-specific schemas reject unknown fields where specified. OAuth token and private gRPC protocols retain their separate admission rules; admin RBAC/Origin requirements are not replaced.
- Browser proof uses its own realm and current shared Redis nonce/replay authority. The proof has fresh JTI, `htm`, canonical `htu`, `iat`, public JWK and server nonce, but no fabricated access-token `ath`. This cookie+proof profile is not automatically RFC 9449 resource access-token DPoP. Wrong kind/key/intent fails before consumption; only authorized success renews activity. Planned SEC09 moves earned/replay authority to primary SQL without cookie-only fallback.
- A pre-handler `401 {"error":"use_dpop_nonce"}` includes `DPoP-Nonce` and `WWW-Authenticate: DPoP error="use_dpop_nonce"`. Retry at most once with a fresh proof/JTI and that nonce. No handler, grant or ceremony has been consumed by this challenge. Do not retry uncertain mutations, authenticator responses or used grants after transport failures.
- Bootstrap supplies `session.id`; send it as `X-Portal-Session` on authenticated mutations. The portal also sends it on post-bootstrap reads. A supplied mismatched/empty/duplicate intent returns `409 session_changed`, including on reads; discard old account state and re-bootstrap. This public ID is an intent marker, not an authentication credential.
- All first-party API responses, including errors and empty responses, are `Cache-Control: private, no-store` and `Referrer-Policy: no-referrer`. They do not inherit Next.js document middleware. Never log bodies, proofs, cookies, grants, recovery codes, names or identity-bearing URLs; use route-template diagnostics.

| Response                                       | Client handling                                                                                                                                                                                                                    |
| ---------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `401 session_required` with Cookie challenge   | Normal browser authority is missing, expired, revoked, restricted, unbound or inactive. Clear private state and require authentication.                                                                                            |
| `401 invalid_dpop_proof`                       | Proof/key/method/URI/replay validation failed; never downgrade to cookie-only access.                                                                                                                                              |
| `401 invalid_credentials` during login/step-up | Credential verification failed, not proof that an existing session was lost. An incorrect TOTP stays in the dialog.                                                                                                                |
| `403 insufficient_user_authentication`         | Obtain a new, single-use step-up grant.                                                                                                                                                                                            |
| `409 profile_conflict`                         | Refresh the saved profile/revision without discarding the unsaved draft.                                                                                                                                                           |
| `409 session_changed`                          | Clear the stale session snapshot before any further account operation.                                                                                                                                                             |
| `409 last_credential` / `409 last_factor`      | The proposed security change would violate current primary-login or privileged-factor policy. The change was refused, even if an earlier list hint allowed it; refresh/review the current state without automatic mutation replay. |
| `429 rate_limited`                             | Surface throttling; do not loop challenges or mutations.                                                                                                                                                                           |
| `503 temporarily_unavailable`                  | Dependency failure; do not authorize from cached state or report a successful mutation.                                                                                                                                            |
| `503 outcome_unknown`                          | The mutation may have committed. Do not automatically retry, restore spent authority or infer rollback from a later `401`; no tentative setup secret or success is returned.                                                       |

### 1.3 Advanced Security, WebAuthn & Step-up Auth

Endpoints for phishing-resistant logins, Multi-Factor Authentication, and short-lived Step-up verification.

#### WebAuthn Device Management

- `GET /api/v1/auth/webauthn/keys`: Array of owned credentials, including `id`, `name`, enrollment/last-use metadata, existing authenticator flags and required boolean `can_remove` on every entry. The shared server policy evaluates removal from the same locked account snapshot. This is an advisory presentation hint, not authorization or a reservation: DELETE rechecks the proposed result. Registration/rename credential responses keep their existing shape without `can_remove`. Never includes COSE keys. A user-chosen label is not a verified device model.
- `PATCH /api/v1/auth/webauthn/keys/{id}`: Strict required `{"name":"..."}` plus fresh `X-Step-Up-Auth`; returns the updated credential projection. Foreign/missing IDs share `404 credential_not_found`. Names use the same optional, single-line, 80-code-point normalization as display names below; an empty string clears the label.
- `DELETE /api/v1/auth/webauthn/keys/{id}`: Remove a specific WebAuthn device (Requires Step-up authentication in `X-Step-Up-Auth`). `{id}` is the unpadded base64url credential ID as returned by `GET /keys`. Scoped to the caller's account: a credential belonging to another account is reported as `404 credential_not_found`, identical to one that does not exist, so credential IDs cannot be probed. Refuses with `409 {"error":"last_credential"}` if neither a passkey nor eligible username/password sign-in would remain. The last passkey is removable only when password login is enabled, its verifier is supported and usable, and the username is retained under the current admitted policy. Accounts with any privileged role also require a surviving passkey or enabled TOTP backed by configured secret material, otherwise `409 {"error":"last_factor"}`. TOTP, verified contacts, backup codes and existing sessions are not primary-login substitutes.

#### WebAuthn Registration & Login Flows

- `POST /api/v1/auth/webauthn/register/generate-options`: Optional `{"name":"..."}` for a new credential on an already authenticated account. The normalized name is frozen in pending state. Accepts exactly one `X-Step-Up-Auth` or the fixed first-passkey `X-Action-Proof` described below. Authority is consumed at start, before options are returned. Enforces RP ID as a clean domain name and validates the exact clientDataJSON origin. The returned `user.id` is a CSPRNG-generated random 64-bit handle, not the account UUID.
- `POST /api/v1/auth/webauthn/register/verify`: Existing serialized credential-response body; it cannot supply a replacement name. Requires the same bound session and accepts neither start authorization header. Returns `201` with the created named credential and security-invalidation outcome. A foreign-session attempt neither completes nor consumes the pending ceremony.
- `POST /api/v1/auth/webauthn/login/generate-options`: Current empty/`{}` body starts discoverable login with empty `allowCredentials`; optional `{email}` selects named primary-email lookup. Current named lookup does not prove fresh/current verified contact and exposes all real descriptors versus one decoy, including a multi-key count signal (assessment F03). No universal enumeration-immunity claim. Planned SEC01/SEC02 email selection requires current verified uniquely associated primary email; named responses cannot expose inventories.
- `POST /api/v1/auth/webauthn/login/verify`: Current same-JKT assertion verification records actual UV, which may be false under preferred UV; full current policy issues `204` cookie or enabled TOTP yields `mfa_required` preauth. Only confirmed normal issuance may bootstrap `/users/me`. Planned SEC02 requires actual UV on every passkey assertion, while SEC03 still requires independent MFA afterward.

Every pending WebAuthn challenge is tagged with its ceremony flow and applicable account/session/key bindings. Shared Redis atomically checks bindings before single-use consumption, allowing start on one API replica and completion on another. Wrong bindings do not burn legitimate state; concurrent valid finishes have one winner. The versioned store has native TTLs (configured default five minutes, maximum fifteen), bounded 64-KiB serialized state and two-second operation deadlines. Redis faults fail closed without process-local fallback. Anonymous login options/verification and reclaim-options admission share a 30-request/IP-subnet/minute budget before allocating challenge/nonce state; the explicit nonce retry also counts. Memory storage is for isolated tests/development only.

#### First Passkey On A Password Account (T25)

This backend and typed-client contract adds no password/OTP dialog, dashboard
wiring or bootstrap capability hint. Normal live session, exact Origin,
DPoP/JKT, `X-Portal-Session`, strict bounded UTF-8 JSON and no-store protections
remain required. Recovery-enrollment sessions cannot use it.

| POST operation                                       | Exact request                                                                                | Successful result                                                                            |
| ---------------------------------------------------- | -------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `/api/v1/auth/action-proofs/first-passkey/challenge` | `{password, channel}`; `email` or `sms` selects the currently evidenced server-owned contact | `202 {challenge, expires_at}` after one delivery attempt; provider acceptance is not receipt |
| `/api/v1/auth/action-proofs/first-passkey/verify`    | `{challenge, code}`                                                                          | `200 {action_proof, expires_at}` with the original contact-code deadline                     |
| `/api/v1/auth/webauthn/register/generate-options`    | Existing optional `{name}` and exactly one start header                                      | Existing `publicKey` plus authoritative `expires_at` for first enrollment                    |
| `/api/v1/auth/webauthn/register/verify`              | Existing creation response, neither start header                                             | Existing safe `201` credential with truthful `user_verified: true`; ordinary login follows   |

The fixed proof authorizes only one first-enrollment start. It requires a fresh
exact-byte existing-password verification, active nondeleted account, supported
password verifier, zero current credential rows, MFA disabled, no privileged
role, and the selected complete current contact evidence. Any privileged role
excludes fallback even when administrative HTTP is disabled. Contact-only login
is insufficient, but the earning session need not have used password as its
primary method. This ceremony does not depend on `LOGIN_ENABLED`.

MFA-enabled or privileged accounts retain the stronger existing TOTP/UV Step-up
path. Every zero-key ordinary start, including TOTP-authorized starts, requires
actual verified user presence and user verification. Password/contact control
never replaces independent MFA. Deletion/password-change/login proofs cannot
authorize enrollment, and the first proof cannot add a second key.

Malformed bodies and mixed, duplicate or empty-present start headers are refused
before consumption, with no fallback from one failed mechanism to another.
One short locked SQL transaction spends the proof once. A known successful
commit is required before publishing pending authority in Redis. No handle,
credential or account-version write occurs at options. Native identity uses
protected immutable username display for both names when present, independently
of email and the cosmetic credential label. Genuinely all-null username storage
may retain the opaque-handle label; unreadable/partial identity fails closed.

First ceremonies retain the original proof or consumed-grant deadline, capped by
session limits and the ceremony ceiling and rounded down to milliseconds.
Redis atomically reserves an account-wide expiring exclusion slot and pending
challenge. Competing starts return `409 enrollment_in_progress`. The slot is
never replaced, released or refreshed, including after Take, cancellation,
verification failure or success; it expires naturally at the original deadline.
Different proofs can both be spent in a race but only one can issue options.
There is no refund, claim/resume receipt or automatic retry after SQL/Redis
uncertainty or response loss. Start uncertainty cannot mean a credential was
saved; finish uncertainty can. Retry timing is feedback, not replay authority.

Finish verifies the frozen exact ceremony and actual UP/UV, then rechecks live
session/version, zero keys, contact/policy where applicable, current deadline
after lock waiting and read-only live slot ownership. Handle assignment,
globally unique credential insertion and one auth-version cutoff commit
atomically. Lifecycle revision, username, password, MFA, roles and contacts are
unchanged. Enrollment does not restamp the old session's authentication evidence.
Confirmed success is decoded before private authority is discarded; malformed
or non-UV success remains uncertain and never authorizes a retry.

#### Multi-Factor Authentication (TOTP) & SMS OTP

T26 extends these existing backend routes, not registration, login or a dashboard
management UI. Every operation requires the normal live cookie session, exact
Origin, DPoP/JKT and `X-Portal-Session` boundary above; restricted recovery sessions
cannot use it. Enabled `is_mfa_enabled` still requires independently earned TOTP
at normal-session boundaries, including UV-passkey sign-in. There is no new
optional/required-MFA flag or privilege exemption.

| Operation                                                  | Exact request / authority                                                                                                | Successful response                                                                                                                             |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /api/v1/auth/action-proofs/mfa-enrollment/challenge` | `{"password":"...","channel":"email"}` or `{"password":"...","channel":"sms"}`; neither authority header                 | `202 {"challenge":"...","expires_at":"..."}` after one delivery attempt; acceptance is not receipt                                              |
| `POST /api/v1/auth/action-proofs/mfa-enrollment/verify`    | `{"challenge":"...","code":"123456"}`; neither authority header                                                          | `200 {"action_proof":"...","expires_at":"..."}` retaining the original contact-code deadline                                                    |
| `POST /api/v1/auth/mfa/generate`                           | Empty body, no query; exactly one fresh UV `X-Step-Up-Auth` OR fixed-purpose `X-Action-Proof`                            | `200 {"enrollment_id":"...","secret":"...","otpauth_url":"...","issuer":"...","account_name":"...","expires_at":"..."}` only after known commit |
| `POST /api/v1/auth/mfa/verify`                             | `{"enrollment_id":"...","code":"123456"}`; neither authority header                                                      | `200 {"status":"enabled"}` and committed security-invalidation metadata                                                                         |
| `DELETE /api/v1/auth/mfa`                                  | Empty body, no query; only fresh `X-Step-Up-Auth` earned through enrolled TOTP (`otp`) or UV WebAuthn (`hwk` AND `user`) | Empty `204`; security-invalidation metadata only for actual removal                                                                             |

All listed JSON fields are required strings. Proof and confirmation bodies are
strict UTF-8 `application/json` objects of at most 8192 bytes, with no unknown,
duplicate or null fields, trailing document or query. `channel` is exactly `email`
or `sms`, not a destination supplied by the caller. Password bytes remain exact;
codes are exactly six ASCII digits, preserving leading zeros. `challenge` and
`action_proof` are canonical unpadded base64url encodings of 32 random bytes (43
characters); `enrollment_id` is a canonical nonzero UUID. `expires_at` is the
authoritative RFC 3339 instant, not a relative lifetime. Mixed, duplicate, empty,
comma-joined, oversized or misplaced authority headers are rejected before
consumption; there is no fallback to a second mechanism after failure.
Keep returned setup secret/URI only in bounded client memory until confirmation;
there is no setup-secret retrieval endpoint or persistent browser-storage contract.

The password/contact path is default-off behind `MFA_ENROLLMENT_PROOFS_ENABLED`
and independently selected email/SMS switches. It requires fresh supported
password verification, an active nondeleted nonprivileged password-only account,
zero passkeys, no enabled or configured active TOTP, usable enabled password login
and a protected username retained under the admitted policy. Any role membership
excludes this fallback, even if administrative HTTP is disabled. Delivery selects
only the server-owned exact canonical contact with complete current protected
verification evidence; populated fields or timestamps alone are not proof. These
conditions are rechecked before delivery, at proof issuance, enrollment start and
final confirmation. Unlike the separate first-passkey proof, this fallback requires
usable admitted password sign-in. See [configuration and rollout](devops-operations.md#first-passkey-proofs-t25).

The new proof has fixed purpose/action `mfa_enrollment` and authorizes one pending
enrollment start only. It cannot authorize disable, first-passkey enrollment,
password change, deletion, login, recovery or generic Step-up; other-purpose codes
and proofs cannot authorize MFA enrollment. Existing strong Step-up grants remain
single-use, session/version/JKT-bound, **not action-scoped**; MFA start specifically
requires genuinely earned UV, not available-factor metadata or a TOTP-only grant.
One MFA-owned locked SQL transaction consumes the purpose proof at start, replaces
previous pending enrollment and freezes its authorization; confirmation never
looks up that spent proof or consumes another grant.

The pending `maintenance` enrollment binds user, initiating session, captured
`auth_version`, DPoP JKT and authorization method (`webauthn_uv` or
`password_contact`); password/contact mode also freezes channel and keyed complete
contact evidence. Its fixed `expires_at` is the earliest of the configured
enrollment ceiling (ten-minute default), original fresh grant/proof expiry and the
initiating session's idle and absolute expiries. Renewal, retry or replacement
under the same authorization cannot extend that deadline. Confirmation revalidates
live session/version/JKT, current protection and frozen contact evidence before
decryption, then checks expiry again at the deciding write. Missing-binding rows
are rejected before decryption, never inferred or backfilled. Foreign session/JKT
requests do not burn the legitimate budget. At most five failed TOTP attempts are
allowed by default; wrong-code counters and expired/exhausted-row deletion commit
despite a returned domain error, while infrastructure/authorization failures roll back.

Disable never accepts password/contact OTP or `X-Action-Proof` as a bypass. Under
the username guard, account lock and user-row lock, current policy evaluates the
proposed `TOTP=false` result. A surviving passkey remains sufficient for primary
login; zero-passkey removal is allowed only for a nonprivileged account with
`LOGIN_ENABLED`, a supported usable password and an admitted protected username.
Any role membership requires a surviving passkey after TOTP removal. Missing or
unavailable policy evidence is not permission; refusals remain `409 last_credential`
or `409 last_factor`.

Known-committed setup and already-absent/pending-only disable success use
`session.OutcomeCommitted`, so post-commit renewal failure cannot replace them.
A no-op clears pending enrollment without a version bump, disabled-factor event or
invalidation header. Actual enable/removal commits the factor change, pending-state
consumption/clearance and one auth-version invalidation; only real changes emit
the existing `MFATOTPEnabled`/`MFATOTPDisabled` security events. Old sessions, tokens,
grants and pending authority are invalidated, not renewed or restamped as
MFA-authenticated. No new audit/lifecycle format is introduced.

Proof errors use `400 invalid_request`, `401 invalid_code`,
`403 insufficient_user_authentication`, `429 rate_limited`,
`503 temporarily_unavailable` or `503 outcome_unknown`. MFA preserves
`400 invalid_request`, `400 mfa_not_setup`, `400 enrollment_expired`,
`400 invalid_code`, `401 unauthorized`,
`403 insufficient_user_authentication`, `409 mfa_already_enabled` and the policy
conflicts above. An uncertain commit returns `503 {"error":"outcome_unknown"}`
without tentative secret, proof, success or success audit. Never automatically
retry or refund spent strong grants. Lost setup output requires an explicit fresh
ceremony to replace pending enrollment; uncertain enable/disable recovers through
ordinary fresh login/current-state inspection, not a new reconciliation or secret
retrieval endpoint. The sole pre-handler DPoP nonce retry above remains distinct.

- There is deliberately no general-purpose `/api/v1/auth/mfa/verify-code` endpoint. Enabled TOTP secrets can only be checked inside a purpose-specific login/Step-up flow, preventing an authenticated-session code-validity oracle. Step-up uses `POST /api/v1/auth/stepup/verify` and collapses wrong, replayed, and stale codes into `401 invalid_credentials`.
- `POST /api/v1/auth/recovery-codes/generate`: Current untyped recovery-pool generation, stored as high-entropy SHA-256 or configured HMAC verifiers with indexed SQL lookup. Requires fresh generic Step-up, not a recovery code; ordinary password-only issuance is missing (F07). These codes authorize restricted replacement-passkey enrollment, not direct normal login or truthful MFA Backup completion. Two explicit families and dedicated issuance purposes are planned SEC05.
- `GET /api/v1/auth/recovery-codes/status`: Returns only `{"remaining":10,"low":false}`. Generation returns `{"codes":["..."],"count":10}` once and atomically invalidates every previous code. There is no GET endpoint for previous plaintext batches. A lost generation response may mean replacement committed; require explicit new generation and fresh step-up rather than replaying/caching the old response.

#### Primary Contact Maintenance (T27)

T27 manages primary email and phone through the normal authenticated cookie,
exact Origin, DPoP/JKT and session-intent boundary. It does not change registration,
backup contacts, login/recovery, notifications or the T38 management UI.

| Operation                                                     | Exact request / authority                                                                                      | Successful response                                                                                             |
| ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `GET /api/v1/users/me/contacts`                               | Empty body/query; neither authority header                                                                     | `{email,phone}`; each is `null` or `{value,verified,verified_at}` from one snapshot                             |
| `POST /api/v1/auth/action-proofs/contact-change/challenge`    | `{password,channel,target}`; `channel` is `email`/`sms`, `target` is `email`/`phone`; neither authority header | `202 {challenge,expires_at}` after one old-contact delivery attempt                                             |
| `POST /api/v1/auth/action-proofs/contact-removal/challenge`   | Same fields, removal-only purpose; neither authority header                                                    | Same `202` shape; present-email removal is refused before avoidable password work/delivery                      |
| Corresponding action-proof `/verify` routes                   | `{challenge,code}`; neither authority header                                                                   | `200 {action_proof,expires_at}` with the original deadline and frozen action/target                             |
| `POST /api/v1/users/me/phone/send-code` or `/email/send-code` | `{phone}` or `{email}`; exactly one fresh `X-Step-Up-Auth` OR matching change `X-Action-Proof`                 | `200 {status:"sent",verification_id,expires_at}` only after known pending commit and code submission/activation |
| Corresponding contact `/verify` routes                        | `{verification_id,code}`; neither authority header or replacement destination                                  | `200 {status:"verified"}` and committed security-invalidation metadata                                          |
| `DELETE /api/v1/users/me/phone` or `/email`                   | Empty body/query; exactly one fresh strong grant OR matching removal proof                                     | Empty `204`; real changes invalidate authority, authorized absent-contact no-ops do not                         |

JSON is bounded to 8192 bytes of valid UTF-8, with required string fields and no
duplicates, unknown/null fields, trailing document or query. All public handles
are canonical unpadded base64url encodings of 32 random bytes; codes are exactly
six ASCII digits, including leading zeros. Mixed, duplicate, empty, comma-joined,
oversized and misplaced authority headers fail before consumption. Destination
canonicalization and the current Iranian SMS.ir destination policy are checked
before spending strong authority. Maintenance does not add signup-only aliases.
No failed authorization mechanism falls back to another one.

Strong authority must be genuinely earned WebAuthn UV (`hwk` AND `user`) or enrolled
TOTP (`otp`). Shared grants remain single-use and session/version/JKT-bound, not
action-scoped. The default-off password/contact alternative requires fresh exact
password verification, an active nondeleted nonprivileged password-only account,
no enabled/configured independent MFA, usable enabled supported password login
and an admitted immutable username. Any role membership excludes this fallback,
even with administrative HTTP disabled. The server selects only a current contact
with complete matching protected evidence. Signup authority, unverified populated
contacts and separately verified new destinations cannot authorize modification.

The contact manager owns the deciding READ COMMITTED transaction under the current
username guard, account mutex and user-row lock. Start spends the matching SQL
proof once or freezes the already-spent strong grant; it changes no contact,
auth version or lifecycle revision. Pending state encrypts the exact destination
with account/attempt/target/authorization binding and stores only digest handles.
Post-commit sending reserves shared quotas, then immediately rechecks the exact
pending attempt and nonrenewing live session/version/evidence before submission,
without holding SQL locks during provider I/O. Detected revocation or replacement
forbids submission and handle release. A change after this final check may race an
already-admitted external send, but its code cannot authorize a stale mutation.

Ownership has distinct `contact_ownership` purpose and is not a bearer action
proof. Finish consumes only the frozen new-destination code once, then read-only
revalidates frozen authorization; it neither redeems the spent start proof nor
requires a second grant. Its deadline is the earliest original authorization,
at-most-three-minute channel ceiling and captured/live session idle/absolute
limit, rounded down without renewal, lock-wait or retry extension. Foreign
account/session/JKT/target attempts do not burn legitimate code budgets.

Contact values are saved before fresh exact evidence so the invalidation trigger
cannot erase the new provenance. Evidence records the successful server ownership
verification instant, at UTC microsecond precision, with truthful `email_otp` or
`sms_otp` method; existing `email_link` evidence remains readable. A real value or
provenance change advances auth version once, including deliberate same-value
reverification. A real primary-email value change also advances lifecycle revision
once and enqueues one metadata-only `email` update; phone/evidence-only changes do
not. Existing credentials, immutable identity, last evidenced primary contact and
privileged/MFA protection remain preserved. Backup fields and timestamps alone
are not survivors. Missing provenance is unknown, not fabricated; independent
strong authority plus fresh exact ownership can repair target provenance.

**Temporary email-removal gate:** removing a present primary email returns
`409 {error:"email_removal_unavailable"}`, including when verified phone, username
or a backup address exists. T28 alternative recovery identification and T41
email-absent notification/deletion/reclaim compatibility are not implemented by
T27. This is an operation refusal, not a mandatory-email schema/shared invariant
or bypass switch: existing email-absent accounts and authorized absent-email
removal remain supported.

Known start/no-op commits use `session.OutcomeCommitted`; security changes use
`session.SecurityChangeCommitted`. Unknown dispatch/activation/commit returns
bounded `503 {error:"outcome_unknown"}` without tentative handle, evidence,
success audit or replacement session. SQL rollback restores SQL changes, not
spent Redis authority. No automatic retry, refund, resume receipt or reconciliation
endpoint exists; recovery is explicit fresh login/current-state inspection or a
freshly authorized new start. Provider submission is not mailbox/handset receipt.
The sole explicit pre-handler DPoP nonce retry remains unchanged.

#### Restricted Recovery Flow

- `POST /api/v1/auth/recovery/start`: Anonymous start endpoint. Accepts `{"email":"user@example.com"}` and returns the same no-store `202` shape for active, inactive, deleted, and unknown accounts after valid request and admission checks: `transaction_id` (256-bit opaque base64url value), `expires_at`, and `expires_in` (600 seconds). The transaction is stored by SHA-256 hash, expires after 10 minutes, and is atomically single-use. A lookup timing floor and deterministic decoy reduce enumeration exposure; content, size and timing-distribution evidence remain required, not guaranteed indistinguishability.
- `POST /api/v1/auth/mfa/verify-recovery-code`: Accepts `{"transaction_id":"...","code":"..."}`. The transaction is consumed before the code check, so a failed guess cannot be retried under it. A valid high-entropy code is located and physically deleted in the same ACID transaction, then the server issues a 10-minute `recovery_enrollment` session and returns `{"next":"enroll_factor","expires_in":600}`. Invalid, spent, foreign, and decoy transactions collapse into `401 {"error":"invalid_credentials"}`; a saturated recovery limit returns `429 {"error":"rate_limited"}`.
- `POST /api/v1/auth/enrollment/webauthn/register/generate-options`: The only ceremony a `recovery_enrollment` session may start. It requires WebAuthn user verification (`UV`), is bound to the restricted session, and cannot be called by a normal session.
- `POST /api/v1/auth/enrollment/webauthn/register/verify`: Completes that UV-required ceremony. The restricted session may claim at most one replacement passkey and is revoked after success; the response is `{"next":"login"}`. A duplicate or already-claimed use returns `409 {"error":"enrollment_already_used"}`. It never becomes a normal authenticated session and cannot access profile, Step-up, recovery-code generation, or other account-management routes.

If issuing the restricted session fails after a recovery code was consumed, the server fails closed and does not resurrect the code. The user must start again with another unused code.

The current restricted flow is not the target ordinary recovery policy. No old
contact proof or privileged exclusion is required and the final restricted-session
deadline is not rechecked in recovery's deciding SQL transaction (F01/F02).
Generation does not revoke already-derived recovery sessions. Enabled TOTP still
gates later normal login; it is inaccurate to describe universal TOTP bypass or
safe consumer recovery merely because the restricted cookie cannot open the portal.

#### Security Mutation Commit And Session Lifetime (T23)

Successful passkey enrollment/removal, actual TOTP enable/disable, and verified-phone/evidence replacement/removal advance `auth_version` once in the deciding transaction. They preserve `lifecycle_revision` and invalidate existing session/token/grant authority, including the initiating browser session. Admission captures the version; the transaction rechecks active status and that captured version under the shared account lock. Pending ceremonies, grants or requests admitted under an older version cannot finish later. Cosmetic credential renames do not revoke authority. True no-ops do not advance the version or revoke sessions.

The committed handler marks self-invalidating success before response release; session middleware does not attempt to renew now-invalid authority or replace that successful result with a refresh/activity failure. `X-Identity-Auth-Invalidated: true` on a marked successful response is outcome metadata only, never authentication authority. The portal strictly decodes a successful mutation, clears private authority, and presents a whole localized saved-outcome message with one explicit return-to-login link. It does not fetch the old session again, automatically log out/replay, or reinterpret a later `401` as a failed mutation. Phone/TOTP no-op successes are unmarked and retain authority. Restricted recovery enrollment retains its existing single `next: login` outcome rather than adding a second redirect. Lost/unreadable responses remain uncertain, not confirmed success.

#### Short-Lived Step-up Authentication

- `POST /api/v1/auth/stepup/challenge`: Generates a challenge for the Step-up auth flow, supporting `userVerification: "required"` (biometrics/PIN via WebAuthn) or TOTP verification. Requires a normal live session and binds the pending WebAuthn assertion to its exact session ID. Returns `methods` (the factors this account can present, WebAuthn first) plus the WebAuthn assertion options when a passkey is enrolled. Unlike the login options endpoint there is no mock/decoy branch — the caller is already authenticated as this account, so there is nothing to enumerate. `409 no_stepup_factor` means the account has neither a passkey nor TOTP and cannot perform Step-up until one is enrolled.
- `POST /api/v1/auth/stepup/verify`: Verifies the WebAuthn UV assertion or active TOTP token. On success, returns a short-lived (3-5 minutes) Step-up token carrying the ACR claim `https://ref.hatef.ir/acr/stepup`. This token must be passed in the `X-Step-Up-Auth` header for sensitive endpoints.
  - **Grant format:** a compact JWS (`typ: stepup+jwt`) signed by the same rotating keystore as access and ID tokens, carrying `iss`, `sub`, `aud`, `acr`, `amr` (RFC 8176: `["hwk","user"]` for a UV assertion, `["otp"]` for TOTP), `auth_time`, `sid`, `jti`, `iat`, `exp`, and `cnf.jkt` when the earning session is DPoP-bound. The distinct `typ` is load-bearing: access tokens are signed by the same keys and already use `aud == iss`, so without it an access token would satisfy every other check.
  - **Single use:** the `jti` is consumed on first successful validation, so one grant authorises one operation subject to that endpoint's earned-factor policy; it is not action-scoped. Outside explicit development, every replica atomically claims the HMAC-derived replay identity in shared Redis for the remaining grant lifetime; Redis errors fail closed. This is what makes Step-up a per-operation check rather than a 5-minute window of elevated privilege.
  - **Session bound:** the `sid` claim pins the grant to the session that earned it. A grant cannot be paired with a different session's cookie, even for the same user.
  - **Factors:** Generic step-up accepts WebAuthn with `userVerification: "required"` (verified server-side) or an active TOTP passcode. Deletion is stricter: it requires the verified grant's `hwk` and `user` AMR and never accepts TOTP. A TOTP passcode is single-use across its acceptance window. Recovery codes are not step-up factors.
  - **Rate limited** per subnet and per account (per-minute and per-hour), with the subnet window evaluated first so a saturated shared proxy cannot burn a targeted account's budget.
  - `403 user_verification_required` distinguishes "your authenticator only proved presence" from a generic failure, because it is the one outcome the user can act on. Every other credential failure collapses into an opaque `401 invalid_credentials`.

**Challenge response on gated endpoints.** A request to any Step-up gated endpoint without a valid grant is answered `403` with `{"error": "insufficient_user_authentication", "acr_values": "https://ref.hatef.ir/acr/stepup"}`. The error code follows RFC 9470 (OAuth 2.0 Step Up Authentication Challenge Protocol); the status is `403` rather than RFC 9470's `401` because these are cookie-session endpoints where `401` already means "session gone, re-authenticate" — reusing it would send the user through a full login instead of the inline overlay in `frontend-pages.md` §5.3. Missing, malformed, expired, already-spent, and foreign-session grants all render identically so the response cannot be probed.

**Fail-closed mounting.** When the Step-up service cannot be constructed (for example, its required database is absent in development), gated endpoints are **not mounted at all** rather than served without their gate. Outside development, missing Redis or replay-key configuration prevents startup. A user with no enrolled Step-up factor receives `409 no_stepup_factor`; no condition turns a gated route into an ungated one.

### 1.4 User Profile & Privacy (GDPR)

- `GET /api/v1/users/me`: Bootstrap projection: `id`, nullable `email`, `email_verified`, nullable `email_verified_at`, `display_name`, `status`, decimal-string `lifecycle_revision`, `deletion_enabled`, and `session: {id, expires_at}`. An absent email is JSON `null`, not an omitted field or replacement mailbox. Verification is true only for protected evidence matching the current account and exact canonical email; its timestamp is the original server verification time, not account creation or a receipt replay. `deletion_enabled` is a server-controlled capability, not a legal-hold disclosure; clients default a missing field to false during rollout. `expires_at` is the session's real absolute RFC 3339 deadline. No private-profile attributes, roles, backup contacts, factor secrets, ciphertext or legal data.
- `PATCH /api/v1/users/me`: Strict required string fields `{"display_name":"Example","expected_revision":"42"}`; returns the same projection. No step-up is required for this cosmetic field. Revision strings are canonical nonnegative decimals, at most `9223372036854775807`; JSON numbers, signs, leading zeros, nulls, unknown/duplicate fields and trailing bodies are rejected.
- `GET /api/v1/users/me/username`: When username support is enabled, normal authenticated admission returns `{username: {display}}` or `{username: null}`. No claim/rename/clear mutation is mounted; absence is not derived from email or `display_name`. See the [username contract](registration-contract.md#username-namespace).
- `GET /api/v1/users/me/private-data`: Normal live session/DPoP admission returns `{private_data, username, lifecycle_revision}` from one consistent account snapshot. Before initialization, `private_data` is `null`. Otherwise it contains `given_name`, `family_name`, `birthday: {gregorian, jalali}`, `gender`, and `location: {country, province_id, locality_id?, catalog_revision}`. Username is a read-only `{display}` projection or `null`; the revision is an exact decimal string. Unreadable or incorrectly bound encrypted records fail, rather than being reported as absent.
- `PATCH /api/v1/users/me/private-data`: Requires the existing captured session-intent header and canonical decimal-string `expected_revision`. First save requires both names, `birthday: {calendar: "gregorian" | "jalali", date}`, explicit `gender`, and `location: {country: "IR", province_id, locality_id?}` together. Subsequent saves may omit unchanged attributes; birthday and location are replaced as whole fields. Unknown, duplicate or null fields and username/display-name/email/mobile edits are rejected. Names, both birthday representations, gender and server-resolved catalog selection are encrypted together. Stale revisions return `409 profile_conflict` before no-op decisions. A normalized no-op preserves ciphertext, timestamps, revision and outbox; a real edit atomically stores the profile, advances the revision once, and enqueues one metadata-only `private_profile` update. Public `display_name` remains independent; the full private editor UI is T38.
- `GET /api/v1/users/me/sessions`: Array of live owned browser authority with public `id`, `current`, creation/activity times and bounded IP/user-agent metadata. A session is not a physical-device identity or standalone OAuth grant.
- `DELETE /api/v1/users/me/sessions/{session_id}`: Owner-scoped individual revocation (`204`/`404`); deleting the current session also clears its cookie. Linked access/refresh authority fails subsequent live validation immediately. Already admitted requests may finish; remote DOM clears on detection, not instantaneously. No bulk-revocation portal action.
- `PUT /api/v1/users/me/password`: Current strict `{operation:"add"|"change",new_password}` under normal bound-session admission. Exactly one fresh strong `X-Step-Up-Auth`, or fixed password-change `X-Action-Proof` for `change` only. `DELETE` on the same path removes with strong authority and empty body. Resulting-state primary/privileged checks and known-commit handling remain; the settings UI and planned durable repair barrier are separate. Source: `apps/identity-api/internal/server/passwords.go:20-70,84-118`. This is normal maintenance, not anonymous lost-password recovery.
- `POST /api/v1/users/me/export-data`: Planned, unmounted interface; no completed data-export capability is implied.

Display and credential names reject invalid UTF-8, Unicode control characters and line/paragraph separators, then trim outer Unicode whitespace and limit the result to 80 code points. Empty clears the optional name; names are not unique. The profile service locks the account and rechecks active status/captured auth-version before comparing the expected lifecycle revision. A stale revision returns `409 profile_conflict`. A no-op at the current revision changes no timestamps/revision and emits no event. A real display-name edit commits the name, one lifecycle revision increment and metadata-only v2 outbox intent in one transaction; enqueue failure rolls it all back. It does not change auth-version or revoke sessions. Name values are excluded from audit/event payloads; ordinary sanitized audit recording remains best-effort, not a durable commit guarantee.

Task 7.4 adds `/dashboard/privacy` and an independent `/recover-account` page.

- `DELETE /api/v1/users/me` and its trailing-slash alias require normal cookie/DPoP/Origin/session-intent admission and a fresh `X-Step-Up-Auth` grant with verified WebAuthn UV. A valid TOTP-only grant is consumed and rejected with the existing `403 insufficient_user_authentication` challenge, without logging the session out.
- **Transactional acceptance:** under the account lock, active status and captured `auth_version` are rechecked. Soft deletion, version advancement, reversible lifecycle event, hashed single-use reclaim request, and encrypted per-recipient notification intents commit together. Encryption/enqueue failure rolls back; concurrent suspension/ban must not be overwritten.
- **Response and revocation:** confirmed acceptance returns empty `204` and clears the current cookie. Live authorization rejects old sessions/grants; revocation cleanup is bounded after commit. No receipt, token, exact deadline or inbox-delivery result is returned. A lost response or post-commit activity failure is an uncertain outcome, not proof of rollback. Never automatically replay DELETE or infer success from a later `401`.
- **Coalescing, not authenticated resend:** concurrent requests admitted under the original authority share its request, token, deadline and notice set. After deactivation, authenticated admission rejects the account. Automatic SMTP retries operate independently, never mint a token or extend the deadline. The old resend-cooldown setting and public resend promise no longer apply.
- **Delivery:** `deletion-notifier` sends separate messages to the server-selected exact canonical primary and configured backup, deduplicated at intent creation. SMTP public origin must equal canonical `PORTAL_ORIGIN`; EAI recipients require strict post-TLS SMTPUTF8. Stable IDs aid retries, but ambiguous acknowledgements can duplicate mail. Relay acceptance does not prove inbox delivery.
- **Enablement:** `GDPR_DELETION_ENABLED` defaults to false. PostgreSQL transactions, envelope encryption, shared Redis, sessions/token revocation, and WebAuthn/step-up must be configured. Recovery and accepted notice draining remain independent of the switch and SMTP availability. First verify a working supervised SMTP worker and an independently accessible recovery mailbox.
- **Limits and authority:** the account/day limit defaults to 3 and returns `429 rate_limited` on saturation. Production recovery/purge policy is exactly `720h`. Live account/version validation prevents recovery from reviving old authority; offline JWT-only consumers retain residual authority until expiry, at most ten minutes. Already admitted requests may finish.

#### Account Reclamation (cancel a pending deletion)

A `pending_deletion` account cannot log in at all, so reclamation is a separate anonymous ceremony rather than an ordinary login: the emailed single-use token plus one verified strong factor. Both endpoints are token-bearing and mounted outside the session group — they deliberately do not live under `/users/me`, because that prefix implies a session and there is none.

- `POST /api/v1/auth/deletion/reclaim/options`: Accepts `{"token":"..."}` and returns the single factor to present: `{"factor":"webauthn","webauthn":{...}}` (a `userVerification: "required"` assertion challenge bound to this deletion request) or `{"factor":"totp"}`. It does **not** consume the token, so a user who abandons the ceremony halfway can restart it. Exactly one factor is named; the response never enumerates the account's factors.
- `POST /api/v1/auth/deletion/reclaim/`: Accepts `{"token":"...","factor":"webauthn","assertion":{...}}` or `{"token":"...","factor":"totp","code":"123456"}`. Success restores `active`, invalidates outstanding reclaim tokens, and returns `204` without a session; normal login follows separately. The deciding transaction rechecks the exact request/token, original expiry, attempt cap and current pending account after factor verification. Expiry or retirement during verification cannot be bypassed.
  - **Both factors are accepted deliberately.** A passkey-only account has no TOTP secret, and forcing TOTP here would make such accounts unrecoverable. The WebAuthn ceremony is tagged distinctly from login and Step-up, so a reclaim challenge can never be redeemed to mint a session and a login challenge can never satisfy a reclaim. A TOTP passcode is single-use across its whole ±1-step acceptance window.
  - **Bounded failed factors:** a wrong factor alone does not consume the token, but `GDPR_RECLAIM_MAX_ATTEMPTS` (default 5) failures retire it. Increment and retirement are atomic under concurrency; infrastructure failures are not bad-factor attempts.
  - **Opaque failures.** Unknown, expired, consumed, and foreign tokens, a wrong factor, a missing account, a wrong account status, and an account with no verifiable factor at all render identically as `401 {"error":"invalid_token"}`. A saturated limit returns `429 {"error":"rate_limited"}`. Only a genuine infrastructure fault returns `500`, and it does not depend on the token's validity. Rate limited per subnet then per account (`GDPR_RECLAIM_PER_SUBNET_PER_HOUR`, `GDPR_RECLAIM_PER_ACCOUNT_PER_HOUR`).
  - **Identifier reservation.** The account's email, phone, and backup-email uniqueness indexes cover `pending_deletion` rows for the whole window, so a third party cannot claim the identifier while a deletion is pending and cause the reclaim to fail. A registration attempt on a reserved identifier must be reported as `409`.

Reclaim is anonymous, not unprotected: exact Origin, bounded JSON, shared admission/rate limits and token-plus-factor verification apply. No cookie or existing IndexedDB/DPoP key is needed. Mail links use a fixed HTTPS origin and `/recover-account#token=<opaque token>`; the browser immediately scrubs the fragment and retains bounded memory only. Opening/scanning a link performs no redemption. There is no query/path token, email-only fallback or public resend endpoint. Legal holds delay erasure, never token expiry.

### 1.5 New-Account Registration

The authoritative [registration contract](registration-contract.md) distinguishes
the existing flow, this coordinated username increment and the deferred final
contact-choice/password/six-stage target. The table below is the enabled
current-flow contract with usernames, not proof of live policy installation.

`REGISTRATION_ENABLED=false` is independently opt-in. When enabled with schema,
shared Redis, private keys, approved finite admission/send budgets, SMS.ir and
verified TLS SMTP prerequisites, all routes below require exact Origin, bounded
strict JSON, public DPoP nonce/replay admission, no-store and no-referrer. Each
transport attempt uses a fresh proof/JTI from the original verified JKT.
Signup uses public DPoP without access-token `ath`, Authorization or
`X-Portal-Session`; it does not use an ordinary/recovery session as authority.
`attempt_id` is not authority: follow-ups also need the returned capability,
except email verification, which needs its distinct token and original JKT.

| POST route                              | Exact request fields                           | Successful result / meaning                                                                                                                                                                                                         |
| --------------------------------------- | ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/api/v1/auth/register/validate`        | `{stage:"username",registration:{username}}`   | `200 {username_display,available}`; read-only NFC display and advisory availability, no proof/reservation/owner disclosure. No other validation stage is mounted by this increment.                                                 |
| `/api/v1/auth/register/start`           | `{email,phone,username}`                       | `201 {attempt_id,capability,canonical_email,username_display,expires_at,email_sent}`; freezes username/policy but reserves nothing until final commit. `email_sent` is submission acceptance, not inbox delivery.                   |
| `/api/v1/auth/register/email/resend`    | `{attempt_id,capability}`                      | `204`; explicit bounded resend replaces email proof and clears phone/ceremony progress, without extending attempt expiry or resetting budgets. No automatic page-load send.                                                         |
| `/api/v1/auth/register/email/verify`    | `{attempt_id,token}`                           | Marks only email ownership from the original JKT; no capability/session/role issuance.                                                                                                                                              |
| `/api/v1/auth/register/phone/send`      | `{attempt_id,capability}`                      | `{verification_id}` for the frozen Iranian phone after verified email; no automatic billed retry.                                                                                                                                   |
| `/api/v1/auth/register/phone/verify`    | `{attempt_id,capability,verification_id,code}` | Consumes the exact signup/JKT/phone OTP and persists phone proof. Code is a six-digit string, including leading zeros.                                                                                                              |
| `/api/v1/auth/register/passkey/options` | `{attempt_id,capability}`                      | `{publicKey}` for a signup-purpose resident UV-required ceremony after both ownership proofs.                                                                                                                                       |
| `/api/v1/auth/register`                 | `{attempt_id,capability,credential}`           | `200`; WebAuthn creation JSON completes the ceremony; `{state:"completed",next:"login",receipt_expires_at,email_verified:true,phone_verified:true}`.                                                                                |
| `/api/v1/auth/register/result`          | `{attempt_id,capability}`                      | Pending: `{state:"pending",expires_at,email_verified,phone_verified}`. Failed: `{state:"failed",receipt_expires_at,email_verified,phone_verified}`. Completed: same shape as final. Not a login or email-based capability recovery. |

The email link is `/register/verify-email#attempt_id=...&token=...`; the browser
scrubs the fragment immediately and verifies only after explicit user action.
Wrong-browser/key links cannot transfer enrollment authority. Attempt/capability/
token/OTP/credential material never belongs in paths, query strings, logs, browser
persistent storage, analytics or cross-tab messages. Caller-supplied user IDs,
handles, roles, status, auth versions or proof flags are not accepted.

Pending state lasts 15 minutes, email proof 10 minutes, passkey challenge at most
5 minutes (also bounded by pending expiry) and completion receipt 1 hour. Pending
attempts are not users and cannot log in. Final SQL commit creates exactly one
active user, canonical email, immutable unique username, frozen handle, resident
UV credential, encrypted verified phone, revision-1 created-event intent and receipt together. No password,
mailbox, role or session is created; normal discoverable login follows separately.
Email/phone/pending-deletion/credential uniqueness remains database-authoritative;
conflict never attaches a credential to an existing account.

Username display receives NFC only; the separate four-fold security key reserves
every equivalent spelling across all surviving account statuses until physical
deletion. Availability is advisory. `invalid_username` (400) and
`username_unavailable` (409) include `field_errors: {username: <same code>}`;
`username_policy_changed` (409) requires explicit restart without extending expiry.
Owner-reviewed policy/reserved names and controlled activation remain
[operational gates](devops-operations.md#username-policy-and-preflight-gates).

For lost/ambiguous final responses, explicitly read `/register/result` using the
same capability/JKT and a new DPoP proof. Same-authority identical completion can
return its committed receipt; changed completion data conflicts. This narrow
registration-only reconciliation does not relax other mutation retry rules,
resurrect spent phone OTPs or promise exactly-once external delivery. Lost browser
authority requires restart or ordinary login, never capability lookup by email.
Hold-aware bounded cleanup does not extend expired proofs/receipts; expiry checks
alone are not physical erasure or proof of supervised cleanup.

Fixed errors include `invalid_request` (400), `invalid_registration` (401),
`registration_expired` (410), `registration_conflict`, `restart_registration`,
`proof_required`, `restart_phone_proof` (409), `result_required`, `send_failed`,
`temporarily_unavailable` (503), and local `rate_limited` (429 with Retry-After).
`result_required` directs explicit same-authority outcome checking; failed proof
commit may require a fresh phone proof rather than restoring a spent OTP. A
provider throttle is a failed send, not falsely reported as the local limiter.

#### Existing-Account Contact Verification

`SMS_ENABLED=false` leaves DB-only verified-phone removal/recovery independent of
provider secrets. Enabled sending uses SMS.ir VERIFY's fixed HTTPS POST endpoint,
Iranian destinations and explicit live/sandbox key mode (production live-only).
Sandbox success-shaped responses send nothing; neither message ID/cost nor ACK
proves handset delivery. No SMS login, password reset or provider-switch fallback
is added by registration. Current optional contact-code login is documented
separately above and conflicts with the target. Phone/backup data stays encrypted.
The current email/phone routes and their exact authorization are owned by
[T27 maintenance](#primary-contact-maintenance-t27), not a second implementation.
Backup-email maintenance routes are **planned/unmounted**, not implemented by T27.
No backup field alone supplies verified recovery authority.

### 1.6 Planned Authentication and Factor Repair Contracts

All rows below are **planned design shapes**, not currently mounted API contracts.
Final route spelling requires task contract review; existing services/prefixes are
extended rather than a second auth service. Old contact-OTP-only password-reset
proposals are superseded by SEC05-SEC07, not a supported fallback. `/recover-account`
remains deletion-cancellation exclusive, and `/register` remains unchanged as the
single public registration route.

| Planned operation / illustrative request                                                                                             | Required authority / outcome                                                                                                                                                                                                                                                                                                                                                |
| ------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Normal login identification `{identifier:{type:"username"\|"email",value},primary:{method:"password",password}}` or passkey ceremony | Explicit username or current verified unique primary email; no implicit fallback/mobile identifier. Eligible primary, actual passkey UV and all required independent MFA. No contact-only normal issuance; SQL records original evidence/deadlines.                                                                                                                         |
| Primary-bound MFA completion `{preauthentication,method:"totp"\|"mfa_backup_code",code}`                                             | Exact account/JKT/security/policy/primary binding, original preauth expiry and durable one-use replay/backup. Backup is not `TOTP=true`; no normal authority until deciding full-policy SQL validation. Privileged downgrade is denied.                                                                                                                                     |
| Family issuance/regeneration `{family:"arc"\|"mfa_backup",issuance_proof}`                                                           | Fresh family-specific authority. Ordinary password-only ARC issuance requires dedicated exact password+fresh eligible old-contact purpose, not generic Step-up or deletion proof; independent-MFA/privileged policy applies. Returns plaintext once in an authorized transient viewer; no ARC email/SMS delivery or previous-batch GET.                                     |
| Ordinary repair start `{identifier,target_factor,channel}`                                                                           | Bounded non-enumerating start; server selects eligible current old destination and captures its association/provenance. No authority from identifier or send acceptance. New/replaced contacts younger than 24h and unknown provenance are denied.                                                                                                                          |
| Repair admission `{ceremony,arc,contact_proof,primary_proof?}`                                                                       | ARC and fresh old-contact proof; TOTP repair additionally eligible pre-existing primary. SQL consumes ARC/proofs and records one target grant only when barrier clear and account ordinary. Ten-minute original ceremony, grant <=5m and remaining deadline.                                                                                                                |
| Password / one-passkey / TOTP repair finish `{repair_grant,repair_material}`                                                         | Final deciding transaction validates exact purpose/account/JKT/factor/destination/generation/version/policy/deadline and original earned evidence. One repair, barrier set, old sessions fenced, durable intents. New passkey UV; verified atomic TOTP swap preserves old TOTP until success. No normal cookie or OAuth/admin/legal/contact/deletion/general-Step-up grant. |
| Fresh normal login after repair                                                                                                      | SQL-recorded full-policy evidence alone may clear barrier. Repaired password is sufficient only for unchanged ordinary password-only policy; required MFA needs actual TOTP/admitted backup. Refresh/contact proof/ARC/time/regeneration cannot clear it or bypass management endpoints.                                                                                    |
| Password/mobile-capable deletion/reclaim                                                                                             | Extend current deletion-exclusive service without ARC/backup/repair-grant reuse. Preserve stronger UV deletion, 30 days, holds, original deadlines and required retained reclaim factors. Release only after verified destination/readers/notification/lifecycle and T27 dependencies.                                                                                      |
| Bounded operation result inspection `{operation_capability}` where a task explicitly defines one                                     | Read-only known committed/absent/unknown facts, not receipt authentication, replay/refund, deadline extension or authority reissue. Do not invent a universal reconciliation endpoint.                                                                                                                                                                                      |

Every planned authority binds account, purpose, target, original browser JKT,
captured security/policy/family/contact versions and absolute UTC expiry. Errors
remain opaque for invalid/unknown/spent/revoked/foreign authority; bounded
`rate_limited`, `temporarily_unavailable`, `outcome_unknown` and policy conflicts
do not reveal inventories or justify automatic fallback. A pre-handler fresh DPoP
nonce retry is distinct from replay of a transmitted mutation. SQL/provider
uncertainty never refunds a saved code, recreates a user or sends tentative secret
material. Primary SQL consumption/mutation is atomic; Redis/provider effects are not.

Planned gRPC/consumer extensions carry trustworthy policy/earned-assurance/freshness
references only after durable token foundations. Preserve `(iss, sub)`, principal
kind, scopes, expected audience, observed proof context and optional protobuf email
presence. `CheckPermission(user_id,permission)` alone is neither end-user delegation
nor privileged hardware evidence. No current RPC is relabeled as enforcing these
planned obligations. Security-event contracts/readers precede notification writers;
events carry metadata only, never repaired secrets, contacts or private attributes.

### 1.7 Admin & Moderation API

Admin routes require an active, non-deleted account, a normal DPoP-bound browser session under the first-party boundary above, and live database permissions. Recovery-enrollment sessions cannot access them. The existing admin Origin allow-list and audit/permission checks remain additional requirements. Mutations and legal attribution consume a single-use, session-bound step-up grant **after** permission checks. All responses use `Cache-Control: private, no-store` and `Referrer-Policy: no-referrer`. Session activity renews only when the final authorized response is released after the durable admin transaction commits, not when a handler writes a tentative buffered response.

| Route under `/api/v1/admin`                    | Seeded role                                  | Contract                                                                                                                                                                                                                                                                                                                                      |
| ---------------------------------------------- | -------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /capabilities`                            | Any permitted, mounted section 1.7 operation | Fixed capability booleans and effective numeric limits from primary-database permissions and mounted routes, including legal-only grants. No role catalogue, personal data, or section 1.8 workflow flags in the response. Durably audited before disclosure.                                                                                 |
| `GET /users`, `GET /users/{user_id}`           | Support, Moderator                           | Safe account summary with canonical-string `lifecycle_revision` from the status snapshot; only Moderator receives email. No roles, legal-hold state, encrypted material or authentication secrets.                                                                                                                                            |
| `POST /users/lookup`                           | Moderator                                    | Exact canonical email in JSON `{email}`; response includes mandatory `canonical_email` bound to the returned user row. Legacy `GET /users?email=...` is rejected.                                                                                                                                                                             |
| `PATCH /users/{user_id}/status`                | Moderator + step-up                          | Required `{status, reason, expected_revision}` with an exact decimal-string revision. Active/suspended/banned only; no self or privileged-account moderation. Pending verification/deletion and deleted accounts are refused. Stale pins return `409 account_conflict` under the existing account locks, before status/auth/lifecycle writes. |
| `GET /audit-logs`                              | DPO                                          | Required `start_time`, `end_time` (RFC3339 or Unix seconds), at most 31 days; optional bounded `event_type`. Returns stored row hashes.                                                                                                                                                                                                       |
| `GET /audit-logs/verify`, `GET /ledger/verify` | DPO, Super Admin                             | Content-free verification; no actors, network data, payloads or account data.                                                                                                                                                                                                                                                                 |
| `POST /legal-holds`                            | DPO + step-up                                | Required `account_ref`, `reason`, `requesting_authority`, `legal_basis`; optional advisory `review_at`; UUID `Idempotency-Key` header.                                                                                                                                                                                                        |
| `GET /legal-holds`                             | DPO                                          | Optional `account_ref`; `status=active\|released\|all`; true snapshot total.                                                                                                                                                                                                                                                                  |
| `DELETE /legal-holds/{hold_id}`                | DPO + step-up                                | Releases only that request; 204 for release or already released, 404 for unknown ID.                                                                                                                                                                                                                                                          |
| `POST /preservation-requests`                  | DPO + step-up                                | Required `account_ref`, `reason`, `requesting_authority`; optional advisory `expires_at`; UUID `Idempotency-Key`. Atomically records a hold and observed evidence presence even without a live account.                                                                                                                                       |
| `POST /legal-inquiry/lookup`                   | DPO + step-up                                | JSON identifier/type (`email` only), authority/case context, time bounds, optional fields and cursor. Requires a verified signer fixture before mounting. No GET alias.                                                                                                                                                                       |

#### Capabilities and Shared Limits

The capability response is `{capabilities,limits}`. Its existing booleans are `users_read`, `users_pii`, `users_lookup`, `users_status_write`, `audit_logs_read`, `audit_chain_verify`, and `ledger_verify`. Task 7.6 adds exactly these five booleans; each is true only with the existing permission **and** the corresponding mounted operation:

| Capability                     | Permission             | Operation                       | Fresh step-up |
| ------------------------------ | ---------------------- | ------------------------------- | ------------- |
| `legal_holds_read`             | `legal.holds.read`     | `GET /legal-holds`              | No            |
| `legal_holds_apply`            | `legal.holds.write`    | `POST /legal-holds`             | Yes           |
| `legal_holds_release`          | `legal.holds.write`    | `DELETE /legal-holds/{hold_id}` | Yes           |
| `preservation_requests_create` | `legal.holds.write`    | `POST /preservation-requests`   | Yes           |
| `legal_inquiry_lookup`         | `legal.inquiry.lookup` | `POST /legal-inquiry/lookup`    | Every page    |

The three write flags are separate mount capabilities, not new permissions. Seeded grants are unchanged: DPO has the legal permissions; Support, Moderator and Super Admin do not gain them. Account lookup still requires both account-read and PII permission. Combined grants expose their union. Missing step-up leaves eligible reads available but gated operations unmounted. Attribution additionally requires the verified signer fixture; hold/preservation management does not require an indexer. A false flag does not distinguish missing permission from missing deployment prerequisites. When no permitted operation is available, capability discovery yields `403 forbidden`; an unmounted surface is unavailable, not an empty result. Capability/storage failure withholds the response. Capabilities guide presentation only, never replace live authorization, and denial must not sign out an otherwise valid ordinary session.

Limits remain numeric, with no new legal-only limit keys:

| Limit                      | Effective contract                                                                                                                                                                 |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `page_size_default`        | Configured integer default, 50 by default, within `1..page_size_max`.                                                                                                              |
| `page_size_max`            | Configured integer ceiling, 200 by default, within `1..200`.                                                                                                                       |
| `audit_max_window_seconds` | Positive configured window, at most 2678400 seconds (31 days). Applies to **both** audit search and legal attribution, including smaller/fractional durations; do not round it up. |
| `chain_verify_max_limit`   | Existing integer verification ceiling, 5000 by default and at most 5000.                                                                                                           |

The legal browser workspace caps page size at `min(page_size_max, 50)` and defaults to `min(page_size_default, that cap)`. This is a presentation/disclosure bound, not a change to server pagination.

User/hold offset lists use `{items,total,limit,offset}` with effective configured defaults/caps above. Lists and counts share a statement snapshot; empty items are `[]`. Account list/detail/lookup revisions are canonical nonnegative decimal strings. Audit logs instead use `{items,limit,has_more,next_before_seq}` and descending `before_seq` keyset pages without a total count. Audit `seq` and `next_before_seq` are decimal strings too, preserving exact values through `9223372036854775807`. Nullable audit `user_id` means only that no linked reference is present, not proof of any particular erasure reason. Legal attribution has its separate contract below.

User-list GET accepts only `limit`, `offset`, and `status`; audit-list GET only `start_time`, `end_time`, `event_type`, `limit`, and `before_seq`; verifier GET only `after_seq`, `through_seq`, `predecessor_hash`, and `limit`. Repeated/unknown keys and malformed query escaping are `400`. Capabilities/detail GET has no query keys. Email lookup and moderation are body-only. Moderation rejects missing/null/numeric/noncanonical/overflow revisions, unknown or duplicate fields, malformed UTF-8/JSON and trailing input. Trim the reason, then require 1..2000 UTF-8 bytes. A matching revision remains required for API-only same-status behavior; the panel presents only actual transitions.

Lookup callers must verify that the returned row's email equals the mandatory
server `canonical_email` before presentation/target selection, then pin that exact
canonical identity for moderation. Missing/mismatched binding is invalid output,
not permission to fall back to raw input or ASCII-only normalization. This additive
metadata changes neither permissions nor legal attribution's content projection.

#### Legal Holds and Preservation (Task 7.6)

Legal subjects are the original `account_ref` UUID (`users.id`, retained independently after deletion), not a `user_id` alias or a live-account resolver. Each create requires exactly one nonzero UUID `Idempotency-Key` header supplied from the controlled external intake record. The browser uses canonical lowercase hyphenated, nonzero UUIDs for subjects, holds and keys; it never synthesizes a request key. Actor references come from the authenticated session, never the body.

Legal POST bodies are single UTF-8 JSON objects bounded to **32 KiB of serialized bytes**. Use `Content-Type: application/json` (optional UTF-8 charset); exact field spelling/types are required, with unknown fields, case aliases, duplicates, null strings, malformed UTF-8/JSON and trailing documents rejected. Live session and permission checks precede bounded declared/chunked body preflight, which precedes grant consumption; interrupted/oversized input cannot consume the grant or buffer unbounded data. The backend 32-KiB ceiling does not depend on browser enforcement. All legal POSTs and release reject query strings, including bare `?`. Release sends no body or idempotency header; the backend refuses either rather than ignoring it. There is no GET lookup alias, by-key recovery/detail endpoint, preservation-list endpoint, release narrative or moderation revision on these routes.

| Operation                       | JSON request                                                                                                                      | Success                                                                                                                                                                    |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /legal-holds`             | Required strings `account_ref`, `reason`, `requesting_authority`, `legal_basis`; optional string `review_at`.                     | `201` with a `LegalHold` for new creation; `200` with `replayed=true` for the matching request's **current** state.                                                        |
| `POST /preservation-requests`   | Required strings `account_ref`, `reason`, `requesting_authority`; optional string `expires_at`. No client-supplied `legal_basis`. | `201` new / `200` replay with `{hold,replayed,account_present,ledger_evidence_present,observed_at,note}`. `hold` is a `LegalHold`; the three following flags are booleans. |
| `DELETE /legal-holds/{hold_id}` | Path is the nonzero UUID of exactly one request.                                                                                  | Empty `204` for released **or already released**; `404 hold_not_found` for an unknown request.                                                                             |

Reason is nonblank and at most **4096 UTF-8 bytes**; authority and normal-hold legal basis are each nonblank and at most **255 UTF-8 bytes**. The service checks the supplied byte lengths before trimming outer whitespace, then stores/compares trimmed values. This is not moderation's 2000-byte rule. The server fixes preservation legal basis to `preservation_request`, request kind to `preservation`, and maps `expires_at` to the hold's `review_at`.

Optional dates may be omitted/empty and may be in the past. The API date parser accepts RFC3339 or Unix-second **strings**, normalizes to UTC and supports years 1..9999; stored hold dates are truncated to microseconds. The browser sends RFC3339 UTC strings with explicit `Z` only, at stable microsecond-or-coarser precision. Freeze and externally record the exact normalized payload before sending, including omission versus a supplied date.

The exact `LegalHold` projection is:

| Fields                                          | JSON type / meaning                                                                                                               |
| ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `id`, `account_ref`, `applied_by`               | UUID strings: request, original subject and opaque applying actor.                                                                |
| `request_kind`                                  | `legal_hold` or `preservation`.                                                                                                   |
| `reason`, `requesting_authority`, `legal_basis` | Optional strings, omitted when restricted details have been purged. Omission is not evidence that the original values were empty. |
| `is_active`, `details_purged`, `replayed`       | Booleans. List projections have `replayed=false`; the normal create response sets it for replay.                                  |
| `applied_at`, `review_at`, `released_at`        | RFC3339 UTC timestamp strings or `null`; clients must handle nullable dates.                                                      |
| `released_by`                                   | Opaque actor UUID string or `null`.                                                                                               |

`GET /legal-holds` accepts exactly `account_ref`, `status`, `limit`, `offset`. Its strict raw-query parser rejects malformed escaping and duplicate/unknown keys. Omit `account_ref` only for an intentional all-subject query; present-but-empty, invalid or zero UUIDs are `400 invalid_request`, never a widened query. `status` is `active|released|all`, defaulting to `active` when omitted/empty. `limit`/`offset` use nonnegative signed-32-bit decimal parsing: omitted/empty/zero limit uses the configured default, an in-range integer above the configured max is clamped, and omitted/empty offset is zero. Negative, noninteger or overflowing values fail. Response is `200 {items: LegalHold[],total,limit,offset}` with numeric count/effective bounds, ordered by `applied_at DESC, id DESC`. One statement supplies the page and total, not a stable inventory across multiple requests. Both kinds appear; no request-kind filter is supported.

On preservation responses, **top-level `replayed` is authoritative**, not `hold.replayed`. Presence flags are fresh observations under the subject lock, including on replay: `account_present` includes soft-deleted rows; `ledger_evidence_present` can include unindexed or expired payloads. A valid hold can exist with both false. `observed_at` is a UTC timestamp and `note` is exactly:

```text
preservation does not restore purged data; ingestion may still be pending; account and ledger presence are observations, not completeness guarantees; expires_at is advisory only
```

Idempotency is scoped to **`(account_ref, request_kind, key)`**, not actor or a globally unique operation ID. Reusing a key for another subject/kind creates an independent request. Within the same tuple, changed normalized details/date or a cleaned narrative tombstone yields `409 idempotency_conflict`. Matching replay returns current state, including a released hold; it never reactivates it. There is no finite replay expiry in the inherited tombstone protocol. After an uncertain send, explicitly reconfirm the original tuple and normalized payload from external intake, with a fresh grant. Never retry automatically, substitute a new key, or infer which request created a hold from a list alone.

Any independent active hold overrides erasure eligibility until **explicit release**. `review_at` and preservation `expires_at` are advisory, never automatic expiry. Release removes only that request and resumes original retention clocks when no other hold protects the subject, potentially allowing the next purge immediately. It never resets clocks, extends account recovery, restores erased data or creates an immutable evidence snapshot. A `204` cannot prove this caller changed the state; an absent list row is not API `404`. Lookup and creation are separate transactions, so a lookup page is not a promise all evidence survived until the hold committed. Section 1.8 case/disclosure approval is not required for preservation, and investigative access is not permission to transfer data externally.

#### Legal Attribution (Task 7.6)

`POST /legal-inquiry/lookup` accepts exactly these fields and consumes fresh step-up on **every page**:

| Field                                    | Request contract                                                                                                                                                                                                                                                                                                         |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `identifier_type`                        | Required string, exactly `email`; all other values return `400 unsupported_identifier_type`.                                                                                                                                                                                                                             |
| `identifier`                             | Required bare-email string; valid UTF-8 raw bound 1024 bytes, canonical bound 254 bytes with local part <=64 bytes. No display-name/list/quoted/literal address.                                                                                                                                                         |
| `requesting_authority`, `case_reference` | Required nonblank strings, each at most 255 UTF-8 bytes before trim.                                                                                                                                                                                                                                                     |
| `purpose`                                | Required nonblank string, at most 4096 UTF-8 bytes before trim.                                                                                                                                                                                                                                                          |
| `start_time`, `end_time`                 | Required nonzero timestamps as strings; API accepts RFC3339 or Unix seconds, within years 1..9999. Require `start <= end` and span no greater than the effective `audit_max_window_seconds`. SQL bounds are inclusive after conversion to microsecond precision. The browser requires explicit RFC3339 UTC (`Z`) bounds. |
| `limit`                                  | Optional signed-32-bit JSON integer; omitted/zero uses `page_size_default`. Effective value must be `1..page_size_max` (at most 200). Unlike the GET list, an excessive limit is **rejected**, not clamped.                                                                                                              |
| `fields`                                 | Optional array of at most six distinct exact names: `client_ip`, `ip_subnet`, `user_agent`, `device_fingerprint`, `client_id`, `scope`. Unknown/duplicate names fail. Omission/empty array gives core fields only; the panel initially sends `[]`.                                                                       |
| `cursor`                                 | Optional opaque string, at most 4096 bytes, returned by the prior page. Omit for the first page. Invalid, tampered or scope-mismatched cursors return `400 invalid_request`.                                                                                                                                             |

The server canonicalizes NFC/local lowercase/NFC plus strict IDNA and computes
email HMAC-SHA256 over those exact bytes, without generic BlindIndex's unchanged
NFKC pass. Cursor scope uses that same canonical identity. The browser performs
no hashing/provider alias normalization. Phone/backup-email/profile resolution and
search-as-you-type are not provided; old signed history is never rehashed.

Window validation and cursor scope use the parsed UTC instants, while the shared database timestamp conversion truncates query bounds to microseconds. Use microsecond-or-coarser inputs to avoid that sub-microsecond selection difference; a client must withhold an out-of-scope result rather than silently widen the submitted interval.

The exact success envelope is `200 {items,next_cursor?,coverage}`. `items` is always an array; `next_cursor` is omitted when there is no continuation. Each item has only core `id`, `account_ref`, `event_type`, `timestamp`, `retain_until`, `seq`, plus explicitly selected optional fields that are present. IDs are UUID strings, `event_type` and optional fields are strings, and the two dates are UTC timestamp strings or `null` in the DTO. `id` is the event UUID from `security_ledger_chain.event_id`. Unselected fields are not disclosed; missing selected values do not prove the metadata never existed. No raw email/phone, blind index/pepper version, credentials, full audit payload, action content or chain hash is returned.

`seq` and `coverage.through_seq` are **canonical nonnegative decimal JSON strings**, from `"0"` through `"9223372036854775807"`, never JSON numbers, signs or zero-padded alternatives. They remain exact above JavaScript's `9007199254740991` safe-integer limit. Internal `int64`, stored hashes, signed canonical bytes and opaque cursor encoding are unchanged. Sequence position is not verified inclusion proof; the integrity API remains separate.

`coverage` contains exactly `through_seq`, UTC `observed_at`, UTC `eligibility_checked_at`, and string `note`. The first page captures a fixed inclusive chain high-water bound and observation time, retained across pages; each page rechecks current retention/holds and reports a fresh eligibility time. Items advance in ascending sequence order within that bound and the inclusive event-time query. Later ingestion above the bound is excluded; releasing a hold can remove expired matches from later pages. There is no total or complete-history flag. Display the full note:

```text
matching indexed retained records only; ingestion may be pending; unindexed or purged history is not covered; separate account references do not establish one person
```

The encrypted cursor binds normalized identity, actor, UTC bounds, trimmed authority/case/purpose and sorted fields. It has **no implemented age TTL** and is not session-bound; it does not bind page size. The browser nonetheless freezes all fields **including limit** through a run and clears cursors on session/scope changes. Never decode a cursor, invent an expiry countdown or silently remove a rejected cursor to restart. Advance explicitly with the unchanged request plus cursor and a fresh grant; retain only the current bounded page, with no fetch-all, polling, export or previous-page cache.

Class B is **pseudonymized personal data**, not anonymous or non-PII. The entered email is transient sensitive input, not returned evidence. Empty/final results mean no matching indexed, currently eligible records in that scope, not no activity, no account or verified real-world identity. Multiple original references remain separate subjects; do not select the first automatically or merge them. Coverage does not establish that every historical pepper generation is searchable.

#### Legal Failures and Auditing

Legal and shared errors use the JSON `error` code (with the existing step-up challenge fields where applicable):

| Outcome                                                                                                                  | Meaning / required handling                                                                                                                                         |
| ------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `400 invalid_request`                                                                                                    | Invalid body, UUID/key, date/page/field/type bounds, strict query or cursor. Correct explicitly; never remove a filter or turn failure into an empty page.          |
| `413 invalid_request`                                                                                                    | Backend legal preflight rejects declared or streamed body above 32 KiB before consuming step-up; no browser-only guarantee.                                         |
| `415 invalid_content_type`                                                                                               | Missing, duplicated or unsupported media type/charset for a nonempty body.                                                                                          |
| `400 unsupported_identifier_type`                                                                                        | Only email attribution is supported.                                                                                                                                |
| `401 use_dpop_nonce`                                                                                                     | Explicit pre-handler challenge permits one retry with a fresh proof and the **same** body/key/grant; no handler/grant has been consumed.                            |
| `401 session_required`, `401 invalid_dpop_proof`, `409 session_changed`                                                  | Clear private state and rebootstrap/re-authenticate through the shared session boundary; never infer write success.                                                 |
| `401 invalid_credentials` during step-up                                                                                 | Factor failure, not ordinary-session loss.                                                                                                                          |
| `403 insufficient_user_authentication`                                                                                   | Fresh single-use verification required. Never reuse an old grant.                                                                                                   |
| `403 forbidden` / `forbidden_origin`                                                                                     | Live permission or exact-Origin admission denied. Clear the privileged view/recheck capabilities for permission loss, without signing out a valid ordinary session. |
| `404 hold_not_found`                                                                                                     | Release target does not exist. Routing/unmounted-service errors are not this observation or proof of no historical record.                                          |
| `409 idempotency_conflict`                                                                                               | Reconcile the original tuple/payload externally; never replace its key or reactivate it.                                                                            |
| `429 rate_limited`                                                                                                       | Bounded `Retry-After` feedback only; no automatic challenge/request scheduling.                                                                                     |
| `503 legal_unavailable`, `audit_unavailable`, `service_unavailable`, `rate_limit_unavailable`, `temporarily_unavailable` | Dependencies/audit unavailable; withhold results and reconcile transmitted writes as unconfirmed where commit is uncertain.                                         |
| `500 response_too_large`, `500 server_error`, lost/malformed/oversized/interrupted responses                             | Do not accept partial results or promise rollback. Explicit smaller-scope recovery for reads; original-tuple recovery for creates.                                  |

Every successful read commits sanitized disclosure intent before any response bytes. Mutations, encrypted restricted context and audit intent commit together; pre-commit audit failure withholds disclosure and rolls back changes. An unavailable store cannot guarantee durable recording of a rejected attempt. **A write can commit before session-activity renewal fails with `503 temporarily_unavailable`** or its response is lost. A transmitted write without a valid success response remains unconfirmed, never an automatic replay or claimed rollback. Confirmed writes remain confirmed if a later list refresh fails; a lost lookup is no accepted result, not "no match" or an uncertain business mutation.

The API buffers at most 4 MiB. Browser 4-MiB response exceptions are exactly `GET /audit-logs`, `GET /legal-holds`, and `POST /legal-inquiry/lookup`; other calls retain 256 KiB. Both declared and streamed bytes are checked, and legal JSON is validated against 32 KiB before spending a grant. Never silently truncate rows or optional fields to fit. Baseline admin audit still contains personal data, including actor/network metadata, linkable action/hold references, timestamps and response digests; narrative minimization is not anonymization. An acknowledged outbox worker delivers Class C intent to the signer. Ordinary security-event recording retains its existing best-effort transport.

#### Audit and Integrity

Canonical-v2 verification defaults to a 1,000-node page (maximum 5,000). Start at `after_seq="0"` without an upper bound, capture the returned inclusive `through_seq`, and keep it fixed. Continue explicitly with the prior `next_after_seq` and `last_hash` as `predecessor_hash`. Valid sequence allocation gaps are allowed. Each request uses one bounded read-only REPEATABLE READ snapshot, separate from the durable administrative audit transaction that still withholds response bytes until commit. Hashes in a filtered audit list do not establish contiguous-chain proof.

Responses include `chain`, `canonical_version: 2`, `seed_source`, `seed_hash`, `scope`, page counts, `verified`, `complete`, positions, and failure metadata. Hashes are 64-character lowercase SHA-256 hex. Every sequence coordinate (`after_seq`, `through_seq`, nullable `first_seq`, `last_seq`, `broken_at_seq`, and `next_after_seq`) is a canonical decimal string; counts and limits stay numeric. `complete` is authoritative even if a cursor is present. A clean partial page is not a complete-run result.

The API returns exact explanatory scope text, which the panel validates/displays without inventing aliases. Audit scope is `database_relative_chain_and_retained_leaves; not complete ingestion, independent historical authenticity, or legal authorization`. Ledger scope is `database_relative_chain_retained_leaves_and_erasure_annotations; annotations do not prove receipt chaining or legal authorization; not complete ingestion or independent historical authenticity`. Both are relative to their seed/snapshot; a stored-predecessor start proves local consistency, not independent trust. `checked` includes erased annotated nodes; `erased_checked` is a subset, never added. Annotations do not recompute erased bodies or certify policy compliance by a compromised purge credential. Both durable heads are validated against their own actual terminal/genesis even for empty/historical `through_seq` requests, not compared to an older requested bound. Initialized-empty is not proof of no activity; missing/malformed head, absent payload without annotation, invalid leaf/link or predecessor/head mismatch stops success.

Operational receipt assurance is separate: the bounded read-only `admin-legal --operation=ledger-receipts` uses `LEDGER_RECEIPTS_DATABASE_URL`, not expanded purge grants or a public API/UI. It distinguishes pending intent, manifest-bound chained receipts, legacy/unbound, missing/unavailable, invalid and incomplete coverage. PubAck/`published_at` does not establish chaining; a partial proof is not a full-chain pass. It never rewrites/certifies old signed bytes or independently proves legal authorization.

Its proof flags/counts concern Class C chain linkage in hash-only bounded pages;
correlated receipt bodies/leaves are checked separately. They do not certify
unrelated audit narrative bodies or complete ingestion.

Canonical v2 retains separate chain nodes and verifies available payload leaf digests. The erased-span checkpoint protocol, `purged_count`, `proof_steps`, and checkpoint restart rules belong to the retired format and are not current fields. There is no browser-side rehash or claim of independent historical authenticity. A privileged coherent database rewrite remains undetectable without external anchoring, which is explicitly deferred.

The panel, API, and other admin REST clients (including attribution callers) must cut over together under closed affected old admin ingress, with in-flight requests drained and incompatible callers/open forms retired. Before reopening ingress, **every API replica** must enforce mandatory canonical-string `expected_revision` and support string-valued account revisions, audit/verification coordinates and legal `seq`/`coverage.through_seq`; all clients must use that contract. There is no numeric or revision-optional fallback. This administrative wire change requires no schema migration or new cryptographic format: internal Go `int64` values, signed canonical bytes, digest rules, opaque lookup cursor encoding, lifecycle protobuf/v2 contracts and durable audit records are unchanged. Verify the actual deployed-signer `admin-legal --operation=lookup-probe` on the current schema/keys before exposing attribution; no fixture bypass is permitted. Omitting its fixture keeps lookup unavailable while hold/preservation may remain independently usable.

Rollback first closes affected admin ingress, then disables/removes the new UI entries, then coordinates compatible API/UI rollback while incompatible traffic remains closed. Retain holds, encrypted contexts, request tombstones, accepted audit/outbox intent and approved retention/cleanup; never downgrade storage, reset policy clocks or rewrite chain data. Reopening requires compatible callers on every replica and verified current prerequisites. Production enablement/governance and unobserved manual gates remain separate from local Task 7.5/7.6 acceptance; follow the [admin rollout gates](devops-operations.md#admin-control-panel-task-75) and [legal panel rollout](devops-operations.md#dpolegal-panel-task-76). Section 1.8 workflows, production approvals and Task 5.3/5.4/5.5 statuses are not changed by this contract.

HTTP role assignment and trigger-reset are unmounted. Use the controlled [admin operations procedure](admin-operations.md) for provisioning. Ban/suspension invalidate credentials across instances. `ValidateToken` applies the live account/version gate; offline JWT consumers still retain at most the configured ten-minute token lifetime. Reactivation does not revive old credentials or prevent re-registration.

### 1.8 Operational Legal Workflow

These routes are under `/api/v1/admin` and require the additional opt-in workflow
and approved immutable policy. Only explicit DPO permissions are seeded; Super
Admin has no bypass. All writes and annual artifact downloads require a fresh
step-up grant, exact Origin and a UUID `Idempotency-Key`. JSON actor/ID/key
overrides, unknown fields, trailing bodies and query strings on body-based routes
are rejected. Read responses and mutations are withheld until durable audit
intent commits. New workflow responses do not create permanent response-body
fingerprints in audit.

| Method and suffix                                        | Contract                                                                                                                                                                                                      |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /legal-cases`                                      | `expected_version=0`, UTC `received_at`, optional advisory `next_review_at`, encrypted `content`, `subject_ids`, `hold_ids`. One request, zero-to-many subjects.                                              |
| `GET /legal-cases`, `GET /legal-cases/{case_id}`         | Bounded `{items,total,limit,offset}` summary list (`status=all                                                                                                                                                | open | closed`) or restricted detail/history; expired unheld/erased detail is unavailable. |
| `POST /legal-cases/{case_id}/revisions`                  | Expected state version, replacement content and current subject/hold selection; historical subject protection is retained.                                                                                    |
| `POST /legal-cases/{case_id}/reviews`                    | Expected state version, `content_revision`, decision, rationale and optional next review.                                                                                                                     |
| `POST /legal-cases/{case_id}/close`                      | Explicit closure without a response; never releases a hold.                                                                                                                                                   |
| `GET /legal-reviews`                                     | Due review queue requiring both case-read and hold-read permissions.                                                                                                                                          |
| `POST /legal-holds/{hold_id}/reviews`                    | Advisory review/history, starting at `expected_version=0`; original hold replay fields are unchanged.                                                                                                         |
| `GET /legal-holds/{hold_id}/reviews`                     | Gated audited handoff requiring live `legal.holds.read` only, no case-read or step-up. Returns effective schedule, current version and bounded decrypted newest-first history. No query/body/idempotency key. |
| `POST /legal-cases/{case_id}/response`                   | Exact content revision, outcome, rationale and encrypted manifest (recipient/evidence/legal basis and exact subject/time/field/artifact selection).                                                           |
| `POST /legal-cases/{case_id}/response/approve`           | Exact expected state, content and proposal revisions; different DPO for data-bearing outcomes.                                                                                                                |
| `POST /legal-cases/{case_id}/response/delivery`          | Same approved revisions, UTC `delivered_at`, external `receipt_reference`; attests one final delivery and closes the case.                                                                                    |
| `GET /legal-transparency/monthly?start=YYYY-MM&months=N` | Exact audited aggregates for 1-12 months, explicit coverage and late-entry limitations.                                                                                                                       |
| `POST /legal-transparency/reports`                       | Prepare a completed UTC `year`, `expected_version=0`; immutable snapshot.                                                                                                                                     |
| `GET /legal-transparency/reports/{report_id}`            | Internal approval representation including digest, source/policy version and staleness.                                                                                                                       |
| `POST /legal-transparency/reports/{report_id}/approve`   | Different DPO approves exact `expected_version`, `data_version`, `policy_version`, `digest`.                                                                                                                  |
| `POST /legal-transparency/reports/{report_id}/download`  | Expected version; returns only the approved aggregate JSON bytes, not the internal report representation.                                                                                                     |

Cases distinguish optimistic state version from immutable content revision, so
review bookkeeping does not invalidate itself. Pending/needs-information/rejected
reviews cannot authorize data disclosure. Scope edits require a fresh accepted
review and approval. Delivery timestamps cannot precede preparation or required
approval. `content.request_type` is `disclosure|preservation|other`;
`notification_disposition` is `pending|notify|restricted|not_applicable`, with
restriction text required for `restricted`. Hold review decisions are
`continue|release_recommended|needs_information`; closure reasons are
`withdrawn|no_response_required`. At most 100 distinct historical subjects are
allowed, not 100 new subjects per amendment. Detail history exposes truncation
explicitly. Replay does not consume a second request/answer counter;
changed input or stale versions produce 409. Retention-erased cases return 410,
policy/storage failures 503, and authorization failures 403. Operator delivery
attestation is not evidence that the API transferred data. Supplements, reopening,
external messaging, uploads, public publishing and the UI are not implemented by
this contract. See [operator procedures](admin-operations.md#legal-review-and-transparency-task-55).

Hold-review GET returns exactly `{version,next_review_at,history,history_truncated}`:
`version` is the existing numeric workflow version, `next_review_at` nullable UTC,
`history` an array of `{id,revision,purpose,actor,action_id,created_at,input}`.
It reuses subject/scope locks and expiry/hold checks before decrypting and durably
audits disclosure before bytes. Never-reviewed is version 0/history `[]` with the
original hold `review_at`; after review, the effective override includes explicit
null (not fallback to the original date). History is newest-first and capped at
200 events/1 MiB decrypted input with explicit truncation. Erased/expired returns
`410 legal_record_unavailable`; missing/inconsistent retained history returns
`503 legal_workflow_unavailable`, not a never-created response. No existing-hold
replay fields, review/retention clocks or scope permissions change, no narratives
are resurrected and no workflow UI is supplied. A missing hold is `404 not_found`.

`admin-legal --operation=workflow-status` is a separate bounded read-only operator
snapshot using installed baseline policy with intake disabled, no keys/actor
configuration. It reports only cutoff/count/age/lower-bound review/backlog metadata,
not identifiers. `--limit` is `1..1000` (default 500), cleanup is `1..500` and
baseline cleanup `1..1000`; operation-specific unsupported flags are rejected
before connection, including explicitly supplied `--dry-run=false` outside cleanup.
Workflow expiry uses at-or-after equality; context/baseline released cleanup is
strict-before. Closed expiry is the minimum of original max age and closure-relative
retention; reviews and hold release never reset it. Distinct-account approvals
are not verification of distinct humans, and delivery remains operator attestation.

Here, baseline cleanup means the governance-policy cleanup operation, not migration
installation. Obsolete legal Backfill/plaintext compatibility is removed.
The complete packaged migration inventory and fail-closed history refusal follow
[admin operations](admin-operations.md#migration-and-contraction); no HTTP, signed
canonical, wire-format or operator approval contract changes with consolidation.

### Geography Catalog (T08/T09)

Anonymous same-origin GET requests require `country=IR` and retain the existing
browser API no-store/no-referrer/nosniff headers. They do not bootstrap a session,
require DPoP, create a CORS exception or expose an import/write endpoint.

| Route                           | Additional query                                        | Result                                                                                                        |
| ------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `/api/v1/geography/provinces`   | Optional `q`, `limit`, `cursor`                         | Active province roots (source type 2).                                                                        |
| `/api/v1/geography/localities`  | Required `province_id`; optional `q`, `limit`, `cursor` | Active source types 5 and 7 within the selected active province.                                              |
| `/api/v1/geography/places/{id}` | Optional `revision`                                     | Current identity or last-seen retired snapshot; explicit revision resolves that complete historical snapshot. |

Lists return `{catalog_revision,items,next_cursor}`. Each item/lookup returns
`{id,label,type:{id,label},province,ancestors,retired,selectable,catalog_revision}`;
province/ancestor summaries contain `{id,label,type_id,type_label}`. Ancestors are
ordered from root toward the immediate parent. IDs, type IDs and revisions are
exact positive BIGINT decimal strings, never JavaScript numbers. Display original
labels and paths without translating or normalizing their bytes.

The default page is 20, maximum 50. Prefix-only search uses the separate normalized
name with deterministic `C` collation and ID keyset tie-breaker. Empty `q` browses;
`%`, `_` and backslash are literal. Queries are at most 80 Unicode code points and
256 UTF-8 bytes; cursors at most 2 KiB bind endpoint, revision, province and normalized
query. They are continuation tokens, not authorization. Database reads have a
one-second deadline and one consistent catalog snapshot.

| Status                        | Meaning                                                                                     |
| ----------------------------- | ------------------------------------------------------------------------------------------- |
| 200                           | Valid bounded list, including genuinely empty search results, or resolved identity.         |
| 400 `invalid_request`         | Malformed/duplicate/unsupported query, noncanonical ID or invalid province.                 |
| 404 `not_found`               | Unknown identity or absent requested snapshot membership.                                   |
| 409 `catalog_changed`         | Active revision changed since the supplied continuation; restart browsing explicitly.       |
| 429 `rate_limited`            | Geography's separate trusted-IP/subnet Redis budget exceeded; honor `Retry-After`.          |
| 503 `temporarily_unavailable` | Uninitialized catalog, database/deadline or limiter failure; never a successful empty list. |

Default geography budgets are 120 requests/IP/minute and 600/subnet/minute,
independent of authentication budgets. Trusted proxy handling is unchanged. The
shared `internal/geography.Service.Validate` accepts only `{country:"IR",
province_id,locality_id?}` and returns a server-owned `catalog_revision`; active
province type 2, optional active locality type 5/7 and matching ancestry are checked
inside one snapshot. It separates invalid selections from availability errors.
Registration does not yet call this validator or persist location.

## 2. Internal APIs (gRPC)

These services are strictly internal, protected by mTLS, and never exposed to the public internet. They allow other microservices in the Hatef ecosystem (e.g., Email Service, Search Core) to interact with the IdP securely and efficiently.

Task 6.1 supplies `internal/grpcauth`; Task 6.2 composes it with `IdentityService` and an opt-in private listener in the existing API process. `GRPC_ENABLED=false` retains HTTP-only operation. Enabling requires PostgreSQL, Redis, a local Workload API socket, an explicit trust domain, exact method grants, and caller validation policies. No SPIRE deployment, production grants, or public gRPC routing is implied.

### 2.1 Identity SAN Validation (gRPC RBAC)

`grpcauth` verifies the client's X.509-SVID at each unary call or stream creation, using exactly one URI **Subject Alternative Name (SAN)** containing a valid workload **SPIFFE ID**, for example `spiffe://hatef.ir/ns/identity/sa/email-service`. The identity must belong to the explicitly configured trust domain and its certificate chain must verify against the current injected bundle. CN, DNS SANs, metadata, forwarding headers, OAuth clients, and administrator roles are not workload authentication.

Service RBAC is an immutable exact-full-method-to-SPIFFE-ID allowlist supplied by the composition root. There are no default, wildcard, or prefix grants. Unknown grants are never inferred from service names, and health/reflection methods have no exemption. Authorization denies the RPC, not other independently permitted calls on the same authenticated connection. The helper installs TLS 1.3 mTLS credentials and both guards without opening a listener or owning credential-source lifetime.

RPC-stage authentication failures return `Unauthenticated`, unavailable trust material returns `Unavailable`, and authenticated callers without a matching grant receive `PermissionDenied`. Allowed handlers can read the verified service identity through `grpcauth.IdentityFromContext`. Streaming authorization is admission-only; already-open streams are not revoked automatically. Interceptor denials produce sanitized, best-effort `grpc.access.denied` audit events, without user/security-ledger attribution or request contents. Handshake failures and unregistered-method dispatch can occur before an interceptor. See [client integration](client-integration.md#3-internal-grpc-integration-zero-trust) for wiring, certificate renewal, error, and audit limits.

### 2.2 `IdentityService`

Implemented by `internal/identitygrpc` using the [canonical protobuf contract](../libs/schemas/proto/hatef/identity/v1/identity_service.proto). Workload admission does not replace token, account, scope, or permission checks.

| RPC                   | Contract                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ValidateToken`       | Required raw `access_token`, explicit `expected_audience`, and observed `authorization_scheme` (`Bearer` or `DPoP`). DPoP also requires `dpop_proof`, original `http_method`, and independently observed absolute `http_uri`. Any supplied HTTP context is validated against the caller's exact permitted origins.                                                                                                                                             |
| `CheckPermission`     | Nonzero `user_id` UUID and exact `permission` identifier, at most 100 characters. Uses the existing primary-DB predicate for active, nondeleted accounts. Role names, OAuth scopes, wildcard expansion, and administrator bypasses are not supported. Unknown users/permissions return `allowed=false`.                                                                                                                                                        |
| `GetInternalUserInfo` | Nonzero `user_id` UUID. Active/pending-verification users return ID, primary email, display name, status and `lifecycle_revision`; suspended/banned users omit both email and display name. Missing, deleted and pending-deletion users return `NotFound`. Name and revision come from the same snapshot. The revision orders shared-profile changes, not credentials or authorization. No encrypted contacts, factors, hashes or legal metadata are returned. |

`ValidateToken` verifies the local rotating key, `typ=at+jwt`, algorithm, issuer, audience, expiry and required claims. User tokens require the matching live normal browser session, OAuth grant, and captured primary-DB `auth_version`; client-credentials tokens use an explicit `CLIENT` principal and never acquire a user identity, even when the client ID is UUID-shaped. Recovery-enrollment sessions, ID tokens, step-up grants, assertions and legacy unlinked access JWTs are rejected.

Active responses contain `principal_type`, `subject`, `client_id`, scopes and JWT `expires_at`; `user_id` is populated only for `USER`. Invalid, expired or revoked authority returns `active=false` without claims. Invalid required proofs additionally return `DPOP_OUTCOME_INVALID_PROOF`. A nonce challenge returns only `DPOP_OUTCOME_USE_NONCE` and `dpop_nonce`, not claims or a revocation assertion. Malformed RPC envelopes return `InvalidArgument`, caller policy violations `PermissionDenied`, dependency/corrupt-state failures `Unavailable`, and cancellation/deadlines preserve their gRPC codes.

Signatures use local keys; shared Redis serves session/grant and DPoP state. Successful user validation still performs an indexed primary-DB account check. Neither validation results nor positive permissions are cached, and `expires_at` is not a safe cache lifetime. Validation and refresh never touch browser activity. Logout, device revocation, two-hour default idle expiry, or 24-hour default absolute expiry end linked access/refresh authority, even if a refresh token's own lifetime is longer. The retained `offline_access` scope name does not grant independent offline lifetime.

Refresh rotation is atomic across instances, cannot change its original DPoP key, and retains consumed-secret evidence. Recognized reuse preserves the account-wide breach policy: advance primary account authority, revoke browser sessions, and invalidate all user grants. A Redis cleanup failure cannot revive old account versions. Missing Redis authority is inactive; backend failures never become successful validation or an in-memory fallback.

`CheckPermission` and profile lookup authorize the calling workload to query a supplied user ID; they do not prove that an end user delegated that operation. Consuming services must bind their action to the validated subject and enforce relevant scopes. Profile disclosures emit sanitized, best-effort audit events, without security-ledger attribution or sensitive response contents. See the client integration guide for error forwarding and rollout requirements.

---

## 3. Asynchronous Events (NATS JetStream)

Task 6.3 uses the canonical [`UserLifecycleEvent`](../libs/schemas/proto/hatef/identity/v1/user_lifecycle_event.proto) contract and a separate `IDENTITY_USERS` stream. The Go worker publishes committed outbox intent with JetStream acknowledgements. The audit stream, signer and legal evidence retention are independent.

| Subject                   | Trigger                                                                                                                                                                                                                                                  |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `identity.user.created`   | Transactional new-account creation, including enabled registration's final commit only. Start/options/proof failures and existing-account passkey enrollment do not create an account or event; synthetic lookup probes are not operator bootstrap.      |
| `identity.user.updated`   | Actual ban/reactivation, pending-deletion/reclamation and primary-email value transitions (v1), or real display-name/private-profile updates (v2). `changed_fields` names fields, never values. Email mutation is current T27, not reserved future work. |
| `identity.user.suspended` | Actual transition into the literal `suspended` status, including from banned. Repeating the same status does not emit an event even when credentials are invalidated.                                                                                    |
| `identity.user.deleted`   | Exactly one hold-checked physical user DELETE and its terminal intent commit atomically. Soft deletion, dry runs, held subjects, no-row deletes and rolled-back transactions never emit a tombstone.                                                     |

Both supported versions use ProtoJSON with snake_case keys: `schema_version`, UUID `event_id`, exact `event_type`, UUID `user_id`, UTC `occurred_at`, positive `revision` as a decimal JSON string, optional named-enum `status`, and `changed_fields`. V1 supports `status`/`email`; v2 additionally supports `display_name` and `private_profile` (`apps/identity-api/internal/lifecycle/event.go:157-174`, `enqueue.go:105-131`). Existing creation/status/deletion and legacy deletion adaptation stay v1. Unknown versions/fields fail, persisted v1 payloads are not rewritten, deletion omits status/changed fields. The 16-KiB envelope excludes private values, credentials, ciphertext, IPs and narratives. Identifiers/timestamps remain linkable metadata, not anonymous data.

`users.lifecycle_revision` is independent of `auth_version` and `auth_epoch`. Existing accounts begin at 0 without synthetic history; transaction-aware creation starts at 1. Each real captured change increments once, and deletion uses the locked account's last revision plus one. Outbox IDs/times/revisions stay stable across retries. Phone, MFA, password, passkey, recovery-code, role and session mutations do not belong to this shared-profile stream. Direct SQL and fixtures are outside the explicit Go capture boundary.

The worker accepts existing exact `{"user_id":"<uuid>"}` deletion payloads, validates them, and creates a versioned terminal envelope from their persisted row ID/time without inventing a revision. This is the only supported revision-less event. Persisted legacy payloads are not rewritten.

Delivery is **at least once**. A PubAck followed by an uncertain database commit can replay the same ID, including outside the broker's finite deduplication window. Limits retention enables independent consumers; it is not the audit stream's work queue. A delayed or poisoned per-account head blocks its later revisions while other accounts can progress. Consumers must implement [idempotency, reconciliation and terminal tombstones](client-integration.md#4-user-lifecycle-consumption). Events synchronize projections, not instantaneous access revocation; continue using live authorization checks.

Deploy dual-version publishing/readers and downstream consumers before enabling display-name writers. Downstream deployment is an explicit release prerequisite, not evidence supplied by repository tests. Rollback must retain v2-capable publishing/consumption while any v2 intent or replay remains; see [portal cutover](devops-operations.md#user-portal-cutover-task-73).

## Notification presentation

Only deletion initiation accepts `X-Hatef-Notification-Locale: en` or `fa-IR`.
Missing, duplicate, oversized or unsupported values use English without changing
authorization, routing, response codes or deadlines. The queued v2 intent freezes
locale/template and v1 remains English. SMS.ir VERIFY uses the operator-configured
provider template. See [localization](localization.md#notification-language-and-compatibility).
