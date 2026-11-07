# Hatef Identity Platform - Frontend Pages Structure

This document outlines the routing architecture for the Next.js frontend application within the `hatefsystems/identity` monorepo. The application utilizes the **Next.js App Router (`app/` directory)** and relies on **shadcn/ui** for its component system.

## Route Groups

The routing is logically divided using Next.js Route Groups (e.g., `(auth)`, `(dashboard)`) to share layouts without affecting the URL path.

---

## 1. Authentication & Public Pages: `(auth)`

These pages are accessible to unauthenticated users. Passkey login serves existing
accounts; separately enabled signup has the conditional contract below. Password
login/reset and neutral TOTP forms remain deliberately disconnected. No source or
UI description here asserts final browser acceptance or deployed enablement.

- `/login` : Passkey-first login screen with an email/password alternative and links to registration and password reset.
- `/login/webauthn` : Live discoverable-passkey sign-in, started only by the explicit "Use a passkey" button. The device chooses an existing account; the portal does not ask for an email first.
- `/login/recovery` : Restricted recovery flow for a user who has lost every normal MFA/WebAuthn factor. The UI first submits the email to `POST /api/v1/auth/recovery/start`, retains the opaque `transaction_id` only in memory, and submits it with the backup code to `POST /api/v1/auth/mfa/verify-recovery-code`. The uniform start response must not be interpreted as proof that an account exists. Success creates a ten-minute `recovery_enrollment` session whose only authority is enrolling one UV-required replacement passkey. The UI completes `POST /api/v1/auth/enrollment/webauthn/register/generate-options` and `/verify` in that same session, then returns the user to normal login; it must never render the dashboard or normal security settings under this restricted cookie. A `409 {"error":"enrollment_already_used"}` means the one permitted enrollment was already claimed and the user must restart recovery.
- `/register` : Existing owned Unicode email and Iranian mobile input, explicit ownership proofs, then resident UV-passkey creation. No password/confirmation, new mailbox, role or session is created; completion links to normal login.
- `/verify-totp` : Neutral six-digit authenticator-code form. This is not an active login challenge, enrollment confirmation, or Step-up session.
- `/forgot-password` : Primary-email reset-link request form with an account-enumeration-resistant acknowledgement presentation. Backup Email and Verified Phone (SMS) recovery choices remain planned, outside Task 7.2.
- `/reset-password` : New-password and confirmation form, with invalid/expired-link presentations. Real reset-link validation and password changes are not connected.
- `/register/verify-email` : Signup-specific fragment landing page. Scrub `/register/verify-email#attempt_id=...&token=...` immediately, then require explicit ownership verification with the original browser JKT; no capability transfer or page-load redemption.

### Public Form Boundary (Tasks 7.2 and 7.3)

- The six screens use the existing shadcn components exported by `@hatef/ui`, an English shared auth layout, and application-local field/status compositions. The light default, system font, and existing dark tokens are preserved; Tailwind explicitly retains the `dark` class so production builds do not remove its palette variables. There is no new theme switcher or localization framework.
- Disconnected password/reset/neutral-TOTP forms retain truthful warnings and disabled initial-HTML submit buttons. Registration uses its separate passkey flow, not a fake password-success handler. Passkey actions remain disabled before hydration/with JavaScript off and never allocate keys, fetch/send proofs or invoke credentials on page load.
- Loading, success, cancellation, unsupported-passkey, rate-limit, and reset-link presentations are exercised through test-only handlers/props on the underlying form components. No public fixture route, magic credential, query parameter, or environment flag can simulate authentication or reset delivery. Reset forms default to an unverified link state; tests must explicitly provide a ready state and a handler to enable submission.
- Inactive form values stay in component state, not URLs, cookies, storage, telemetry or logs. Passkey sign-in checks the authenticated profile before entering the portal. Return paths are restricted to fixed dashboard/admin routes; expired admin detail links return to `/admin/users` without the account reference. Arbitrary redirects and OAuth continuations are unsupported. No public fixture route or magic account simulates login success.
- Fields have visible labels, stable help/error associations, appropriate autocomplete, keyboard-operable password toggles, and at least 44px control targets. Local errors appear on blur; a test-enabled invalid submission focuses the first invalid field. Submission feedback is announced, duplicate submissions are blocked, and successful completion clears form values. A single text input preserves leading zeroes in TOTP codes, accepts whole-code paste, and requires exactly six ASCII digits without silently normalizing whitespace or non-ASCII digits. It never auto-submits or offers to resend an authenticator code.
- Disconnected password forms do not invent backend password policy. Signup has no password field or reset authority. Existing backend TOTP enrollment/Step-up endpoints are not public login verification.
- Auth HTML remains dynamically rendered and private/no-store under strict nonce CSP, with existing tokens/local resources and no new CSP exception. Required acceptance includes both palettes, desktop/mobile reflow, keyboard/focus/status, leading-zero code paste and JavaScript-disabled safety. Historical UI evidence is not signup acceptance; screen-reader/physical-authenticator/native-browser/deployed-ingress checks remain separately evidenced gates.

### Conditional Signup UX

Use a text input with email input mode, not native `type="email"` rejection of
supported Unicode. Keep the raw input bound and show the server-returned
`canonical_email` as inert, directionally isolated text; NFC/local lowercase/NFC
and strict IDNA are server authority, never browser/provider alias rules. Verify
that passkey `publicKey.user.name`/display name binds to that canonical email and
the frozen handle is exactly eight bytes, with resident key and UV required.

Start, resend email, send SMS, verify each proof and create a passkey are explicit
actions. Submission ACK/`email_sent` is not ownership; sandbox SMS.ir sends nothing.
Resend replaces email proof and clears phone/ceremony progress without extending
the 15-minute attempt. Email proof lasts 10 minutes, passkey at most 5 minutes
and completion receipt 1 hour. Codes are six-digit strings with leading zeros,
never numeric conversion or non-ASCII/whitespace digit normalization.

Retain attempt/capability/token/OTP/credential/nonce state only in bounded memory,
not URL query/history state, storage, telemetry, snapshots or cross-tab messages.
The existing non-exportable DPoP key/JWK record is the only persistent credential
material. Revalidate that original JKT before signing/transmission, after replies
and on foreground return; key change/loss cannot rebind authority. The email
landing action must not initialize a replacement key for a foreign-browser link.
Cancel/navigation/pagehide/key loss clears authority; OTP inputs clear on hide.
Only bounded in-memory idle intent may survive a tab switch for email handoff;
never resume a transmitted mutation automatically or claim memory zeroization.

When final delivery is ambiguous, offer explicit protected result checking using
the same capability/JKT and a fresh DPoP proof. A committed result reports
`next:"login"`, not dashboard access. New retries are registration-only; other
portal/admin writes keep their existing no-automatic-replay rule. Lost authority
requires a new attempt or ordinary login, never capability recovery by email.
No screenshots/logs/artifacts may retain signup tokens, codes, mail bodies or
provider credentials. Final immutable-image registration browser acceptance is
required, not asserted by these UX instructions.

---

## 2. SSO Authorization: `/oauth2`

These routes handle the OpenID Connect (OIDC) Authorization Code flow when third-party applications or other Hatef services request authentication.

- `/oauth2/authorize` : The Consent Screen. Displays "Application X wants to access your profile." If the user is not logged in, they are redirected to `/login` and then back here.
- `/oauth2/error` : Displayed if the authorization request is invalid or rejected.

---

## 3. User Portal: `/dashboard`

Task 7.3 implements four routes under `app/dashboard/layout.tsx`. The server renders only a non-sensitive shell. Cookie presence is not authorization, and Next.js cannot produce the browser-held DPoP proof. Private content mounts only after the real Go bootstrap succeeds; no profile, grant or recovery batch appears in SSR/Flight HTML.

- `/dashboard`: Truthful profile, passkey/recovery status and session summaries. No fabricated login history, security score or device geography.
- `/dashboard/profile`: Repeated display-name saves with read-only primary email/status. Names are optional, single-line Unicode text, at most 80 code points after trimming outer whitespace; control/line-separator characters are rejected. Empty clears the name. Exact decimal lifecycle revisions support optimistic concurrency without JS-number rounding. A conflict refresh preserves the unsaved draft.
- `/dashboard/security`: List/add/name/rename/remove passkeys and inspect the remaining recovery-code count. Names are user labels, not verified hardware models. A fresh step-up grant is needed for adding, renaming, removing or generating codes. Ordinary registration consumes its grant at options generation, freezes the name, and completes with the same session without a second grant. Final-passkey removal is disabled in the UI and independently rejected by the API with `409 last_credential`.
- `/dashboard/sessions`: List current/other server-side browser sessions using public IDs and the server's `current` flag. Show bounded, escaped reported user-agent/IP metadata without asserting a physical device or location. Confirm individual remote revocation or current-session sign-out. A disappeared target prompts a list refresh, not a conclusion about another account. There is no bulk-revocation control.

Avatar uploads, password changes, email/phone/backup-contact changes, TOTP enrollment, recovery-login UI, OAuth consent, general exports and localization remain outside this portal scope. Task 7.4 supplies the separate privacy/deletion view. Task 7.5 adds a neutral Admin entry, but ordinary dashboard bootstrap never requests admin capabilities. Existing TOTP may satisfy step-up when advertised; independent backend requirements remain authoritative.

---

## 4. Admin & Moderation Panel: `/admin`

Tasks 7.5 and 7.6 use the existing web app and shared secure session lifetime. The initial document is a non-sensitive shell; a normal browser-bound session must bootstrap and then pass `GET /api/v1/admin/capabilities` before private children mount. Capabilities are presentation metadata, never cached authorization. Denied access does not sign out an otherwise valid account session. Disabled, unavailable and no-access states remain distinct where the response permits; a false capability alone does not identify the missing permission or deployment prerequisite.

- `/admin`: Elevated-access framing and links only to permitted workspaces, not invented counts, metrics or alerts.
- `/admin/users`: Explicit bounded account queries with status/page controls. Support sees safe metadata only. Body-only email lookup requires read+PII capability; mandatory returned `canonical_email` must exactly bind the returned row before display/selection/moderation pin, with no raw-input/ASCII-only fallback.
- `/admin/users/[id]`: Permitted metadata and exact lifecycle revision. Eligible targets can be suspended, banned or reactivated with fresh step-up. Self, deleted, pending-verification and pending-deletion targets are disabled locally and independently rejected by the API. Privileged-target denials remain generic.
- `/admin/audit-logs`: Explicit UTC search, initially the last 24 hours or a shorter configured bound. Frozen filters drive descending keyset pages; there is no total count. Cursor history is bounded in memory. Payloads are escaped text in a native details dialog, never HTML, links, remote images or exports.
- `/admin/integrity`: Independent, explicitly advanced canonical-v2 audit/ledger runs. Capture `through_seq` at genesis and carry it with exact cursors and prior hashes. Show checked range, page/cumulative counts, seed provenance and API scope. Partial, interrupted, mismatched, empty and erased-content outcomes never imply complete or independent historical verification.
- `/admin/legal`: One fixed DPO/Legal workspace with capability-gated Legal Holds, Preservation and Attribution sections. Section changes are local, not query/hash/router-state navigation, and clear the departing workflow. No legal data is prefetched.

Default grants give Support account metadata, Moderator account/PII/lookup/status work, DPO audit, verification and section 1.7 legal work, and Super Admin content-free verification only. Combined grants expose their union, including legal-only principals. The UI has no password-reset, role-management, bulk-action or administrative account-deletion controls. Task 7.6 does not add section 1.8 case management, reviews, two-person disclosure approvals, delivery attestation or transparency reporting.

Moderation first rereads and pins the target/status/revision, then verifies UV or advertised TOTP. Only after verification and a matching target reread does the reason/final-confirmation form appear. The one-use grant remains inside the ceremony lifetime through confirmation; its deadline is bounded by both grant and session expiry. Every action needs a trimmed 1..2000-byte UTF-8 reason. A conflict requires fresh review and verification, never an updated revision under an old grant. Cancel, navigation, hide/pagehide, expiry, session/key changes and permission loss abort work and clear drafts, challenges and authority. Only a waiting TOTP action kind/desired status can resume after same-session/current-route capability and target revalidation, without its old code or snapshot.

Long-lived suspension/ban is not erasure, does not prevent re-registration, and remains until explicit restoration. Live credential checks reject old authority; already admitted requests and offline JWT consumers can retain bounded residual access. Reactivation does not restore old credentials. Once a mutation may have been sent, interrupted delivery reports only "Outcome unconfirmed; the action was not retried." Current-state reads are explicit and cannot prove that the interrupted request succeeded. Confirmed writes and failed refreshes are separate outcomes.

Query transport allowlists exact route/key combinations, signs DPoP `htu` without query/fragment, and uses exact decimal-string coordinates rather than JS numbers. The 4 MiB response exceptions are exactly `GET /api/v1/admin/audit-logs`, `GET /api/v1/admin/legal-holds`, and `POST /api/v1/admin/legal-inquiry/lookup`; all other calls retain 256 KiB. Both declared and streamed bytes are checked. A single pre-handler nonce challenge is the only automatic retry; 429/503, invalid/oversized data and interrupted operations require explicit recovery. All sensitive links disable prefetch. Data/filters/proof progress stay out of browser navigation URLs, history state, storage, logs and unmasked artifacts. The documented account-reference filter and hold-ID path are confined to their exact authorized API requests and redacted/template-only diagnostics, not page routes.

Release the panel with compatible admin API/REST clients under closed/drained affected old admin ingress. Before reopening, **every API replica** must enforce mandatory moderation revisions and support canonical-string account revisions, audit/verifier coordinates and legal item `seq`/`coverage.through_seq`. Retire incompatible callers and open forms; no numeric fallback is provided. Rollback closes affected ingress first, removes the new UI entries second, and coordinates compatible API/UI rollback third. Retain holds, encrypted contexts, tombstones, accepted audit/outbox intent and approved retention without clock resets, storage downgrade or hash rewriting. Reopening requires compatible callers and verified current prerequisites. See the [admin rollout gates](devops-operations.md#admin-control-panel-task-75) and [legal panel cutover](devops-operations.md#dpolegal-panel-task-76).

Local Task 7.5 completion may be recorded only after the required automated checks pass with current-worktree evidence. Native hidden-tab/bfcache restoration, physical-authenticator behavior, screen-reader/manual accessibility and production/governance gates require separate evidence. Injected events/history tests, virtual authenticators and headless checks do not close those gates or the independent Task 5.3/5.4/5.5 deployment gates.

### 4.1 DPO/Legal Workspace (Task 7.6)

`/admin/legal` reuses `PortalProvider(surface="admin")`, the shared `PortalClient`, existing native Step-up dialog and English `@hatef/ui` design. It has no second session, capability cache or retry loop. Its SSR/Flight/no-JavaScript output is a neutral shell with actions disabled. Only the selected authorized section mounts; section controls have accessible names, selected state and keyboard support. Shared labels/errors, visible focus, 44px targets, light/dark tokens and local table scrolling at 320px remain required. Long identifiers and narrative text wrap; all legal text/telemetry is inert, never rendered as HTML or links. No new CSP/style exception is introduced.

Presentation uses the five exact capabilities `legal_holds_read`, `legal_holds_apply`, `legal_holds_release`, `preservation_requests_create`, and `legal_inquiry_lookup`. Each operation still requires live backend authorization and durable audit handling. Read permission does not imply write permission; a write-only principal need not gain list/profile browsing. Missing step-up does not remove eligible reads. Loading, no access, unavailable/unmounted and valid empty results are not interchangeable.

**Legal Holds and Preservation**

- Legal Holds is an explicit bounded read with `status=active|released|all`, an optional original `account_ref` and offset pagination. All-subject access requires explicit selection; invalid or blank supplied references never widen the query. Display request kind, immutable hold/reference UUIDs, active/released state, dates and opaque actors. Restricted reason/authority/basis appears only in an intentional details view. Purged details are unavailable, not originally empty. Counts describe that response snapshot, not a stable multi-page inventory. Both request kinds are visible here; there is no preservation-list API or client-only filtering under an unfiltered total.
- A reusable request form creates normal holds, preservation requests or an inline request for an explicitly selected attribution reference. The subject is the original nonzero `account_ref` UUID from controlled intake or a selected result, not a profile lookup, proof of a live account or verified real-world identity. Never select the first match automatically, merge references, perform bulk holds or send a `user_id` alias.
- Each create requires an operator-entered canonical nonzero operation UUID already recorded externally. Do not generate it in the browser. After UV or advertised TOTP verification, collect reason and authority plus legal basis for a normal hold. Trim once and freeze reason (1..4096 UTF-8 bytes), authority/basis (1..255 bytes) and optional RFC3339 UTC review/expiry date at microsecond-or-coarser precision. Past dates are allowed. Preservation fixes legal basis server-side and maps `expires_at` to advisory `review_at`; normal holds never default a legal basis. Validate the entire serialized JSON against 32 KiB before consuming the grant.
- Final confirmation pins the original target, request kind, operation UUID and normalized inputs. The one-use grant remains owned by the existing dialog until that confirmation, bounded by grant/session expiry. Use synchronous double-submit protection and track transmission. Target/scope changes discard authority; every create, release and lookup page requires a fresh grant.
- `201` is new creation; `200` with `replayed=true` is the existing request's current state, possibly already released. Preservation uses its **top-level** replay indicator and displays the full API note and observation time. Account presence includes soft-deleted rows; payload presence may include unindexed/expired evidence. Neither flag guarantees completeness, and both may be false for a valid hold. A lookup and a later hold commit are separate transactions.
- Release starts only from an authorized list row and pins its exact `hold_id`. Warn that other independent holds may remain and original retention may already be elapsed. Send only the body-free DELETE with fresh step-up, no key, reason or revision. `204` confirms this request is released, including an already released request; it does not prove the caller changed it. Hold/review/expiry dates never release automatically. Holds cannot restore erased data, extend account recovery or create an immutable evidence copy.

**Attribution**

- Start only on explicit action with a bare email (raw at most 1024 UTF-8 bytes, canonical at most 254), authority/case (each 1..255 bytes), purpose (1..4096 bytes), explicit UTC inclusive bounds and a page size within effective limits. Use the same potentially fractional `audit_max_window_seconds`, not a hard-coded 31 days. Legal page size remains capped at `min(page_size_max, 50)`. The server uses shared canonical NFC/lower/NFC+strict IDNA identity and exact email HMAC input; never hash or provider-normalize in the browser or offer phone/backup-email/profile resolution.
- Class B is **pseudonymized personal data**, not anonymous or non-PII. Show only core `id`, `account_ref`, `event_type`, `timestamp`, `retain_until`, and exact decimal-string `seq` by default. Six unchecked opt-ins request `client_ip`, `ip_subnet`, `user_agent`, `device_fingerprint`, `client_id`, `scope` for the stated purpose. Initially send `fields: []`; never fetch unselected fields for hidden columns. Reject unexpected disclosure fields and project only requested data. The entered email is transient sensitive input, not returned evidence.
- Freeze the whole query including page size. Explicit next-page actions reuse it with the opaque cursor and fresh verification. Preserve exact string `coverage.through_seq` and original `observed_at`, verify ascending sequence progress within the bound, and display the fresh `eligibility_checked_at` and complete API note. No total or complete-history flag exists. Cursors have no implemented age TTL and are not session-bound on the server; the UI still clears them on session changes. Do not decode them, show an invented expiry countdown or silently restart a rejected cursor.
- Keep only a bounded current page; no polling, automatic fetch-all, previous-page cache, exports, bulk-copy, uploads or external transfers. Changed input/field scope starts a fresh run and clears prior results. Empty/final results mean no matching indexed, currently eligible records in that scope, not no account or activity. Retention/holds are rechecked on every page, so hold release can remove expired matches and later ingestion above the bound is excluded. Multiple references do not establish one person; sequence positions do not prove inclusion or full historical pepper coverage. Integrity verification remains separate.
- Selecting a reference opens an inline hold/preservation form in Attribution. Only that reference is conveyed, never query/hash/router state, a new profile resolver or a persisted draft. Each reference requires independent confirmation and fresh step-up. Investigative lookup is not authorization to disclose externally; section 1.8 approval/delivery workflows remain out of scope, and preservation does not wait for a case or full disclosure order.

**Privacy and Uncertain Outcomes**

Abort and clear legal inputs, selected references, narratives, operation IDs, results, cursors and grants on section/route changes, cancel, hide/pagehide, session/key changes, expiry and permission loss. Pending forms also clear on grant expiry. Clear detached controls/hide sensitive regions synchronously and ignore late replies even if abort is ignored. No browser storage, history state, logging, analytics or cross-tab transfer holds this data. A waiting-TOTP resume marker may retain only an operation name; fresh same-session/capability revalidation cannot restore the old target, scope, key or transmitted request. Neutral interruption feedback remains outside cleared children.

The transport exposes a scoped `idempotencyKey` option only for the two create POSTs, not arbitrary header overrides. The sole automatic pre-handler DPoP nonce retry preserves the exact body/key/grant. Lost, malformed, oversized or interrupted write responses and potentially post-commit `503` are **unconfirmed**, never rollback or success inferred from a later `401`. Create recovery requires explicit reentry/reconfirmation of the same `(account_ref, request_kind, operation UUID, normalized payload)` from external intake and fresh verification; no fresh-key fallback. `409 idempotency_conflict` requires external reconciliation. A list can show current state, not identify which uncertain request created it. Confirmed writes remain confirmed when a subsequent refresh fails.

Lost lookup data means no accepted result, not "no match" or a failed business mutation; require explicit fresh verification/restart rather than moderation's account-state refresh advice. Oversized results require explicit smaller scope/page size, never silent row/field truncation. Permission denial clears the privileged view and rechecks capabilities without signing out the ordinary session; factor failure is distinct from session loss. Full error/DTO rules are in [API section 1.7](api-design.md#17-admin--moderation-api), with [external retry procedures](admin-operations.md#dpolegal-panel-task-76).

---

## Layout Structure Details

- `app/layout.tsx`: Request-time root document for fresh CSP nonces. Public page loads do not initialize an authentication key or start a ceremony.
- `app/(auth)/layout.tsx`: Shared brand link, main landmark, and fluid-width card layout. Minimum viewport height and normal vertical scrolling keep forms usable on narrow or short screens.
- `app/dashboard/layout.tsx`: Account shell backed by the shared `app/_components/portal-provider.tsx`. Existing account actions retain their immediate post-verification behavior and do not perform admin capability discovery.
- `app/admin/layout.tsx`: The same provider in admin mode, with capability-gated navigation, elevated framing, return-to-account and sign-out. Shared controls and native dialogs use existing `@hatef/ui` tokens, visible focus and 44px targets. Compact tables use bounded local horizontal overflow at 320px without widening the document.

---

## 5. Security Hardening & Session Isolation (Next.js & Browser Client)

The portal combines server-side authority, browser-held signing keys, strict CSP and bounded transient state. These controls reduce risk; they do not make same-origin XSS harmless or certify full browser-memory erasure.

### 5.1 Cookie-Based Session Protection

- Go issues host-only `__Host-` cookies with `Path=/`, `Secure`, `HttpOnly` and `SameSite=Strict`. The browser adapter uses same-origin credentials and never reads the cookie or stores access/refresh tokens.
- Every normal API request also needs a valid DPoP proof from the originally bound key. Exact Origin protects unsafe requests, including login/logout; authenticated mutations require the matching public session ID. Post-bootstrap reads include that ID too so a missed cross-tab notification cannot mix account data.
- Session loss is distinct from a nonce challenge or failed factor check. Old unbound/restricted/revoked/expired cookies cannot bootstrap the portal. Missing/unusable key storage blocks access and requires fresh passkey login, never a weaker fallback.
- Profile/session data are not authorization caches. Default authority is 24 hours absolute and two hours idle; only successfully authorized browser requests renew activity. The frontend does not poll to keep a session alive.

### 5.2 Client-Side Sender-Constrained Tokens (DPoP) & Strict-Nonce CSP

Task 7.3 implements adapters in `apps/web/app/_lib/portal`, on top of the unchanged strict Task 7.1 document CSP.

- **Asymmetric binding:** A user-triggered passkey login creates or opens a WebCrypto ECDSA P-256 key. Concurrent tabs transactionally select one active key and verify the persisted structured clone before use.
- **Minimal IndexedDB state:** `hatef-portal-dpop` / `keys` / `active` holds only a non-exportable private `CryptoKey` and public JWK metadata. No private JWK, cookie, token, grant, proof, nonce, profile or recovery batch is persisted in IndexedDB/localStorage/sessionStorage. Non-exportability blocks private-key export, not same-origin XSS invoking signing operations.
- **Proofs and requests:** Typed fetch uses same-origin cookies, no-store, bounded responses, abort signals and redirect rejection. Each API request gets a fresh signed JTI/method/canonical URL/time/public JWK and a request-local server nonce; cookie requests do not invent an access-token `ath`. Retry once only after explicit pre-handler `use_dpop_nonce`. Never automatically replay an uncertain mutation or authenticator response.
- **Origin-preserving fetch:** The adapter uses `mode: 'cors'` with strictly validated same-origin URLs and `credentials: 'same-origin'`. This preserves the unsafe-request Origin under `referrerPolicy: 'no-referrer'`; it does not permit cross-origin APIs.
- **Cross-tab state:** Broadcast invalidation notifications only, never credentials or profile data, and exclude the sending document. Cancel late work by abort/generation checks, clear old state and bootstrap the new session. Hidden/pagehide views are cleared; resume rechecks authority before redisplaying private information. Failed sign-out remains cleared with explicit reconciliation rather than automatically restoring private content.
- **TOTP app switching:** Ordinary visibility suspension may retain only a non-secret pending action intent in memory. A fresh same-session bootstrap can restore a new confirmation/TOTP challenge; codes, grants, challenges, proofs and recovery batches are cleared, and an already transmitted mutation is never resumed automatically. Navigation, pagehide or session change discards the intent. Cancelled transmitted account/moderation mutations offer an explicit authenticated state refresh; legal operations use section 4.1's operation-specific recovery without retaining an old target/query/key. Late reads cannot overwrite a confirmed mutation.
- **Strict-Nonce CSP (Task 7.1):** `apps/web/proxy.ts`, Next.js 16's middleware successor, generates a fresh 32-byte cryptographic nonce for each covered request. It replaces caller-supplied nonce/CSP values, forwards the policy and `x-nonce` to the renderer, and returns the same enforcing `Content-Security-Policy` header. Next.js uses the request policy to nonce its bootstrap and Flight scripts. This mitigates script/style injection; it does not replace safe rendering, authorization, or other XSS defenses. The document CSP does not cover Go API responses; Task 7.3 independently enforces their private/no-store/no-referrer policy.
- **Rendering and caching:** The root layout waits for `connection()`. All portal HTML, including otherwise static-content pages and the application 404, is rendered on demand and is private/no-store. SSG, ISR, PPR, static export, and shared HTML caching are not supported with this per-request nonce contract. Fingerprinted JS/CSS assets remain publicly cacheable and immutable.
- **Coverage:** Page routes, dotted/unknown URLs, and prefetch requests are protected, including future `/oauth2/authorize` and `/oauth2/error` screens. Backend `/api` paths, `/_next/static`, `/_next/image`, and the favicon are excluded. Upstream outage pages and framework responses produced before the proxy are outside this guarantee.
- **Strict styles:** Use CSS classes or external stylesheets. A nonce does not authorize a `style` attribute. Application 404, ordinary-error and global-error components use classes; the global fallback supplies its own document and stylesheet. Any future authored `next/script` or inline style element must receive the current request's `x-nonce` rather than generate or cache another nonce.
- **Origin contract:** Production resources and connections are same-origin. No external script, font, image, analytics, worker, or API integration is implicitly authorized. Future integrations must review the relevant directives and rendering behavior rather than add wildcard allowances.
- **Trusted Types deferral:** `require-trusted-types-for 'script'` and Trusted Types policies are deliberately not enabled in Task 7.1. The earlier design requirement remains outstanding until framework/DOM-sink compatibility is implemented and browser-tested; nonce compliance alone does not satisfy it.
- **Development only:** `NODE_ENV=development` permits script `unsafe-eval`, inline styles for Next.js tooling, and `ws:`/`wss:` connections for HMR. It omits `style-src-attr`, the style nonce, and `upgrade-insecure-requests`. Script `unsafe-inline` is never allowed. Production/test policies remain strict.

The production header is serialized onto one line; `[random]` is the same fresh nonce in both sources:

```text
default-src 'self';
script-src 'self' 'nonce-[random]' 'strict-dynamic';
script-src-attr 'none';
style-src 'self' 'nonce-[random]';
style-src-attr 'none';
connect-src 'self';
img-src 'self';
font-src 'self';
object-src 'none';
base-uri 'self';
form-action 'self';
frame-ancestors 'none';
frame-src 'none';
upgrade-insecure-requests;
```

### 5.3 UX Step-up Authentication Trigger Flow

The shared portal ceremony supports account security actions, Task 7.5 moderation and Task 7.6 legal operations. Account actions retain immediate execution after verification; moderation and legal forms hold the grant through their separate details/final-confirmation stage. Every legal lookup page also requires fresh verification. Section 1.8 case/review/disclosure-approval workflows and the disconnected public `/verify-totp` screen are not part of this flow:

1. **Trigger:** Adding/renaming/removing a passkey or replacing recovery codes pins the action and target before confirmation. Validate names locally first. `403 insufficient_user_authentication` means fresh step-up, not full login; `401 invalid_credentials` means a failed factor and stays in the dialog.
2. **Step-up Overlay:** Instead of directing to a separate page, a secure, modal dialog (overlay) interrupts the flow. `POST /api/v1/auth/stepup/challenge` reports which factors the account can present (`methods`) plus the WebAuthn assertion options when a passkey is enrolled. Keep the returned challenge state in memory and complete it from the same authenticated session: the server binds the challenge to its exact user, session, and Step-up flow, and a mismatched session cannot consume the legitimate challenge. A `409 {"error": "no_stepup_factor"}` means the account has neither a passkey nor TOTP and must enrol one before sensitive operations become reachable.
3. **MFA/Biometric Challenge:**
   - The dialog triggers a WebAuthn prompt utilizing platform authenticators (TouchID, FaceID, Windows Hello) with **`userVerification: "required"`** to confirm biometrics/PIN, OR requests the user's active TOTP token.
   - Recovery codes are **not** accepted here. They are a login bypass, so honouring one would let a stolen code authorise the very operations this gate protects — including regenerating the code batch itself.
4. **Step-up Assertion:** Upon user confirmation, the frontend sends this assertion to `POST /api/v1/auth/stepup/verify`. A `403 {"error": "user_verification_required"}` means the authenticator only proved presence (a security key tapped without a PIN); the remedy is a PIN/biometric-capable device, or TOTP.
5. **Short-Lived Authorization:** On success, the frontend receives a temporary **Step-up ACR token** carrying `https://ref.hatef.ir/acr/stepup`. Honor the returned expiry and the earlier session deadline; never assume a fixed remaining lifetime.
6. **Execution:** Send the in-memory grant once in `X-Step-Up-Auth`, alongside the bound cookie, DPoP proof and `X-Portal-Session`. `Authorization` is not used for portal cookies. Registration spends the grant at options generation, then completes with its bound pending state. Cancelled/uncertain operations discard the grant and reconcile only non-secret state where safe.
7. **Dialog:** A class-styled native `<dialog>` provides a semantic heading/description, contained keyboard focus, Escape/Cancel, initiating-focus return and announced feedback. It does not introduce inline-style CSP exceptions. WebAuthn UV is offered first; existing TOTP is offered only when advertised. Recovery codes cannot satisfy step-up.
8. **Single use:** A used grant cannot be replayed or moved to another session/key. A pre-handler nonce challenge is the only automatic retry, because it consumed neither grant nor handler state. Transport uncertainty instead requires a new explicit action and fresh verification.

### 5.4 Account-Harvesting Resistant Login UX & Discoverable Credentials

To completely prevent user-enumeration (account harvesting) through timing side-channels, the platform implements two distinct defenses:

- **Discoverable Credentials (Usernameless Passkeys) as Primary:** The primary login route relies on discoverable credentials. The user is prompted for biometrics directly without inputting an email first (`navigator.credentials.get` is called with an empty `allowCredentials` list). The authenticator resolves the user's registered identity locally and securely transfers the associated username/ID within the signed cryptographic assertion, completely eliminating the possibility of account harvesting.
- **Legacy user-named fallback:** The backend retains decoy options and a timing floor for legacy clients, but the portal does not offer this flow. Browser credential lookup can behave differently for dummy IDs, so a uniform server response alone does not eliminate that client-side enumeration risk. The live portal starts discoverable ceremonies without naming an account.

The admin UI follows [API section 1.7](api-design.md#17-admin--moderation-api): exact-email account search and Task 7.6 legal attribution are body-only. Super Admin receives content-free verification only; Support receives no email, roles or hold details. DPO attribution grants do not imply permission to browse live account profiles.

### 5.5 One-Time Recovery Viewer

Use `remaining`/`low` status for existing batches, never an old-plaintext GET. Generation explicitly warns that all prior codes become invalid and requires fresh step-up. Returned codes live only in the security view's memory. Copy and plaintext Download are deliberate actions with success/failure feedback and a private-storage warning; the filename contains no account identifier and temporary object URLs are promptly revoked. There is no auto-copy, auto-download, email or print workflow, and CSP is not weakened for exports.

Clear the batch on Done, navigation/unmount, pagehide/history transitions, hiding the private view, local logout, detected session loss or five minutes after generation, bounded by absolute session expiry. Resume requires a fresh authority check; there is no background keepalive polling. Cancellation/navigation discards late responses. A lost generation response is an uncertain replacement: explain that old codes may already be invalid and require a new explicit generation with fresh step-up. Do not retrieve a cached response or silently regenerate.

Clearing component state cannot erase a user's clipboard/download, browser snapshots or guarantee memory zeroization. The UI must not promise those effects.

### 5.6 Account Deletion and Reclaim

`/dashboard/privacy` uses the protected shell and server `deletion_enabled` capability. The user acknowledges the consequences and explicitly requests fresh UV-capable passkey verification. The shared dialog's deletion mode never offers TOTP, including in error advice. Presence-only or unavailable authenticators do not authorize deletion; generic TOTP support remains unchanged elsewhere.

Explain immediate identity-platform deactivation, the original 30-day recovery window, primary/configured-backup notification, reserved identifiers and eventual Class A deletion. Explain separately retained pseudonymized records, lawful preservation, backup rotation and downstream-service limits without exposing subject-specific holds or promising complete erasure at day 30. Acknowledgement is not consent to retention or a waiver of rights.

The provider owns confirmed/unconfirmed terminal screens outside authenticated children. Confirmed `204` clears private state and emits one neutral invalidation, without another logout request or deleting the shared browser signing key. Post-send cancellation, dropped responses and ambiguous failures remain unconfirmed: no automatic replay, cached success or inference from a subsequent `401`. The screen says notification is queued, not delivered; the email carries the authoritative deadline.

`/recover-account` is an anonymous, noindex auth-card page, separate from the dashboard and backup-code recovery. Capture one canonical 43-character fragment token, scrub the URL immediately, and retain private memory for at most five minutes. Explicit user action fetches the single server-selected UV/TOTP factor. TOTP is one six-digit text field with leading-zero/paste support. Tokens never enter server props, browser persistence, telemetry or broadcasts; loading a link sends no recovery request.

Backgrounding aborts work and clears codes/proofs/challenges. The bounded token can survive a brief authenticator-app switch, followed by explicit fresh options. Pagehide, unmount, expiry and completion clear it. Hash replacement fails closed rather than silently switching authority; reopen the email as a new document after cleanup. Invalid tokens/factors remain opaque, uncertain completion is not replayed, and confirmed recovery offers normal login without issuing a session.

## 6. Portal Validation Boundary

`web:test-portal-browser` runs `.github/scripts/web-portal.browser.mjs` against production Next.js, two real Go API processes and isolated PostgreSQL/Redis/JetStream through local HTTPS ingress. Deletion/reclaim gets a separate run-owned stack and authenticated TLS SMTP sink, avoiding exhaustion of production subnet limits by unrelated scenarios instead of raising those limits. Test-only build-tagged fixtures supply random accounts and virtual-authenticator credentials; there is no production bootstrap endpoint or magic account. `.github/scripts/web-csp.browser.mjs` remains the independent image/CSP regression suite.

The suite covers login/profile/security/sessions plus UV-only deletion, durable SMTP enqueue/restart/retry/cleanup, cross-session revocation, lost responses/post-send aborts, keyless UV/TOTP reclaim across replicas, bounded token cleanup and used/malformed links. It also covers strict CSP, focus/announcements, six no-JavaScript routes and eighteen light/dark mobile/desktop viewports. One-time JSON is observed with bounded capture at the actual upstream connection, not replayed requests or cached browser bodies. Artifacts contain masked screenshots and metadata-only evidence, not tokens, mail bodies, browser traces or plaintext batches. Unobserved native hidden-tab/bfcache behavior remains a manual gate.

Repository test execution is not deployment approval. Manual assistive-technology/platform-authenticator review, real deployed HTTPS ingress/log-redaction verification and compatible downstream lifecycle consumers remain release gates unless separately evidenced. Follow [portal cutover](devops-operations.md#user-portal-cutover-task-73); do not mark task acceptance or operator gates complete solely because tests exist.

Task 7.6 extends the existing `web:test-admin-browser` gate, not an independent authentication/browser harness or new CI job. Required evidence includes the **real** signer plus `admin-legal --operation=lookup-probe` before/after synthetic-account deletion, two API replicas, fixture omission/mismatch, DPO success and other seeded-role denial, strict contracts/string precision, independent/replayed/released holds, fresh verification per page, opt-in fields, actual audit-failure rollback and committed-but-lost write responses without retransmission. Exercise privacy clearing and late replies, direct routes/revoked capability, no-JavaScript shells, desktop/320px, both palettes, focus/keyboard/dialog escape and strict CSP. Mask legal narrative/result regions explicitly in artifacts; retain only sanitized scenarios/status/counts and masked screenshots, not raw traces or storage snapshots. These are required gates, **not recorded passing results**. Manual screen-reader, physical-authenticator, native zoom, hidden-tab/bfcache and deployed-ingress checks remain unfinished until separately observed; no Task 5.3/5.4/5.5 status or production approval is implied.
