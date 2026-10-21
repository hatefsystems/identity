# Hatef Identity Platform - Frontend Pages Structure

This document outlines the routing architecture for the Next.js frontend application within the `hatefsystems/identity` monorepo. The application utilizes the **Next.js App Router (`app/` directory)** and relies on **shadcn/ui** for its component system.

## Route Groups

The routing is logically divided using Next.js Route Groups (e.g., `(auth)`, `(dashboard)`) to share layouts without affecting the URL path.

---

## 1. Authentication & Public Pages: `(auth)`

These pages are accessible to unauthenticated users and define the entry points into the ecosystem. Task 7.2 implements six **UI-only** screens; their production submission actions are deliberately disabled. Recovery and email-verification screens remain planned.

- `/login` : Passkey-first login screen with an email/password alternative and links to registration and password reset.
- `/login/webauthn` : Dedicated usernameless passkey screen explaining hardware keys, device PINs, and platform biometrics. It does not start a WebAuthn ceremony yet.
- `/login/recovery` : Restricted recovery flow for a user who has lost every normal MFA/WebAuthn factor. The UI first submits the email to `POST /api/v1/auth/recovery/start`, retains the opaque `transaction_id` only in memory, and submits it with the backup code to `POST /api/v1/auth/mfa/verify-recovery-code`. The uniform start response must not be interpreted as proof that an account exists. Success creates a ten-minute `recovery_enrollment` session whose only authority is enrolling one UV-required replacement passkey. The UI completes `POST /api/v1/auth/enrollment/webauthn/register/generate-options` and `/verify` in that same session, then returns the user to normal login; it must never render the dashboard or normal security settings under this restricted cookie. A `409 {"error":"enrollment_already_used"}` means the one permitted enrollment was already claimed and the user must restart recovery.
- `/register` : Email, new password, and password-confirmation form. Account creation is not connected.
- `/verify-totp` : Neutral six-digit authenticator-code form. This is not an active login challenge, enrollment confirmation, or Step-up session.
- `/forgot-password` : Primary-email reset-link request form with an account-enumeration-resistant acknowledgement presentation. Backup Email and Verified Phone (SMS) recovery choices remain planned, outside Task 7.2.
- `/reset-password` : New-password and confirmation form, with invalid/expired-link presentations. Real reset-link validation and password changes are not connected.
- `/verify-email` : Email verification landing page.

### Task 7.2 UI Boundary

- The six screens use the existing shadcn components exported by `@hatef/ui`, an English shared auth layout, and application-local field/status compositions. The light default, system font, and existing dark tokens are preserved; Tailwind explicitly retains the `dark` class so production builds do not remove its palette variables. There is no new theme switcher or localization framework.
- `apps/web/app/(auth)/_components/screens.tsx` is the client boundary. Its public screens supply **no submission handler**. Each form shows "This form is not connected yet. Do not enter real credentials." and renders its submission button disabled in the initial HTML. Navigation, password visibility, and local blur validation remain usable. POST semantics and guarded submit handlers prevent credentials from becoming URL query strings; disabled buttons also prevent native submission before hydration or with JavaScript disabled.
- Loading, success, cancellation, unsupported-passkey, rate-limit, and reset-link presentations are exercised through test-only handlers/props on the underlying form components. No public fixture route, magic credential, query parameter, or environment flag can simulate authentication or reset delivery. Reset forms default to an unverified link state; tests must explicitly provide a ready state and a handler to enable submission.
- Form values stay in component state, not URLs, cookies, browser storage, telemetry, or logs. The UI neither calls an API nor invokes `navigator.credentials`, manages a session, follows OAuth continuation parameters, or redirects to a dashboard. Generic reset acknowledgements and credential errors do not disclose account existence.
- Fields have visible labels, stable help/error associations, appropriate autocomplete, keyboard-operable password toggles, and at least 44px control targets. Local errors appear on blur; a test-enabled invalid submission focuses the first invalid field. Submission feedback is announced, duplicate submissions are blocked, and successful completion clears form values. A single text input preserves leading zeroes in TOTP codes, accepts whole-code paste, and requires exactly six ASCII digits without silently normalizing whitespace or non-ASCII digits. It never auto-submits or offers to resend an authenticator code.
- Password checks intentionally cover presence and, for new passwords, matching confirmation only. Passwords are not trimmed, paste is not blocked, and the UI does not invent a length/complexity policy or claim backend enforcement. Account signup, password login/reset, email verification, browser-session/DPoP integration, and authoritative password policy require separate implementation. Existing backend TOTP enrollment and Step-up endpoints must not be repurposed as public login verification.
- Auth HTML remains dynamically rendered and private/no-store under Task 7.1's strict nonce CSP. Styling uses classes and local resources only; the CSP, root rendering boundary, and deployment model are unchanged. Automated unit and production-browser checks cover these UI contracts, including both palettes, keyboard focus, contrast, narrow/short viewport reflow, native TOTP paste, and JavaScript-disabled submission safety. Desktop/mobile screenshots were visually inspected. Manual screen-reader review has not been performed; these checks are not a claim of full assistive-technology or WCAG certification.

---

## 2. SSO Authorization: `/oauth2`

These routes handle the OpenID Connect (OIDC) Authorization Code flow when third-party applications or other Hatef services request authentication.

- `/oauth2/authorize` : The Consent Screen. Displays "Application X wants to access your profile." If the user is not logged in, they are redirected to `/login` and then back here.
- `/oauth2/error` : Displayed if the authorization request is invalid or rejected.

---

## 3. User Dashboard & Privacy Settings: `(dashboard)`

Protected routes. Requires a valid user session. This is the central hub for users to manage their Hatef identity.

- `/dashboard` : Overview page. Shows a summary of account status, recent logins, and security health.
- `/dashboard/profile` : Manage personal information (Name, Avatar, Contact info).
- `/dashboard/security` : The core security center.
  - Change Password.
  - Setup/Manage **Multi-Factor Authentication (TOTP)**. Starting setup requires a fresh Step-up grant. Keep the returned `enrollment_id` in memory and submit it with the code from the same authenticated session; completion does not request a second grant. There is no general-purpose `/auth/mfa/verify-code` endpoint for probing whether an enabled TOTP is valid.
  - Setup/Manage **WebAuthn Passkeys** (Register new YubiKey or Laptop Fingerprint). Ordinary registration consumes a fresh Step-up grant when options are generated; attestation must finish in the same session and does not request a second grant. Deleting the final passkey returns `409 {"error":"last_credential"}` even when TOTP is enabled because passkeys are the current browser login credential.
  - Setup/Manage **Backup Recovery Methods**:
    - Add/Verify **Phone Number** (Used for SMS Password Reset and Anti-Abuse verification for Hatef Mail). Sending a code consumes a fresh Step-up grant and returns a `verification_id`; verification submits only that ID plus the code from the same session, without accepting a replacement phone value or another grant.
    - Add/Verify **Alternative Email** (Backup email for password recovery).
    - Generate/View **Recovery Codes** (Backup Codes) for emergency account access.
  - Disabling TOTP returns `409 {"error":"last_factor"}` if no passkey remains. Treat both factor-removal conflicts as actionable security guidance rather than generic failures.
- `/dashboard/sessions` : View active sessions across devices (e.g., "Windows PC - Chrome", "iPhone - Safari"). Includes a button to "Revoke Session" remotely.
- `/dashboard/privacy` : GDPR & Data Privacy center.
  - View privacy policy consents.
  - Download account data archive (Data Portability).
  - **Delete Account**: Triggers the "Right to be Forgotten" soft-delete process. Requires re-authentication (WebAuthn/MFA) to confirm.

---

## 4. Admin & Moderation Panel: `(admin)`

Protected by strict RBAC. Accessible only to users with `Support`, `Moderator`, `Admin`, or `DPO` roles.

- `/admin` : Admin overview dashboard (Metrics, active user counts, recent alerts).
- `/admin/users` : Search and list user accounts.
- `/admin/users/[id]` : Detailed view of a specific user.
  - Action: Trigger Password Reset Email (Support role).
  - Action: Suspend Account.
  - Action: Ban Account.
  - _Note: "Delete User" button does not exist by design (Zero Trust philosophy)._
- `/admin/roles` : Future delegated-role workflow; no HTTP assignment endpoint in Task 5.3. Use the controlled operator procedure.
- `/admin/audit-logs` : (DPO only) View system audit logs (PostgreSQL in the MVP) showing which admin performed what action. Enforces default date range selection (defaulting to the past 24–48 hours) and paginated loading controls to protect client and network performance.

---

## Layout Structure Details

- `app/layout.tsx`: Request-time root document for fresh CSP nonces. Theme/Auth Context providers and DPoP key initialization remain planned.
- `app/(auth)/layout.tsx`: Shared brand link, main landmark, and fluid-width card layout. Minimum viewport height and normal vertical scrolling keep forms usable on narrow or short screens.
- `app/(dashboard)/layout.tsx`: Includes the main authenticated navigation sidebar (Profile, Security, Privacy, Sessions) and a top header.
- `app/(admin)/layout.tsx`: A distinct layout (often with different color schemes or warning banners) to clearly indicate to the user that they are in an elevated, sensitive environment.

---

## 5. Security Hardening & Session Isolation (Next.js & Browser Client)

To maintain absolute client-side security and resist advanced threat vectors (such as XSS, session hijacking, or credential leakage), the Next.js frontend implements several high-performance defensive controls:

### 5.1 Cookie-Based Session Protection

- **`__Host-` Secure Cookies:** All session tokens are delivered from the Go IdP using the **`__Host-`** cookie prefix. The Next.js middleware and client are configured so that these cookies are strictly:
  - Bound to the exact host domain (no subdomains).
  - Encrypted in transit via forced HTTPS (`Secure` flag).
  - Hidden from any JavaScript access (`HttpOnly` flag).
  - Kept in strict local context (`SameSite=Strict` flag) to completely neutralize Cross-Site Request Forgery (CSRF).

### 5.2 Client-Side Sender-Constrained Tokens (DPoP) & Strict-Nonce CSP

The browser DPoP key generation and signing controls below remain planned; Task 7.1 implements the portal's CSP, not these identity flows.

- **Asymmetric WebCrypto Binding:** Upon initial load, `app/layout.tsx` triggers the generation of an ephemeral, cryptographically secure asymmetric keypair (ECDSA P-256) inside the browser via the standard **WebCrypto API**.
- **IndexedDB Isolation:** The private key is persisted securely within the browser's origin-isolated `IndexedDB` with the `extractable: false` flag so that it cannot be read or stolen via XSS.
- **DPoP Signatures:** For every outgoing fetch request to `/api/v1/*`, the frontend dynamically creates and signs a local proof-of-possession JWT (carrying target URI, HTTP method, and a server-provided cryptographic nonce), attaching it in the `DPoP` header.
- **Strict-Nonce CSP (Task 7.1):** `apps/web/proxy.ts`, Next.js 16's middleware successor, generates a fresh 32-byte cryptographic nonce for each covered request. It replaces caller-supplied nonce/CSP values, forwards the policy and `x-nonce` to the renderer, and returns the same enforcing `Content-Security-Policy` header. Next.js uses the request policy to nonce its bootstrap and Flight scripts. This mitigates script/style injection; it does not replace safe rendering, authorization, or other XSS defenses. This task does not modify Go response policies.
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

To protect highly critical administrative or identity operations (such as Password Change, TOTP MFA disablement, Backup contact removal, or Account Deletion), the frontend enforces an inline Step-up verification pattern:

1. **Trigger Condition:** The user clicks on any sensitive action button in the Dashboard (e.g., _Remove Backup Phone_ or _Delete Account_). Alternatively, the flow is entered reactively: a sensitive request sent without a grant is answered with `403 {"error": "insufficient_user_authentication", "acr_values": "https://ref.hatef.ir/acr/stepup"}`, which is the signal to open the overlay. Note this is deliberately **not** a `401` — the session is still valid, so a `401` would send the user through a full re-login instead of this inline flow.
2. **Step-up Overlay:** Instead of directing to a separate page, a secure, modal dialog (overlay) interrupts the flow. `POST /api/v1/auth/stepup/challenge` reports which factors the account can present (`methods`) plus the WebAuthn assertion options when a passkey is enrolled. Keep the returned challenge state in memory and complete it from the same authenticated session: the server binds the challenge to its exact user, session, and Step-up flow, and a mismatched session cannot consume the legitimate challenge. A `409 {"error": "no_stepup_factor"}` means the account has neither a passkey nor TOTP and must enrol one before sensitive operations become reachable.
3. **MFA/Biometric Challenge:**
   - The dialog triggers a WebAuthn prompt utilizing platform authenticators (TouchID, FaceID, Windows Hello) with **`userVerification: "required"`** to confirm biometrics/PIN, OR requests the user's active TOTP token.
   - Recovery codes are **not** accepted here. They are a login bypass, so honouring one would let a stolen code authorise the very operations this gate protects — including regenerating the code batch itself.
4. **Step-up Assertion:** Upon user confirmation, the frontend sends this assertion to `POST /api/v1/auth/stepup/verify`. A `403 {"error": "user_verification_required"}` means the authenticator only proved presence (a security key tapped without a PIN); the remedy is a PIN/biometric-capable device, or TOTP.
5. **Short-Lived Authorization:** On success, the frontend receives a temporary **Step-up ACR token** (valid for 3-5 minutes) carrying the ACR claim `https://ref.hatef.ir/acr/stepup`.
6. **Execution:** The frontend automatically executes the original sensitive request, embedding the Step-up ACR token in the **`X-Step-Up-Auth`** header (not `Authorization`, which continues to carry the session or access token) along with the required DPoP proof. Once executed, the state is cleared.
7. **Single Use:** A grant authorises exactly one request. It is consumed on presentation, so a retry — including a retry after a client-side validation failure — requires a fresh challenge. It is also bound to the session that earned it, so it cannot be carried to another tab, device, or session.

### 5.4 Account-Harvesting Resistant Login UX & Discoverable Credentials

To completely prevent user-enumeration (account harvesting) through timing side-channels, the platform implements two distinct defenses:

- **Discoverable Credentials (Usernameless Passkeys) as Primary:** The primary login route relies on discoverable credentials. The user is prompted for biometrics directly without inputting an email first (`navigator.credentials.get` is called with an empty `allowCredentials` list). The authenticator resolves the user's registered identity locally and securely transfers the associated username/ID within the signed cryptographic assertion, completely eliminating the possibility of account harvesting.
- **Mock Challenges for User-Named Fallbacks:** For legacy user-named credential flows, if an unregistered username/email is entered, the server returns a fully formed mock challenge. The frontend initiates `navigator.credentials.get` using this dummy credential ID, prompting the standard OS biometric dialog to preserve UX consistency. The backend introduces exact timing delays to match a successful credentials lookup, though discoverable credentials remain the recommended path due to browser-level key-lookup speed variances on local devices. (Note: Because modern browsers throw instant client-side exceptions when an `allowCredentials` list contains only dummy IDs, a client-side behavioral side-channel remains on user-named credentials. Therefore, discoverable credentials are the only fully secure WebAuthn authentication route).

The Admin UI remains future work. Follow [API section 1.7](api-design.md#17-admin--moderation-api): body-based exact-email search and legal attribution; no identity query strings. Super Admin receives content-free verification only; Support never receives email, roles or hold details.
