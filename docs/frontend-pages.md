# Hatef Identity Platform - Frontend Pages Structure

This document outlines the routing architecture for the Next.js frontend application within the `hatefsystems/identity` monorepo. The application utilizes the **Next.js App Router (`app/` directory)** and relies on **shadcn/ui** for its component system.

## Route Groups
The routing is logically divided using Next.js Route Groups (e.g., `(auth)`, `(dashboard)`) to share layouts without affecting the URL path.

---

## 1. Authentication & Public Pages: `(auth)`
These pages are accessible to unauthenticated users and handle the entry points into the ecosystem.

- `/login` : Primary login page (Username/Password).
- `/login/webauthn` : Passwordless login flow using hardware keys or platform biometrics (FaceID/TouchID).
- `/login/recovery` : Form to enter a backup recovery code if the user has lost access to their primary MFA/WebAuthn device.
- `/register` : Account creation form.
- `/forgot-password` : Request a password reset. Users can choose to receive the recovery OTP/Link via Primary Email, Backup Email, or Verified Phone (SMS).
- `/reset-password` : The page users land on from the email link to set a new password.
- `/verify-email` : Email verification landing page.

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
  - Setup/Manage **Multi-Factor Authentication (TOTP)**.
  - Setup/Manage **WebAuthn Passkeys** (Register new YubiKey or Laptop Fingerprint).
  - Setup/Manage **Backup Recovery Methods**:
    - Add/Verify **Phone Number** (Used for SMS Password Reset and Anti-Abuse verification for Hatef Mail).
    - Add/Verify **Alternative Email** (Backup email for password recovery).
    - Generate/View **Recovery Codes** (Backup Codes) for emergency account access.
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
  - *Note: "Delete User" button does not exist by design (Zero Trust philosophy).*
- `/admin/roles` : (Super Admin Only) Assign platform roles to specific users.
- `/admin/audit-logs` : (DPO / Super Admin) View system audit logs (fetched from ClickHouse) showing which admin performed what action. Enforces default date range selection (defaulting to the past 24–48 hours) and paginated loading controls to protect client and network performance.

---

## Layout Structure Details

- `app/layout.tsx`: Root layout, includes global providers (Theme, Auth Context, DPoP key initialization).
- `app/(auth)/layout.tsx`: Minimalistic layout, usually a centered card design to focus entirely on the login/register action.
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
- **Asymmetric WebCrypto Binding:** Upon initial load, `app/layout.tsx` triggers the generation of an ephemeral, cryptographically secure asymmetric keypair (ECDSA P-256) inside the browser via the standard **WebCrypto API**.
- **IndexedDB Isolation:** The private key is persisted securely within the browser's origin-isolated `IndexedDB` with the `extractable: false` flag so that it cannot be read or stolen via XSS.
- **DPoP Signatures:** For every outgoing fetch request to `/api/v1/*`, the frontend dynamically creates and signs a local proof-of-possession JWT (carrying target URI, HTTP method, and a server-provided cryptographic nonce), attaching it in the `DPoP` header.
- **Strict-Nonce CSP Enforcement:** To guarantee that the IndexedDB origin-isolation cannot be circumvented via sophisticated cross-site scripting (XSS), the Next.js layouts and Go backend routers inject a rigid Strict-Nonce Content Security Policy (CSP) header:
  `Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-[random]' 'strict-dynamic'; object-src 'none'; base-uri 'self'; require-trusted-types-for 'script';`
  This prevents the execution of any untrusted inline or third-party scripts.

### 5.3 UX Step-up Authentication Trigger Flow
To protect highly critical administrative or identity operations (such as Password Change, TOTP MFA disablement, Backup contact removal, or Account Deletion), the frontend enforces an inline Step-up verification pattern:
1. **Trigger Condition:** The user clicks on any sensitive action button in the Dashboard (e.g., *Remove Backup Phone* or *Delete Account*).
2. **Step-up Overlay:** Instead of directing to a separate page, a secure, modal dialog (overlay) interrupts the flow.
3. **MFA/Biometric Challenge:**
   - The dialog triggers a WebAuthn prompt utilizing platform authenticators (TouchID, FaceID, Windows Hello) with **`userVerification: "required"`** to confirm biometrics/PIN, OR requests the user's active TOTP token.
4. **Step-up Assertion:** Upon user confirmation, the frontend sends this assertion to the Go backend step-up verify API.
5. **Short-Lived Authorization:** On success, the frontend receives a temporary **Step-up ACR token** (valid for 3-5 minutes).
6. **Execution:** The frontend automatically executes the original sensitive request, embedding the Step-up ACR token in the authorization header along with the required DPoP proof. Once executed, the state is cleared.

### 5.4 Account-Harvesting Resistant Login UX & Discoverable Credentials
To completely prevent user-enumeration (account harvesting) through timing side-channels, the platform implements two distinct defenses:
- **Discoverable Credentials (Usernameless Passkeys) as Primary:** The primary login route relies on discoverable credentials. The user is prompted for biometrics directly without inputting an email first (`navigator.credentials.get` is called with an empty `allowCredentials` list). The authenticator resolves the user's registered identity locally and securely transfers the associated username/ID within the signed cryptographic assertion, completely eliminating the possibility of account harvesting.
- **Mock Challenges for User-Named Fallbacks:** For legacy user-named credential flows, if an unregistered username/email is entered, the server returns a fully formed mock challenge. The frontend initiates `navigator.credentials.get` using this dummy credential ID, prompting the standard OS biometric dialog to preserve UX consistency. The backend introduces exact timing delays to match a successful credentials lookup, though discoverable credentials remain the recommended path due to browser-level key-lookup speed variances on local devices. (Note: Because modern browsers throw instant client-side exceptions when an `allowCredentials` list contains only dummy IDs, a client-side behavioral side-channel remains on user-named credentials. Therefore, discoverable credentials are the only fully secure WebAuthn authentication route).
