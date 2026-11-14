# Registration Contract (T01)

This is the authoritative registration contract for the existing service, client,
form, public `/register` page and `/api/v1/auth/register` prefix. It separates
repository behavior from the username increment and the deferred final target.
It is not deployed acceptance, policy approval or authorization to execute the
[remaining backlog](../.kilo/plans/registration-single-contract-tasks.md).

## Delivery Boundaries

| Layer | Contract and limits |
|---|---|
| Existing conditional flow | Email-link ownership, then Iranian mobile SMS ownership, then a resident UV-required passkey. Completion returns `next: "login"`; discoverable login is separate. Registration and SMS default disabled. |
| Username increment | Add one required username to that same flow, explicit advisory username validation, atomic reservation, and an authenticated read of the saved username or truthful absence. No contact choice, password, private-data editor or six-stage shell is activated by this increment. |
| Deferred final target | Required private names, date-only birthday, explicit gender, username, one selected verified contact, selected primary credentials, location and separate legal acceptances; six stages and future fresh-commit session issuance described below. These are specifications, not implemented-task or test-pass claims. |

Do not add a second registration implementation or versioned registration route.
Do not alter generic BlindIndex/email normalization, signed history, audit/lifecycle
formats, existing recovery/deletion systems or unrelated authentication machinery.
No SQL Server access, dataset redistribution, production install, data repair,
destructive rollback or commit is authorized by this contract. Dependent backlog
tasks remain independently scoped; documenting them does not complete them.

## Existing Flow and Username Increment

The pre-increment baseline was inspected in `internal/server/registration.go` and
`internal/registration/{service,store}.go` under `apps/identity-api`, and in the
existing browser registration client. It accepted `/start` with
`{email,phone}`; the coordinated username increment requires
`{email,phone,username}` and adds `username_display` to the start response.
See [exact current-flow requests](api-design.md#15-new-account-registration) and
[client handling](client-integration.md#14-conditional-new-account-registration).
Neither repository inspection nor these enabled-feature contracts prove live
installation, runtime tests, real delivery or physical-authenticator acceptance.

- `POST /validate` accepts exactly
  `{stage: "username", registration: {username}}` and returns
  `{username_display,available}`. It uses the existing public Origin/DPoP boundary
  and bounded admission; it creates no attempt, proof, credential or reservation.
  Availability is advisory and reveals no owner or account status.
- `/start` freezes NFC display, security name and admitted policy identity inside
  encrypted pending details. No username is reserved until account creation commits.
  Options and a new final commit revalidate that frozen identity against active
  policy. `username_policy_changed` requires explicit restart, never silent folding
  under a different policy or an extended deadline.
- `invalid_username` (400) and `username_unavailable` (409) carry
  `field_errors: {username: <same code>}`. Other registration conflicts remain
  sanitized; dependency/stale-authority failure is unavailability, not "available"
  or "not found". Unique reservation, account, credential, creation intent and
  receipt must commit together; a losing equivalent spelling cannot attach its
  credential to the winner or leave partial ownership.
- Follow-up bodies remain unchanged. Email verification uses
  `{attempt_id,token}` with the original JKT, not the capability. Keep
  `/register/verify-email#attempt_id=...&token=...`, immediate fragment scrubbing and
  explicit verification until the separately authorized email-code transition.
  SMS verification still follows email verification, not contact selection.
- `GET /api/v1/users/me/username` uses normal live cookie/DPoP/session admission and
  returns `{username: {display}}` or `{username: null}`. It is not a claim or rename
  boundary. Do not substitute email or cosmetic `display_name` for absence.
- Original validity remains 15 minutes for pending state, 10 minutes for email
  proof, at most 5 minutes for passkey challenge, and 1 hour for receipts; inner
  proof/challenge deadlines are also bounded by the existing attempt/proof limits.
  Explicit resend does not reset attempt expiry or budgets. Same-authority receipt
  replay and `/result` reconcile outcomes, never recreate accounts or issue sessions.
  Lost capability/browser-key authority requires restart or ordinary login.

Keep strict field/UTF-8 admission, exact Origin, public DPoP nonce/replay and
JKT/capability binding, cookie omission for signup, no-store/no-referrer and stable
redacted failures. Do not put contacts, usernames, proofs, keys or private collision
reports into logs, URLs, analytics, cross-tab messages or browser artifacts.
Provider/relay acceptance is not delivery. Native cancellation and locale changes
are not permission to replay enrollment, resend, rebootstrap or extend authority.

## Username Namespace

The confirmed policy supersedes the backlog's historical T03 `7..40`, Latin-mode
and ZWNJ wording. One environment-configured full-match Go regex owns syntax, not
a second hard-coded length/spelling validator or JavaScript/HTML `pattern`.
The initial policy candidate admits the 32 Persian letters, Alef with madda,
standalone Hamza, Waw/Yeh with Hamza, and only Arabic Yeh/Kaf keyboard aliases,
with nonempty letter sequences separated by single internal dots. No business
length limit was approved. Technical ceilings are 1024 UTF-8 bytes for input and
each normalized representation, 4096 regex-source bytes and 16 KiB for the artifact.

Validate UTF-8/bounds, compute `display = NFC(input)`, full-match admission against
display, then derive a separate `security_name` with exactly these scalar folds:

| Input | Security scalar |
|---|---|
| Arabic Yeh `U+064A` | Persian Yeh `U+06CC` |
| Arabic Kaf `U+0643` | Persian Kaf `U+06A9` |
| Waw with Hamza `U+0624` | Waw `U+0648` |
| Yeh with Hamza `U+0626` | Persian Yeh `U+06CC` |

Display receives no security folds. NFC-supported decompositions may compose into
admitted letters; remaining combining/vowel marks, numeral/mixed scripts, controls,
bidi marks, whitespace, ZWNJ/ZWJ, presentation forms and unsupported aliases are
rejected, not stripped. Dots are unchanged; leading/trailing/double dots and
underscores fail. Alef with madda remains distinct from Alef; standalone Hamza and
sound-alike letters remain significant. No trim, NFKC, transliteration, general
confusable skeleton, deletion or spelling-combination enumeration is allowed.

The one database namespace uses:

```text
HMAC-SHA256(username_lookup_key,
            "hatef.identity.username.lookup" || NUL || UTF8(security_name))
```

Use a dedicated secret, not email/phone/ledger pepper. Policy/key IDs are provenance,
not HMAC-message or uniqueness partitions. Protected details bind account UUID,
username purpose, NFC display, security name and policy provenance/activation epoch.
The tuple is all absent or all present. Existing NULL accounts remain unclaimed; no backfill is
derived from email/display name and no legacy normalization version is invented.

One unconditional unique key reserves the whole equivalence class across every
surviving account, including suspended, banned, pending and soft-deleted rows.
Holds, deletion requests and reclamation do not release it; only committed physical
account deletion does, and purge rollback retains it. Populated usernames cannot
be cleared or renamed, even to an equivalent display spelling. Ordinary SQL must
also respect immutability; any reviewed maintenance exception remains disabled
without proven privilege separation and cannot alter display or ownership.

All assignment/availability/lookup operations check database-authoritative active
policy/key identity and activation epoch in their transaction and hold a shared
policy guard through the deciding operation/commit. Lock order is policy guard, account/attempt locks,
then separate deciding reads/writes. Hard deletion and maintenance share that
coordination. Startup/readiness alone cannot fence stale writers. Lookup uses the
same bounded security normalizer without retroactively applying a narrowed
new-assignment regex, then applies account/login policy separately.

The production regex, artifact and system/support reserved-name set require owner
review. This document supplies no reserved names, system accounts, installed policy
or activation approval. A new ID, structurally valid artifact or clean scan does
not approve additional mergers. Installation/cutover, complete real-data preflight,
no-split evolution, writer drain and rollback gates are in
[operations](devops-operations.md#username-policy-and-preflight-gates).

## Deferred Final Fields

| Field | Required final meaning |
|---|---|
| `given_name`, `family_name` | Private Persian-script names under T02; independent from optional public/cosmetic `display_name`. |
| `birthday` | `{calendar: "gregorian" \| "jalali", date: "YYYY-MM-DD"}`. T05 normalizes permitted date digits and derives an atomic equivalent Gregorian/Jalali date-only pair with one pinned/reviewed converter. Gregorian range is `1900-01-01` through today's server-side Tehran civil date. No timestamp or independently trusted pair. |
| `gender` | Exactly `female` or `male`, explicitly selected; no UI default or invented legacy value. |
| `username` | Chosen spelling under the namespace above; required for new accounts, immutable after assignment. |
| `contact` | Exactly `{type: "email" \| "mobile", value: string}`. Verify the exact server-canonical selected destination. Unselected contact is absent, never a fabricated mailbox or empty-email digest. |
| `authentication_method` | Explicit `passkey`, `password` or `both`, with corresponding primary credentials required. No code-only account creation. Password bytes remain exact, including spaces; confirmation is client-only. T15 owns creation strength and bounded hashing. |
| `location` | `{country: "IR", province_id: string, locality_id?: string}`; source-preserving opaque IDs with correct ancestry. No fabricated dataset, translation or source labels; T07-T09 and data rights remain separate. |
| `legal_acceptance` | Separate `terms` and `privacy` entries, each `{version, accepted: true}`, referring to approved server-configured documents. Acceptance time is server-owned; document approval is not supplied here. |

Six stages, in order: names; personal information (birthday/gender); username;
contact verification; authentication method; location/final review. Back navigation,
legal links and language/calendar changes preserve ordinary progress and original
meaning without replaying API/native work or extending deadlines. Validate the
complete candidate before native enrollment; cancellation never silently downgrades
`both`. These frontend guarantees are target behavior, not current acceptance.

## Deferred Final Requests

Let `A = {attempt_id,capability}` and `F` contain every final field except
`contact`, which is canonicalized and attempt-bound. Operations below are POSTs
under the existing registration prefix, not a second route version. Only username
validation above belongs to the increment. Final validation stage selectors are
`names`, `personal_information`, `username` and `full_review`; these deferred
selectors do not imply currently mounted branches.

| Operation | Final request / meaning |
|---|---|
| `/validate` | `{stage,registration,password?}`. Exact subsets: `names` (`given_name`,`family_name`), `personal_information` (`birthday`,`gender`), `username` (`username`), or `full_review` (all final fields, with password only for password/both). Read-only normalized results/field errors; no proof, reservation or credential creation. |
| `/start` | `{contact}`. Explicit selected-channel issuance starts a bounded attempt and returns authority, canonical contact, original deadline and bounded code/submission information, never delivery evidence. This is not the increment's `{email,phone,username}` body. |
| `/email/resend`, `/phone/send` | `A`. Explicit selected-channel replacement preserves original expiry/budgets and invalidates superseded proof/ceremony. |
| `/email/verify`, `/phone/verify` | `A + {verification_id,code}`. Selected-purpose/destination proof only. T19/T31 own email codes; do not remove the current email-link page in anticipation. |
| `/passkey/options` | `A + {registration: F,password?}` for passkey/both. Validate and bind the complete candidate before native enrollment; password-bearing intent fingerprints must be keyed. |
| Registration root | `A + {registration: F,password?,credential?}`. Passkey requires credential/no password; password requires password/no credential; both require both. One atomic creation transaction includes protected attributes, selected verified contact, legal versions, credentials and creation intent. |
| `/result` | `A`. Bounded pending/failed/completed information; no session issuance or recreation. |

Only deferred T33 may issue a normal session after a known fresh commit, using the
same browser key and bootstrapping exactly the returned new subject. Result reads
and replayed receipts never mint sessions. Failed session issuance leaves the
committed account eligible for ordinary login, not account recreation. Password,
username/contact-code login, MFA alternatives, optional-email consumers,
notifications, private snapshots/editing and broader recovery remain separate tasks.

## Deferred Legacy Claim and Evidence

The future `POST /api/v1/users/me/username` body is `{username}`, but it remains
unmounted and no claim UI is offered. A shared NULL-only assignment primitive is
not public authorization. Existing sessions have no earned `auth_time`; generic
fresh WebAuthn step-up grants are not username/action-bound and UI intent labels
are not server-enforced proof. Session/account creation timestamps cannot replace
fresh authentication evidence.

A separately approved extension must bind real fresh WebAuthn UV to
`username.initial_claim`, exact NFC display/security assignment, account/session/JKT,
auth version, active policy, original expiry and one-time redemption. Require strict
signed authentication-time/lifetime checks and a final locked active-account recheck.
Reject generic grants and cross-action proof substitution; no usable UV passkey
means no claim under this proposal, not password/TOTP fallback or fabricated T16
evidence. Proof consumption, assignment audit/revision and ambiguous-result handling
remain that future task's explicit design, not existing display-name events or a
new invented private snapshot format.

Required username evidence includes normalization/idempotence and rejection
properties; exact crypto/config admission; every-status reservation and SQL
immutability; real separate-connection equivalent-name races and rollback atomicity;
purge lifetime; stale-policy/wrong-key guards; complete cross-page/reserved collision
and no-split checks; and bilingual explicit-validation/absence/no-claim UI checks.
Source fixtures, mocks and availability reads alone do not establish these results.
Report actual passed/failed/blocked/skipped/unrun checks separately. No runtime,
database, deployed-data or browser acceptance is asserted by this documentation.
Real email/SMS receipt, physical authenticators, source-data rights, approved legal
documents, independent Persian security/legal review and deployed-ingress gates
remain open until separately observed.
