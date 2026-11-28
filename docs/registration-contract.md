# Registration Contract (T01)

This is the canonical contract for the existing registration service, client and
mounted form at `/register`, using the `/api/v1/auth/register` prefix. The T01
source review on 2026-11-24 inspected HEAD
`17d2ff19412ac1aea9489cd7206c79ff3d68149e` with no staged, unstaged or untracked
changes at intake. The reviewed routes, handlers, registration service, client
and mounted form are identical to the corresponding files at the assessment's
`85abb13a27196c229efa7f59d7ef5beebb1d7e49`; the relevant differences between those
revisions are documentation. The T01 working-tree delta is documentation only.

The [policy](authentication-and-recovery-policy.md#stable-invariants) owns SEC01–SEC16.
The [assessment](security-architecture-assessment.md) records source findings,
including F10 and F11. [Readiness](security-testing-and-readiness.md#release-gates)
owns release evidence and records G01 as approved on 2026-11-26. [ADR 0001](adr/0001-authentication-recovery-and-security-state-authority.md#status)
records the owner's acceptance. See the [T01 backlog record](../.github/tasks/registration-single-contract-tasks.md#t01)
for scope and the CP01 disposition.

## Delivery Boundaries

| Layer                                    | Contract and limits                                                                                                                                                                                                                                                                                                   |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Current conditional flow                 | Required email+Iranian mobile+username, email-link then mobile-SMS ownership, then resident UV passkey. Atomic completion returns `next: "login"`, not a normal session. Registration/SMS default disabled.                                                                                                           |
| Current username support                 | Advisory validation, admitted-policy frozen username, atomic reservation and normal-authenticated saved read/truthful NULL. No claim/rename or second route; no selected-contact/password/private/legal registration collection yet.                                                                                  |
| Current geography/private data (T08-T10) | Immutable imported geography catalog, bounded public reads/shared validator and bilingual selector; normal-authenticated private-data snapshots/edits encrypt validated attributes. Registration collection/integration remains planned T31-T37; private editor UI is separate T38.                                   |
| Existing-account MFA maintenance (T26)   | Extend existing TOTP routes with a default-off, password/contact `mfa_enrollment` start proof and fresh strong-factor disable. No registration fields/stages, login policy, optional-MFA flag, management UI or other task status changes.                                                                            |
| Existing-account primary contacts (T27)  | Unified normal-session email/phone maintenance, frozen strong or action/target-specific password-contact authorization and separate new-destination ownership. Present-email removal is temporarily refused pending independently verified T28/T41. No signup, backup-contact, notification or T38 UI changes.        |
| Deferred final target                    | Required private names, date-only birthday, explicit gender, username, one selected verified contact, selected primary credentials, location and separate legal acceptances; six stages and future fresh-commit session issuance described below. These are specifications, not implemented-task or test-pass claims. |

Do not add a second registration implementation or versioned registration route.
Do not alter generic BlindIndex/email normalization, signed history, audit/lifecycle
formats, existing recovery/deletion systems or unrelated authentication machinery.
No SQL Server access, dataset redistribution, production install, data repair,
destructive rollback or commit is authorized by this contract. Dependent backlog
tasks remain independently scoped; documenting them does not complete them.

## Existing Flow and Username Increment

The current API mounts only when a registration service is provisioned. The
[route list](../apps/identity-api/internal/server/registration.go#L24-L32),
[strict request parser](../apps/identity-api/internal/server/registration.go#L43-L115)
and [handler](../apps/identity-api/internal/server/registration.go#L218-L303) define
the current wire behavior. The [existing service](../apps/identity-api/internal/registration/service.go#L122-L179)
admits `{email,phone,username}`; its [completion path](../apps/identity-api/internal/registration/service.go#L542-L678)
commits the birth and receipt together. The [public page](../apps/web/app/%28auth%29/register/page.tsx#L9-L11)
mounts [RegistrationScreen](../apps/web/app/%28auth%29/_components/screens.tsx#L22-L24)
and the [current form](../apps/web/app/_components/registration.tsx#L415-L649)
uses the [existing client](../apps/web/app/_lib/portal/registration-client.ts).
The [current API table](api-design.md#15-new-account-registration) lists all nine
POSTs, their exact bodies and their success responses. The [current browser flow](client-integration.md#14-conditional-new-account-registration)
maps form phases to those calls. Static inspection supplies no runtime acceptance.

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
- The account-creation transaction persists protected verification evidence for
  each successfully verified canonical email/mobile destination, bound to account,
  channel, proof method and the original server-recorded verification time. No OTP
  or verification token is retained in that evidence. Receipt replay preserves it;
  changing or removing a destination invalidates its evidence transactionally, and
  restoring an earlier destination requires fresh verification. Populated contacts
  and active status are not proof, and no historical evidence is backfilled.

Keep strict field/UTF-8 admission, exact Origin, public DPoP nonce/replay and
JKT/capability binding, cookie omission for signup, no-store/no-referrer and stable
redacted failures. Do not put contacts, usernames, proofs, keys or private collision
reports into logs, URLs, analytics, cross-tab messages or browser artifacts.
Provider/relay acceptance is not delivery. Native cancellation and locale changes
are not permission to replay enrollment, resend, rebootstrap or extend authority.

Existing-account T26 maintenance is a separate normal-session ceremony, not signup
authority. Its [exact challenge/verify and TOTP contracts](api-design.md#multi-factor-authentication-totp--sms-otp)
use fresh exact-byte password verification plus a code to an exactly evidenced
server-owned contact only for nonprivileged password-only accounts with usable
enabled admitted username/password sign-in, zero passkeys and no enabled/configured
active TOTP. Any role membership excludes that fallback. The fixed-purpose proof
is spent once at pending start; confirmation rechecks its frozen session/version/JKT,
contact and policy binding, using only the new-secret TOTP and no second authority
header. The deadline is the earliest enrollment/original-authorization/session
idle/absolute limit and never extends through renewal, retry or replacement.
Existing UV Step-up remains a stronger start path; shared grants are single-use,
not action-scoped. Disable requires fresh enrolled-TOTP or UV Step-up, never the
password/contact proof, and preserves resulting-state primary-login and every-role
protection. Enabled MFA still requires independently earned TOTP at normal-session
boundaries, including UV-passkey sign-in. Signup proofs, receipt replay and `/result`
cannot authorize or reconcile these maintenance mutations, and enrollment does not
restamp an existing session as MFA-authenticated.

T27's [primary-contact maintenance contract](api-design.md#primary-contact-maintenance-t27)
is also separate from registration authority. A valid registration commit supplies
durable destination provenance, not fresh action authority. Email/phone change and
removal proofs are action/target-bound; new-destination ownership cannot authorize
changing the account. Starts freeze original authorization and session deadlines,
and final mutations consume only the matching ownership code before read-only
locked revalidation. Fresh `email_otp` evidence is truthful and existing
`email_link`/`sms_otp` readers remain valid. Signup codes/tokens/receipts and `/result`
cannot authorize or reconcile maintenance, and no registration request or stage
changes. Present-email removal remains operation-gated on T28/T41; already-NULL
accounts are supported without fabricated email or verification. Implementation
and verification evidence are separate from real delivery or release activation.

## Username Namespace

The owner approved a minimum of four admitted Persian-script letters and a
maximum of 40 total Unicode code points on 2026-11-27. This assignment ruleset
supersedes both historical T03's 7–40 canonical code points and the subsequently
unbounded business-length policy. The fingerprinted policy JSON requires explicit
`min_letters` and `max_code_points`. The server counts each admitted letter once,
including both Arabic keyboard aliases. ASCII separator dots count toward the
maximum and are excluded from the minimum.

The existing full-match Go regex owns spelling within the same server normalizer.
It admits the 32 Persian letters, Alef with madda, standalone Hamza, Waw/Yeh with
Hamza and Arabic Yeh/Kaf keyboard aliases. Single internal dots separate
nonempty letter sequences. Technical ceilings are 1024 UTF-8 bytes for input
and each normalized representation, 4096 regex-source bytes and 16 KiB for the
artifact.

Validate UTF-8 and byte bounds, compute `display = NFC(input)`, and apply the
regex and both counts to that display for advisory validation, availability
for new assignments, registration start, and final guarded assignment.
Derive a separate `security_name` with exactly these scalar folds:

| Input                   | Security scalar      |
| ----------------------- | -------------------- |
| Arabic Yeh `U+064A`     | Persian Yeh `U+06CC` |
| Arabic Kaf `U+0643`     | Persian Kaf `U+06A9` |
| Waw with Hamza `U+0624` | Waw `U+0648`         |
| Yeh with Hamza `U+0626` | Persian Yeh `U+06CC` |

Display receives no security folds. NFC-supported decompositions may compose into
admitted letters; remaining combining/vowel marks, numeral/mixed scripts, controls,
bidi marks, whitespace, ZWNJ/ZWJ, presentation forms and unsupported aliases are
rejected, not stripped. The initial assignment expression rejects leading,
trailing and doubled dots. Lookup keeps dots exactly as assigned under the
bounded security normalizer. Underscores are outside the supported repertoire.
Alef with madda remains distinct from Alef; standalone Hamza and
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
The tuple is currently all absent or all present. Existing NULL rows are read
truthfully; no backfill is derived from email/display name and no normalization
version is fabricated. **Planned SEC01/SEC13:** every production human birth and
admission requires immutable username ownership; current nullable constraints do
not enforce that everywhere (`apps/identity-api/db/migrations/00003_username_reservations.sql:59-71,97-137`).
This missing prerequisite is not authorization for T12 or a username-less lane.

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
same bounded security normalizer and preserves assigned names across changes to
the assignment regex or length bounds. Account/login policy still applies.

### Approved Initial Username Assignment Policy

[T04A](../.github/tasks/registration-single-contract-tasks.md#t04a) publishes the
exact [Go assignment regex](../apps/identity-api/internal/username/testdata/policy-review/regex.txt)
and [policy JSON](../apps/identity-api/internal/username/testdata/policy-review/policy.json)
approved by the owner on 2026-11-27. The regex file contains the exact source bytes with
no terminal newline. The JSON supplies `id`, `normalization`, the four
`{from,to}` folds, `min_letters: 4`, `max_code_points: 40` and `reserved_names`. The existing normalizer combines
this policy with the regex and pinned implementation/Unicode identity to form
the canonical artifact. Key material and key custody are separate.

| Approved Persian reservation | Intended use           |
| ---------------------------- | ---------------------- |
| `هاتف`                       | Main service identity  |
| `هاتف.سامانه`                | System notices         |
| `هاتف.مدیریت`                | Service administration |
| `هاتف.امنیت`                 | Security response      |
| `هاتف.پشتیبانی`              | User support           |
| `هاتف.حریم.خصوصی`            | Privacy inquiries      |

Each entry reserves its exact security name and the existing four-fold
equivalents. Dotted extensions and other distinct spellings use the ordinary
namespace. A reservation creates no account or role. The source artifact defines initial assignment policy. Production requires its
verified fingerprint, key provenance and actual inventory evidence under
[T04B](../.github/tasks/registration-single-contract-tasks.md#t04b).
[Operations](devops-operations.md#username-policy-and-preflight-gates) owns the
read-only preflight, separate authorizations, writer fence and rollback gates.

## Deferred Final Fields

### Confirmed Private-Name Validation (T02)

`internal/profile.NormalizePersonalName` under `apps/identity-api` is the shared
validator for required private `given_name`/`family_name`. Current registration
does not collect them; existing-account `PrivateService` stores validated encrypted
attributes (`apps/identity-api/internal/profile/private.go:29-49,93-119,258-307,310-368`).
It is inaccurate to describe every endpoint as standalone-validator-only. No
private value is inferred; cosmetic `NormalizeName` remains independent.

- Reject invalid raw UTF-8 and input over 1024 bytes before normalization. Apply
  NFC and only Arabic Yeh/Kaf-to-Persian Yeh/Kaf normalization. Preserve standalone
  Hamza, Alef with madda, plain Alef and Waw/Yeh with Hamza distinctions; private
  names do not receive the username security folds for Waw/Yeh with Hamza.
- Admit the explicitly defined 32 Persian letters, Alef with madda, standalone
  Hamza, Waw/Yeh with Hamza and Arabic Yeh/Kaf keyboard aliases. This repertoire
  is independent of the configured username regex.
- Trim only leading/trailing ASCII spaces and collapse repeated ASCII spaces.
  Retain a single internal ASCII space or ZWNJ only directly between admitted
  letters. Outer/repeated ZWNJ and adjacent separators are invalid. This is a
  structural rule, not linguistic or legal-name verification.
- Require 1..80 normalized Unicode code points, including retained separators,
  and at most 1024 normalized UTF-8 bytes. Empty/space-only values are invalid.
  The output byte bound is an invariant; its exact boundary is unreachable under
  the admitted alphabet and code-point limit.
- Reject Latin/mixed scripts, every numeral script, punctuation, remaining
  combining/vowel marks, presentation forms, unsupported aliases, ZWJ, controls,
  bidi formatting and non-ASCII whitespace rather than stripping them. NFC
  decompositions that compose into admitted letters remain valid. Validation
  errors are static and redacted, never rejected private values.

### Confirmed Birthday and Gender Validation (T05/T06)

`internal/profile.NormalizeBirthday(calendar, date string, now time.Time)` returns
one `Birthday` with canonical ASCII `Gregorian` and `Jalali` date-only strings.
`ValidateGender(raw string)` returns a string-backed `Gender` with explicit
`GenderFemale` and `GenderMale` constants. Registration `/validate` remains
username-only and `/start` requires `{email,phone,username}`; registration does not
collect birthday/gender. Existing-account private-data endpoints use these validators
and encrypted storage, while final registration controls/integration are planned.
The [standalone T05 record](../.github/tasks/registration-single-contract-tasks.md#t05)
tracks current birthday verification separately from the original T05/T06
evidence. Validator acceptance does not establish target registration
integration, browser acceptance for birthday controls, or backfill.

- Require calendar exactly `gregorian` or `jalali`; preference identifiers
  `gregory`/`persian`, locale/browser inference and missing values are invalid.
- Require valid UTF-8, at most 18 raw bytes and exactly ten code points in
  `YYYY-MM-DD`. Convert only ASCII `U+0030..U+0039`, Persian `U+06F0..U+06F9` and
  Arabic-Indic `U+0660..U+0669` digits, including mixtures, preserving padding.
  Hyphens must be ASCII. Do not trim, apply NFKC, strip bidi/control marks or accept
  other digits, slashes, signs, nonpadded fields or timestamp suffixes.
- Validate actual selected-calendar month/day/leap rules before conversion; derive
  and reverse-check the other representation with the single integer-only
  [jalaali-js v1.2.8 core](https://github.com/jalaali/jalaali-js/tree/f592be0e06867d2752f93924fa3e338f366ce4f4).
  `internal/profile/jalali.go` retains the full MIT notice and exact source pin.
  Independent source review checked all arithmetic expressions and signed
  division/remainder semantics; no runtime dependency or alternate converter exists.
- The core's Jalali years are `-61..3177`; paired conversion conservatively bounds
  Gregorian years to `560..3798` and rejects dates whose inverse leaves those
  limits. Birthday grammar has four unsigned year digits; accepted birthdays are
  further bounded by Gregorian civil components from `1900-01-01` through today.
  Unsupported dates fail closed without rollover, panic or fallback. Upstream
  documents divergence from `Intl` after Gregorian 2256. This is a pinned algorithm,
  not official-calendar certification or unlimited astronomical accuracy.
- The server supplies one trusted current instant per validation, never a client
  field. Extract today in explicit `Asia/Tehran`, including historical DST; cache
  only the immutable location and include standard `time/tzdata` fallback. The
  bound advances on the Tehran civil date even when a historical DST transition
  skipped midnight, and does not advance during a repeated late-evening hour. Zero
  clocks, Tehran years outside `1900..9999`, or zone failure return static
  `ErrBirthdayClock`. Input rejection uses separate static `ErrInvalidBirthday`.
  Every failure returns an entirely zero pair, never DOB-bearing errors/logging.
  DOBs use only civil integer components, comparison and date-only strings, never
  timestamp parsing, `time.Date`, Unix time, duration arithmetic or an age policy.
- Fixed fixtures include pinned upstream vectors and independently sourced
  [authority-derived year starts/leap flags](https://github.com/roozbehp/persiancalendar/blob/63562e04042fd9735b0aaa555719830311c6981d/kabise.txt),
  also reproduced in [ICU fixtures](https://github.com/unicode-org/icu/blob/8e0e87c31f34cb9ee028e6487f5199dc607e0f59/icu4j/main/core/src/test/java/com/ibm/icu/dev/test/calendar/PersianTest.java).
  The original University of Tehran PDF was unavailable during review; the two
  copies are not separate calendar authorities. Synthetic proleptic anchors and
  leap-end companions supplement the 46,340-day `1900-01-01..2026-11-15` civil
  round-trip sweep; round trips alone are not independent correctness evidence.
- Gender accepts exactly `female` or `male`: no trim, case folding, aliases,
  localized labels, numeric coercion or default. Invalid/missing new values return
  zero `Gender` and static, redacted `ErrInvalidGender`. Absent private attributes
  remain absent. The [standalone T06 record](../.github/tasks/registration-single-contract-tasks.md#t06)
  tracks exact-input, fuzz and concurrency verification. T31 owns required field
  presence at registration, and T35 owns explicit selection in the form.

| Field                       | Required final meaning                                                                                                                                                                                                                                                                                                          |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `given_name`, `family_name` | Private Persian-script names under T02; independent from optional public/cosmetic `display_name`.                                                                                                                                                                                                                               |
| `birthday`                  | `{calendar: "gregorian" \| "jalali", date: "YYYY-MM-DD"}`. T05 normalizes permitted date digits and derives an atomic equivalent Gregorian/Jalali date-only pair with one pinned/reviewed converter. Gregorian range is `1900-01-01` through today's server-side Tehran civil date. No timestamp or independently trusted pair. |
| `gender`                    | Exactly `female` or `male`, explicitly selected; no UI default or invented legacy value.                                                                                                                                                                                                                                        |
| `username`                  | Chosen spelling under the namespace above; required for new accounts, immutable after assignment.                                                                                                                                                                                                                               |
| `contact`                   | Exactly `{type: "email" \| "mobile", value: string}`. Verify the exact server-canonical selected destination. Unselected contact is absent, never a fabricated mailbox or empty-email digest.                                                                                                                                   |
| `authentication_method`     | Explicit `passkey`, `password` or `both`, with corresponding primary credentials required. No code-only account creation. Password bytes remain exact, including spaces; confirmation is client-only. T15 owns creation strength and bounded hashing.                                                                           |
| `location`                  | `{country: "IR", province_id: string, locality_id?: string}`; exact positive BIGINT decimal source IDs with correct active province ancestry. T08/T09 supply the catalog and independent selector. T31/T32 own registration integration and persistence.                                                                        |
| `legal_acceptance`          | Separate `terms` and `privacy` entries, each `{version, accepted: true}`, referring to approved server-configured documents. Acceptance time is server-owned; document approval is not supplied here.                                                                                                                           |

### Planned Stage-to-Request Trace

All six stages below are planned. The existing username validator is the sole
current stage selector. Each row contributes to the same candidate and final
submission through the [planned requests](#deferred-final-requests).

| Stage                        | Fields and validator owner                                                                                                                                                                                                                                                            | Request or action                                                                                                                                                                                                                                     | Expected outcome                                                                                                                                                                                        |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. Names                     | Required `given_name` and `family_name`, owned by `profile.NormalizePersonalName` (T02)                                                                                                                                                                                               | `/validate` with `stage: "names"` and exactly the two names                                                                                                                                                                                           | Both normalized private names or redacted errors on the invalid fields. Cosmetic display name cannot substitute.                                                                                        |
| 2. Personal information      | Required `birthday` and `gender`, owned by `profile.NormalizeBirthday` and `profile.ValidateGender` (T05/T06)                                                                                                                                                                         | `/validate` with `stage: "personal_information"` and exactly birthday and gender                                                                                                                                                                      | The equivalent Gregorian/Jalali date-only pair and the explicit gender, or redacted errors. Retain the explicit input calendar/date for subsequent requests.                                            |
| 3. Username                  | Required `username`, owned by `username.Normalizer.Normalize` and the guarded SQL namespace (T03/T04A)                                                                                                                                                                                | `/validate` with `stage: "username"` and exactly username                                                                                                                                                                                             | NFC display and advisory availability. Assignment is immutable and succeeds only in the deciding birth transaction.                                                                                     |
| 4. Contact verification      | One `contact` with `type` and `value`. The server owns canonicalization using `emailaddress.Canonicalize` or the admitted Iranian-mobile normalization around `smsotp.NormalizePhone`. T19/T19A and the registration service own selected-purpose code verification and T14 evidence. | Explicit `/start` with the selected contact, then its channel's send/resend and verify requests as needed                                                                                                                                             | Original attempt authority and deadline; successful verification proves only that exact selected destination. Choosing another destination requires a separate explicit attempt; proof cannot transfer. |
| 5. Authentication method     | Required `authentication_method`. T15 owns `password.Validate` and bounded `password.HashContext`; the registration WebAuthn service owns resident enrollment verification with actual UV.                                                                                            | Select `password`, `passkey` or `both` and collect the applicable password locally. Password confirmation is client-only. Server review and any native work occur in stage 6.                                                                         | The candidate specifies what must be verified. Native cancellation leaves passkey/both incomplete.                                                                                                      |
| 6. Location and final review | Required `location`, owned by `geography.Service.Validate` (T08/T09), and distinct `legal_acceptance.terms` and `legal_acceptance.privacy`, owned by the server's approved legal configuration and T31/T32. Review includes both birthday representations.                            | Use existing geography reads for explicit selection and approved document links for independent acceptance. Submit `full_review` before any `/passkey/options` and explicit native action, then submit the final request with the chosen credentials. | Review returns validated fields or redacted errors. A valid final request commits one complete birth. T33 alone adds a possible fresh-session handoff.                                                  |

Back navigation, legal links and presentation changes preserve ordinary draft meaning,
the original browser key and absolute deadlines. They do not trigger sends, retries,
native prompts or bootstrap. Server validation reruns on final submission. Changes
to an already bound candidate require validation and, for passkey/both, newly bound
options and explicit native enrollment within the original authority and deadlines.

## Deferred Final Requests

These are the target POST contracts under the existing prefix. The username
`/validate` branch already exists with the same request and response. The
[other current wire shapes](api-design.md#15-new-account-registration) continue
to apply until a separately authorized cutover. GATE02 applies to all target calls.

Let `A = {attempt_id,capability}`. In review, `registration` contains exactly
all fields in [Deferred Final Fields](#deferred-final-fields). Let `F` be those
same fields with `contact` omitted. The service loads the single canonical contact
from the attempt for options and completion, forming the same full candidate used
in review. The selected contact, proof generation, attempt, browser JKT, candidate
and policy/catalog/legal versions must still match at commit. `password` and
`credential` are top-level credential inputs. Omit inapplicable fields entirely.

| POST                               | Exact target request                                                         | Target success response and authority                                                                                                                                                                                                       |
| ---------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/validate`                        | `{stage,registration,password?}`, with exact stage fields listed below       | `200` with stage-specific normalized results. Read-only and advisory. Invalid candidates return redacted field errors.                                                                                                                      |
| `/start`                           | `{contact}`                                                                  | `201 {attempt_id,capability,canonical_contact,expires_at,submission}`. `canonical_contact` has `{type,value}`. The first send follows explicit submission and targets only that destination.                                                |
| `/email/resend` or `/phone/send`   | `A`                                                                          | `200 {submission}` for the matching selected channel. Replacement invalidates superseded proof and ceremony, preserving original expiry and budgets.                                                                                        |
| `/email/verify` or `/phone/verify` | `A + {verification_id,code}`                                                 | `204` after selected-destination proof only. The code is an exact six-digit ASCII string under T19, preserving leading zeros. Target email codes use this body; current email-link verification uses `{attempt_id,token}` until transition. |
| `/passkey/options`                 | `A + {registration: F,password?}`. Passkey omits password; both requires it. | `200 {publicKey}` for explicit resident UV enrollment after selected contact proof and full candidate validation. The ceremony is bound to the complete candidate and original JKT. Password-only never calls this operation.               |
| Registration root                  | `A + {registration: F,password?,credential?}`                                | `200` for the known committed outcomes below. Password requires password only, passkey requires credential only, and both requires both. A successful response after replay is a non-authenticating receipt.                                |
| `/result`                          | `A`                                                                          | `200` for the observed pending, failed or completed receipt shape below; `503 result_required` if the authoritative outcome remains unknown. Read-only and unauthenticated in every case.                                                   |

For the selected-channel responses, `submission` carries `state` of
`"accepted"` or `"unconfirmed"`. Accepted submission includes `verification_id`
and a server `expires_at` for the current code, bounded by the original attempt
expiry. Unconfirmed submission supplies no usable challenge reference and does
not itself authorize a resend. Provider acceptance is not inbox or handset
delivery. Wrong-channel calls are denied. Both channel proofs are signup-only
and cannot authorize login, repair, deletion or factor management.

The target `/validate` subsets and successful response shapes are exact:

- `names` takes `{given_name,family_name}` and returns those normalized fields.
- `personal_information` takes `{birthday,gender}`, with input birthday
  `{calendar,date}`, and returns `{birthday:{gregorian,jalali},gender}`.
- `username` takes `{username}` and returns `{username_display,available}`.
- `full_review` takes the full `registration` object and the top-level password
  only for password/both. It returns `{registration}` with server-normalized
  review fields, using the birthday pair, NFC username display and canonical
  contact. It returns no password, proof, credential or reservation.

The legal inputs must each contain the approved version string for that document
and literal boolean `accepted: true`. The server owns document identity/version
checks and the acceptance time. Reject missing, stale, swapped, unapproved or
mismatched versions. Approval of versions and links is an independent prerequisite.

## Planned Atomic Birth and Fresh Session

SEC01/SEC02/SEC13 require all final fields and the actual selected primary
credentials. Contact proof alone cannot create an account or authorize normal or
preauthentication login. Username is mandatory and immutable. Eligible primary
email may identify an account only when deliberately selected under SEC01 and
currently verified and uniquely associated. Email is never an implicit fallback
after username failure. Mobile is never a login identifier. The unselected contact
stays absent. Initial contact verification records its explicit SEC08 cooldown
exemption; later associations do not inherit it.

The existing service owns one caller-controlled SQL commit for the account,
protected attributes, username reservation, exact selected-contact evidence,
consumption of the required proofs/ceremony, selected credentials, immutable legal
evidence, metadata creation intent and receipt. Validate and bind expensive
password/native work outside long-held locks. Recheck authority, versions,
candidate, proof and absolute deadlines after waits under the
[global lock order](data-architecture.md#global-lock-order). Password-bearing
intent fingerprints use a dedicated keyed construction with domain separation.
Advisory availability grants no reservation. If two allowed spellings resolve to
the same security name, the database unique constraint decides. The losing
transaction rolls back every birth write, cannot leave a partial account, and
cannot attach a credential to the winner. Contact/credential collisions and
final proof or field failures also leave no partial birth.

### Target Completion and Reconciliation

| Observation                                                 | Target result and client action                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Direct known fresh commit, T33 session issued               | Final returns `{state:"completed",next:"portal",subject,receipt_expires_at}` with the normal strict session-cookie handoff. Only the direct response from the active final action may enter bootstrap. Use the original browser JKT and match the authenticated profile to the returned new subject exactly once before private portal mount. Clear obsolete in-memory authority without replacing the browser key.                                                                                                                                     |
| Known commit with no session issuance                       | Final returns the completed receipt below with `next:"login"`. Clear registration secrets and offer ordinary login for the committed account. A missing/unusable cookie, wrong subject/key, stale reply or failed bootstrap also goes to ordinary login.                                                                                                                                                                                                                                                                                                |
| Matching completion replay or completed `/result`           | `{state:"completed",next:"login",receipt_expires_at}`. Read-only receipt, without subject/session material or `Set-Cookie`. A changed body cannot replay the receipt. The client never submits again or calls session bootstrap from this branch.                                                                                                                                                                                                                                                                                                       |
| Known absent birth within a readable attempt                | `/result` reports `{state:"pending",expires_at,contact_verified}` or `{state:"failed",receipt_expires_at,contact_verified}`. Pending can return to the indicated stage only with still-valid original authority and appropriate fresh proof or ceremony when required. Failed is closed. Neither restores a spent proof nor automatically repeats a request.                                                                                                                                                                                            |
| Unknown commit, ambiguous completion or lost final response | Use explicit `/result` with original `A`/JKT and a fresh DPoP proof. An authoritative read may resolve committed or absent after the deciding outcome is known. A pending snapshot while completion may still be in flight, unavailable or expired authority, and an unknown read are never evidence of absence. While unknown, keep outcome checking bounded and offer ordinary login without automatic body/native work, a new attempt, or a session bootstrap. If `Set-Cookie` may have been lost, a completed receipt still directs ordinary login. |

T33 may issue a normal session only from the in-flight, known fresh successful
birth, for its exact returned subject and original JKT, after current SQL account,
role, revocation and full-policy checks. All selected primary evidence must be
server-verified, including actual UV for passkey. Enrollment does not substitute
for an assertion on ordinary passkey login or satisfy independent MFA where required.
Old completions, receipts, concurrent duplicate submissions, `/result`, uncertain
reconciliation and replacement keys cannot issue a session. A birth stays committed
if session issuance or delivery fails. T32 completion before T33 can return only
the unauthenticated target receipt. Current completion always returns the current
login receipt with its two proof flags and performs no T33 issuance.

### T01 Verification Trace

**T01-U01** is N/A for the documentation contract. These are required future
unit cases, with the field owners listed in the [stage trace](#planned-stage-to-request-trace):

- [T31-U01](../.github/tasks/registration-single-contract-tasks.md#t31) exercises
  the registration handler's exact top-level and nested objects for every row
  in the [request table](#deferred-final-requests). Test each admitted selector
  and reject unknown selectors, missing or extra fields (including cross-stage
  fields), duplicates at every level, casing aliases, nulls, wrong types, array
  or nonobject bodies, malformed UTF-8/JSON/string encodings, trailing content,
  over-limit bodies and query strings. Preserve canonical nonzero UUIDs for
  attempt IDs and canonical unpadded base64url encodings for 32-byte capabilities
  and verification references. Reject the current `{email,phone,username}` start
  and email-link token body as target inputs. Verify current reader compatibility
  separately under T31-I01.
- Exercise one email or one mobile; reject both, neither, unknown type, empty
  value, extra contact keys and non-ASCII/numeric or lost-leading-zero code
  representations. Test exact matching channel, purpose, canonical destination,
  proof ID, generation, key and deadline. Test the password/passkey/both matrix
  for review, options and final, including each missing, extra, null or wrong-type
  credential, wrong WebAuthn envelope, client confirmation, code-only birth and
  cancelled `both`. Final/options reject any caller contact, subject, role,
  verification status, normalized birthday pair or acceptance time.
- Reuse T02/T05–T11/T15 rule fixtures through the exact registration shapes.
  Include missing/invalid names, wrong calendar or impossible/future date, absent
  or nonadmitted gender, invalid username-policy input, wrong country or
  inactive/mismatched decimal province/locality IDs, and exact password bytes
  including spaces. For legal, check both exact nested tuples, missing entries,
  false or string acceptance, unknown keys and stale/unapproved/swapped versions.
- [T32-U01](../.github/tasks/registration-single-contract-tasks.md#t32) tests
  required-row and receipt invariants for all three credential modes. Check keyed
  and domain-separated password-bearing fingerprints, matching canonical candidate
  replay and mismatch on changed password bytes, other fields, selected contact,
  proof generation or authority. A changed candidate cannot reuse a ceremony or
  an existing completion. Exercise known, absent and unknown results without
  deriving proof, subject admission or a session from a receipt.

**T01-I01** is N/A for documentation execution. The required future SQL/HTTP
evidence maps as follows:

| Planned outcome                                                                                                                                               | SQL/HTTP acceptance                                                                                                                                                                                                                                                                                 |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Admitted fields, selected proof only and correct credential mode; deny wrong channel/capability/JKT/generation/deadline, code-only and invalid/missing fields | [T31-I01](../.github/tasks/registration-single-contract-tasks.md#t31) exercises the existing HTTP registration routes, exact schemas, default-off incomplete composition and concrete reader compatibility. T31-S01/X01 cover invalid proof and stale policy/catalog/legal or provider uncertainty. |
| One full birth with selected proof consumed, credentials and legal evidence committed; no partial rows, winner attachment or extra creation intent            | [T32-I01](../.github/tasks/registration-single-contract-tasks.md#t32) injects failures at every real SQL write and checks exactly one expected subject on success. T32-S01/X01 cover locked deciding checks, collision races on separate connections, and read-only known/absent/unknown results.   |
| Fresh full-policy session for exact subject/JKT, strict cookies; receipt/replay/result/unknown commit and failure mint no new authority or birth              | [T33-I01](../.github/tasks/registration-single-contract-tasks.md#t33) verifies real SQL/HTTP admission and unauthenticated reconciliation. T33-S01/X01 cover mismatches, intervening role/revocation, duplicate completion and lost session delivery.                                               |

**T01-B01** is N/A for contract-only work. [T34-B01](../.github/tasks/registration-single-contract-tasks.md#t34)
covers the shared shell for stages 1–6 including labels, progress, focus/back,
stable key/provider/deadlines and safe no-JavaScript states.
[T35-B01](../.github/tasks/registration-single-contract-tasks.md#t35) owns stages
1, 2 and 3, [T36-B01](../.github/tasks/registration-single-contract-tasks.md#t36)
owns stages 4 and 5 including explicit native action after review,
and [T37-B01](../.github/tasks/registration-single-contract-tasks.md#t37) owns
stage 6 with separate legal controls, validate-before-native and expected-subject
handoff verified under T33-B01. All follow
[GATE03](../.github/tasks/registration-single-contract-tasks.md#per-record-delivery-rules)
and [localization](localization.md#registration-synchronization) for typed
`en`/`fa-IR` messages, accessible names, keyboard/focus/status, responsive reflow,
palettes, privacy clearing, structural screenshot masks and exact wire bytes.
Physical authenticator/Windows Hello, screen reader/native zoom/bfcache, real
provider receipt, professional Persian/security/legal and deployed ingress
observations remain independent.

## Planned Dependencies and Gates

The [T07 dataset release](devops-operations.md#t07-dataset-release) must carry
verified provenance and complete coverage of the admitted snapshot. T08 imports
that release into PostgreSQL and T09 serves active catalog selections.
Registration location validation uses that PostgreSQL snapshot.

| Capability                              | Prerequisite / invariant                                                                                                                                                                                                                                                                                                                                                                         | Evidence before activation                                                                                                                             |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| One birth (T31/T32)                     | T31 depends on T01, T02, T03, T04A, T05, T06, T09, T10, T13, T14, T15, T19A, T23, and T41C, plus approved legal versions. See the [T32 backlog record](../.github/tasks/registration-single-contract-tasks.md#t32) for its direct dependencies. Selected-single-contact birth stays Blocked until T41C. Default-off field code is not a separate registration contract. SEC01/SEC02/SEC13/SEC14. | Full candidate, all credential choices, SQL collision/rollback/proof/legal-version tests; private storage does not mean registration collects it.      |
| Fresh session (T33)                     | T16A/T21A SQL-earned full-policy authority; known fresh T32 commit, SEC03/SEC09/SEC11/SEC13                                                                                                                                                                                                                                                                                                      | Expected subject/original key; no session from replay/result/unknown commit or duplicate birth after output failure.                                   |
| Phone-only production / T27 retirement  | Alternative recovery identification, code/barrier/cooldown, verified notification readers and password/mobile deletion/reclaim (T28-T30/T41); SEC06-SEC12                                                                                                                                                                                                                                        | Complete independently verified lifecycle/real delivery and retained reclaim factors; NULL readers alone do not retire the gate.                       |
| Six-stage browser integration (T34-T37) | Fixed API/legal/private/credential/session contracts and current shell; SEC15                                                                                                                                                                                                                                                                                                                    | Both locales, progress preserved, original UTC deadlines, explicit send/native work, no silent `both` downgrade, once-only expected-subject bootstrap. |
| Production username launch (T04B)       | Verified T04A, T18A and T32 plus authorized actual-target access, approved policy/reservations and verified key provenance.                                                                                                                                                                                                                                                                      | Complete protected production inventory and no-split evidence, separate installation/activation/deployment authorization and observed activation.      |
| Broader release (T42)                   | Durable token/interactive OIDC/confidential client/privileged consumer/restore foundations; SEC04/SEC16                                                                                                                                                                                                                                                                                          | Independent security, real provider/hardware/Persian/accessibility/ingress/legal evidence. T12 remains excluded.                                       |

Dependencies form a DAG, not numeric task order. Security-event contracts/readers
and verified-destination notifications precede security-changing writers and
phone-only lifecycle activation. T31–T37 can verify development flows using
T04A without the separate production gate. T42 requires T04B before launch. UI consumes fixed contracts, never invents
authority. Historical statuses/counts retain their original evidence and do not
approve these target gates.

## Username Claim Scope and Evidence

Identity is pre-launch. The legacy one-time username-claim proposal (T12) is out
of scope and excluded from both launch backlogs. Users choose their username
during registration with database-enforced uniqueness. Keep the authenticated
read-only username endpoint; no POST claim endpoint or claim UI is offered. A
shared NULL-only assignment primitive does not authorize a public claim operation.

Required username evidence includes normalization/idempotence and rejection
properties; exact crypto/config admission; every-status reservation and SQL
immutability; real separate-connection equivalent-name races and rollback atomicity;
purge lifetime; stale-policy/wrong-key guards; complete cross-page/reserved collision
and no-split checks; and bilingual explicit-validation/absence/no-claim UI checks.
Source fixtures, mocks and availability reads alone do not establish these results.
Report actual passed/failed/blocked/skipped/unrun checks separately. No runtime,
database, deployed-data or browser acceptance is asserted by this documentation.
Real email/SMS receipt, physical authenticators, approved legal documents,
independent Persian security/legal review and deployed-ingress gates
remain open until separately observed.
