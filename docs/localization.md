# Browser and notification localization

The application supports English (`en`) and Iranian Persian (`fa-IR`) on the same
URLs. English is the initial presentation until the user explicitly saves a valid
browser preference. `Accept-Language` does not redirect, authenticate, or choose a
language automatically. Preferences belong to a browser, not an account profile.

## Request and preference boundary

`apps/web/i18n/config.ts` defines the supported locales, calendar, appearance and zone
validation. `server.ts` resolves each request's cookie; `request.ts` configures
`next-intl` using an explicit catalog allowlist. The root retains `connection()`
for fresh per-request CSP nonces, renders the initial `lang`/`dir` and passes only
static public messages and display preferences into a stable client provider.
Dashboard/admin SSR and Flight remain non-sensitive shells: the browser's existing
DPoP bootstrap still gates private content. Locale is never an authentication
signal, component key, security-effect dependency, or authorization cache.

The `__Host-hatef-ui` cookie has this bounded versioned representation:

```text
2~en~auto~UTC~system
2~fa-IR~persian~Asia/Tehran~dark
```

It contains only `locale`, `calendar`, `timeZone` and `theme`, is at most 128 characters,
and uses `Secure; HttpOnly; Path=/; SameSite=Lax; Max-Age=31536000` without a Domain.
The authentication cookie remains `SameSite=Strict`. Missing, oversized, duplicate,
malformed or unsupported-version preference cookies resolve to English, automatic
calendar, UTC and System appearance. An unsupported individual field receives its
own default. V1 cookies (`1~locale~calendar~timeZone`) remain readable and migrate
to System without losing the other saved choices. V2 readers must be deployed
before V2 writes in a rolling release, and retained during rollback.
Untrusted cookie text never becomes an import path, HTML, log payload or authority.
The Server Action accepts exactly those four properties and rejects unknown keys,
unsupported locale/calendar/theme and invalid zones; it writes only the preference
cookie. A failed save keeps the previous presentation and reports localized
feedback. Saves are serialized so a stale response cannot replace a newer choice.

The public and protected shells expose one labeled language select and a separate
Display settings disclosure. Changes use Next's cookie-triggered Server Action
rerender with its normal same-origin/CSRF protection. There is no routing middleware,
locale prefix, full reload, duplicate refresh or permissive allowed-origin rule.
Client drafts, current notices and one-time viewers retain their identity and
original deadlines. Native security dialogs continue to make background controls
inert. Existing tabs retain their presentation until an explicit change or later
server navigation; preferences do not use the authentication invalidation channel.
Use the existing local HTTPS harness to exercise the secure cookie.

Appearance accepts exactly `system`, `light` and `dark`. Explicit Light/Dark render
in SSR. System uses one constant, request-nonced head initializer before paint,
reading only the validated selected-mode attribute and OS color-scheme query.
The stable client controller synchronizes successful saves before paint and
follows OS changes only while System is active; unavailable detection uses light.
The `.dark` class and CSS `color-scheme` agree, including native widgets. There is
no localStorage, inline style, authentication-channel broadcast or CSP exception.
Other tabs keep their selected presentation until explicit change/server navigation;
active System tabs still independently follow OS changes. Failed saves preserve
the old appearance as well as language/calendar/zone and do not replay API work.

Normal page errors and not-found text use the request language. If the root itself
fails, `global-error.tsx` intentionally provides independent English and Persian
sections with explicit language/direction and local styles. This fatal fallback
requires no root provider, error message, digest, account state or browser sniffing.

## Registration synchronization

Registration uses whole English/Persian messages and stable descriptors, including
pending, uncertain and completed states. Preference changes preserve the mounted
client, in-memory capabilities and original wall/monotonic deadlines. Existing
Unicode email validation and canonical identity bytes remain server-owned.

## Catalogs and maintenance

`apps/web/messages/en.ts` is the `as const` type source. Namespaces are `common`,
`metadata`, `auth`, `portal`, `security`, `privacy`, `admin`, `audit`, `integrity`,
`legal`, `preferences`, `registration` and `errors`. Each Persian namespace satisfies the same
recursive string-valued shape. `i18n/types.ts` and the `next-intl` AppConfig
augmentation type locale, message keys and formats. Committed catalogs must remain
complete; the runtime merge supplies an English leaf if a deployment accidentally
misses a translation. This fallback does not make an incomplete catalog acceptable
in CI. Error diagnostics expose only an error category/key, never interpolation
values, original exceptions or private server evidence.

The source guard checks direct JSX/accessible labels, metadata, feedback and
interpolated prose, including single-word messages. Its reviewed `idle`,
`pending` and `error` exceptions apply only to the `useAuthForm` state-machine
setter in its owning file; they do not exempt rendered text or other setters.
There are no file-wide source-prose exemptions.

Use `getTranslations` for server text/metadata and `useTranslations` for client
text. Store stable message descriptors/status keys and bounded parameters in state;
translate while rendering so feedback can change language without rerunning an
operation. Use whole ICU messages and rich slots instead of concatenated prose or
translated-label React keys. Do not call hooks from transport/domain code. Keep
`libs/ui` locale-agnostic.

To add or change a message:

1. Add the English leaf and a complete Persian leaf with the same interpolation,
   plural and rich-slot contract. Preserve the original security meaning.
2. Use a stable key/semantic ID in the owning view and translate every visible,
   accessible, validation and metadata presentation of that state.
3. Update explicit accessible-name tests for both languages. Run the catalog,
   source-prose, preference and relevant security/lifetime tests via Nx.
4. Review Persian legal/security wording and mixed-direction presentation. A passing
   automated suite does not constitute independent professional wording review.

A future locale requires an explicit allowlist/type/cookie/header decision, a full
catalog, direction/font review, browser coverage and versioned Go templates where
needed. Do not infer a locale module path from external input.

## Direction, typography and display dates

Persian documents use `lang="fa-IR" dir="rtl"`; English uses `lang="en" dir="ltr"`.
Use logical spacing/alignment and preserve meaningful keyboard DOM order. Do not
double-reverse flex layouts or mirror nondirectional icons. Password suffix position
and input padding must deliberately account for the LTR input inside an RTL shell.
Names and user narratives use `dir="auto"`/isolation. Emails, URLs, codes, UUIDs,
IP addresses, hashes, revisions, sequence values and technical timestamps use
isolated LTR presentation. Bidi marks must never enter wire, clipboard or download
bytes. Passwords remain exact. Numeric browser controls for registration phone/SMS
and authenticator verification convert Persian (`U+06F0..U+06F9`) and Arabic-Indic
(`U+0660..U+0669`) digits, including mixtures with ASCII, before strict validation
and submission. Leading zeroes are preserved. Fullwidth digits, bidi marks, spaces
and other OTP junk are not converted or stripped; phone formatting follows its
existing rules. TOTP/SMS still require exactly six canonical ASCII digits. Raw
validators, API/provider contracts and Go validators remain ASCII-only. Email,
passwords, recovery credentials/tokens and WebAuthn data are never normalized.

Technical email inputs and displayed mailbox values use explicit LTR isolation,
including RTL-first international local parts and domains. Email controls use
unrestricted text with `inputMode="email"`, retaining native caret/selection APIs
without restrictive HTML email validation. Existing mailbox validation remains
authoritative. No bidi marks or display normalization enter submitted/copy bytes;
passwords and display names keep their existing policies.

Persian uses the unmodified variable Vazirmatn v33.003 WOFF2 under SIL Open Font
License 1.1. The tagged release, source archive member, local SHA-256 values,
license and authors are recorded in `apps/web/app/fonts/provenance.json`, `OFL.txt`
and `AUTHORS.txt`. Those hashes record a local HTTPS download; they are not upstream
signature authentication. Only the font/license/provenance files are vendored, not
the source archive. `next/font/local` serves fingerprinted same-origin assets with
weights 100–900, `display: swap`, fallback metrics and no preload. English keeps the
system font. No remote font request or CSP exception is authorized.

`Intl.DateTimeFormat` receives explicit locale, calendar and time zone. Automatic
calendar means Gregorian for English and Persian/Jalali for Persian. An explicit
calendar choice survives language changes. Time zone starts at UTC and accepts
canonical supported IANA IDs; the device shortcut submits the concrete validated
zone only after an explicit click. Zone is never inferred from language or IP.
These settings affect ordinary date display only. Stored timestamps, `<time
 dateTime>`, UTC filters/inputs, countdowns, expiry, authorization and legal deadlines
remain unchanged. Audit/legal primary timestamps retain exact Gregorian UTC strings,
including textual fractional precision, and large decimal strings stay exact.

Recognized fixed legal/integrity explanations have full localized prose after
strict contract validation. The original evidence remains available as inert
technical details. Unknown evidence, user narratives, audit payloads, enum wire
values, normalized request tuples and OAuth `error_description` are preserved
unchanged; no external translation service is involved. A localized explanatory
wrapper does not claim an unknown backend statement was verified or translated.

## Notification language and compatibility

Only existing notification-producing operations accept the presentation header:

```text
X-Hatef-Notification-Locale: en
X-Hatef-Notification-Locale: fa-IR
```

Missing, duplicate, oversized or unsupported values use English without changing
response codes or authorization. Deletion snapshots the initiating tab's active
locale, not the browser cookie another tab may have saved. Its transport option is
typed and restricted to the deletion route; request bodies, DPoP canonical URLs,
middleware, factors, rate limits and recipient selection are unchanged.

The Go `internal/notification` catalog is small and typed and renders privacy
notifications. Its legacy SMS prose is retained as catalog data only. Encrypted deletion payload v2 freezes validated locale and template
version atomically with the existing intent. Legacy v1 decodes as English/template
1; malformed v2 values fail closed. Existing envelope/row/request/token/deadline
bindings and size bounds remain enforced. No new preference column or worker
privilege is needed. Primary and backup recipients receive the same frozen
language, each with one recipient, stable message identity, original token and
original deadline across retries/restarts.

SMTP keeps UTF-8 quoted-printable text/HTML alternatives, MIME-encoded Persian
subjects, a 16 KiB final-message ceiling, explicit HTML language/direction and
isolated canonical UTC/link values. Each alternative contains exactly one recovery
link with the unchanged `/recover-account#token=...` contract. There are no locale
queries, token queries, redirect chains or remote assets. A different browser uses
its own saved preference or English and can change language in place. Mail
contains the authoritative exact UTC deadline regardless of UI settings.

The current SMS.ir VERIFY adapter sends the unchanged ASCII code using its
operator-configured provider template. UI language does not change the SMS.ir
template ID or request provider-side translation. There is no logging-sender
fallback. Do not log bodies, codes, recipients, recovery links or locale request
payloads. The new passkey-only registration UI is localized without changing its
email/phone proof, key ownership, explicit-delivery or durable-result contracts.

## Queue rollout and rollback

1. Deploy and verify v1/v2-capable notifier readers before an API writer can enqueue
   v2. Keep the existing encryption key versions and least-privilege delivery role.
2. Deploy the locale-aware API writer and frontend only after every eligible reader
   is compatible. Monitor due age, retries, permanent failures and lease cleanup
   using sanitized existing diagnostics.
3. Do not rewrite queued messages, change locale/template in existing ciphertext,
   regenerate tokens or extend the original deadline to change language.
4. For rollback, stop new v2 writes before replacing writers, retain compatible
   readers until all live v2 deliveries are handled under existing expiry/retention
   rules, and preserve recovery routes and keys. Never put an old v1-only worker
   on a queue containing live v2 work. Disabling new deletion requests does not
   authorize discarding accepted work or disabling recovery.

No retention, independent-hold, session, factor or cryptographic policy changes are
part of localization. Repository execution is not permission to deploy shared
infrastructure.

## Validation and evidence boundary

Use fresh configured Nx targets with `NX_DAEMON=false CI=true
NEXT_TELEMETRY_DISABLED=1` and `--skipNxCache`. The existing portal/admin/CSP browser
programs execute both locales with isolated fixtures/services and unchanged real
security workflows. Browser evidence records locale; screenshots include sanitized
route/state, locale, viewport and theme. Font readiness and settled layout precede
capture; structural masks cover inputs, private records, codes, session/profile
metadata and legal regions. No traces, HARs, mail bodies, storage snapshots or raw
responses are artifact inputs. Only the preference cookie may be added to an
anonymous page's browser jar; anonymous reclaim API requests still send zero
cookies/DPoP/session/grants.

The matrix includes both locales and all System/Light/Dark choices against light
and dark OS preferences. It uses representative 320/390/768/1280 widths and short
320×256 reflow, plus focused 320/375/390/430/768/1024/1280/1440/1920 boundary probes.
The short viewport and 200% text-size probes are automated approximations, not
observed native browser zoom. Forced colors and composited checked/enabled
destructive-control contrast are separate checks from disabled states. The seven
serial disposable integration targets are security-db, admin, retention, legal
workflow, gRPC, lifecycle and portal; the helper must not silently run only five.
Execution results belong in the delivery evidence/PR, not inferred from test
existence or historical acceptance notes.

Manual release gates remain: independent professional Persian security/legal
wording review; screen reader, keyboard/platform-authenticator and native zoom
review; native hidden-tab/bfcache behavior where not observed; deployed HTTPS
nonce/Server Action/font/cookie behavior and ingress/log-redaction checks; mailbox,
SMTP provider and compatible queue rollout/rollback review. Mark each unperformed
or unavailable check explicitly. Public authentication offers implemented passkey
sign-in and registration, including its separate email-verification tab. Password
reset and general authenticator-login URLs remain localized availability notices
with supported next actions; disconnected forms are covered only by test fixtures.
Backup-code login UI, invitations, password-reset delivery and OAuth consent/error
pages are separate product work. Browser/OS-owned WebAuthn prompts cannot be
translated by this application.

## UX audit release gates

The isolated registration fixture gives its shared subnet a bounded hourly SMS
budget of 100 for the expanded bilingual journeys and adversarial attempts. It
does not change production defaults or the per-phone minute/hour limits. The
browser rate-limit checks remain real per-phone checks; they do not certify the
production default subnet budget of ten per hour.
Each locale uses fresh private services and a fresh browser after verified prior
locale teardown. The hard-coded signup-start subnet limit is unchanged; no Redis
rate bucket is cleared or shared evidence reused between the locale journeys.

Implementation, Jest geometry, headless browser checks and synthetic gallery
frames do not certify human/platform/deployed-ingress acceptance. Release remains
blocked until actual owners are assigned and the following observations are
recorded; no reviewer or device owner is implicitly assigned by a test run.

| Gate | Required Owner | Current Observation |
| --- | --- | --- |
| Persian deletion cancellation, passkey interruption, sessions and irreversible actions | Independent professional Persian security reviewer, not assigned | Unrun |
| Persian UTC queries, legal references, holds and integrity interpretation | Independent professional Persian legal reviewer, not assigned | Unrun |
| Same-phone authenticator return/restart, native typing/paste/autofill/IME and cross-tab registration handoff | Platform/device owner, not assigned | Unrun on physical devices |
| Native passkey prompts, orientation, short landscape and mobile safe areas | Platform/device owner, not assigned | Unrun on physical devices |
| Screen reader announcements, native keyboard and implicit Enter in long reviews | Accessibility reviewer, not assigned | Unrun with native assistive technology |
| Native browser zoom at 200% and 400%, plus supported system text scaling | Accessibility/device owner, not assigned | Unrun; CSS viewport/text probes are not substitutes |
| Deployed HTTPS nonces, Server Actions, strict cookies, fonts and ingress/log redaction | Deployment/security operator, not assigned | Unrun against deployed ingress |
| Real mailbox/provider behavior and compatible notifier rollout/rollback | Mail/platform operator, not assigned | Unrun against production providers |

The internal [page-gallery workflow](page-gallery.md) uses tracked tooling under
`tools/page-gallery/`, not local Kilo scripts. The original 464-frame gallery
remains a preserved baseline. A new run must derive
its counts from the declared inventory, use a distinct run-owned destination and
pass its sanitizer/offline/manifest checks after formal browser acceptance.
Synthetic post-sanitization presentation clones are illustration only; they cannot
stand in for live cancellation, authorization, focus, delivery or mutation evidence.
