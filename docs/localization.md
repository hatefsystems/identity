# Browser and notification localization

The application supports English (`en`) and Iranian Persian (`fa-IR`) on the same
URLs. English is the initial presentation until the user explicitly saves a valid
browser preference. `Accept-Language` does not redirect, authenticate, or choose a
language automatically. Preferences belong to a browser, not an account profile.

## Request and preference boundary

`apps/web/i18n/config.ts` defines the supported locales, calendar options and zone
validation. `server.ts` resolves each request's cookie; `request.ts` configures
`next-intl` using an explicit catalog allowlist. The root retains `connection()`
for fresh per-request CSP nonces, renders the initial `lang`/`dir` and passes only
static public messages and display preferences into a stable client provider.
Dashboard/admin SSR and Flight remain non-sensitive shells: the browser's existing
DPoP bootstrap still gates private content. Locale is never an authentication
signal, component key, security-effect dependency, or authorization cache.

The `__Host-hatef-ui` cookie has this bounded versioned representation:

```text
1~en~auto~UTC
1~fa-IR~persian~Asia/Tehran
```

It contains only `locale`, `calendar` and `timeZone`, is at most 128 characters,
and uses `Secure; HttpOnly; Path=/; SameSite=Lax; Max-Age=31536000` without a Domain.
The authentication cookie remains `SameSite=Strict`. Missing, oversized, duplicate,
malformed or unsupported-version preference cookies resolve to English, automatic
calendar and UTC. An unsupported individual field receives its own default.
Untrusted cookie text never becomes an import path, HTML, log payload or authority.
The Server Action accepts exactly those three properties and rejects unknown keys,
unsupported locale/calendar and invalid zones; it writes only the preference
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
bytes. Passwords remain exact; TOTP still accepts exactly six ASCII digits, including
leading zeroes, without converting Persian, Arabic-Indic or fullwidth digits.

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

The matrix includes light/dark, 320/390/768/1280 widths and short 320×256 reflow.
The latter is a CSS-viewport approximation, not observed native zoom. The seven
serial disposable integration targets are security-db, admin, retention, legal
workflow, gRPC, lifecycle and portal; the helper must not silently run only five.
Execution results belong in the delivery evidence/PR, not inferred from test
existence or historical acceptance notes.

Manual release gates remain: independent professional Persian security/legal
wording review; screen reader, keyboard/platform-authenticator and native zoom
review; native hidden-tab/bfcache behavior where not observed; deployed HTTPS
nonce/Server Action/font/cookie behavior and ingress/log-redaction checks; mailbox,
SMTP provider and compatible queue rollout/rollback review. Mark each unperformed
or unavailable check explicitly. Password/signup/reset/TOTP previews remain
unconnected. Primary-email verification, backup-code login UI, invitations,
password-reset delivery and OAuth consent/error pages are separate product work;
browser/OS-owned WebAuthn prompts cannot be translated by this application.
