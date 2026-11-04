# Persian localization validation

This delivery implements English (`en`) and Iranian Persian (`fa-IR`) on the
existing routes. The implementation and rollout contract are described in
[localization.md](localization.md). This report distinguishes repository
verification from manual release acceptance. No production deployment or merge
is authorized by these results.

## Recorded checks

All Nx checks below use `NX_DAEMON=false`, `CI=true`,
`NEXT_TELEMETRY_DISABLED=1` and fresh execution with `--skipNxCache` where supported.
The API checks use Go 1.26.5; the integration runner reads the checked-in module
version explicitly instead of inheriting a newer host Go.

| Check | Current evidence |
| --- | --- |
| Web Jest with coverage | PASS: 31 suites / 704 tests, including router-history, legal-catalog and single-word prose-guard regressions |
| Shared UI Jest with coverage | PASS: 3 suites / 17 tests |
| Web/UI lint and typecheck | PASS; repeated after the router-history repair |
| Recovery/router and localization regression tests | PASS: 83 tests |
| Go unit and race | PASS: 3,524 passing test/subtest events and 47 tested packages in each run |
| Go vet and golangci-lint 2.12.2 | PASS, normal and integration-tagged; lint reports zero issues |
| Go portal and excluded fixture tests | PASS |
| Protobuf lint, sqlc vet and generated reproducibility | PASS: 27 generated files compared, zero mismatches |
| API and operational binaries | PASS: ten build targets |
| API runtime image and packaged command smoke | PASS: actual Dockerfile, nine entrypoints, non-root amd64 runtime |
| Web runtime image | PASS: actual Dockerfile, non-root amd64 runtime, both-locale image CSP/auth acceptance |
| Seven serial DB integrations | PASS: security 1,464; admin 758; retention 81; legal workflow 620; gRPC 560; lifecycle 370; portal 2,106. Zero failed or skipped tests in the pinned-toolchain run |
| Supplemental initial-schema migration | PASS: eight test/subtest events against a disposable database |
| Existing browser/release/container-policy script tests | PASS: 168 tests, zero failures or skips; repeated with a fresh TMPDIR and no existing `kilo` parent |
| Production image CSP/auth | PASS: English and Persian; strict nonce/CSP attack probes, keyboard/contrast/reflow, no-JS and exact same-origin font bytes |
| Real-API portal browser | PASS per locale: 13 checks, 30 viewport states and six no-JS documents; teardown completed |
| Real-API admin browser | PASS per locale: 28 checks and 70 layouts; teardown completed and worktree identity unchanged throughout each run |

The ordinary Go unit/race commands explicitly skip
`TestInitialSchemaMigration` and `TestPgAdvisoryLockerMutualExclusion` when
`DATABASE_URL` is absent. The former has a separate disposable-database run; the
latter is covered by the required security DB integration target. Seven Go
packages have no test files. These are not counted as passing tests.

The race check uses the existing Go 1.26.5 Debian image with CGO and a compiler,
network disabled and only test-owned containers/cache mounts. Image builds need
host networking locally to reach the existing loopback package proxy; this does
not change application ingress, cookie or CSP policy.

The final admin target completed in 12 minutes 22 seconds including its uncached
build dependencies. The browser program itself took 11 minutes 46 seconds for
both locales. CI browser budgets retain room for cold toolchain/image setup.

These are fresh local results. Remote GitHub Actions and its uploaded screenshot
artifacts are separate evidence; their status must be read from the PR checks.
The PR remains a draft while manual release acceptance is open.

## Security and presentation evidence

- Catalog parity, ICU arguments/rich slots, typed keys/arguments, English leaf
  fallback, safe failures, request isolation and the owned-prose source guard.
- Secure host-only HttpOnly preference cookie, exact Server Action input,
  independent calendar/zone choices, serialized saves and failed-save behavior.
- Original passwords and ASCII-only TOTP; exact clipboard/download bytes,
  technical decimal strings and fractional UTC timestamps.
- Language changes preserve drafts, pending operations, client/key identity,
  one-time viewers and their original absolute/monotonic deadlines. Recovery
  additionally synchronizes the scrubbed URL with a parent router installed
  after child mount effects, preventing bearer-fragment restoration on rerender.
- Public catalogs receive the fixed preservation wire value as a rendering
  argument, rather than serializing that value in the public message tree; the
  unchanged SSR private-data assertion remains enforced.
- Frozen notification language/template version, legacy v1 English delivery,
  strict encrypted bindings, UTF-8 MIME/quoted-printable, exact recovery links,
  recipient separation and final encoded message-size limits.

Browser artifacts are limited to structurally masked screenshots and sanitized
summaries. Public/auth, portal and admin artifacts use the existing CI upload
mechanism (`auth-browser-evidence`, `portal-browser-evidence`, and
`admin-browser-evidence`). Representative local English/Persian auth, privacy
and legal screenshots were visually inspected. The local successful runs contain
128 auth, 60 portal and 140 admin masked screenshots. Runtime services, mail,
tokens, storage snapshots, HARs and traces are not source or artifact inputs. Local execution records are kept under the ignored
`.kilo/localization-evidence` directory and are not committed.

The unmodified upstream `OFL.txt` and `AUTHORS.txt` contain two trailing-space
lines. Their bytes are preserved for provenance; source whitespace checks exclude
only those two verified vendor files. The requested WOFF2 and license hashes are
recorded in `apps/web/app/fonts/provenance.json`; locally computed hashes are
not upstream signature authentication.

## Unperformed manual release gates

- Independent professional review of Persian security/legal wording.
- Physical authenticators, assistive technology and native browser zoom.
- Native hidden-tab/bfcache observations wherever headless execution reports only
  injected lifecycle events.
- Deployed HTTPS ingress, nonce/Server Action/font/cookie behavior and log redaction.
- Real mailbox/SMTP-provider review and coordinated v1/v2 reader-before-writer
  rollout and rollback under the existing retention policy.

These gates remain explicitly open. Disabled password/signup/reset/TOTP previews
stay disconnected; primary-email verification, backup-code login, invitations,
password-reset delivery and OAuth consent/error pages remain separate product work.
