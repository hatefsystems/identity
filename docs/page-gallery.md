# Internal Page Gallery

This is an opt-in development tool, not a public service, UI redesign, screenshot
framework or release gate. `tools/page-gallery/generate-page-gallery.mjs` owns the
inventory and launch sequence. Its helpers reuse `.github/scripts` for real
application fixtures, browser preferences, immutable image validation and cleanup.
The formal browser acceptance framework remains unchanged.

## Supported Environment

Use Linux with native Linux tools and a local Docker Unix socket. WSL2 with Linux
Node/npm/Go/OpenSSL, a Linux filesystem checkout and a local Docker Unix socket is
the Windows-host execution path. WSL2 has not been independently revalidated for
this migration. Native PowerShell/CMD Windows and macOS are unsupported and are
not made compatible by weakening POSIX permissions, TLS or teardown assertions.
The registration fixture builds/runs `linux/amd64` images; Linux amd64 is the
validated host path. Other architectures and Docker emulation are untested.

Install these prerequisites before checking or generating:

| Prerequisite | Requirement |
| --- | --- |
| Node.js | >=24.0.0, as in root `package.json`; Linux Node, not a Windows bridge |
| npm | >=11.0.0; use `npm ci` and the tracked npm lockfile |
| Go | >=1.26.5, currently declared by `apps/identity-api/go.mod`; the checker reads this declaration |
| Git | A real checkout with HEAD and a matching workspace root |
| Docker | Running local Linux daemon and CLI with Unix socket access; modern image build, inspect, save/load and network/volume commands; no remote TCP daemon |
| OpenSSL | >=3.0, executable on PATH for ephemeral fixture certificates |
| Playwright | Lockfile-installed version plus its matching Chromium and Linux system libraries |
| Temporary storage | Writable OS temporary directory; optional `TMPDIR` must already exist; private run directories are created automatically |

On a Playwright-supported Debian/Ubuntu Linux distribution, install Chromium and
its system dependencies with `npm exec -- playwright install --with-deps chromium`.
The system-package step may require administrator privileges. Install dependencies
before invoking the gallery; do not run it as root to bypass socket, browser or
filesystem failures. See Playwright's supported Linux distributions for the
installed version. Docker socket access is privileged host access and must be
approved for the development account.

Cold dependency/image builds need approved registry/module/package network access.
Build-only host networking is used only on Linux when an explicitly configured
loopback forwarding proxy requires it. Private fixture services still use owned
networks. No personal image ID, browser cache path or Go cache directory is pinned.
Registration builds the API Dockerfile from the current source, with unique
run-owned labels/tag; the existing acceptance helpers export, hash, inspect and
reload the immutable image and verify source identity. Its private archive never
enters the gallery. Base service images remain the existing fixture defaults
(`postgres:16-alpine`, `redis:7-alpine`, `nats:2.10-alpine`, `node:24-bookworm-slim`).

## Fresh-Clone Workflow

1. Clone the repository and enter its root. No `.kilo` directory is required.
2. Install the toolchain, start the approved local Docker daemon, run `npm ci`,
   and install Playwright Chromium/system dependencies as above. No gallery runs
   as an install hook.
3. Resolve the configured tasks and run the separate prerequisite check:

```bash
npm exec -- nx show project web --json
npm exec -- nx show project identity-api --json
npm exec -- nx run web:check-page-gallery
```

The check validates helper files, Node/npm/Go/OpenSSL, safe TLS/diagnostics/profiling
settings, workspace identity, temporary-directory access, the local Docker endpoint
and daemon, and Chromium launch/close with its system libraries. It performs no
build, image pull, fixture startup, capture or gallery publication. Chromium may
create and remove its normal temporary profile. A passing check does **not** assert
formal acceptance, available registry networking, sufficient resources or a
successful full fixture run.

4. Satisfy fresh final-source formal browser acceptance separately, following
   [current bundle requirements](admin-operations.md#automated-validation),
   [portal/registration acceptance](devops-operations.md#automated-portal-acceptance)
   and [localization gates](localization.md#validation-and-evidence-boundary).
   This includes `web:test-portal-browser`, `web:test-admin-browser`, the existing
   image CSP/auth check, and `web:test-registration-browser` with an explicitly
   validated immutable API image and matching checksum/source manifest. Keep the
   remaining manual/platform/deployed-ingress gates honestly recorded. Old images,
   screenshots, cached checks or historical reports are not fresh acceptance.
   Do not overlap service/browser harnesses on the same Docker daemon. The gallery
   cannot certify or replace these prerequisites.
5. Only after that formal browser acceptance genuinely passes for the current
   application source, explicitly acknowledge it for this invocation and generate:

```bash
PAGE_GALLERY_BROWSER_ACCEPTANCE=passed npm exec -- nx run web:page-gallery
```

The acknowledgement is never set by the tool or an Nx target. It is an explicit
caller statement, not independent verification. The generator first checks
prerequisites, then performs uncached Nx web/API and fixture builds from source,
captures the complete inventory, checks decoded PNGs/offline HTML and teardown,
and only then updates latest. Missing acceptance fails before build/capture.

## Cost And Output

Expect a heavyweight local run: production Next.js and Go/schema/SQL builds,
an API Docker image build and private export/load, multiple disposable real API,
database, cache, queue, signer/publisher/notifier/controller processes, and several
Chromium instances. Budget roughly 8 GiB RAM and 10-20 GiB free disk as planning
headroom, not measured minimums. Cold downloads/builds can take tens of minutes;
an entire run can take an hour or longer on a slow machine. Each launcher command
has a one-hour deadline; registration image preparation has a 45-minute budget
and each registration locale has a 20-minute budget. Image/build caches may remain
in Docker's normal storage. No automatic Docker pruning is performed.

Counts come only from the scenario inventory. To inspect them without capture:

```bash
node tools/page-gallery/generate-page-gallery.mjs --inventory
```

Coverage retains both `en`/`fa-IR`, light/dark, desktop/mobile, short admin modals,
baseline/supplementary states and conditional paired control-detail images. Live
appearance changes use actual application preferences or System OS media changes,
never injected live styles/classes. Sensitive data is sanitized in source memory
before a detached, offline, cookie-free synthetic clone crosses the browser/Node
boundary. Demo values and frozen clone controls are **illustrations**, never
native-input, first-paint, security, authorization or transaction evidence. The
existing formal framework continues to use structural masks for its evidence.

Each new run lives at `test-output/page-gallery/<run-id>/` with `manifest.json`,
`index.html` and locale/device/theme PNG paths. `test-output/page-gallery/index.html`
points to the latest completely validated run. Open that file locally; no server,
publication or upload is required. Prior galleries, ZIPs and incomplete runs are
preserved. New run directories are private (0700) and artifacts are written 0600.
Both `.kilo` and `test-output` remain ignored. Do not stage screenshots, generated
HTML, credentials, archives, temporary profiles or runtime evidence.

Temporary image archives use `mkdtemp` under the OS temporary directory, not an
existing `/tmp/kilo`. Cleanup checks directory owner, mode and inode/device and
removes only run-owned resources; unique Docker image tag labels are checked before
removal. Tracked fixture helpers create their own required temporary parents.
Interruptions await owned-child teardown before releasing the generation lock;
failure diagnostics use stage/categories, never raw private process/Playwright
errors. Unconfirmed cleanup or image/network/manifest validation prevents latest
publication. After a hard kill, retain the incomplete run and investigate private
run-owned temporary resources. Remove `.generation.lock` only after confirming
no generator is running. Never delete name-matched foreign Docker state or use
global prune as gallery cleanup.

## Tool Tests

```bash
npm exec -- nx run web:test-page-gallery
```

This uncached opt-in target runs the migrated launcher/inventory tests, isolated
synthetic renderer tests and existing tracked browser-helper unit tests. It has
no build dependency and does not run a full gallery or formal application
acceptance. Renderer PNGs stay in memory and use synthetic test documents, not
old gallery screenshots. Tests verify versionable runtime import closure,
catalog/font inputs, no local Kilo dependency, prerequisite-only behavior,
acknowledgement enforcement, environment isolation, failure/interruption handling,
foreign-lock protection, privacy and offline rendering. Ordinary `web:test`,
builds, installation and CI/release paths do not invoke gallery generation.
