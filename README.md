# Hatef Identity Platform (LDP)

Run the complete local stack (PostgreSQL, Redis, NATS, migrations, Go API,
Next.js and local HTTPS) from this directory:

```sh
docker compose up -d
```

Open **https://localhost:8443** after the first build. See
[container startup, local certificate trust and GHCR deployment](docs/container-deployment.md)
for the one-time CA import, persistent keys, production environment template and
host Nginx setup. GitHub Actions publishes tested API/web images on `main` and
version tags; it does not deploy a server.

The **Hatef Identity Platform (LDP)** is a centralized, privacy-first Identity Provider (IdP) and Single Sign-On (SSO) system designed to serve as the unified authentication and authorization backbone for the entire Hatef ecosystem (including the Search Engine, Email Service, and future applications).

Built with Go and Next.js inside an Nx monorepo, the platform has scoped
authentication, cryptographic and browser protections. Identity is pre-launch;
repository support and historical local acceptance are not deployed security or
blanket standards-conformity claims. The 2026-11-24
[security assessment](docs/security-architecture-assessment.md) distinguishes
current behavior from the owner-confirmed
[authentication and recovery policy](docs/authentication-and-recovery-policy.md).
The [ADR](docs/adr/0001-authentication-recovery-and-security-state-authority.md)
remains Proposed; application implementation requires separate owner approval.

---

## 1. System Overview & Architecture

LDP is a centralized, client-agnostic IdP with three primary layers:

- **Frontend (Next.js):** Public authentication, account and administrator portals. Interactive OAuth/OIDC consent remains incomplete, not a completed public page.
- **Identity/API (Go):** Scoped OIDC/OAuth endpoints and opt-in private gRPC, using `sqlc`/`pgx`. OAuth 2.1 is an active draft, not a finalized compliance label.
- **Storage/Queue:** PostgreSQL accounts/credentials/private data and deciding mutations; Redis currently carries earned session/preauthentication/token/replay authority, not only a disposable cache; NATS JetStream distributes durable metadata intents.

Planned target: primary PostgreSQL governs earned authority, deadlines, revocation,
replay, policy/security versions and repair barriers. Redis becomes non-authoritative
acceleration/coordination/rate limiting; loss cannot silently remove critical
limits. No SQL+Redis/provider atomicity is claimed.

### Zero-Trust & Security-First Safeguards

- **Opt-in mTLS/SPIFFE:** Workload certificates and exact-method SAN admission are implemented; deployment of SPIRE and consumers is a separate gate, not certificate-less communication.
- **Scoped OAuth/OIDC:** PKCE S256, key-bound refresh and applicable access-token DPoP controls exist. Interactive authorization and confidential authentication on code/refresh exchanges remain prerequisites. The first-party cookie-plus-browser-key profile is distinct from RFC 9449 resource-token DPoP.
- **WebAuthn:** Discoverable/named passkeys and actual assertion-UV recording exist; ordinary login currently permits non-UV assertions under preferred UV. The target requires actual UV on every passkey authentication and independently required MFA afterward. Physical hardware admission remains unverified.
- **Advanced Cryptography:** Argon2id password hashing, real AES-GCM-256 envelope encryption with environment-injected process-local key custody, and SHA-256 database-indexed recovery codes. Infisical/SOPS/Sealed Secrets are operator provisioning options, not live application key-fetch, cache or hot-rotation integrations.
- **Recovery, current versus planned:** The untyped saved-code pool consumes a code before restricted UV-passkey enrollment, but old-contact proof, privileged denial, final expiry continuity and a durable anti-chaining barrier are missing. Enabled TOTP still gates subsequent normal login. The target separates primary-bound MFA Backup Codes from ARC-plus-eligible-old-contact one-factor repair; neither grants general authority.
- **Step-up:** Fresh UV/TOTP and fixed-purpose actionproofs protect scoped mutations. Current Redis replay and incomplete final deciding-transaction continuity require SQL remediations, not a blanket one-use/freshness guarantee.

---

## 2. MVP Resource Optimization Strategy

To support early development and minimize hosting overhead during the **MVP (Minimum Viable Product) Phase**, the system incorporates lightweight fallbacks while retaining robust post-MVP production schemas in design:

- **Nginx Edge Ingress:** Replaces Traefik temporarily to route traffic based on path rules directly to loopback/private container ports, conserving memory. The API trusts forwarding headers only from exact `TRUSTED_PROXY_CIDRS`, and Nginx overwrites client-supplied `X-Forwarded-For`.
- **PostgreSQL Audit Ledger (`mvp_audit_logs`):** Replaces the ~1.2 GB RAM ClickHouse analytical cluster. Audit logs are written asynchronously via NATS to PostgreSQL, strictly maintaining append-only database policies and cryptographic ledger-chain integrity.

---

## 3. Repository Directory Structure

The project is structured as an Nx-driven monorepo to maximize code reuse, enforce atomic changes, and simplify linting/testing across Go and TypeScript:

```text
├── apps/
│   ├── web/                    # Next.js frontend application (Nx TypeScript)
│   └── identity-api/           # Core Identity Provider API (Go/Golang)
├── libs/
│   ├── ui/                     # Shared UI components (React/shadcn)
│   ├── utils/                  # Shared utilities and helpers
│   └── schemas/                # Protocol Buffers (.proto) for TS & Go generation
├── docs/                       # Comprehensive design & operational specifications
├── tools/page-gallery/          # Opt-in internal bilingual gallery tooling
└── README.md                   # This overview & entry point
```

---

## 4. Documentation Index

The policy owns target invariants, the assessment owns current-source findings,
and readiness owns evidence gates. Other guides apply that authority to their
scope; no documented prerequisite is completed merely because its design exists.

| Document                                                                          | Responsibility                                                                                                                                                     |
| --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [Authentication and Recovery Policy](docs/authentication-and-recovery-policy.md)  | Normative glossary, SEC01-SEC16, account/evidence/operation matrix and code/credential lifecycle.                                                                  |
| [Security Architecture Assessment](docs/security-architecture-assessment.md)      | Refreshed source strengths, conditional findings and missing prerequisites.                                                                                        |
| [ADR 0001](docs/adr/0001-authentication-recovery-and-security-state-authority.md) | Proposed decision, alternatives, consequences and approval boundary.                                                                                               |
| [Security Testing and Readiness](docs/security-testing-and-readiness.md)          | Required tests, independent/manual gates, standards and source-bound evidence.                                                                                     |
| [Documentation Alignment Report](docs/documentation-alignment-report.md)          | A-K map, inventory, supersessions, traceability and actual documentation checks.                                                                                   |
| [Revised Task Backlog](.github/tasks/registration-single-contract-tasks.md)       | T01-T42 IDs, bounded remediation subtasks, DAG and explicit acceptance. Historical `tasks.md`/local plans remain unchanged evidence, not current target authority. |
| [Architecture](docs/architecture.md)                                              | Current/target trust boundaries, IdP and service scope.                                                                                                            |
| [API Design](docs/api-design.md)                                                  | Current versus planned HTTP/gRPC/event contracts and client obligations.                                                                                           |
| [Data Architecture](docs/data-architecture.md)                                    | Persisted facts, constraints, lock order, revisions and security-state authority.                                                                                  |
| [Threat Modeling](docs/threat-modeling.md)                                        | STRIDE/precondition/control/gap/residual-risk/evidence matrix.                                                                                                     |
| [Registration Contract](docs/registration-contract.md)                            | One current service and planned fields, credentials, atomic birth and fresh-only session.                                                                          |
| [Frontend Pages](docs/frontend-pages.md)                                          | Distinct normal/MFA/repair/deletion journeys and browser authority boundaries.                                                                                     |
| [Localization](docs/localization.md)                                              | Typed bilingual presentation, exact secrets and stable ceremony/deadline contracts.                                                                                |
| [Localization Validation](docs/localization-validation.md)                        | Preserved historical counts and new bilingual/manual acceptance gaps.                                                                                              |
| [Client Integration](docs/client-integration.md)                                  | OIDC subject/proof profiles, private gRPC and consumer authority prerequisites.                                                                                    |
| [Admin Operations](docs/admin-operations.md)                                      | Privileged admission, provisioning, legal/audit boundaries and open release gates.                                                                                 |
| [DevOps Operations](docs/devops-operations.md)                                    | Canonical migration/configuration inventory, SQL/Redis, workers and rollout/rollback.                                                                              |
| [Container Deployment](docs/container-deployment.md)                              | Current local/container install, default-disabled capabilities and ingress gates.                                                                                  |
| [Disaster Recovery](docs/disaster-recovery.md)                                    | Restore quarantine, durability/failover and security rollback prevention.                                                                                          |
| [Compliance and Data Governance](docs/compliance-and-data-governance.md)          | Data/retention/rights/vendor obligations and non-certifying applicability.                                                                                         |
| [Page Gallery](docs/page-gallery.md)                                              | Sanitized illustrations only, not runtime/physical security evidence.                                                                                              |

---

The complete original acceptance narratives and execution input are available in
the [archived registration backlog](docs/history/registration-backlog-2026-11-23.md)
and [archived security architecture plan](docs/history/security-architecture-plan-2026-11-24.md).
Both are superseded history, not executable task sources. Shared documentation
does not require private agent settings or one machine's temporary artifacts.
See [reproducible documentation checks](docs/security-testing-and-readiness.md#reproducible-documentation-checks)
for the repository-owned checker and pinned optional diagram tooling.

## 5. Local Setup & Development (MVP Targeted Stack)

Ensure the following prerequisites are installed locally:

- **Docker & Docker Compose**
- **Go 1.26.x**, matching `.github/workflows/identity-api.yml`, with `GOTOOLCHAIN=local` after verifying the selected installed toolchain.
- **Node.js 24.18.0** from `.nvmrc` and **npm 11.21.0** matching CI. Verify actual command resolution; a minimal non-interactive PATH may need a local verified NVM `bin` prefix.
- **Workspace-local Nx** (invoke through `npm exec -- nx`)

> Note: `buf` (Protobuf) and `sqlc` (SQL codegen) are **not** installed
> globally. They are pinned as Go `tool` dependencies (in `libs/schemas/go.mod`
> and `apps/identity-api/go.mod` respectively) and invoked via `go tool`, so the
> Go toolchain is the only requirement.

### Getting Started

1. **Clone the repository:**

   ```bash
   git clone https://github.com/hatefsystems/identity.git
   cd identity
   ```

2. **Install frontend/workspace dependencies:**

   ```bash
    npm ci
   ```

3. **Create the local environment file:**

   ```bash
   cp .env.example .env
   ```

   Inject/export the selected variables into each process; copying the file does not automatically load it into Go. `APP_ENV` must be exactly `development`, `test`, or `production`; missing, empty, whitespace and unknown modes fail. Test is not a development exemption. KEK/pepper placeholders are intentionally unusable. Keep `TRUSTED_PROXY_CIDRS` empty for direct API access. The empty `STEPUP_REPLAY_HMAC_KEY` is development-only; test/production require a private base64 key of at least 32 decoded bytes, identical across replicas. See [key custody and rotation](docs/devops-operations.md#2-secrets-injection--configuration).

4. **Spin up local backing services (PostgreSQL, Redis, NATS):**

   ```bash
   docker compose -f docker-compose.dev.yml up -d
   ```

5. **Compile schemas and generate database code:**

   ```bash
   # Generate TypeScript and Go contracts from Proto definitions
   # (buf, pinned as a go tool in libs/schemas)
   npm exec -- nx run schemas:generate

   # Generate type-safe SQL queries from raw SQL definitions
   # (sqlc, pinned as a go tool in apps/identity-api)
   npm exec -- nx run identity-api:sqlc-generate
   ```

6. **Start frontend and backend development servers separately:**
   ```bash
   npm exec -- nx run identity-api:serve
   npm exec -- nx run web:dev
   ```
   Inject explicit `APP_ENV=development` and required settings. The portal uses one canonical ingress origin; separate dev-server ports are not a cross-origin authentication mode.

### Active Installation and Registration

Use the [canonical packaged migration inventory](docs/devops-operations.md#canonical-packaged-migration-inventory)
and [installation runbook](docs/admin-operations.md#migration-and-contraction),
not a duplicated version list here. Current packaged migrations are forward-only
and tracked by `public.identity_schema_version`; unsupported histories are refused,
not adopted or stamped. No Down/reset/live-target mutation is authorized by this
guide. Genesis, actual grants, custody inventory and policy approval remain separate
operator obligations; preserve historical migration/acceptance evidence.

`REGISTRATION_ENABLED=false` and `SMS_ENABLED=false` are safe defaults. When
explicitly enabled with complete dependencies and approved budgets, `/register`
verifies an existing owned Unicode email and Iranian mobile number, then creates
a resident UV-required passkey. It creates no mailbox, password, role or session;
completion requires normal login. Pending/email/passkey/receipt validity is
15m/10m/at-most-5m/1h. Capability+original-DPoP-key result reconciliation uses a
fresh proof after ambiguity; external email/SMS delivery is not exactly once.
See [HTTP contract](docs/api-design.md#15-new-account-registration) and
[enablement/cleanup](docs/devops-operations.md#registration-enablement-and-cleanup).

The target keeps one `/register` implementation but adds mandatory private
attributes, one selected verified contact, password/passkey/both and legal evidence;
only a known fresh committed birth may issue the expected-subject session. Those
features, two-family recovery, privileged admission and complete password/mobile
lifecycle remain Planned/Blocked. `/recover-account` stays deletion-exclusive.
See the [backlog](.github/tasks/registration-single-contract-tasks.md) and
[readiness gates](docs/security-testing-and-readiness.md). Final-source acceptance
remains required under [automated validation](docs/admin-operations.md#automated-validation);
this setup is not a test result or production approval.

---

## 6. Coding Standards & Contribution Policy

- **Go Code:** Formatted using `gofmt` and linted with `golangci-lint`. Avoid manual database manipulation or inline SQL; define queries in `.sql` files and let `sqlc` build type-safe abstractions.
- **TypeScript/React:** Enforce strict ESLint rules and Prettier formats defined in the workspace root.
- **Security Checks:** Every pull request is subject to static security analysis. Secret commits, plain-text PII storage, or insecure hashing algorithms (e.g., MD5, SHA-1, or raw bcrypt for passwords) are strictly rejected.

## Browser localization

English and Iranian Persian share the existing routes, including passkey-only
registration. Explicit browser preferences control language, calendar and time
zone without changing authentication or operation deadlines. Deletion notification
queue v2 freezes its locale; deploy compatible v1/v2 readers before v2 writers.
The configured SMS.ir VERIFY template remains operator-owned. See the
[localization contract](docs/localization.md) for maintenance and rollout gates.

## Internal Page Gallery

The versioned tooling in `tools/page-gallery/` produces sanitized offline
illustrations, not security or transaction evidence. It reuses the existing
browser acceptance helpers and requires separate formal browser acceptance.
Nothing runs during installation, ordinary builds or unrelated tests.

```bash
npm exec -- nx run web:check-page-gallery
# Only after fresh formal browser acceptance genuinely passes:
PAGE_GALLERY_BROWSER_ACCEPTANCE=passed npm exec -- nx run web:page-gallery
```

See [the fresh-clone workflow](docs/page-gallery.md) for Linux/WSL2 prerequisites,
acceptance requirements, resource costs, tests and ignored output locations.
