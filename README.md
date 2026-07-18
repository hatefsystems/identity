# Hatef Identity Platform (LDP)

The **Hatef Identity Platform (LDP)** is a centralized, privacy-first Identity Provider (IdP) and Single Sign-On (SSO) system designed to serve as the unified authentication and authorization backbone for the entire Hatef ecosystem (including the Search Engine, Email Service, and future applications). 

Built with Go (Golang) and Next.js, and managed inside an Nx monorepo, the platform enforces strict zero-trust security principles, enterprise-grade cryptography, and standards-compliant authentication protocols.

---

## 1. System Overview & Architecture

LDP is architected as a decentralized, highly scalable client-agnostic system consisting of three primary layers:
* **Frontend Layer (Next.js):** Handles the user-facing portal, OAuth/OIDC authorization pages, user profile management, and the administrator dashboard.
* **Identity & API Layer (Go):** The core Identity Provider (IdP) engine. Exposes standard OpenID Connect (OIDC) and OAuth 2.1 endpoints externally and high-performance gRPC services internally. Uses `sqlc` for compile-time type-safe PostgreSQL queries instead of heavy, unpredictable ORMs.
* **Storage & Queue Layer:**
  * **PostgreSQL:** Transactional storage for users, credentials, and state.
  * **Redis:** High-speed in-memory session caching, OAuth token metadata, and distributed rate limiting.
  * **NATS JetStream:** Lightweight, ultra-fast, and persistent message broker for asynchronous events.

### Zero-Trust & Security-First Safeguards
* **Mutual TLS (mTLS) with SPIFFE/SPIRE:** Dynamic, certificate-less service-to-service communication within the microservices grid, with method-level gRPC RBAC verified via SAN checks.
* **OAuth 2.1 & OpenID Connect Compliance:** Enforces Proof Key for Code Exchange (PKCE S256), Refresh Token Rotation (RTR), and sender-constrained access tokens via **DPoP (RFC 9449)**.
* **Phishing-Resistant Passwordless (WebAuthn / FIDO2):** Primary secure path using passkeys, platform authenticators, and discoverable credentials.
* **Advanced Cryptography:** NIST-compliant Argon2id password hashing, AES-GCM-256 Application-Layer Envelope Encryption for sensitive PII (via Infisical KMS), and SHA-256 for database-indexed recovery codes to prevent CPU DoS.

---

## 2. MVP Resource Optimization Strategy

To support early development and minimize hosting overhead during the **MVP (Minimum Viable Product) Phase**, the system incorporates lightweight fallbacks while retaining robust post-MVP production schemas in design:
* **Nginx Edge Ingress:** Replaces Traefik temporarily to route traffic based on path rules directly to container ports, conserving memory.
* **PostgreSQL Audit Ledger (`mvp_audit_logs`):** Replaces the ~1.2 GB RAM ClickHouse analytical cluster. Audit logs are written asynchronously via NATS to PostgreSQL, strictly maintaining append-only database policies and cryptographic ledger-chain integrity.

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
└── README.md                   # This overview & entry point
```

---

## 4. Documentation Index

The `docs/` directory contains deep-dive low-level (LLD) and high-level (HLD) specifications covering every facet of the system. Developers must consult these files before executing changes:

1. [System Architecture (`docs/architecture.md`)](docs/architecture.md)
   * Core design, communication flows, mTLS SPIFFE/SPIRE, monorepo setup, and the MVP Nginx routing.
2. [API Design (`docs/api-design.md`)](docs/api-design.md)
   * Full specification of REST APIs, OIDC well-known endpoints, gRPC protobuf methods, and response models.
3. [Data Architecture (`docs/data-architecture.md`)](docs/data-architecture.md)
   * PostgreSQL DDL, index optimizations, Redis key layouts, envelope encryption workflow, and the cryptographic append-only ledger chain.
4. [Threat Modeling (`docs/threat-modeling.md`)](docs/threat-modeling.md)
   * STRIDE security threat assessments, trust boundaries, mitigations, and application-level controls.
5. [Client Integration Guide (`docs/client-integration.md`)](docs/client-integration.md)
   * Guidelines for third-party or internal applications (Go, C++) to authenticate against the IdP via OIDC and validate tokens.
6. [Frontend Pages & UX (`docs/frontend-pages.md`)](docs/frontend-pages.md)
   * User interaction maps, UI templates, session cookie security (`__Host-` prefix), and Next.js Content Security Policy (CSP).
7. [DevOps & Operations (`docs/devops-operations.md`)](docs/devops-operations.md)
   * Kubernetes deployment, CI/CD pipeline structures with Nx, Prometheus metrics, and secret management.
8. [Disaster Recovery Plan (`docs/disaster-recovery.md`)](docs/disaster-recovery.md)
   * Data backup regimes, RTO/RPO metrics, recovery dry-runs, and ledger-integrity validation playbooks.

---

## 5. Local Setup & Development (MVP Targeted Stack)

Ensure the following prerequisites are installed locally:
* **Docker & Docker Compose**
* **Go (latest stable release)**
* **Node.js (LTS version)**
* **Nx CLI** (global or local runner)

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
   npm install
   ```

3. **Spin up local backing services (PostgreSQL, Redis, NATS):**
   ```bash
   docker compose -f docker-compose.dev.yml up -d
   ```

4. **Compile schemas and generate database code:**
   ```bash
   # Generate TypeScript and Go contracts from Proto definitions
   # (buf, pinned as a go tool in libs/schemas)
   nx generate schemas

   # Generate type-safe SQL queries from raw SQL definitions
   # (sqlc, pinned as a go tool in apps/identity-api)
   nx run identity-api:sqlc-generate
   ```

5. **Start frontend and backend development servers simultaneously:**
   ```bash
   nx run-many --target=serve --all
   ```

---

## 6. Coding Standards & Contribution Policy

* **Go Code:** Formatted using `gofmt` and linted with `golangci-lint`. Avoid manual database manipulation or inline SQL; define queries in `.sql` files and let `sqlc` build type-safe abstractions.
* **TypeScript/React:** Enforce strict ESLint rules and Prettier formats defined in the workspace root.
* **Security Checks:** Every pull request is subject to static security analysis. Secret commits, plain-text PII storage, or insecure hashing algorithms (e.g., MD5, SHA-1, or raw bcrypt for passwords) are strictly rejected.
