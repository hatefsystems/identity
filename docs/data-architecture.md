# Hatef Identity Platform - Data Architecture & Database Schemas

This document defines the storage topology, physical database schemas, application-layer encryption workflows, and logging systems for the Hatef Identity Platform. It covers PostgreSQL (primary transactional system), Redis (session, rate limit, and temporary storage), and ClickHouse (append-only analytical audit ledger).

---

## 1. PostgreSQL Relational Schema (DDL)

PostgreSQL serves as the primary system of record for accounts, authentication credentials, and access configurations. In Go, database interaction is implemented strictly using **`sqlc`** for compile-time type safety, working alongside the high-performance **`pgx`** (v5) driver. Object-Relational Mappers (ORMs) are prohibited.

### 1.1 Physical Schema Definition (DDL)

The following is a selected schema illustration, not executable production
provisioning or a substitute for the applied migrations in
`apps/identity-api/db/migrations`. Current storage is created by the single fresh
`00001_initial_schema.sql` baseline, tracked as version 1 in
`public.identity_schema_version`; additional account/auth/outbox/workflow columns
are described below and in that baseline. Canonical-v2 payloads do not contain their
own event UUID or chain digest, and contracted legal requests have no plaintext
narrative columns.

All legacy `public.goose_db_version` targets, untracked nonempty application schemas
and contradictory histories are refused, never upgraded or adopted. Fresh setup
requires an explicitly scoped PostgreSQL target plus matching fresh/isolated Redis
and NATS state with old writers stopped. Disposable-data confirmation does not
authorize resetting an existing named environment. See
[active setup](admin-operations.md#migration-and-contraction); historical acceptance
and prior plans retain their original evidence, not acceptance of this baseline.

```sql
-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Users Table (Core Identity)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) NOT NULL, -- Global UNIQUE constraint removed to allow reuse after Soft Delete/Deactivation
    password_hash VARCHAR(255) NULL, -- NULL for passwordless WebAuthn-only accounts
    backup_email_encrypted BYTEA NULL, -- Wrapped PII (AES-GCM-256)
    backup_email_blind_index VARCHAR(64) NULL, -- Cryptographic blind index: SHA-256(Email + Pepper)
    phone_encrypted BYTEA NULL,        -- Wrapped PII (AES-GCM-256)
    phone_blind_index VARCHAR(64) NULL, -- Cryptographic blind index: SHA-256(Phone + Pepper)
    mfa_totp_secret_encrypted BYTEA NULL, -- Wrapped PII (AES-GCM-256)
    is_mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(50) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'pending_verification', 'pending_deletion')),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE NULL -- Support soft deletion for Right to be Forgotten retention windows (30-day Grace Period)
);

-- Partial Unique Index to enforce email uniqueness only for active accounts, permitting reuse after soft-deletion
CREATE UNIQUE INDEX idx_users_email ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_status ON users(status);
CREATE UNIQUE INDEX idx_users_phone_blind ON users(phone_blind_index) WHERE deleted_at IS NULL AND phone_blind_index IS NOT NULL;
CREATE UNIQUE INDEX idx_users_backup_email_blind ON users(backup_email_blind_index) WHERE deleted_at IS NULL AND backup_email_blind_index IS NOT NULL;

-- 2. Roles & Permissions Table (RBAC)
CREATE TABLE roles (
    id VARCHAR(50) PRIMARY KEY,
    description TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE permissions (
    id VARCHAR(100) PRIMARY KEY,
    description TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE role_permissions (
    role_id VARCHAR(50) REFERENCES roles(id) ON DELETE CASCADE,
    permission_id VARCHAR(100) REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id VARCHAR(50) REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, role_id)
);

-- 3. WebAuthn Credentials Table
CREATE TABLE webauthn_credentials (
    id BYTEA PRIMARY KEY, -- Credential ID (raw binary)
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key BYTEA NOT NULL, -- Public Key in COSE format
    attestation_type VARCHAR(50) NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0, -- Signature counter to detect cloned devices
    user_present BOOLEAN NOT NULL DEFAULT TRUE,
    user_verified BOOLEAN NOT NULL DEFAULT FALSE,
    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state BOOLEAN NOT NULL DEFAULT FALSE,
    aaguid UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP WITH TIME ZONE NULL
);

CREATE INDEX idx_webauthn_user_id ON webauthn_credentials(user_id);

-- 4. Pending, session-bound TOTP enrollment state (active secrets stay on users)
CREATE TABLE mfa_totp_enrollments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(), -- public enrollment_id
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id UUID NOT NULL,
    purpose VARCHAR(32) NOT NULL CHECK (purpose IN ('maintenance')),
    secret_encrypted BYTEA NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_mfa_totp_enrollments_user ON mfa_totp_enrollments(user_id);
CREATE INDEX idx_mfa_totp_enrollments_expires ON mfa_totp_enrollments(expires_at);

-- 5. Recovery Codes (Backup Codes) Table
CREATE TABLE recovery_codes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(64) NOT NULL, -- deterministic SHA-256, or HMAC-SHA-256 with deployment pepper
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    used_at TIMESTAMP WITH TIME ZONE NULL
);

-- Index is critical to perform O(1) matching. It avoids sequential password-like decryption loops.
CREATE UNIQUE INDEX idx_recovery_codes_hash ON recovery_codes(code_hash) WHERE used_at IS NULL;
CREATE INDEX idx_recovery_codes_user_id ON recovery_codes(user_id);

-- 6. Canonical-v2 chains retain one node per event, including after payload erasure.
CREATE SEQUENCE public.audit_log_chain_seq AS BIGINT;
CREATE TABLE public.audit_log_chain (
    seq BIGINT PRIMARY KEY DEFAULT nextval('public.audit_log_chain_seq'),
    event_id UUID NOT NULL UNIQUE,
    leaf_hash BYTEA NOT NULL CHECK (octet_length(leaf_hash) = 32),
    chain_hash BYTEA NOT NULL CHECK (octet_length(chain_hash) = 32)
);
ALTER SEQUENCE public.audit_log_chain_seq OWNED BY public.audit_log_chain.seq;
CREATE SEQUENCE public.security_ledger_chain_seq AS BIGINT;
CREATE TABLE public.security_ledger_chain (
    seq BIGINT PRIMARY KEY DEFAULT nextval('public.security_ledger_chain_seq'),
    event_id UUID NOT NULL UNIQUE,
    leaf_hash BYTEA NOT NULL CHECK (octet_length(leaf_hash) = 32),
    chain_hash BYTEA NOT NULL CHECK (octet_length(chain_hash) = 32)
);
ALTER SEQUENCE public.security_ledger_chain_seq OWNED BY public.security_ledger_chain.seq;

-- MVP Class C payload, separate from immutable chain nodes.
CREATE TABLE mvp_audit_logs (
    seq BIGINT PRIMARY KEY REFERENCES public.audit_log_chain(seq) ON DELETE RESTRICT,
    user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    actor_id UUID NOT NULL,
    actor_spiffe_id VARCHAR(255) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    action_status VARCHAR(50) NOT NULL,
    client_ip VARCHAR(50) NOT NULL,
    user_agent TEXT NOT NULL,
    payload TEXT NOT NULL, -- Minimized JSON; audit records still contain personal data
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_mvp_audit_logs_event_type ON mvp_audit_logs(event_type);
CREATE INDEX idx_mvp_audit_logs_timestamp ON mvp_audit_logs(timestamp DESC);

-- 7. Security Event Ledger (Class B - Minimal, Persistent, Survives Account Deletion)
-- Purpose: retain minimal pseudonymized personal data to attribute an abusive or
-- security-relevant action AFTER an account is hard-deleted (e.g., a court inquiry
-- arriving at day 60 about an action taken before a day-30 deletion).
-- CRITICAL: rows here are decoupled from users(id). There is NO foreign key that would
-- cascade or null on account deletion; the stable account_ref persists independently.
CREATE TABLE security_event_ledger (
    seq BIGINT PRIMARY KEY REFERENCES public.security_ledger_chain(seq) ON DELETE RESTRICT,
    account_ref UUID NOT NULL,               -- Stable identity reference; survives hard-delete (NO FK to users)
    identity_blind_index VARCHAR(64) NULL,   -- HMAC-SHA256(normalized identity, keyed by pepper); no raw email/phone
    blind_index_version SMALLINT NOT NULL CHECK (blind_index_version >= 0),
    event_type VARCHAR(100) NOT NULL,        -- e.g., 'auth.login', 'token.issued', 'security.rtr_breach'
    client_ip VARCHAR(50) NULL,
    ip_subnet VARCHAR(50) NULL,              -- /24 (IPv4) or /48 (IPv6) grouping
    user_agent TEXT NULL,
    device_fingerprint VARCHAR(128) NULL,
    client_id VARCHAR(100) NULL,             -- OAuth client that received an authorization, if any
    scope TEXT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retain_until TIMESTAMP WITH TIME ZONE NOT NULL -- Event occurrence + SECURITY_LEDGER_RETENTION (8760h = 365 days)
);

-- Attribution lookups by identity (court supplies an identifier -> we compute the blind index)
CREATE INDEX idx_security_ledger_blind_index ON security_event_ledger(identity_blind_index);
CREATE INDEX idx_security_ledger_account_ref ON security_event_ledger(account_ref);
CREATE INDEX idx_security_ledger_retention ON security_event_ledger(retain_until, seq);
CREATE INDEX idx_security_ledger_event_type ON security_event_ledger(event_type);

-- 8. Legal Holds (Precedence Lock over erasure eligibility)
-- An active hold defers Class A/Class B erasure, never the account recovery deadline.
-- Holds > retention. A hold has no predefined duration; it stays until explicitly released.
CREATE TABLE legal_holds (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    account_ref UUID NOT NULL,               -- Subject reference (matches security_event_ledger.account_ref)
    request_kind TEXT NOT NULL DEFAULT 'legal_hold' CHECK (request_kind IN ('legal_hold','preservation')),
    idempotency_key UUID,
    details_encrypted BYTEA,                 -- Record/account/kind-bound reason, authority and legal basis
    details_purged_at TIMESTAMPTZ,
    applied_by UUID NOT NULL,                -- Actor (e.g., DPO / Legal) who created the hold
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    review_at TIMESTAMP WITH TIME ZONE NULL, -- Optional expected review date (advisory only)
    released_at TIMESTAMP WITH TIME ZONE NULL,
    released_by UUID NULL,
    CONSTRAINT legal_holds_encrypted_or_purged CHECK (
        (details_encrypted IS NOT NULL AND octet_length(details_encrypted) > 0 AND details_purged_at IS NULL)
        OR (details_encrypted IS NULL AND NOT is_active AND released_at IS NOT NULL AND details_purged_at IS NOT NULL)
    )
);

-- The hard-delete Cron and the ledger purge job MUST consult this index before purging.
CREATE INDEX idx_legal_holds_active ON legal_holds(account_ref) WHERE is_active = TRUE;
CREATE UNIQUE INDEX legal_holds_request_identity ON legal_holds(account_ref, request_kind, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
```

### 1.1.1 Persistence & Deletion Rules for Ledger and Holds

- **`security_event_ledger` is intentionally NOT linked to `users(id)`.** The ledger keeps the original `account_ref` and an `identity_blind_index` after account deletion, subject to its own retention/holds. This is **pseudonymized personal data**, not anonymous or non-PII. The nullable Class C `user_id` link and minimized payload do not anonymize `mvp_audit_logs`: baseline administrative audit retains actor/network metadata, linkable action/hold references, timestamps and response digests, which are personal data too.
- **Purge of the ledger** is driven by `retain_until` and active holds (scheduled job), never by account deletion alone.
- **Legal Hold precedence:** Both the 30-day hard-delete worker and the ledger purge recheck independent active holds on the original `account_ref`. Protection does not depend on a surviving user row. Candidate prefilter exclusions are not individually inspected skips; ledger skipped receipts/counts describe only candidates actually rechecked after locks. Release resumes original clocks, never resets them.
- **No raw email/phone identifiers in Class B.** Exact identity lookup uses the keyed blind index; Class A contacts follow their own deletion policy. Stable references, IP/subnet, user-agent and device/client metadata remain personal data. Removing raw identifiers is minimization, not anonymity.
- **Independent requests and original clocks:** `review_at` and preservation `expires_at` are advisory, never automatic release. Releasing one request cannot release another. Once no hold protects the subject, original retention clocks resume, potentially making data eligible immediately; no recovery extension, clock reset, restoration of purged data or immutable evidence snapshot is created.

### 1.1.2 Retention Proof and Durable Head (Task 5.4)

The single fresh baseline creates permanently retained canonical-v2 chains and
separate erasable payloads directly, with exact terminal head advancement and
audit coordination separate from purge-run locking. It contains no v1 checkpoint/
routine transition or historical data repair. Supported entrypoints refuse all
legacy history and untracked nonempty application schemas; inventory failure is
not an empty-history result. There is no in-place v1/v2 upgrade or automatic
adoption, reset or rehash. Old outbox/JetStream envelopes require separate inventory/
drain/quarantine and must not enter the fresh isolated environment. Migrations
neither initialize genesis nor provision deployment logins. Operators must
inventory/verify history and explicitly bootstrap both
known terminal positions with writers stopped as described in
[admin operations](admin-operations.md#security-ledger-retention-task-54).

| Protected relation | State |
|---|---|
| `audit_log_chain`, `security_ledger_chain` | `seq bigint`, unique `event_id uuid`, `leaf_hash bytea(32)`, `chain_hash bytea(32)`; one append-only node per event with no expiry. |
| `audit_log_head`, `security_ledger_head` | `singleton boolean` primary key constrained to true, nonnegative `seq bigint`, 32-byte `chain_hash`; each head must match its actual terminal node, or its derived chain-specific genesis when empty. |
| `security_ledger_erasures` | Positive inclusive `first_seq`, `last_seq`, `operation_id uuid`, `erased_at timestamptz`; append-only span annotations, not checkpoint digests or policy certificates. |
| `security_ledger_retention_settings` | `singleton boolean` primary key constrained to true, `audit_subject text`; explicitly provisioned subject binding for maintenance receipts, never worker-writable. |

Genesis is explicit initialized proof state, not an inference from empty payloads.
Missing/malformed heads and terminal mismatches fail closed even for historical or
empty requested ranges. Numeric sequence allocation gaps are legal; erasure spans
are maximally coalesced per new batch, not globally compacted checkpoints. All
chain event IDs/digests and each operation's erasure/receipt metadata survive
payload erasure. Storage is not constant-size, and digests/UUIDs may remain linkable
to retained external or internal records even without a payload/account column.

The purge candidate index is `(retain_until, seq)`. Bounded keyset traversal uses
one database cutoff and logical high-water mark per run, never OFFSET over a
shrinking table. Eligibility is strict `retain_until < cutoff`, and any active
hold on the original account blocks deletion even without a `users` row. Review
dates do not expire holds; last-hold release resumes the original expiry.

Signer and purge transactions use READ COMMITTED and the common lock order:
ledger coordination advisory transaction lock (`5200002`), account locks in UUID
order, then deterministic row locks. No account-locked path may acquire the
ledger lock later. Purge overlap uses a separate run lock (`5200003`), not the
daemon-lifetime signer lock (`5200001`). Audit head coordination is `5200004`,
not purge-run `5200003`. After account-lock acquisition a fresh statement rechecks
holds and canonical leaves; the fixed cutoff/high-water excludes late/backdated
rows beyond that bound.

There is no v2 maintenance function/owner or purge EXECUTE. Dedicated non-owner
`identity_ledger_purge` gets required Class B payload/chain/head/erasure/hold/settings
SELECT, payload DELETE, erasure INSERT and receipt-outbox INSERT only, no sequence,
chain/head-write/role/DDL authority. The trusted Go worker enforces retention/holds
and canonical candidate rechecks; SQL does not constrain arbitrary DELETE by a
compromised purge credential to these predicates. Signer separately gets chain/
payload append, chain sequence USAGE, both heads and ledger erasures SELECT, and
verified `advance_chain_head` EXECUTE. Payload UPDATE/TRUNCATE and chain/erasure
UPDATE/DELETE/TRUNCATE guards remain armed; Class C permits only its existing
FK `user_id` nulling. No trigger bypass is an operational exemption.

Canonical-leaf rechecks, exact-row DELETE, span annotations and sanitized Class C
`admin_action` receipt intent commit atomically; dry-run rolls them back. Inspected
held-only batches write one skipped receipt with an empty span manifest, but
prefiltered holds are not individually inspected/reported. New receipts commit
`span_manifest_version=1` and SHA-256 of the domain-separated ordered inclusive
span manifest, plus operation/cutoff/count/high-water metadata. Retained structural
verification uses bounded read-only REPEATABLE READ snapshots and checks chain
links, retained leaves and absent-payload annotations. It does not prove receipt
chaining or legal authorization. Legitimate pending receipts do not block signer
restart. The separate bounded read-only `ledger-receipts` CLI uses its own SELECT-
only credentials to correlate erasures, receipt outbox and Class C linkage
coverage in hash-only pages with correlated receipt bodies/leaves checked separately,
distinguishing pending/chained/legacy-unbound/missing/invalid/incomplete.
PubAck or `published_at` is not chaining; missing retained material is unavailable
assurance. All-erased is not content verification. Neither operation independently
detects coherent privileged rewrite/rollback; external anchoring stays deferred.


### 1.1.3 Lifecycle Revisions and Outbox (Task 6.3)

The fresh baseline includes nonnegative `users.lifecycle_revision`, independent
of credential `auth_version`/`auth_epoch`.
Explicit Go business transactions advance it and insert metadata-only lifecycle
intent in `event_outbox` in the same commit. No CDC or lifecycle triggers are
installed. Existing users begin at 0 without synthesized history; transactional
creation starts at 1, and purge uses the removed locked user's last revision plus
one for its terminal event.

Nullable `lifecycle_user_id`/`lifecycle_revision` outbox metadata supports indexed
per-account ordering and uniqueness without a user FK, so tombstones survive
erasure. Existing admin and legacy deletion rows remain valid. The lifecycle
publisher excludes `admin_action` rows and unrelated subjects; a lower unpublished
revision blocks that account's later events even during retry. Stable IDs/times
and acknowledged delivery bookkeeping permit replay after a crash, not loss of
accepted intent.

Payloads exclude profile values/secrets but contain linkable identifiers/times.
Apply approved transport/acknowledged-outbox retention, preserve active-held rows,
and never expire unpublished intent. Raw legacy `{"user_id":"<uuid>"}` deletions
are adapted at delivery without rewriting them or inventing revisions. The
broadcast stream is not the audit work queue or legal-evidence archive. See the
[wire contract](api-design.md#3-asynchronous-events-nats-jetstream) and
[operations boundaries](devops-operations.md#user-lifecycle-publisher-task-63).

### 1.1.4 Portal Names and Profile Transactions (Task 7.3)

The fresh baseline includes `users.display_name` and
`webauthn_credentials.name` as non-null text defaulting to the empty string, with
`char_length(...) <= 80` constraints. Existing users/credentials remain valid;
names are optional, not unique, and no historical profile events are synthesized.
Application validation rejects invalid UTF-8, control and line-separator characters
before trimming outer Unicode whitespace and counting Unicode code points.

Both fields are Class A profile data, erased with their owning rows. Registration
temporarily freezes the optional credential label in its bounded Redis ceremony;
it expires with that challenge and cannot be replaced by the verification body.
Names are not copied into audit or lifecycle payload values. Sanitized ordinary
audit metadata uses the existing best-effort recorder, not a new ledger category.

Profile updates acquire the common account advisory/row lock, recheck active
status and captured auth-version, and compare the exact lifecycle revision.
A no-op at the current revision writes nothing. A real update, one revision
increment and one metadata-only `identity.user.updated` v2 outbox row commit
together; outbox failure rolls back the name. Credential auth-version/epoch and
sessions are unchanged. HTTP revisions stay decimal strings to avoid JavaScript
rounding. gRPC name and revision are read from the same minimized snapshot.

V1 lifecycle validation/producers are retained. V2 adds only the explicit
`display_name` changed-field capability; both versions and legacy v1 tombstones
remain readable. Unknown versions/fields still fail validation. Retain additive
columns and v2-compatible publisher/readers during rollback, and upgrade downstream
consumers before deploying name writers.

### 1.2 `sqlc` & `pgx` Configurations

To generate the idiomatic, type-safe Go code, the database queries must be defined inside `.sql` files.

#### Sample `query.sql` for Recovery Code verification and atomic deletion:
```sql
-- name: GetActiveRecoveryCodeForUpdate :one
SELECT id, user_id, code_hash 
FROM recovery_codes 
WHERE code_hash = $1 AND user_id = $2 AND used_at IS NULL 
FOR UPDATE;

-- name: DeleteRecoveryCodePhysically :exec
DELETE FROM recovery_codes 
WHERE id = $1;
```

#### Verification Lifecycle:
1. When a user supplies a recovery code, the Go backend SHA-256 hashes the code.
2. The hash is used in a single query via `GetActiveRecoveryCodeForUpdate` passing both the hash and the authenticating `user_id`. The database uses `idx_recovery_codes_hash` to locate it in $O(1)$ time and applies a row-level lock (`FOR UPDATE`).
3. If a match is found, the backend directly triggers its permanent, transactional physical deletion (`DeleteRecoveryCodePhysically`) in the same ACID database transaction, avoiding redundant intermediate database UPDATE operations.

#### Factor-mutation lock invariant:

Passkey deletion and TOTP disablement both begin a transaction and acquire `GetUserByIDForUpdate` first. Passkey deletion then locks that user's WebAuthn rows in stable credential-ID order before it counts and deletes. TOTP disablement counts passkeys while holding the same user-row mutex before clearing the secret. This common lock order serializes cross-factor races and guarantees at least one passkey remains, reflecting that WebAuthn is currently the only browser session-issuing login surface.

---

## 2. PII Storage & Application-Layer Encryption

To comply with high-security privacy directives, Personal Identifiable Information (PII) is encrypted at the application layer before reaching PostgreSQL. This is handled using **AES-GCM-256 Envelope Encryption**.

```
                           +--------------------------------------+
                           |          Infisical (KMS)             |
                           +--------------------------------------+
                                              |
                                              | Retrieves master KEK (Key Encryption Key)
                                              v
+------------------+       +--------------------------------------+
| Plaintext PII    | ----> |       Go Application Layer           |
| (Phone / Email)  |       |                                      |
+------------------+       | 1. Generates 256-bit cryptographically|
                           |    secure random DEK (Data Enc Key).  |
                           | 2. Encrypts PII with DEK (AES-GCM).  |
                           | 3. Encrypts DEK with KEK (AES-GCM).  |
                           +--------------------------------------+
                                              |
                                              | Writes encrypted payload to database
                                              v
                           +--------------------------------------+
                           |          PostgreSQL                  |
                           |                                      |
                           | { ciphertext, encrypted_dek, nonce } |
                           +--------------------------------------+
```

### 2.1 Cryptographic Implementation Details

Each encrypted record has a composite structure serialized into a binary payload (`BYTEA`) featuring distinct nonces and authenticated tags for both layers of encryption:

```
+-------------------------------------------------------------------------------------------------------------------+
| Version (1 Byte) | DEK-Wrap Nonce (12 Bytes) | DEK-Wrap Tag (16 Bytes) | PII-Enc Nonce (12 Bytes) | PII-Enc Tag (16 Bytes) |
+-------------------------------------------------------------------------------------------------------------------+
| Encrypted DEK (Variable Size)                                                                                     |
+-------------------------------------------------------------------------------------------------------------------+
| Encrypted Ciphertext PII (Variable Size)                                                                          |
+-------------------------------------------------------------------------------------------------------------------+
```

1. **Version (1 byte):** Enables key rotation and cryptopackage schema upgrades.
2. **DEK-Wrap Nonce (12 bytes) & Tag (16 bytes):** Cryptographically secure nonce and GCM authentication tag generated for wrapping the DEK with the Master KEK.
3. **PII-Enc Nonce (12 bytes) & Tag (16 bytes):** Cryptographically secure nonce and GCM authentication tag generated for encrypting the PII with the local DEK.
4. **Encrypted DEK:** The Data Encryption Key (DEK) used to encrypt the payload, wrapped by the Master Key Encryption Key (KEK) fetched from Infisical.
5. **Encrypted Ciphertext:** The GCM-authenticated ciphertext of the PII value.

### 2.2 Cryptographic Blind Indexes for Secure Exact-Match Searches

To prevent $O(N)$ full-table decryptions when performing user queries by phone number or backup email, the database stores a secure cryptographic blind index:

$$\text{blind\_index} = \text{HMAC-SHA256}_{\text{secret\_pepper}}(\text{lowercase}(\text{NFKC}(\text{trim}(\text{identity}))))$$

This is the existing server-side keyed construction, not plain concatenation or anonymous data. Legal email attribution uses the same normalization; callers must not introduce provider-specific normalization or send the digest/pepper material to the browser. This documentation does not add phone attribution or historical multi-pepper search.

- **Uniqueness & Indexing:** Blind indexes are stored in separate database columns (`phone_blind_index`, `backup_email_blind_index`) and indexed via B-tree. This enables $O(1)$ fast lookups without revealing plain text.
- **Salt/Pepper Management:** The secret pepper is retrieved dynamically at application bootstrap from Infisical and kept strictly in memory. Non-exact queries (such as wildcards or substring matches) on PII columns are prohibited to ensure data minimization.

---

## 3. Redis Session & OTP Storage Layout

Redis provides low-latency credential authority and temporary state. Session/grant misses are not cache misses that may be reconstructed from a signed token. Task 7.3 also shares WebAuthn ceremonies across API replicas, separately from the existing session/grant and DPoP namespaces.

### 3.1 Redis Keyspaces & TTL Policies

| Keyspace Pattern | Data Type | TTL Value | Purpose |
| :--- | :--- | :--- | :--- |
| `identity:session:v1:token:<token_hash>` | Hash | Remaining idle lifetime | User, kind, captured auth-version, IP/device metadata, key binding, absolute/idle times and restricted-enrollment claim. Normal sessions default to 2h idle / 24h absolute; restricted sessions have a hard 10-minute lifetime. |
| `identity:session:v1:id:<n>:<user_id>:<session_id>` | String | Idle lifetime; revoked marker until absolute expiry | Owner-scoped public-ID lookup. `<n>` is the UTF-8 byte length of the user ID. Revoked markers prevent delayed creation retries from restoring authority. |
| `identity:session:v1:user:<n>:<user_id>` | Hash | Latest indexed absolute expiry | Owner index for live-session lists and atomic account-wide session revocation. |
| `identity:v1:oauth:code:<code_hash>` | String (JSON) | At most 60s, capped by parent absolute expiry | Single-use code with captured normal-session ID/version, client, redirect URI and PKCE challenge. Consumed with `GETDEL`. |
| `identity:v1:oauth:grant:<grant_id>` | String (JSON) | Parent browser absolute expiry; client grant at most 10m | Immutable principal/client/scope/key/session/version binding and active/revoked state. Every access JWT references this authority. |
| `identity:v1:oauth:refresh:<token_hash>` | String (JSON) | Grant lifetime | Active/rotated/revoked refresh metadata. Active-token expiry is checked separately; retired evidence survives while the grant can remain usable. Atomic rotation writes the successor and retires the old token together. |
| `identity:v1:oauth:user:<user_id>` | ZSET | Latest grant expiry | Account-wide grant index, never a global key scan on the request path. |
| `dpop:v1:replay:<scoped_hash>` | String | Complete acceptance window plus a rounded-up Redis millisecond | Hash of realm, verified JKT and JTI; includes allowed future-clock skew and proof-age skew rather than a fixed 60-second cache. |
| `dpop:v1:nonce:<scoped_hash>` | String | 5 Minutes | Single-use nonce bound to the authorization-server, resource-origin or dedicated browser realm and verified proof key. No raw proof, nonce or JTI is stored in a key. |
| `webauthn:challenge:v1:<sha256_challenge>` | Hash | Ceremony TTL, default 5m, maximum 15m | Versioned, bounded pending ceremony with exact flow/account/session/applicable DPoP binding and frozen optional registration name. Atomic binding check precedes deletion; wrong bindings do not consume it. |
| `otp:sms:secret:{verification_id}` | Hash | 3 Minutes | Pending phone proof addressed by a 256-bit opaque ID and bound to the exact user, initiating session, normalized phone, HMAC-SHA-256 code hash, issue time, and attempt counter. |
| `recovery:transaction:{sha256(transaction_id)}` | String | 10 Minutes | One-time recovery-start subject. `GETDEL` consumes the transaction before the submitted recovery code is evaluated, so spent, invalid, and replayed transactions converge on the same failure surface. |
| `rate:otp:phone:{phone}` | String | 1 Hour | Tracks SMS OTP requests made to a specific phone number. |
| `rate:otp:subnet:{ip_subnet}` | String | 1 Hour | Tracks SMS OTP requests made by an IP subnet to prevent distributed spam. |
| `stepup:replay:v1:{hmac_sha256}` | String | Remaining logical lifetime (<=5 min) | Cluster-wide replay claim for either a grant JTI or a TOTP exchange. The suffix is HMAC-SHA-256 over the namespaced logical identity with `STEPUP_REPLAY_HMAC_KEY`; Redis never receives a raw JTI, user ID, or guessable TOTP-derived value. Atomic `SET NX` permits exactly one claimant. |
| `rate:stepup:verify:subnet:{ip_subnet}` | ZSET | 1 Hour | Bounds Step-up verification attempts per IP subnet. |
| `rate:stepup:verify:account:minute:{user_id}` | ZSET | 1 Minute | Bounds Step-up verification attempts per account per minute. This is the window that keeps a 6-digit TOTP passcode out of brute-force reach. |
| `rate:stepup:verify:account:hour:{user_id}` | ZSET | 1 Hour | Bounds sustained Step-up verification attempts per account. |

> **Deployment invariant:** outside explicit development, Step-up replay claims
> use Redis and every replica must share the same `STEPUP_REPLAY_HMAC_KEY`.
> `SET NX` failures and Redis errors fail closed. The in-process replay guard is a
> development-only fallback; it is not safe for horizontally scaled deployment.
> Task 6.2 likewise uses shared Redis for browser sessions, OAuth codes/grants,
> refresh families, and DPoP replay/nonces. Memory backing is only for explicit
> development without Redis and with gRPC disabled; dependency failures never
> trigger fallback. Multi-key session/grant operations require standalone Redis,
> not Redis Cluster.

User JWTs carry `principal_type`, `grant_id`, `sid`, and the captured numeric
`auth_version`. A captured zero is valid; omission is not. Redis JSON stores
versions as decimal strings to prevent Lua double rounding, and session hashes
also preserve exact time/version strings. Each user-token RPC checks current
primary-PostgreSQL status/version after reading Redis authority. Restrictions and
reactivation therefore cannot restore old credentials after failed cache cleanup.
Client grants have no user/session/version authority and do not perform a user
lookup. No successful authorization decision is positively cached.

Normal browser cookies are not sufficient authority: Task 7.3 requires a bound
DPoP key and checks cookie kind/account/expected key/session intent before shared
nonce/replay consumption. Failed authorization does not renew idle activity.
The WebAuthn store preserves 64-bit auth versions/epochs as exact decimal strings,
not Lua JSON numbers; rejects collisions/oversized or corrupt state; uses native
TTLs and two-second request deadlines; and never falls back after Redis errors.
Anonymous login options/verification and reclaim options share subnet rate limits
before allocating challenge/nonce state.

Redis eviction/reset fails closed and requires reauthentication or a new ceremony. Use appropriate
ACLs/TLS and an eviction/availability policy suitable for authority, not a
disposable performance cache. Never restore stale session/grant/replay snapshots
after revocation; invalidate the namespace and require new authentication instead.
Client-assertion replay storage remains a separate single-process boundary; shared
portal/WebAuthn state does not claim unrelated OAuth client-assertion scaling.

### 3.2 OTP Rate Limiting Structure

To prevent toll-fraud and SMS bombing, SMS OTP triggers are tracked across independent Redis keys instead of composite structures (e.g., `phone:IP`).

#### Sliding Window Implementation via Redis sorted sets (ZSET):
* **Key:** `rate:otp:phone:{phone}`
* **Key:** `rate:otp:subnet:{ip_subnet}` (Subnet calculations group IPs to `/24` for IPv4 and `/48` for IPv6 to block proxy-rotation scripts).
* **Process:** On each request, execution is performed atomically inside a single round-trip using a Redis Lua script:
  ```lua
  local key = KEYS[1]
  local now = tonumber(ARGV[1])
  local window = tonumber(ARGV[2])
  local limit = tonumber(ARGV[3])
  local member = ARGV[4]

  redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
  local current_requests = redis.call('ZCARD', key)
  if current_requests < limit then
      redis.call('ZADD', key, now, member)
      redis.call('EXPIRE', key, window)
      return 1 -- Allowed
  else
      return 0 -- Rejected
  end
  ```

---

## 4. ClickHouse Analytical Append-Only Schema (Post-MVP Target)

> ⚠️ **MVP Phase Postponement:** To conserve system resources and avoid over 1.2 GB of RAM overhead on MVP servers, **ClickHouse is completely bypassed in the initial phase**. In its place, the Go backend uses the **`mvp_audit_logs`** table in PostgreSQL (defined in Section 1.1) for audit trailing. The ClickHouse specifications detailed below are retained exclusively as the target deployment blueprint for the post-MVP production phase.

ClickHouse is designed to store audit logs and security analytics. Administrative users do not have `ALTER...DELETE` rights.

### 4.1 ClickHouse DDL definition

```sql
CREATE TABLE audit_logs (
    event_id UUID DEFAULT generateUUIDv4(),
    user_id Nullable(UUID),
    actor_id UUID,                -- Admin/system executing the task
    actor_spiffe_id String,       -- Captured client SPIFFE ID
    event_type LowCardinality(String), -- e.g., 'user.banned', 'role.assigned'
    action_status Enum('success' = 1, 'failed' = 2),
    client_ip String,
    user_agent String,
    payload String,               -- Minimized JSON; audit records still contain personal data
    timestamp DateTime64(6, 'UTC') DEFAULT now64(),
    
    -- Chained Cryptographic hash for auditing integrity
    chain_hash FixedString(32)    -- SHA-256 hash chaining records together
) ENGINE = MergeTree()
ORDER BY (event_type, timestamp, actor_id);
```

### 4.2 Cryptographic Log Chaining & Batch Signing

To prevent parallel write bottlenecks and lock contention inherent to multi-writer column-oriented ClickHouse configurations, the cryptographic chaining ledger is decoupled from direct database writes:

1. **Asynchronous Ledger Queue:** Go API instances write log records concurrently to a partitioned NATS JetStream queue subject `identity.audit.logs`.
2. **Single-Threaded Signing Consumer:** The current MVP consumer batches both PostgreSQL payloads and their separate canonical-v2 chain nodes, then advances both heads in the append transaction. ClickHouse remains a future deployment blueprint, not the current writer or proof layout.
3. **Current MVP Canonical-v2 Formula:**
   $$\text{leaf\_hash}(N) = \text{SHA-256}\Big(\text{leaf\_prefix} \ \big|\big|\ \text{serialize}\big(\text{record}(N)\big)\Big)$$
   $$\text{chain\_hash}(N) = \text{SHA-256}\Big(\text{chain\_prefix} \ \big|\big|\ \text{chain\_hash}(N-1) \ \big|\big|\ \text{leaf\_hash}(N)\Big)$$

Where:
* `record(N)` is serialized by the existing Go canonical serializer with chain-specific NUL-terminated prefixes; nullable Class C `user_id` is excluded. Stored bytes/hashes are never retroactively rewritten.
* Verification checks links/retained leaves/ledger annotations against the durable heads. Monitoring integration and thresholds remain operator gates; sequence allocation gaps alone are not integrity failures.

### Task 5.5 workflow storage

The fresh baseline includes immutable governance artifacts and policy binding,
legal cases and encrypted revision/review/response history, historical subject
associations, existing-hold links, advisory hold-review state, business replay
records, case-free monthly/year counters and frozen report artifacts. No workflow
subject reference cascades through `users`; original account identity survives
hard deletion while its approved legal purpose remains.

Ciphertexts are bound to their record, scope, purpose and revision. General audit
holds opaque action IDs and bounded outcomes/counts, not case narratives or their
hashes. Cleanup deletes restricted history/associations after original expiry
only when no historically associated subject is held; replay stubs remain under
explicit policy approval. Counters contain no per-case IDs and never derive
request totals from audit attempts. Coverage starts at the first committed
counter. Report payloads and replay results preserve exact bytes; JSONB would
reorder or reformat an approved artifact. Report approvals are revision
bound; year-version synchronization prevents an unchanged approval from covering
different counts. See the [operational gate](admin-operations.md#legal-review-and-transparency-task-55)
for actual tombstone fields and pending retention approval.

### Retained Metadata Inventory

These are actual current inventories, not blanket legal approval. `no_expiry`
means no implemented finite expiry, not anonymous data, approved indefinite
retention or deletion from external records/backups. Baseline's eleven-field hold
and workflow's five-field replay approvals do not cover every table below.
The DDL migrations and current cleanup/replay serializers remain the source of
truth; restore their state consistently and include them in notices/ROPA/DPIA/DSAR.

| Relation / material | Retained fields and linkage | Actual lifetime / cleanup |
|---|---|---|
| `admin_action_contexts` | `action_id`, nullable `account_ref`, `details_encrypted`, `created_at`, `retain_until`; encrypted moderation/inquiry context is still personal data. | Original `created_at +` approved context duration; strict `retain_until < cutoff`, hold-aware physical cleanup. No clock rewriting. |
| Contracted `legal_holds` | `id`, `account_ref`, `applied_by`, `is_active`, `applied_at`, `review_at`, `released_at`, `released_by`, `request_kind`, nullable `idempotency_key`, `details_purged_at`; `details_encrypted` persists while needed. Original subject/actor/time linkage survives. | Active until explicit release. Narrative clears only strict-before approved release-relative expiry and absent all independent active holds. Eleven-field tombstone remains `no_expiry`; no runtime plaintext columns in the fresh baseline. |
| Live workflow/case associations | `legal_cases` original clocks, policy/state/revision and preparer/approver/auth-version fields; `legal_case_subjects(case_id,account_ref,current)`; `legal_case_holds(case_id,hold_id,account_ref,current)`. Historical associations remain even when not current. | Expiry is `min(created_at + max_age, closed_at + closed_retention)` where closed; at-or-after equality cleanup only without any historically associated subject hold. Reviews/retries/releases do not reset it. |
| `legal_workflow_events` | `id`, `scope`, `scope_kind`, `revision`, `purpose`, `actor`, `auth_version`, `action_id`, `created_at`, `body_encrypted`. Bound encrypted revision/review/response/delivery narratives are restricted personal data. | Physical deletion with case/hold-review cleanup at original workflow expiry, subject to independent holds. Not a permanent narrative archive. |
| `legal_hold_reviews` | `hold_id`, `account_ref`, `policy_id`, `version`, nullable `next_review_at`; original `legal_holds.review_at` is not overwritten. | At-or-after release-relative approved expiry, absent any active hold on account; state and encrypted history are deleted, not represented as never-created history. |
| `legal_workflow_replays` | Before cleanup, five fields plus `event_id` joining encrypted history. After cleanup exactly `operation`, `scope`, `idempotency_key`, `result_id`, `erased` (`event_id=NULL`). `hold_review` scope/result joins the surviving hold tombstone, so subject/actor/time correlation remains possible. Case scope/result joins a case sentinel/external intake. | `no_expiry` remains the supported replay protocol. No narratives, actors or fingerprints inside the erased stub, but no claim of absence of joinable personal metadata. |
| Erased `legal_cases` sentinel | Retains `id`, `status='erased'`, zero `version`, `content_revision`, `proposal_revision`, `reviewed_revision`, `response_content_revision`, `approved_proposal_revision`, and `decision='pending'`. Policy, received/created/closed/review/expiry times, content/response event IDs, preparer/approver/auth versions become NULL; associations/history are deleted. | No sentinel expiry implemented (`no_expiry`). ID remains correlatable with replay or external records; it is not a reconstructed case or narrative. |
| `legal_transparency_reports` | `id`, `version`, `year`, `data_version`, `schema_version`, `policy_id`, exact `payload`, `digest`, `status`, `prepared_by`, `prepared_auth_version`, `prepared_at`, nullable `approved_by`, `approved_auth_version`, `approved_at`, `downloaded_at`. Restricted personal approval provenance differs from export-safe aggregate payload. | No report/provenance cleanup implemented (`no_expiry`). Snapshot/provenance is immutable apart from permitted approval/download transitions. |
| `legal_transparency_replays` | `operation`, `scope`, `idempotency_key`, bounded JSON `input`, exact-byte `result`. Prepare/approve results retain `id`, `version`, `year`, `data_version`, `policy_version`, `digest`, `payload`, `status`, `prepared_by`, optional `approved_by`, `stale`, `replayed`; download result retains `payload`, `replayed`. Inputs include year/version or exact approval data version/policy/digest; scope links a year or report. | No expiry/minimization worker (`no_expiry`). Not covered by the five-field erased workflow-stub approval. No actor/auth-version timestamps are fabricated into the result, but report actor provenance remains joinable. |
| Governance provenance | `legal_governance_policies`: `id`, complete `artifact` (approval/inventory references, fixture, clocks, numeric periods, field inventories/lifetimes and optional workflow), `installed_by`, `operator_identity`, `action_id`, `installed_environment`, `installed_at`. Baseline: `singleton`, `policy_id`, `bound_at`. | Immutable with no expiry (`no_expiry`). Personal operator/action/time provenance and external approval/inventory references require their own governance inventory, not inferred replay approval. |
| Aggregate reporting state | Coverage `singleton,started_at`; years `year,data_version`; months `month,received,answered,full_disclosure,partial_disclosure,no_responsive_data,refusal,preservation_acknowledgement`. No per-case IDs. | Permanent/no expiry. Exact small-cell counters stay internal; suppression is not anonymity or differential privacy. |
| Both chain nodes/heads | Chain `seq,event_id,leaf_hash,chain_hash`; heads `singleton,seq,chain_hash`; sequence allocation state. Event UUIDs/digests can correlate to other records and remain one node per event after body erasure. | No expiry (`no_expiry`), no constant-size post-erasure compaction. Class B payload expiry does not delete these nodes. |
| Ledger erasures/receipts/outbox | Erasures `first_seq,last_seq,operation_id,erased_at`; settings `singleton,audit_subject`. Receipt body `operation_id,cutoff,deleted_count,held_count,dry_run,outcome,highwater_seq` and new `span_manifest_version,span_manifest_sha256`; Class C carries system actor/event UUID/time and leaf/chain digest. Shared outbox retains `id,subject,payload,created_at,published_at,attempts,last_error,admin_action,next_attempt_at` and nullable lifecycle IDs/revisions. These are operation/time/digest-correlatable metadata, not account narratives. | Erasures/settings and retained administrative receipt outbox/Class C material have no finite cleanup here (`no_expiry`); publication is not chaining. Missing future retained receipt material is unavailable assurance, not success. Lifecycle rows have separate approved acknowledged/transport cleanup, not the admin receipt policy. |
| Class C retained payload | `seq,user_id,actor_id,actor_spiffe_id,event_type,action_status,client_ip,user_agent,payload,timestamp`; nullable user FK can clear but actor/network/action/hold/digest linkage remains. | No Class C purge worker or approved implemented expiry supplied here; current indefinite retention is an open storage-limitation gap, not approval. |

`SECURITY_LEDGER_RETENTION=8760h` is exactly 365 days, between 4320h (180 days)
and 13140h (547.5 days); it is not the top of that range. Those are engineering
bounds, not a legally justified period. Class B's original stored expiry and holds
govern payload cleanup only. Identifiers, pepper lifecycle and finite replay expiry
remain separate work; no additional permanent inventory is silently certified.

### Task 5.3 inherited boundary

Legal requests are independent encrypted rows, unique by `(account_ref, request_kind, idempotency_key)`, not actor or globally unique operation ID. The original account reference survives account deletion. Restricted moderation/inquiry narratives are encrypted under the durable action ID; general audit excludes raw lookup identifiers, blind indexes and legal narratives but **is still personal data**. Baseline section 1.7 auditing retains actor/network metadata, action/hold IDs, timestamps and response digests; section 1.8's narrower workflow projection must not be generalized to it.

Review/expiry dates are advisory. Released legal narratives and action contexts require explicitly approved retention durations and hold-aware cleanup. The inherited replay tombstones are linkable pseudonymous records requiring explicit approval of their actual field inventory and nonexpiring lifetime, not anonymous tokens; no finite expiry is implemented. Matching replay returns current state without reactivating a released hold; cleaned narrative tombstones conflict rather than recreating a request. Fresh storage has no plaintext narrative columns. Optional standalone backfill retains encryption/read-back/binding and error contracts only as a separately scoped focused compatibility operation, not a new-lineage upgrade path. See [admin operations](admin-operations.md#standalone-compatibility-backfill).

Task 5.4 adds separately credentialed ledger payload retention, structural chain/leaf/annotation verification and separate read-only receipt reconciliation under the rollout gates above. It does not close Task 5.3 deployment approval or Task 5.5 restricted-narrative retention. External anchors, phone attribution and pepper rotation remain separate work. Do not grant API ledger DELETE, head EXECUTE or trigger bypass. Install only the fresh `00001` baseline in `public.identity_schema_version`, stop old writers and isolate PostgreSQL/Redis/NATS state before compatible cutover. Baseline Down/reset refuse; any reset of an existing environment requires separate explicit scoped authorization.

### Task 7.6 Legal Disclosure Boundary

The panel changes no schema, signed canonical bytes, stored hashes, retention policy or cleanup. Canonical-v2 attribution joins event UUIDs from `security_ledger_chain.event_id` to retained payload by `seq`. The real signer fixture check must use that same layout before attribution is exposed. Legal JSON `seq` and `coverage.through_seq` are canonical nonnegative decimal strings through `9223372036854775807`; internal `int64` and opaque cursor encoding remain unchanged. Coordinate all callers/replicas without a numeric fallback.

Lookup discloses only core event/reference/time/sequence metadata plus explicitly selected supported fields. It never returns the raw identity, blind index/version, full audit payload or action content. Each page retains the original high-water/observation and rechecks current retention/holds; empty results do not establish no historical activity, one real-world person or complete historical pepper coverage. Preservation presence flags observe current account/payload existence, including soft-deleted/unindexed/expired rows, not completeness. A lookup and a later hold are separate transactions.

The external controlled intake record must retain the exact normalized create tuple for explicit recovery; the browser stores no durable drafts, identifiers, cursors or operation keys. Deploying or rolling back the panel never drops holds, contexts, tombstones, accepted audit/outbox intent or chain data and never resets policy clocks. Baseline audit/narrative/replay/ledger policy approval, privacy notices and ROPA/DPIA/DSAR duties remain operator gates; this boundary does not close Task 5.3/5.4/5.5 or add a Class C purge policy.
