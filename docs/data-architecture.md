# Hatef Identity Platform - Data Architecture & Database Schemas

This document defines the storage topology, physical database schemas, application-layer encryption workflows, and logging systems for the Hatef Identity Platform. It covers PostgreSQL (primary transactional system), Redis (session, rate limit, and temporary storage), and ClickHouse (append-only analytical audit ledger).

---

## 1. PostgreSQL Relational Schema (DDL)

PostgreSQL serves as the primary system of record for accounts, authentication credentials, and access configurations. In Go, database interaction is implemented strictly using **`sqlc`** for compile-time type safety, working alongside the high-performance **`pgx`** (v5) driver. Object-Relational Mappers (ORMs) are prohibited.

### 1.1 Physical Schema Definition (DDL)

Below is the production DDL schema:

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

-- 6. MVP FALLBACK: Audit Logs Table (Used in place of ClickHouse during the MVP Phase to reduce memory)
CREATE TABLE mvp_audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    actor_id UUID NOT NULL,
    actor_spiffe_id VARCHAR(255) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    action_status VARCHAR(50) NOT NULL,
    client_ip VARCHAR(50) NOT NULL,
    user_agent TEXT NOT NULL,
    payload TEXT NOT NULL, -- Serialized JSON representation (masked of PII)
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    chain_hash VARCHAR(64) NOT NULL -- Chained Cryptographic hash for auditing integrity
);

CREATE INDEX idx_mvp_audit_logs_event_type ON mvp_audit_logs(event_type);
CREATE INDEX idx_mvp_audit_logs_timestamp ON mvp_audit_logs(timestamp DESC);

-- 7. Security Event Ledger (Class B - Minimal, Persistent, Survives Account Deletion)
-- Purpose: retain the minimum non-PII metadata needed to attribute an abusive or
-- security-relevant action AFTER an account is hard-deleted (e.g., a court inquiry
-- arriving at day 60 about an action taken before a day-30 deletion).
-- CRITICAL: rows here are decoupled from users(id). There is NO foreign key that would
-- cascade or null on account deletion; the stable account_ref persists independently.
CREATE TABLE security_event_ledger (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    account_ref UUID NOT NULL,               -- Stable identity reference; survives hard-delete (NO FK to users)
    identity_blind_index VARCHAR(64) NULL,   -- SHA-256(email/phone + pepper); enables attribution without raw PII
    event_type VARCHAR(100) NOT NULL,        -- e.g., 'auth.login', 'token.issued', 'security.rtr_breach'
    client_ip VARCHAR(50) NULL,
    ip_subnet VARCHAR(50) NULL,              -- /24 (IPv4) or /48 (IPv6) grouping
    user_agent TEXT NULL,
    device_fingerprint VARCHAR(128) NULL,
    client_id VARCHAR(100) NULL,             -- OAuth client that received an authorization, if any
    scope TEXT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retain_until TIMESTAMP WITH TIME ZONE NOT NULL, -- Event occurrence + SECURITY_LEDGER_RETENTION (default 8760h)
    chain_hash VARCHAR(64) NOT NULL          -- Same cryptographic chaining as audit logs
);

-- Attribution lookups by identity (court supplies an identifier -> we compute the blind index)
CREATE INDEX idx_security_ledger_blind_index ON security_event_ledger(identity_blind_index);
CREATE INDEX idx_security_ledger_account_ref ON security_event_ledger(account_ref);
CREATE INDEX idx_security_ledger_retain_until ON security_event_ledger(retain_until);
CREATE INDEX idx_security_ledger_event_type ON security_event_ledger(event_type);

-- 8. Legal Holds (Precedence Lock over ALL retention timers)
-- An active hold overrides the 30-day grace window AND the security-ledger retention.
-- Holds > retention. A hold has no predefined duration; it stays until explicitly released.
CREATE TABLE legal_holds (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    account_ref UUID NOT NULL,               -- Subject reference (matches security_event_ledger.account_ref)
    reason TEXT NOT NULL,                    -- Why the hold exists
    requesting_authority VARCHAR(255) NOT NULL, -- Court / agency / case reference
    legal_basis VARCHAR(255) NOT NULL,       -- e.g., 'legal obligation', 'legal claims / investigation'
    applied_by UUID NOT NULL,                -- Actor (e.g., DPO / Legal) who created the hold
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    review_at TIMESTAMP WITH TIME ZONE NULL, -- Optional expected review date (advisory only)
    released_at TIMESTAMP WITH TIME ZONE NULL,
    released_by UUID NULL
);

-- The hard-delete Cron and the ledger purge job MUST consult this index before purging.
CREATE INDEX idx_legal_holds_active ON legal_holds(account_ref) WHERE is_active = TRUE;
```

### 1.1.1 Persistence & Deletion Rules for Ledger and Holds

- **`security_event_ledger` is intentionally NOT linked to `users(id)`.** Unlike `mvp_audit_logs` (whose `user_id` is `ON DELETE SET NULL` and whose `payload` is PII-masked), the ledger keeps a stable `account_ref` and an `identity_blind_index` so an action remains attributable after the account row is physically deleted - within the bounded `retain_until` window.
- **Purge of the ledger** is driven solely by `retain_until` (scheduled job), never by account deletion.
- **Legal Hold precedence:** Before any purge - the 30-day hard-delete Cron on `users`, or the ledger purge job - the worker MUST check `legal_holds` for an active row matching the `account_ref`. If one exists, the purge is skipped and the skip is recorded in the audit log.
- **No raw PII in the ledger.** Only the blind index is stored; raw email/phone stay in Class A and are erased on hard-delete.

### 1.1.2 Retention Proof and Durable Head (Task 5.4)

Additive migration `00011` protects the logical chain independently of surviving
payloads. The migration does not initialize genesis or provision deployment
logins. Operators must inventory and verify history, stop/drain the old signer,
and explicitly bootstrap the known terminal position as described in
[admin operations](admin-operations.md#security-ledger-retention-task-54).

| Protected relation | State |
|---|---|
| `security_ledger_head` | `singleton boolean` primary key constrained to true, `seq bigint`, `chain_hash text`; latest committed logical position even if its payload has been erased. |
| `security_ledger_checkpoints` | `first_seq`, `last_seq`, `predecessor_seq`, `predecessor_hash`, `terminal_hash`, `erased_count`; compact maximal erased spans in committed chain order. |
| `security_ledger_retention_settings` | `singleton boolean` primary key constrained to true, `audit_subject text`; explicitly provisioned subject binding for maintenance receipts, never worker-writable. |

Genesis is an explicit initialized head, not an inference from an empty ledger.
Missing/malformed state fails closed. Checkpoints retain only sequence boundaries,
counts and digests, never erased account refs, source event IDs, blind indexes,
network/device metadata or bodies. Numeric sequence allocation gaps are legal;
a checkpoint must never cover a surviving row. Only chain-adjacent, hash-linked
spans can merge. Fully erased history compacts to a bounded prefix proof plus
the head, not one tombstone per erased event.

The purge candidate index is `(retain_until, seq)`. Bounded keyset traversal uses
one database cutoff and logical high-water mark per run, never OFFSET over a
shrinking table. Eligibility is strict `retain_until < cutoff`, and any active
hold on the original account blocks deletion even without a `users` row. Review
dates do not expire holds; last-hold release resumes the original expiry.

Signer and purge transactions use READ COMMITTED and the common lock order:
ledger coordination advisory transaction lock (`5200002`), account locks in UUID
order, then deterministic row locks. No account-locked path may acquire the
ledger lock later. Purge overlap uses a separate run lock (`5200003`), not the
daemon-lifetime signer lock (`5200001`). After account-lock acquisition a fresh
statement rechecks holds. Routine checks remain authoritative if a run-lock
connection is lost or the routine is invoked without the Go worker.

The trusted maintenance function, owned by non-login
`identity_ledger_maintenance_owner`, is the only ledger DELETE/checkpoint
compaction authority. `identity_ledger_purge` is a non-owner login with narrow
reads and approved EXECUTE only, never owner membership or direct chain writes.
Signer head advancement is separately granted and validates the actual newly
inserted terminal row in the append transaction. UPDATE/TRUNCATE guards stay
unconditional; there is no trigger disabling or caller-settable bypass. This
replaces the old broad append-only exemption comment, not the guards on Class C.

Canonical-body verification, exact-row deletion, checkpoint compaction and
sanitized Class C `admin_action` outbox intent commit atomically. Dry-run rolls
all of them back. Retained-segment verification uses a bounded read-only
REPEATABLE READ snapshot of the head, live rows and checkpoints. It recomputes
only retained bodies, distinguishes authorized erasure from unexplained damage,
and never invents an erased interior digest. All-purged is not successful content
verification. This proof is database-relative; external anchoring is deferred,
so a privileged coherent database rewrite/rollback is not independently detected.


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

$$\text{blind\_index} = \text{SHA-256}(\text{PII} \ + \ \text{secret\_pepper})$$

- **Uniqueness & Indexing:** Blind indexes are stored in separate database columns (`phone_blind_index`, `backup_email_blind_index`) and indexed via B-tree. This enables $O(1)$ fast lookups without revealing plain text.
- **Salt/Pepper Management:** The secret pepper is retrieved dynamically at application bootstrap from Infisical and kept strictly in memory. Non-exact queries (such as wildcards or substring matches) on PII columns are prohibited to ensure data minimization.

---

## 3. Redis Session & OTP Storage Layout

Redis acts as a low-latency data cache for session tokens, DPoP nonces, and temporary state (such as OTP verification metadata).

### 3.1 Redis Keyspaces & TTL Policies

| Keyspace Pattern | Data Type | TTL Value | Purpose |
| :--- | :--- | :--- | :--- |
| `session:token:{token_hash}` | Hash | By session kind | Stored session meta: User ID, kind, IP, client device, DPoP key fingerprint, absolute/idle expiry, and the recovery-enrollment claim flag. Normal `authenticated` sessions use the configured lifetime; `recovery_enrollment` sessions have a hard ten-minute lifetime and may claim at most one replacement passkey. |
| `dpop:jti:{jti}` | String | 60 Seconds | Caches the DPoP proof identifier `jti` to prevent replay attacks. |
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
> The session store remains separately abstracted and may still use its documented
> single-node MVP implementation.

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
    payload String,               -- Serialized JSON representation (masked of PII)
    timestamp DateTime64(6, 'UTC') DEFAULT now64(),
    
    -- Chained Cryptographic hash for auditing integrity
    chain_hash FixedString(32)    -- SHA-256 hash chaining records together
) ENGINE = MergeTree()
ORDER BY (event_type, timestamp, actor_id);
```

### 4.2 Cryptographic Log Chaining & Batch Signing

To prevent parallel write bottlenecks and lock contention inherent to multi-writer column-oriented ClickHouse configurations, the cryptographic chaining ledger is decoupled from direct database writes:

1. **Asynchronous Ledger Queue:** Go API instances write log records concurrently to a partitioned NATS JetStream queue subject `identity.audit.logs`.
2. **Single-Threaded Signing Consumer:** A dedicated single-threaded consumer pulls events sequentially, computes the stateful signature hash, and performs bulk inserts into ClickHouse in batches (e.g., every 5 seconds or 1000 records). **(MVP Fallback: During the MVP phase, the consumer performs bulk inserts directly into the `mvp_audit_logs` PostgreSQL table, applying the same batching optimization and maintaining the exact same cryptographic chaining formula below).**
3. **Log Chaining Formula:**
   $$\text{chain\_hash}(N) = \text{SHA-256}\Big(\text{chain\_hash}(N-1) \ \big|\big|\ \text{serialize}\big(\text{audit\_log\_record}(N)\big)\Big)$$

Where:
* `audit_log_record(N)` is a deterministic canonical serialization of the record attributes (IDs, event types, payloads, timestamps).
* The ledger's integrity is verified periodically by recalculating the chains. Any break in the sequence alerts the security operations team instantly.

### Task 5.5 workflow storage

Migrations `00012`-`00014` add immutable governance artifacts and baseline binding,
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

### Task 5.3 inherited boundary

Legal requests are independent encrypted rows, unique by account, kind and opaque idempotency key. The original account reference survives account deletion. Restricted moderation/inquiry narratives are encrypted under the durable action ID; general audit excludes identifiers, blind indexes and legal narratives. Reviewed dates are advisory. Released legal narratives and action contexts require explicitly approved retention durations and hold-aware cleanup; opaque replay tombstones prevent cleaned requests from reapplying holds. Existing plaintext rows require controlled backfill and verification before enabling intake. See [admin operations](admin-operations.md).

Task 5.4 adds separately credentialed ledger retention and retained-segment proof under the rollout gates above. It does not close Task 5.3 deployment approval or Task 5.5 restricted-narrative retention. External trust anchors are explicitly deferred; phone attribution and pepper rotation remain separate work. Do not grant the API ledger DELETE, maintenance EXECUTE or trigger-bypass privileges.
