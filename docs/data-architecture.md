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
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NULL, -- NULL for passwordless WebAuthn-only accounts
    backup_email_encrypted BYTEA NULL, -- Wrapped PII (AES-GCM-256)
    backup_email_blind_index VARCHAR(64) NULL, -- Cryptographic blind index: SHA-256(Email + Pepper)
    phone_encrypted BYTEA NULL,        -- Wrapped PII (AES-GCM-256)
    phone_blind_index VARCHAR(64) NULL, -- Cryptographic blind index: SHA-256(Phone + Pepper)
    mfa_totp_secret_encrypted BYTEA NULL, -- Wrapped PII (AES-GCM-256)
    is_mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(50) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'pending_verification')),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE NULL -- Support soft deletion for Right to be Forgotten retention windows
);

CREATE INDEX idx_users_email ON users(email) WHERE deleted_at IS NULL;
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

-- 4. Recovery Codes (Backup Codes) Table
CREATE TABLE recovery_codes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(64) NOT NULL, -- SHA-256 hash of the recovery code
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    used_at TIMESTAMP WITH TIME ZONE NULL
);

-- Index is critical to perform O(1) matching. It avoids sequential password-like decryption loops.
CREATE UNIQUE INDEX idx_recovery_codes_hash ON recovery_codes(code_hash) WHERE used_at IS NULL;
CREATE INDEX idx_recovery_codes_user_id ON recovery_codes(user_id);

-- MVP FALLBACK: Audit Logs Table (Used in place of ClickHouse during the MVP Phase to reduce memory)
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
```

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
| `session:token:{token_hash}` | Hash | 24 Hours | Stored session meta (User ID, IP, Client Device, DPoP key fingerprint). |
| `dpop:jti:{jti}` | String | 60 Seconds | Caches the DPoP proof identifier `jti` to prevent replay attacks. |
| `otp:sms:secret:{phone}` | Hash | 3 Minutes | Contains the cryptographically hashed OTP code, generation timestamp, and attempt counter. |
| `rate:otp:phone:{phone}` | String | 1 Hour | Tracks SMS OTP requests made to a specific phone number. |
| `rate:otp:subnet:{ip_subnet}` | String | 1 Hour | Tracks SMS OTP requests made by an IP subnet to prevent distributed spam. |

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
