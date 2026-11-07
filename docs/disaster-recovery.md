# Hatef Identity Platform - Disaster Recovery & High Availability

This document outlines the replication topologies, failover procedures, backup strategies, and emergency recovery drills required to maintain a minimum of 99.99% operational uptime for the Hatef Identity Platform.

---

## ⚠️ MVP Phase Disclaimer: No HA Deployment
Due to physical memory constraints in the initial MVP phase, **all clustering and High Availability (HA) mechanisms outlined in this document (including Patroni PostgreSQL and Redis Sentinel) are postponed**. 
For Phase-1 (MVP), a robust **Single-Instance deployment** of PostgreSQL and Redis is strictly enforced. The HA specifications documented here serve as the blueprint for post-MVP scaling.

---

## 1. Database High Availability & Failover

To prevent single points of failure, the databases (PostgreSQL, Redis, and ClickHouse) are configured in multi-node clusters with automated failover orchestration.

```
       [ Client Request / Go APIs ]
                    |
          +---------+---------+
          |                   |
          v                   v
   +--------------+    +--------------+
   |  PgBouncer   |    |  PgBouncer   |  (Connection Poolers)
   +--------------+    +--------------+
          |                   |
          +---------+---------+
                    |
                    v
    =================================
    Patroni-Managed PostgreSQL Cluster
    =================================
          |                   |
          v (Leader)          v (Hot Standby)
    +------------+      +------------+
    |  Primary   | ===> |  Replica   |  (Streaming Replication)
    |  Node      |      |  Node      |
    +------------+      +------------+
          ^                   ^
          |                   |
    +--------------------------------+
    |       Consul / etcd DCS        |  (Distributed Consensus)
    +--------------------------------+
```

### 1.1 PostgreSQL Patroni-Driven Clustering

Primary-replica failover is managed dynamically using **Patroni** with an **etcd** or **Consul** Distributed Consensus Store (DCS).

* **Replication Mode:** Asynchronous Streaming Replication with a physical replication slot to prevent WAL segments from being recycled before replica consumption.
* **Failover Parameters (etcd):**
  * `ttl`: 30 seconds (time-to-live for leader lock in etcd).
  * `loop_wait`: 10 seconds (frequency of leader heartbeat checks).
  * `retry_timeout`: 10 seconds (consecutive network failures before step-down is forced).
* **Automatic Failover Flow:**
  1. If the primary node crashes, the etcd lease expires after 30 seconds.
  2. Standby nodes initiate leader election. The node with the most advanced log sequence number (LSN) is elected.
  3. Patroni reconfigures PgBouncer to route write-traffic to the new leader immediately.
  4. The old primary is automatically converted to a streaming replica upon recovery (node bootstrapping).

### 1.2 Redis Sentinel Setup

To prevent token validation and rate-limiting outages, Redis is deployed in a high-availability master-replica topology supervised by **Redis Sentinel**.

```
                +-----------------+
                | Redis Sentinel  |
                | (Quorum = 2)    |
                +-----------------+
                  /      |      \
        Monitors /       |       \ Monitors
                /        v        \
    +------------+        +------------+
    |   Master   | =====> |  Replica   | (Asynchronous Replication)
    |   Node     |        |   Node     |
    +------------+        +------------+
```

* **Cluster Sizing:** 3 Sentinel nodes, 1 Redis Master node, 2 Redis Replica nodes.
* **Sentinel Core Settings:**
  * `sentinel monitor hatef-cache redis-master.internal 6379 2` (Quorum is set to 2).
  * `sentinel down-after-milliseconds hatef-cache 3000` (Sentinel marks Master dead after 3 seconds of unresponsiveness).
  * `sentinel failover-timeout hatef-cache 10000` (Max duration of the failover process).
* **Failover Process:**
  1. Once two Sentinels agree the master is down, one Sentinel is elected leader to orchestrate the promotion.
  2. The chosen replica is promoted to Master (`SLAVEOF NO ONE`).
  3. The remaining replica is reconfigured to follow the new master.
  4. Client applications (using the standard Go Redis client) listen to Sentinel pub/sub events to update their connection pool destinations dynamically.

---

## 2. Key Custody and Recovery

The current adapter loads one environment-injected KEK/version and one blind-index
pepper/version into process-local custody at startup. It uses real AES-GCM/HMAC
primitives, but performs no live Infisical fetch, expiring cache, offline fallback,
pub-sub invalidation or hot rotation. Infisical/SOPS/Sealed Secrets are operator
delivery options, not an automatic application recovery mechanism.

### 2.1 Process-Local Key Recovery

Already-running processes use their loaded material; provider availability is not
a per-record fetch dependency. New/restarted processes still need the correct
approved secret injection. Missing/wrong keys fail encrypted reads and admission,
not an alternate secret, plaintext downgrade or silently generated production key.
Exactly configured environment modes are required; test is not development.

Keep a protected independent inventory/backup of every original KEK/version and
pepper generation needed by retained ciphertext and consistent backups. An
envelope version byte does not provide a retired-key reader. Restore matching
key material under controlled authorization before compatible readers resume;
investigate wrong bindings/authentication failures without rewriting data.
Secret-provider recovery, launcher controls and independent key restoration must
be demonstrated separately. Primitive unit tests do not prove any of these gates.

### 2.2 Master Key Encryption Key (KEK) Rotation Schedule

* **Controlled Rotation:** Operators own the approved schedule and compromise-response procedure. Drain affected writes/readers and inventory retained versions before replacing the single loaded key; current code does not automatically rewrap data or fetch retired keys.
* **Retired-Key Custody:** Retain protected original keys with backup recovery obligations. Key erasure, backup rotation and lawful erasure require coordinated policy; changing the active KEK alone does not preserve old-row readability.
* **Pepper and Replay Keys:** Exact canonical-email capture/fallback/lookup must share one declared pepper generation. Generic BlindIndex NFKC behavior is unchanged; no signed-history rehash or dual-normalization/multi-pepper lookup is supplied. Coordinate replay-key cutover across replicas rather than splitting replay domains. See [secret rollout](devops-operations.md#2-secrets-injection--configuration).

---

## 3. Backup & Recovery Playbook

Data backup strategies must prevent data loss and support recovery within a designated target window.
* **Recovery Point Objective (RPO):** $<15$ minutes.
* **Recovery Time Objective (RTO):** $<2$ hours.

### 3.1 Backup Schedules & Specifications

| Database | Backup Type | Frequency | Storage Location | Retention |
| :--- | :--- | :--- | :--- | :--- |
| **PostgreSQL** | `pg_dump` Logical Backup | Daily (01:00 UTC) | S3-Compatible Encrypted Object Storage (Air-Gapped) | 30 Days |
| | WAL-G Physical Backup | Continuous (WAL archiving) | S3-Compatible Storage | 14 Days |
| **Redis** | RDB Snapshot | Every 6 hours | Local Kubernetes Persistent Volume + S3 | 7 Days |
| | AOF file | Continuous (fsync every sec) | Local High-IOPS SSD | 24 Hours |
| **ClickHouse** | Disk-Level Parts Copy | Weekly (03:00 UTC) | Cold Object Storage (Postponed; Post-MVP only) | 90 Days |

### 3.2 Recovery Validation Drills

A backup is only as good as its recovery validation. The operations team executes simulated disaster recovery drills quarterly:

1. **Clean Environment Bootstrapping:** Provision a temporary, isolated Kubernetes namespace.
2. **PostgreSQL Base Recovery:**
   * Fetch the latest physical base backup via WAL-G.
   * Replay WAL files up to a targeted Point-In-Time recovery (PITR) coordinate.
3. **MFA Encryption Validation:**
   * Validate retained PII/envelope bindings with the exact separately recovered original KEK/version, not a fictitious contingency key or live/mock Infisical fetch. Record private-key recovery independently of primitive crypto tests.
4. **Redis Cache Reconstruction:**
   * Restore the latest RDB file. Validate that the rate limiting sliding window sets are parsed correctly.
5. **Ledger Integrity Audit (MVP PostgreSQL / Post-MVP ClickHouse):**
   * Verify canonical-v2 `audit_log_chain` and `security_ledger_chain` against their own durable heads and derived genesis, recomputing leaves only from retained `mvp_audit_logs` / `security_event_ledger` bodies. Ledger erasure annotations explain absent bodies; they do not prove receipt chaining or legal authorization. These are database-relative checks, not complete-ingestion assurance or detection of a coherently rolled-back backup. Post-MVP ClickHouse still requires its separately approved verification procedure.

### 3.3 Security Ledger Retention Recovery

This procedure applies to the current single-node Compose MVP as well as future
HA deployments. The independent backup rotations above do not change when a
live ledger row expires. Deleted payloads may exist in an older backup until it
rotates out; restoration is not a mechanism to bypass erasure or active holds.

1. Disable the host retention schedule and revoke the purge login's payload
   DELETE and erasure-index INSERT grants before recovery. Wait for or stop
   in-flight workers; revocation does not cancel an executing statement. There
   is no v2 purge EXECUTE grant. Stop/drain signer and ingestion, and stop affected
   publishers while selecting a recovery point. Preserve the original system
   and incident evidence; do not delete proof state to make a check pass.
2. Restore the matching new-lineage `public.identity_schema_version`, both payload
   tables (`security_event_ledger`, `mvp_audit_logs`), both
   chains (`security_ledger_chain`, `audit_log_chain`), both heads, chain sequence
   allocation state, `security_ledger_erasures`, `security_ledger_retention_settings`,
   legal holds/governance/workflow state, `registration_attempts` and `event_outbox` from one consistent
   backup/WAL point. Never mix a chain/head, payload, erasure or receipt inventory
   from different points. The retired checkpoint table is not v2 proof state.
   Restore protected ownership/grants through the controlled provisioning
   procedure, not the runtime worker login.
3. Keep ingestion and destructive purge closed while verifying canonical
   retained bodies, erasure boundaries/non-overlap, actual terminal nodes,
   head and sequence allocation state. Missing proof, unexplained gaps or
   historic hash defects require investigation. Never rehash history, reset the
   sequence, invent erasure annotations or infer fresh genesis from empty payloads.
   A consistent all-purged result is neither successful content verification
   nor a tampering alarm.
4. Reconcile authoritative post-backup holds, releases and deletion obligations
   through the established recovery/legal process before reopening processing.
   Restore active holds before evaluating erasure and honor all independent
   requests, including accounts with no live user row. A review date never
   authorizes expiry of a hold. Reapply eligible deletions without bypassing
   holds; preserve original event expiry rather than restarting its clock.
5. Deploy only compatible signer/API/worker versions. Validate non-owner roles,
   outbox acknowledgement/redelivery and online append/head/annotation consistency.
   Run bounded read-only receipt reconciliation with its separate SELECT-only
   credentials: distinguish recorded-pending intent, chained manifest-bound receipts,
   legacy/unbound, invalid/missing and unavailable/incomplete coverage. PubAck or
   `published_at` is not chaining. Run a bounded dry-run against recovered state.
   Keep destructive scheduling off
   until operations and legal owners approve these checks. Then resume eligible
   expiry on the hourly host schedule and monitor backlog/cutoff/failure totals.

Rollback is forward recovery after initialization/proof state or erasure exists:
disable schedule/revoke purge DELETE and erasure INSERT first, wait for in-flight
work, retain both chains/heads/payloads/erasures/holds/settings/outbox, and repair
with compatible code. A pre-v2 signer or verifier is
not a safe downgrade. Exact provisioning, revocation and rollout commands are
in [admin operations](admin-operations.md#security-ledger-retention-task-54).
The unchanged `00001_initial_schema.sql` plus additive `00002_registration_attempts.sql`
bundle is forward-only; reset/rollback to zero refuse even after later migrations. Use forward recovery,
not an up/down/up drill, even when payload tables appear empty. Recovery restores
matching new-lineage metadata and application state consistently; it is not an
in-place upgrade or adoption of legacy backups. Supported migration entrypoints
refuse ALL `public.goose_db_version` targets, untracked nonempty application schemas
and contradictory histories without mutation. Retain legacy backups/history as
required evidence; this runner does not convert them, rehash records, infer genesis
or recover history already discarded.

For replacement installation, stop all old writers and identify an explicitly
scoped fresh PostgreSQL 16 target plus matching fresh/isolated Redis 7/NATS JetStream
2.10 state. Do not carry stale sessions, queued envelopes or consumer checkpoints
into the replacement database; recovery of accepted intent needs separate consistent
reconciliation. Existing data was confirmed disposable, not approved for automatic
reset: any reset of an existing named environment needs a separate explicit request
identifying its exact targets. No broad volume deletion or shared-schema reset is
part of these instructions. Follow [active setup](admin-operations.md#migration-and-contraction).

Obsolete legal Backfill/plaintext compatibility is removed, not a recovery,
new-lineage upgrade or fresh-install step. Operator-only genesis,
restricted provisioning, real key inventory, policy approval, original retention
clocks and manual/production restore gates remain unchanged. Historical acceptance
and prior plans retain their original evidence; new outcomes may be recorded only
after actual [final-source acceptance](admin-operations.md#automated-validation).

No procedure promises restoration of erased payloads. Database-relative chains,
erasure annotations
and Class C receipts cannot independently detect a coherent privileged rewrite
or backup rollback without an external anchor. External anchoring remains
explicitly deferred; drills and production restore validation are release gates,
not guarantees supplied by this document.

### 3.4 Legal Workflow Recovery

Restore governance artifacts/baseline, case revisions, original subject/hold
associations, replay stubs, response approvals/receipts, counters, frozen reports
and audit intent from one consistent recovery point. Disable case intake,
downloads and metadata cleanup during recovery. Reconcile authoritative external
hold/deletion instructions and external delivery receipts before reopening.
Never resend a response because a restored backup lacks its delivery marker,
regenerate an artifact under an old approval, reset retention clocks or delete
replay keys to bypass conflicts. Reapply erasure subject to current holds; deleted
ciphertext cannot be reconstructed from the aggregate counters. Preserve the
independent backup-rotation policy. A restored database is not an external trust
anchor or proof of complete external-response history.

### 3.5 Registration Recovery

Keep signup intake and cleanup scheduling disabled while restoring migration
versions 1+2, users/credentials, `registration_attempts`, created-event intent and
holds from one consistent point with matching private KEK/pepper generations.
Preserve original attempt/proof/receipt clocks and current authoritative hold/
deletion instructions. Restoring a snapshot never extends 15m pending, 10m email,
at-most-5m passkey or 1h receipt validity, resurrects a spent OTP, rebinds a JKT or
recreates an erased account. Completed receipts remain subject to user cascade.

External email/SMS acknowledgement is not exactly-once delivery. A restored
missing marker cannot prove that a message was never sent; do not automatically
resend, recreate an account or issue a capability from an email. Only the original
capability/JKT may query the bounded durable result with a fresh DPoP proof; lost
authority requires ordinary login or a new approved attempt. Reconcile created
event/outbox state without synthesizing duplicate user birth.

Before reopening, verify compatible schema/readers, actual dedicated cleanup
login with nonmutating `registration-cleanup check`, supervised bounded `once`
scheduling, key recovery, shared Redis and message-free SMTPUTF8/TLS/auth readiness.
Live SMS.ir provenance, billing/egress/handset receipt, Unicode-mailbox delivery,
retention budgets and deployed restore evidence remain independently approved
gates, not supplied by these instructions or local primitive tests. No reset,
legacy adoption, automatic target replacement or new live permission is granted.
