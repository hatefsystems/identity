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

The implemented crypto provider reads environment-injected material at startup:
one active `ENVELOPE_MASTER_KEK`/version and one blind-index pepper/version in
process memory. Infisical retrieval, one-hour caches, rotation subscriptions,
sealed contingency fallback and retired-key fetching are not implemented. An
external secret manager may deliver environment values; that deployment is not
established by this repository or a primitive encryption unit test.

Retain an approved inventory of key versions, independently recoverable backups,
access-controlled custody and the material required by retained database backups.
Do not replace the active KEK and assume old ciphertext remains readable. Before
rotation, implement and rehearse the required decrypt/rewrap/verification path in
an independently approved recovery environment. The current single loaded pepper
cannot automatically search every retained historical generation. Signed evidence
is immutable; do not rehash history to hide a normalization/key change.

Coordinate step-up replay-key rotation across every replica with revoked old
authority, preserved replay-domain semantics and a documented cutover. Redis
restart/loss and unknown SQL commits require separate recovery evidence. Schema
creation, local crypto tests and historical acceptance do not prove these controls.

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
   * Validate that the restored databases can successfully decrypt user PII using the approved retained KEK/version inventory in the isolated recovery environment. No automatic Infisical or contingency retrieval is implemented.
4. **Redis Cache Reconstruction:**
   * Restore the latest RDB file. Validate that the rate limiting sliding window sets are parsed correctly.
5. **Ledger Integrity Audit (MVP PostgreSQL / Post-MVP ClickHouse):**
   * Recompute Class C's stored chain in `mvp_audit_logs`. For the Class B security ledger, validate the restored durable head, retained bodies and authorized checkpoint transitions as described below; erased bodies cannot be recomputed. These are database-relative checks, not proof of complete ingestion or detection of a coherently rolled-back backup. Post-MVP ClickHouse still requires its separately approved verification procedure.

### 3.3 Security Ledger Retention Recovery

This procedure applies to the current single-node Compose MVP as well as future
HA deployments. The independent backup rotations above do not change when a
live ledger row expires. Deleted payloads may exist in an older backup until it
rotates out; restoration is not a mechanism to bypass erasure or active holds.

1. Disable the host retention schedule and revoke the purge routine's EXECUTE
   grant before recovery. Stop/drain signer and ingestion, and stop affected
   publishers while selecting a recovery point. Preserve the original system
   and incident evidence; do not delete proof state to make a check pass.
2. Restore `security_event_ledger`, `security_ledger_head`,
   `security_ledger_checkpoints`, protected maintenance settings, legal holds,
   Class C history and `event_outbox` from a consistent backup/WAL point. Never
   combine payloads from one point with a later or earlier head/checkpoint set.
   Restore protected ownership/grants through the controlled provisioning
   procedure, not the runtime worker login.
3. Keep ingestion and destructive purge closed while verifying canonical
   retained bodies, checkpoint boundaries/counts/non-overlap, logical terminal
   head and sequence allocation state. Missing proof, unexplained gaps or
   historic hash defects require investigation. Never rehash history, reset the
   sequence, invent checkpoints or infer fresh genesis from an empty ledger.
   A consistent all-purged result is neither successful content verification
   nor a tampering alarm.
4. Reconcile authoritative post-backup holds, releases and deletion obligations
   through the established recovery/legal process before reopening processing.
   Restore active holds before evaluating erasure and honor all independent
   requests, including accounts with no live user row. A review date never
   authorizes expiry of a hold. Reapply eligible deletions without bypassing
   holds; preserve original event expiry rather than restarting its clock.
5. Deploy only compatible signer/API/worker versions. Validate non-owner roles,
   outbox acknowledgement/redelivery, online append/head/checkpoint consistency
   and a dry-run against the recovered state. Keep destructive scheduling off
   until operations and legal owners approve these checks. Then resume eligible
   expiry on the hourly host schedule and monitor backlog/cutoff/failure totals.

Rollback is forward recovery after initialization/proof state or erasure exists:
disable schedule/revoke maintenance EXECUTE first, retain head/checkpoints/holds/
outbox, and repair with compatible code. A pre-retention signer or verifier is
not a safe downgrade. Exact provisioning, revocation and rollout commands are
in [admin operations](admin-operations.md#security-ledger-retention-task-54).
Migration `00011` refuses Down unconditionally; use forward recovery rather than
an up/down/up drill even when a restored payload table appears empty.

No procedure promises restoration of erased payloads. Database-only checkpoints
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
