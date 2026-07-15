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

## 2. Key Management Service (KMS) Fallback Protocols

Because the platform depends on **Infisical** for application-layer envelope encryption keys (Master Key Encryption Key - KEK) and configuration secrets, any communication failure with Infisical would block database writes and reads of encrypted PII.

### 2.1 KMS Offline Contingency Fallback

To prevent a hard lock of the authentication flow during a regional cloud network split or complete Infisical unavailability, the Go IdP utilizes a secure offline key fallback mechanism.

```
                  +-----------------------------------+
                  | Retrieve Master KEK (Infisical)   |
                  +-----------------------------------+
                                    |
                    Success? ----+--+--+---- No?
                             |         |
                             v         v
             +-----------------+     +-----------------------------------+
             | Cache KEK in    |     |  Read Sealed Contingency Key      |
             | Memory (1 Hour) |     |  from Local K8s Secrets volume    |
             +-----------------+     +-----------------------------------+
                                                       |
                                                       v
                                     +-----------------------------------+
                                     | Validate HMAC Signature of Key    |
                                     +-----------------------------------+
                                                       |
                                                       v
                                     +-----------------------------------+
                                     | Decrypt DEKs using Contingency Key|
                                     +-----------------------------------+
```

1. **In-Memory Cache & Active Invalidation:** The active Master KEK is cached securely in-memory inside the Go application for up to 1 hour to reduce network traffic. To ensure that on-demand forced key rotations take effect immediately and do not leave compromised keys active, the Go IdP instances subscribe to a NATS JetStream/Redis pub-sub key rotation channel (e.g., `identity.crypto.kek-rotated`). Upon receiving a rotation signal, the in-memory cache is instantly invalidated and flushed.
2. **Sealed Local Contingency Key:** If the application starts up or needs to reload the KEK while Infisical is offline, it reads a sealed backup configuration payload from a local, dedicated Kubernetes volume (bound only to the application's service account).
3. **Decryption Logic:** This sealed payload can be decrypted using an emergency private key stored in Kubernetes Secrets. Once decrypted, it yields the temporary contingency KEK.
4. **Log Warning:** A high-severity system alert `IDP_CRITICAL_KMS_OFFLINE` is pushed to monitoring indicating that the platform has downgraded to local contingency key storage.

### 2.2 Master Key Encryption Key (KEK) Rotation Schedule

* **Regular Key Rotation:** Master KEKs are rotated automatically every 180 days via Infisical's integrated key rotation pipelines.
* **On-Demand Key Rotation:** In the event of an operational leakage or suspected administrator key compromise, a forced rotation is initiated via the administrative console.
* **Backward Compatibility:** All past rotated keys are kept in Infisical's secure version history. The application-layer encryption payload retains the `Version` byte. When reading older database rows, the Go backend uses the version byte to fetch the corresponding retired KEK from Infisical's version tree to decrypt the DEK.

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
   * Validate that the restored databases can successfully decrypt user PII using the contingency and production KEK retrieved from the test Infisical mock server.
4. **Redis Cache Reconstruction:**
   * Restore the latest RDB file. Validate that the rate limiting sliding window sets are parsed correctly.
5. **Ledger Integrity Audit (MVP PostgreSQL / Post-MVP ClickHouse):**
   * Recompute the cryptographic log chains. In the MVP phase, this audit is performed against the `mvp_audit_logs` table in PostgreSQL. Verify that no logs are missing and that the cryptographic signature sequence (`chain_hash`) matches perfectly from the starting genesis block to the latest record. Post-MVP, this is executed against ClickHouse.
