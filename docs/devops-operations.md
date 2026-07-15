# Hatef Identity Platform - DevOps & Operational Playbook

This playbook provides configuration specifications, deployment practices, secrets-management designs, and monitoring strategies for operating the Hatef Identity Platform in production Kubernetes environments.

---

## ⚠️ MVP Phase Disclaimer: Single-Node Deployment (No Kubernetes & No ClickHouse)
In the current MVP phase, the system is deployed using standard **Docker Compose** on a single node instead of Kubernetes (K8s) to minimize resource and memory overhead. Additionally, **ClickHouse is completely bypassed** in this phase to reduce RAM utilization by ~1.2 GB, using PostgreSQL fallback tables for logging instead.

The K8s manifests, Traefik IngressRoute, SPIRE daemonsets, and ClickHouse monitoring configurations documented below are strictly for the post-MVP production deployment and **must not be provisioned in the current MVP phase**.

---

## 1. Kubernetes Deployment & Networking

The platform leverages **Traefik** as the Ingress Controller and API Gateway at the cluster boundary, and **SPIRE** to orchestrate dynamic zero-trust workloads.

### 1.1 Traefik Ingress Configuration

To ensure optimal performance and isolate concerns, path-based routing separates Next.js (web frontend) from the Go IdP API engine.

```yaml
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: hatef-identity-ingress
  namespace: identity
spec:
  entryPoints:
    - websecure
  routes:
    # 1. Route for public UI, dashboard, admin panel, and OAuth authorize/error screens (Next.js)
    - match: Host(`identity.hatef.ir`) && (PathPrefix(`/login`) || PathPrefix(`/register`) || PathPrefix(`/forgot-password`) || PathPrefix(`/reset-password`) || PathPrefix(`/verify-email`) || PathPrefix(`/dashboard`) || PathPrefix(`/admin`) || Path(`/oauth2/authorize`) || Path(`/oauth2/error`) || PathPrefix(`/_next`) || PathPrefix(`/static`))
      kind: Rule
      services:
        - name: hatef-frontend-service
          port: 3000

    # 2. Route for Core IdP API operations, token exchange, and JWKS endpoints (Go Backend)
    - match: Host(`identity.hatef.ir`) && (PathPrefix(`/api`) || PathPrefix(`/.well-known`) || (PathPrefix(`/oauth2`) && !Path(`/oauth2/authorize`) && !Path(`/oauth2/error`)))
      kind: Rule
      middlewares:
        - name: rate-limit-middleware
        - name: security-headers-middleware
      services:
        - name: hatef-idp-core-service
          port: 8080
  tls:
    certResolver: letsencrypt
    options:
      name: strict-tls@kubernetescrd
```

#### 1.1.1 Security Middlewares Configuration:
```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: security-headers-middleware
  namespace: identity
spec:
  headers:
    browserXssFilter: true
    contentTypeNosniff: true
    forceSTSHeader: true
    stsSeconds: 31536000
    stsPreload: true
    stsIncludeSubdomains: true
    frameDeny: true
    # Next.js and Go templates dynamically generate strict random nonces for CSP.
    # Traefik forwards these headers verbatim.
```

### 1.2 SPIRE Runtime Environment Agent Deployment

To assign secure cryptographic identities to workloads, a SPIRE Agent runs as a Kubernetes `DaemonSet` on every node, communicating directly with the central SPIRE Server.

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: spire-agent
  namespace: spire
spec:
  selector:
    matchLabels:
      app: spire-agent
  template:
    metadata:
      labels:
        app: spire-agent
    spec:
      hostPID: true # Required for the agent to inspect process attributes on the node
      containers:
        - name: spire-agent
          image: ghcr.io/spiffe/spire-agent:1.8.0
          args: ["-config", "/run/spire/config/spire-agent.conf"]
          resources:
            requests:
              cpu: "100m"
              memory: "128Mi"
            limits:
              cpu: "500m"
              memory: "256Mi"
          volumeMounts:
            - name: spire-config
              mountPath: /run/spire/config
              readOnly: true
            - name: spire-agent-socket
              mountPath: /run/spire/sockets
            - name: cgroup
              mountPath: /host/sys/fs/cgroup
              readOnly: true
      volumes:
        - name: spire-config
          configMap:
            name: spire-agent-config
        # Unix Domain Socket exposed to the applications on the host node
        - name: spire-agent-socket
          hostPath:
            path: /run/spire/sockets
            type: DirectoryOrCreate
        - name: cgroup
          hostPath:
            path: /sys/fs/cgroup
```

Workloads access the SPIFFE Workload API by mounting the local folder hosting `/run/spire/sockets/agent.sock` into their application containers.

---

## 2. Secrets Injection & Configuration

To prevent hardcoding of credentials or exposure of raw configuration strings, secrets are injected from **Infisical** via the **Kubernetes External Secrets Operator (ESO)**.

```
+------------------+         +----------------------------+         +-------------------+
|    Infisical     | ======> |  External Secrets Operator | ======> | Kubernetes Secret |
| (Central Vault)  |  (Sync) |       (ESO Controller)     | (Write) |   (Local Pods)    |
+------------------+         +----------------------------+         +-------------------+
```

### 2.1 ExternalSecret Definition

The ESO Controller polls Infisical at a set interval (e.g., 5 minutes) and updates the Kubernetes Secret objects dynamically.

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: hatef-idp-secrets
  namespace: identity
spec:
  refreshInterval: "5m" # Sync frequency with Infisical
  secretStoreRef:
    name: infisical-backend-store
    kind: ClusterSecretStore
  target:
    name: idp-runtime-secrets
    creationPolicy: Owner
  data:
    - secretKey: POSTGRES_PASSWORD
      remoteRef:
        key: /production/database/postgres_password
    - secretKey: ENVELOPE_MASTER_KEK
      remoteRef:
        key: /production/crypto/envelope_master_kek
    - secretKey: SMS_GATEWAY_API_KEY
      remoteRef:
        key: /production/services/sms_gateway_api_key
```

Application Pods bind this generated secret as standard environment variables or files:

```yaml
env:
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: idp-runtime-secrets
        key: POSTGRES_PASSWORD
```

---

## 3. Prometheus Monitoring & Alerting

Observability is core to detecting anomalies, token-theft attempts, and system exhaustion.

### 3.1 Core Operational Metrics

The Go backend and Next.js applications expose Prometheus metrics on `/metrics`.

| Metric Name | Type | Labels | Description |
| :--- | :--- | :--- | :--- |
| `idp_http_request_duration_seconds` | Histogram | `path`, `method`, `status` | Latency distribution of external REST requests. |
| `idp_grpc_request_duration_seconds` | Histogram | `method`, `status` | Latency distribution of internal validation RPCs. |
| `idp_database_pool_active_connections` | Gauge | `pool` | Active connections to PostgreSQL and Redis. |
| `idp_otp_failures_total` | Counter | `channel` (`sms`, `totp`) | Unsuccessful OTP login attempts. |
| `idp_rtr_breach_detections_total` | Counter | `client_id` | Number of times a revoked/replayed Refresh Token was detected. |
| `idp_envelope_encryption_errors_total` | Counter | `operation` (`encrypt`, `decrypt`) | Cryptographic failures in envelope encryption logic. |

### 3.2 Prometheus Alerting Rules

```yaml
groups:
  - name: hatef-identity-alerts
    rules:
      # 1. Alert for Refresh Token Rotation Breach (Potential Session Theft)
      - alert: RefreshTokenRotationBreach
        expr: rate(idp_rtr_breach_detections_total[1m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Potential Token Theft Breach Detected"
          description: "A client attempted to present an already-used Refresh Token. All user active sessions have been automatically invalidated by the system."

      # 2. Alert for Sudden Spike in SMS OTP Failures (Potential Brute-force / Toll-fraud)
      - alert: HighOTPFailuresRate
        expr: rate(idp_otp_failures_total{channel="sms"}[5m]) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High volume of SMS OTP failures"
          description: "SMS OTP failures exceed 10/minute over 5m, indicating possible automated enumeration or brute-force attempts."

      # 3. Alert for Envelope Cryptographic Failures
      - alert: EnvelopeEncryptionFailure
        expr: rate(idp_envelope_encryption_errors_total[1m]) > 0
        for: 0m
        labels:
          severity: page
        annotations:
          summary: "Application-Layer Cryptographic Operations Failure"
          description: "Database row envelope encryption or decryption is failing. This indicates KEK/DEK mismatch or corruption."

      # 4. Alert for Database Connection Pool Exhaustion
      - alert: DBConnectionPoolExhausted
        expr: idp_database_pool_active_connections / idp_database_pool_max_connections > 0.90
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Database connection pool utilization is critically high"
          description: "Active database connections are over 90% of pool limits, risking query queuing and increased request latencies."
```
