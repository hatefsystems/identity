# Hatef Identity Platform - DevOps & Operational Playbook

This playbook provides configuration specifications, deployment practices, secrets-management designs, and monitoring strategies for operating the Hatef Identity Platform in production Kubernetes environments.

---

## ⚠️ MVP Phase Disclaimer: Single-Node Deployment (No Kubernetes, No ClickHouse & No Traefik)

In the current MVP phase, the system is deployed using standard **Docker Compose** on a single node instead of Kubernetes (K8s) to minimize resource and memory overhead. Additionally, **ClickHouse is completely bypassed** in this phase to reduce RAM utilization by ~1.2 GB (using PostgreSQL fallback tables for logging instead).

Furthermore, **Traefik is not provisioned in the MVP phase**. Instead, the platform leverages the **existing host-level Nginx** on the Ubuntu host to handle Reverse Proxying, TLS Termination, and path-based routing directly to the Docker containers. Traefik Ingress will be adopted post-MVP when migrating to a production Kubernetes cluster.

The K8s manifests, Traefik IngressRoute, SPIRE daemonsets, and ClickHouse monitoring configurations documented below are strictly for the post-MVP production deployment and **must not be provisioned in the current MVP phase**.

---

## 1. Kubernetes Deployment & Networking

The platform leverages **Traefik** as the Ingress Controller and API Gateway at the cluster boundary, and **SPIRE** to orchestrate dynamic zero-trust workloads.

### 1.0 MVP Phase: Host-Level Nginx Configuration (Reverse Proxy & TLS Termination)

In the MVP phase, we use the host's existing **Nginx** web server running on Ubuntu. Nginx handles SSL/TLS termination, routes the traffic to the corresponding Docker containers (Next.js frontend on port `3000`, Go Backend on port `8080`), and handles base HTTP security headers. Port `8080` must be published only on loopback or a private container network; it must never be reachable from an untrusted network that can bypass Nginx.

The API trusts `X-Forwarded-For` only when its immediate socket peer is listed in `TRUSTED_PROXY_CIDRS`. For host Nginx connecting over loopback, use `TRUSTED_PROXY_CIDRS=127.0.0.1/32` (and `::1/128` only when that path is actually used). If Docker NAT makes the peer appear as a bridge gateway, inspect the API's observed peer and allow only that exact address or narrowly controlled ingress CIDR. Empty means no proxy is trusted, malformed entries and `/0` networks are rejected, and broad Docker or public ranges are prohibited. Nginx must overwrite any client-supplied forwarding chain with `$remote_addr`; do not use `$proxy_add_x_forwarded_for` at this single public edge. The API deliberately ignores `X-Real-IP` and `True-Client-IP`.

Below is the production-ready Nginx configuration file (`/etc/nginx/sites-available/identity.hatef.ir`) for the MVP:

```nginx
# http{} scope: constant route template, never request URI/query/referrer/headers.
log_format admin_safe '$request_method /api/v1/admin/* $status $request_time';
server {
    listen 443 ssl http2;
    server_name identity.hatef.ir;

    # SSL Certificate Configuration (Certbot / Let's Encrypt)
    ssl_certificate /etc/letsencrypt/live/identity.hatef.ir/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/identity.hatef.ir/privkey.pem;

    # Secure SSL Protocols and Ciphers
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Secure HTTP Headers (XSS, Framing, Content-Type sniffing)
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # 1. Route for public UI, dashboard, admin panel, and OAuth authorize/error screens (Next.js)
    location ~ ^/(login|register|forgot-password|reset-password|verify-email|dashboard|admin|_next|static) {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        # Overwrite untrusted inbound forwarding headers at the public edge.
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSockets support for Next.js Fast Refresh
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # OIDC UI Page Exceptions
    location = /oauth2/authorize {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location = /oauth2/error {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Admin prefix wins over the general API regex, including rejected legacy GETs.
    location ^~ /api/v1/admin {
        access_log /var/log/nginx/admin-access.log admin_safe;
        # Nginx error records can embed raw URLs; use sanitized API diagnostics.
        error_log /dev/null crit;
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # 2. Route for Core IdP API operations, token exchange, and JWKS endpoints (Go Backend)
    location ~ ^/(api|\.well-known|oauth2) {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Forward OAuth Authorization and DPoP headers verbatim
        proxy_pass_header Authorization;
        proxy_pass_header DPoP;
    }

    # 3. Default route (routes back to Next.js frontend app)
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### Portal Document CSP (Task 7.1)

The standalone Next.js server owns the portal's enforcing `Content-Security-Policy`. Its proxy generates a new nonce per request and the root layout renders HTML on demand, including static-content pages and the application 404. This does not enable backend CSP, Trusted Types, static export, SSG, ISR, or PPR. See the [frontend policy contract](frontend-pages.md#52-client-side-sender-constrained-tokens-dpop--strict-nonce-csp).

- Forward the application's single CSP header unchanged in every Next.js location above, including OAuth UI exceptions and the default route. Do not add a second CSP, replace it with a constant nonce, or hide the upstream header in Nginx/Traefik.
- Preserve `Cache-Control: private, no-store` on portal HTML (Next may add stricter no-cache directives). Do not enable shared HTML caching or override these headers at the reverse proxy/CDN. Reusing cached HTML with a new response nonce breaks script execution; reusing the nonce itself violates the security contract.
- Continue serving `/_next/static` JS/CSS with their public, immutable cache headers. The proxy excludes framework assets and the existing favicon from document nonce handling. Do not globally disable asset caching to solve an HTML-cache issue.
- Run the production image with `NODE_ENV=production`. Development relaxations are only for local Next.js tooling. New external origins and inline-style components require explicit policy compatibility work.
- During an operator-approved release, fetch `/` and an unknown/dotted URL repeatedly through the real HTTPS ingress. Verify the expected 200/404 status, exactly one enforcing CSP, matching HTML/header nonces, different nonces between document responses, and private/no-store headers. Verify scripts, CSS, and client navigation in a browser and confirm immutable asset caching. Container tests cannot establish ingress behavior.
- Upstream outage pages and responses emitted before the Next.js proxy are outside its coverage. Rollback must restore the matching application image and header behavior together; do not weaken the CSP independently to hide a rendering failure.

Frontend CI runs nonce/cache checks and Chromium enforcement tests against the actual non-root image before release export. The browser tests verify clean rendering and hydrated client navigation, then separately verify allowed nonced code and blocked parser-inserted scripts, handlers, and styles. The release publication smoke remains dependency-free and does not require browser packages. No publish or deployment is implied by local test completion.

To repeat the browser check after building an image, from the repository root with npm dependencies installed:

```bash
npm exec -- playwright install --with-deps chromium
npm exec -- nx exec -p web -- node "$PWD/.github/scripts/web-csp.browser.mjs" identity-web:ci
```

### 1.0.1 Private IdentityService Runtime (Task 6.2)

The API can also host private TLS 1.3 gRPC on `GRPC_ADDR` (default
`127.0.0.1:9090`). It is disabled by default and must not be added to the public
Nginx/Traefik routes above. `GRPC_ENABLED=true` requires PostgreSQL, standalone
Redis, a maintained local SPIRE Workload API, an explicit canonical trust domain,
exact method grants and audience/origin policies. This implements application
support, not permission to provision the post-MVP SPIRE/Kubernetes manifests.
See [client configuration](client-integration.md#34-runtime-configuration-and-rollout)
for the environment contract and a non-production example.

Build from the repository root so the existing schemas Go module is available:

```bash
docker build --file apps/identity-api/Dockerfile --tag identity-api:dev .
```

The Dockerfile-specific ignore rules exclude secrets, unrelated workspace
content and local generated outputs. The image regenerates schema Go and sqlc
code using pinned local tools before building all existing API/worker binaries.
Generated Go remains uncommitted; Go 1.26.5 or later is required. No remote
TypeScript generator is needed for this backend build.

Before enabling consumers, deploy the shared-state-aware issuers on all API
instances, drain process-local sessions and require reauthentication. New user
tokens bind to their browser session, OAuth grant and captured account version.
Legacy unlinked JWTs cannot pass the RPC. Do not promise complete multi-node HTTP
login readiness: WebAuthn challenges and client-assertion replay state are still
separate single-process boundaries. Independent offline grants and the consent
UI completion remain separate tasks.

Operate Redis as security authority: use appropriate ACLs/TLS and an eviction
policy that does not silently treat credential state as expendable cache data.
Missing records invalidate credentials, while errors/corruption fail validation
with Unavailable. Runtime clients honor context deadlines, have bounded I/O, and
do not transparently retry consumptive commands. Never roll Redis back to a
snapshot that could restore revoked grants or forget consumed proofs; discard
credential/replay namespaces and reauthenticate instead.

Enabled `/readyz` verifies the private listener, current usable SVID/bundle,
PostgreSQL and Redis; `/healthz` remains dependency-independent. SVID acquisition
is bounded to ten seconds. Connections age out after five minutes with
30-second grace; requests default to a two-second deadline. On either listener's
failure or termination, both stop admissions and drain under the shutdown bound,
then force-close if needed before audit/source/backing-resource cleanup.
Monitor readiness, dependency errors, forced shutdowns and certificate renewal;
no successful token response is a reusable authorization cache entry.

Use `npm exec -- nx run identity-api:test-grpc-integration --skipNxCache` with
disposable PostgreSQL/Redis and run database suites serially. Missing test
dependencies fail rather than skip. Unit transport tests use real mTLS and
generated clients. Production enablement still needs approved workload grants,
socket access controls, private networking and verified consumer error/nonce
forwarding. Disable/drain the listener for rollback; never silently weaken a
consumer to an offline or unauthenticated fallback.

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
          args: ['-config', '/run/spire/config/spire-agent.conf']
          resources:
            requests:
              cpu: '100m'
              memory: '128Mi'
            limits:
              cpu: '500m'
              memory: '256Mi'
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
  refreshInterval: '5m' # Sync frequency with Infisical
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
    - secretKey: STEPUP_REPLAY_HMAC_KEY
      remoteRef:
        key: /production/crypto/stepup_replay_hmac_key
```

Application Pods bind this generated secret as standard environment variables or files:

```yaml
env:
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: idp-runtime-secrets
        key: POSTGRES_PASSWORD
  - name: STEPUP_REPLAY_HMAC_KEY
    valueFrom:
      secretKeyRef:
        name: idp-runtime-secrets
        key: STEPUP_REPLAY_HMAC_KEY
```

### 2.2 Step-up Replay Key Deployment and Rotation

`STEPUP_REPLAY_HMAC_KEY` is an independent secret for deriving opaque Redis replay-key names; it is not the OIDC signing key. Supply standard base64 that decodes to at least 32 random bytes (for example, `openssl rand -base64 32`). It is required outside explicit development, must be identical on every API replica, and requires a healthy shared Redis deployment. Redis `SET NX` claims enforce one redemption across the cluster and replay-guard errors fail closed.

Do not rotate this key with an ordinary mixed-version rolling deployment. Replicas using different values create disjoint replay domains, allowing the same still-valid grant or TOTP proof to be claimed once per domain. The current implementation does not support dual-key overlap. Use this coordinated runbook:

1. Stop issuing and accepting Step-up-protected operations, then drain or stop all API replicas.
2. From the last issued grant, wait at least the larger of the configured grant lifetime and TOTP replay window. With the current policy, the maximum `STEPUP_TOKEN_TTL` is five minutes and is the controlling interval.
3. Replace the Infisical/ExternalSecret value, ensure every replica observes the same decoded key, and restart all replicas as one coordinated cutover.
4. Restore protected traffic, verify Redis health and a single-use grant across replicas, and let old versioned replay entries expire naturally by TTL.

---

## 3. Prometheus Monitoring & Alerting

Observability is core to detecting anomalies, token-theft attempts, and system exhaustion.

### 3.1 Core Operational Metrics

The Go backend and Next.js applications expose Prometheus metrics on `/metrics`.

| Metric Name                            | Type      | Labels                             | Description                                                    |
| :------------------------------------- | :-------- | :--------------------------------- | :------------------------------------------------------------- |
| `idp_http_request_duration_seconds`    | Histogram | `path`, `method`, `status`         | Latency distribution of external REST requests.                |
| `idp_grpc_request_duration_seconds`    | Histogram | `method`, `status`                 | Latency distribution of internal validation RPCs.              |
| `idp_database_pool_active_connections` | Gauge     | `pool`                             | Active connections to PostgreSQL and Redis.                    |
| `idp_otp_failures_total`               | Counter   | `channel` (`sms`, `totp`)          | Unsuccessful OTP login attempts.                               |
| `idp_rtr_breach_detections_total`      | Counter   | `client_id`                        | Number of times a revoked/replayed Refresh Token was detected. |
| `idp_envelope_encryption_errors_total` | Counter   | `operation` (`encrypt`, `decrypt`) | Cryptographic failures in envelope encryption logic.           |

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
          summary: 'Potential Token Theft Breach Detected'
          description: 'A client attempted to present an already-used Refresh Token. All user active sessions have been automatically invalidated by the system.'

      # 2. Alert for Sudden Spike in SMS OTP Failures (Potential Brute-force / Toll-fraud)
      - alert: HighOTPFailuresRate
        expr: rate(idp_otp_failures_total{channel="sms"}[5m]) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: 'High volume of SMS OTP failures'
          description: 'SMS OTP failures exceed 10/minute over 5m, indicating possible automated enumeration or brute-force attempts.'

      # 3. Alert for Envelope Cryptographic Failures
      - alert: EnvelopeEncryptionFailure
        expr: rate(idp_envelope_encryption_errors_total[1m]) > 0
        for: 0m
        labels:
          severity: page
        annotations:
          summary: 'Application-Layer Cryptographic Operations Failure'
          description: 'Database row envelope encryption or decryption is failing. This indicates KEK/DEK mismatch or corruption.'

      # 4. Alert for Database Connection Pool Exhaustion
      - alert: DBConnectionPoolExhausted
        expr: idp_database_pool_active_connections / idp_database_pool_max_connections > 0.90
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: 'Database connection pool utilization is critically high'
          description: 'Active database connections are over 90% of pool limits, risking query queuing and increased request latencies.'
```

### Admin deployment gate

Before enabling `/api/v1/admin`, follow [admin operations](admin-operations.md), including role separation, approved retention, encrypted backfill, version-aware issuers, acknowledged outbox delivery, signer lookup probe and ingress log validation. The Traefik successor must disable admin access/debug/tracing capture or allowlist only method, router/template, status and duration. RequestPath/RequestLine, query strings, bodies, cookies, step-up headers and referrers must never reach log sinks. Test both the new POST and rejected legacy GET with synthetic identity values. Do not claim a deployed collector is safe from this example alone.
