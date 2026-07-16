# identity-api

The Go backend for the Hatef Identity Platform (IdP). This service will implement
OIDC/OAuth 2.1, RBAC, token issuance, WebAuthn, and gRPC inter-service APIs. At
this scaffolding stage (Task 1.2) it exposes health and readiness probes only.

## Layout

```
apps/identity-api/
├── cmd/server/          # main entry point (HTTP server + graceful shutdown)
├── internal/
│   ├── config/          # env-based configuration (no hardcoded secrets)
│   └── server/          # router, middleware, health handlers
└── db/
    ├── migrations/      # SQL migrations (Task 2.1)
    └── queries/         # sqlc query definitions (Task 2.2)
```

## Endpoints

| Method | Path       | Purpose                                     |
| :----- | :--------- | :------------------------------------------ |
| GET    | `/healthz` | Liveness probe. Always 200 while running.   |
| GET    | `/readyz`  | Readiness probe. Reports service readiness. |

## Configuration

All configuration comes from environment variables. Secrets must be injected at
runtime (via Infisical/KMS or the container environment) and never committed.

| Variable  | Default       | Description                          |
| :-------- | :------------ | :----------------------------------- |
| `HOST`    | `0.0.0.0`     | Bind interface.                      |
| `PORT`    | `8080`        | HTTP listen port.                    |
| `APP_ENV` | `development` | Deployment environment label.        |

## Local development

The workspace package manager is used to drive tasks through Nx:

```bash
pnpm nx serve identity-api   # go run ./cmd/server
pnpm nx build identity-api   # go build -o bin/identity-api ./cmd/server
pnpm nx test identity-api    # go test ./...
pnpm nx lint identity-api    # golangci-lint run ./...
```

Or directly with the Go toolchain from this directory:

```bash
go run ./cmd/server
go test ./...
```

Then verify:

```bash
curl http://localhost:8080/healthz
curl http://localhost:8080/readyz
```
