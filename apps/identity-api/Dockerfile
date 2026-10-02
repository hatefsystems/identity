# Container image for the identity-api Go module.
#
# Build context is this directory (the Go module root), not the workspace root:
#
#   docker build -t identity-api:dev apps/identity-api
#
# ONE IMAGE, SEVERAL ENTRYPOINTS
# Every binary under ./cmd is built; the runtime binaries listed below are copied
# into one image. The deployment selects one with an explicit --entrypoint:
#
#   identity-api    the HTTP API      (default entrypoint)
#   audit-signer    audit chain signer worker
#   admin-audit-publisher  acknowledged administrative/maintenance outbox publisher
#   purge-worker    Class A GDPR erasure worker (host cron/systemd)
#   security-ledger-purge  Class B retention worker (host cron/systemd)
#   migrate         goose migration runner (controlled operator invocation)
#
# This is deliberate rather than lazy. The API publishes audit envelopes and the
# signer serializes them into a hash chain; the two must agree byte-for-byte on
# internal/audit's canonical serializer, or the chain the signer writes will not
# verify against the records the API produced. Shipping them as one immutable
# artifact makes compatible versions available together. Rollout must still prevent
# old signer binaries from running after ledger retention is enabled.
# The same argument applies to migrate: the embedded migrations and the sqlc-generated
# code are generated from the same files in the same build.

ARG GO_VERSION=1.26
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot

# ---------------------------------------------------------------------------
# Build stage
# ---------------------------------------------------------------------------
FROM golang:${GO_VERSION}-alpine AS builder

WORKDIR /src

# Dependencies are resolved before the source is copied so an edit to a .go file
# does not invalidate the (slow) module download layer.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# internal/db is sqlc-generated and deliberately untracked (see .gitignore), so it
# does not exist in a clean checkout and must be generated here. Skipping this would
# fail the build with "no required module provides package .../internal/db" — or,
# worse, silently compile a stale copy if one ever leaked into the context.
RUN go tool sqlc generate

# CGO is disabled so the result is a static binary that runs on a distroless static
# base with no libc. -trimpath keeps absolute build paths out of panic traces, and
# -s -w drops the symbol table and DWARF data.
#
# GOFLAGS=-mod=readonly makes an out-of-date go.sum a build failure rather than a
# silent dependency change.
ENV CGO_ENABLED=0 GOOS=linux GOFLAGS=-mod=readonly

# A single -o directory builds every command package at once; adding a new one under
# ./cmd requires no edit here.
RUN go build -trimpath -ldflags='-s -w' -o /out/ ./cmd/...

# Fail loudly at build time if a command failed to produce a binary, instead of
# shipping an image whose entrypoint does not exist.
RUN test -x /out/server && test -x /out/purge-worker && test -x /out/migrate \
    && test -x /out/audit-signer && test -x /out/admin-audit-publisher \
    && test -x /out/security-ledger-purge

# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
FROM ${RUNTIME_IMAGE}

# The distroless static base provides ca-certificates (needed for outbound TLS to
# the SMS provider and NATS) and tzdata, and nothing else: no shell, no package
# manager, no busybox. That removes the entire class of "exec into the container and
# poke at the audit chain" incidents, which matters for a process holding the
# blind-index pepper and the ledger's single-writer lock.

WORKDIR /

COPY --from=builder /out/server /usr/local/bin/identity-api
COPY --from=builder /out/purge-worker /usr/local/bin/purge-worker
COPY --from=builder /out/migrate /usr/local/bin/migrate
# The audit chain signer (Task 5.2). It shares this image rather than getting its own
# so both processes are guaranteed to carry the same envelope schema version and the
# same serialize() implementation: a signer built from different source than the
# publisher would hash records the publisher did not describe. Deploy it by
# overriding the entrypoint, with replicas: 1 — see cmd/audit-signer.
COPY --from=builder /out/audit-signer /usr/local/bin/audit-signer
COPY --from=builder /out/admin-audit-publisher /usr/local/bin/admin-audit-publisher
COPY --from=builder /out/security-ledger-purge /usr/local/bin/security-ledger-purge

# The HTTP API's default listen port (config.defaultPort). Informational only.
EXPOSE 8080

# nonroot is uid/gid 65532, provided by the base image. Declared explicitly so the
# image is unusable as root even if a Pod spec omits securityContext.
USER nonroot:nonroot

# No HEALTHCHECK: the base image has no shell and no HTTP client to run one with.
# Liveness and readiness are the orchestrator's job, against GET /healthz and
# GET /readyz (see docs/devops-operations.md).

ENTRYPOINT ["/usr/local/bin/identity-api"]
