# Containers and GHCR

## Local full stack

Docker Engine/Desktop with Linux containers and Docker Compose v2 is sufficient;
host Go, Node, npm and code generation are not required. From the repository root:

```sh
docker compose up -d
docker compose ps -a
docker compose logs --tail=50 init migrate api web ingress
```

The first run builds the Go binaries/generated contracts and the production
Next.js standalone app. Open **https://localhost:8443** after `api` and `web` are
healthy. Only this loopback port is published. This is a development stack with
local database credentials, not a production deployment. `.env` is not loaded as
an API env file: the existing example's host URLs and placeholder keys cannot
override the container configuration. Local `APP_ENV=development` is explicit.

`init` and `migrate` exiting successfully is normal. Init creates independent
private KEK/pepper/replay/mock keys, two OIDC keys and a private local certificate
authority. Keys and TLS are separate persistent volumes. Existing complete keys
are validated and reused; partial/expired/invalid initialization refuses rather
than replacing key material. Keep these volumes with the matching database.
After the one-year leaf certificate expires, renew it under the retained CA using
an explicitly scoped maintenance procedure; automatic key rotation is not provided.

Export the **public CA certificate only**:

```sh
docker compose cp init:/run/local-tls/ca.crt ./local-ca.crt
```

Trust it once in your OS/browser. On Windows, import into Current User > Trusted
Root Certification Authorities (`certutil -user -addstore Root .\local-ca.crt`);
on Linux copy to `/usr/local/share/ca-certificates/hatef-local.crt` and run
`sudo update-ca-certificates`. Firefox may require its own Authorities import.
Do not export the CA private key, application keys or whole volumes into browser
artifacts. Do not disable TLS verification to use the application.

```sh
docker compose restart api web ingress
docker compose up -d --build          # after changing source
docker compose down                  # retains keys and all data
```

The project `hatef-idp-local` and project-scoped volumes are independent of
`docker-compose.dev.yml`. Never use `down -v` on retained data as a repair step.
The dedicated local proxy subnet is `172.30.84.0/29`; its sole trusted ingress
address is `172.30.84.2/32`. If that subnet overlaps an existing network, change
the subnet, ingress address and API trust CIDR together. Never trust a broad
Docker/public range. Ingress strips inbound forwarding assertions and preserves
Host (including the port), Origin, DPoP, cookies and application CSP/cache headers.

Signup, SMS, SMTP, admin, legal workflow, gRPC and operational workers are not
automatically enabled. They retain their existing activation requirements;
this stack does not seed users or claim that a fresh installation can send mail/SMS.

## Production using tested GHCR images

The canonical workflow publishes both `identity-api` and `identity-web` packages
under `ghcr.io/hatefsystems/`. Main pushes publish `sha-<full-commit>` plus `main`;
version-tag pushes (`v1.2.3`) publish `1.2.3`. Only stable version releases can
advance `latest`; prereleases and main cannot. PR/fork/manual events cannot publish.
All existing quality/security/browser gates precede publication, and publication
loads the tested archives, checks provenance and smoke-tests their registry digests.
Stale main runs retain their immutable SHA but do not move the main alias.

Use the **matching API_IMAGE/WEB_IMAGE digest pair from the Actions summary**.
Do not deploy moving `main`/`latest` aliases. Version tags or `sha-<full-commit>`
are also accepted operational references; neither artifact is rebuilt on the server.
The platform is currently linux/amd64. Newly created GHCR packages may be private:
configure package Actions access; for private pulls log in with a read-packages
credential. Changing public visibility remains an administrator action.

1. Copy `.env.production.example` to `.env.production` (private, `chmod 600`).
   Set the immutable image pair, independent private keys, nonempty approved OIDC
   client registry, canonical HTTPS origin and matching RP configuration. Compose
   supports single-quoted multiline PEM values. Obtain keys through the approved
   secret custody process, not from the local development volumes.
2. Configure PostgreSQL owner credentials and a separate non-owner API DSN. Internal
   DSNs use `postgres:5432` and `redis:6379`; URL-encode passwords. The template
   intentionally contains no usable secrets. API receives only its own settings,
   never the schema-owner/migration credential.
3. Follow the fresh-baseline, role/grant, key-inventory and worker supervision
   requirements in [the operations playbook](devops-operations.md#fresh-baseline-environment-cutover).
   Default production volumes are not proof of freshness. Existing legacy schema
   history is refused; do not reset or relabel it. Stop/drain existing writers and
   separately supervised workers before migration.
4. Configure host Nginx using `tools/docker/nginx.production.conf.example` and
   `tools/docker/proxy-headers.conf`; replace the sample hostname/certificate paths.
   Run `sudo nginx -t` before reloading. API/web bind only to host loopback 8080/3000;
   infrastructure ports are not published. Determine Nginx's actual socket peer
   inside the Docker network and set only that exact address in
   `TRUSTED_PROXY_CIDRS`. Host loopback does not imply the API sees 127.0.0.1:
   Docker NAT may present the bridge gateway. Use scoped network inspection or
   an ephemeral connection probe; do not log authentication traffic to discover it.

For an already provisioned target, run each step only if the preceding command
succeeded (shell `&&` enforces this). On a fresh target, pause after migration to
provision the separate API role/grants using the playbook, then run the final `up`:

```sh
docker compose --env-file .env.production -f compose.production.yaml config --quiet &&
docker compose --env-file .env.production -f compose.production.yaml pull &&
docker compose --env-file .env.production -f compose.production.yaml stop api web &&
docker compose --env-file .env.production -f compose.production.yaml run --rm migrate up &&
docker compose --env-file .env.production -f compose.production.yaml up -d --wait
```

For a fresh database, provision the separate API role/grants after migration and
before the final `up`, using the operator procedures in the playbook. Do not give
the API owner credentials to make startup succeed. A failed migration leaves the
application stopped; correct the cause before continuing. Migrations are explicit
operator operations, not an automatic `up` side effect in production.

```sh
docker compose --env-file .env.production -f compose.production.yaml ps -a
docker compose --env-file .env.production -f compose.production.yaml logs --tail=50 api web
docker compose --env-file .env.production -f compose.production.yaml down
```

Updates select another compatible tested image pair and repeat the gated sequence.
Take the required backups first. Image rollback does not undo schema/data changes;
the baseline is forward-only. Data/keys, queued notification versions and original
deadlines must survive rollback. No deployment, database reset, worker activation
or production approval is performed by GitHub Actions. Optional capabilities need
reviewed Compose overrides for their existing configuration and separate worker
credentials; see the corresponding operations sections.

Verify the real deployed HTTPS ingress, strict cookies, DPoP origin binding,
request-unique CSP/nonces and no-store HTML before allowing traffic. Existing
Persian/manual/platform gates remain explicit. Avoid `compose config` without
`--quiet`, environment dumps and unmasked screenshots: they may expose secrets.
