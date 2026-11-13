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

### Enable real local signup

The default `REGISTRATION_ENABLED=false` deliberately leaves
`POST /api/v1/auth/register/start` unmounted (404 after origin validation).
To use the registration form with real SMS.ir and email delivery:

1. Copy `.env.registration.example` to **`.env.registration`** and fill it privately.
   It is gitignored. Single-quote credentials containing `$` to preserve their
   exact bytes through Compose interpolation. Use a live SMS.ir verification key, approved template ID and
   exact code parameter (without `#`). The SMTP relay must support authenticated,
   verified TLS **and SMTPUTF8 after TLS**, including when your test address is ASCII.
   Use `starttls`/587 or your provider's `implicit`/465 settings.
2. Set explicit positive budgets: `SMS_OTP_GLOBAL_PER_DAY` and
   `REGISTRATION_GLOBAL_DAILY_LIMIT` at most 100000,
   `REGISTRATION_PENDING_CAPACITY` at most 10000 and
   `REGISTRATION_EMAIL_HOURLY_LIMIT` at most 10. Choose these to match your intended
   live spend; the pending SMS/signup capacities are kept identical automatically.
3. Generate an independent base64 32-byte `SMS_OTP_HASH_PEPPER` and a separate
   32..128 character URL-safe `REGISTRATION_CLEANUP_PASSWORD` (letters, digits,
   `_` and `-`). For example, privately run `openssl rand -base64 32` and
   `openssl rand -hex 32`. Keep these stable with the retained data. Do not reuse
   the envelope key/pepper and do not paste credentials or generated secrets in chat.
4. Enable the local overlay using **both** Compose files:

   ```sh
   docker compose --env-file .env.registration -f compose.yaml -f compose.registration.yaml up -d --wait
   ```

The overlay creates one dedicated local cleanup login with only the existing
registration cleanup privileges, then supervises a bounded cleanup pass every
60 seconds. Existing login passwords/privileges are not overwritten; the worker
checks its real credentials/schema/privileges and API startup waits for it to be
healthy. This local owner-based role bootstrap must not be applied to production.
No users are seeded, tokens are bypassed, or production roles/gates are changed.
If an interrupted first provisioning left an incomplete role, inspect and repair
only `identity_registration_cleanup` explicitly; never reset the database/volumes.

Continue using the same `--env-file` and **both** `-f` arguments for subsequent
`up`, `ps` and `logs` commands. Running plain `docker compose up -d` selects the
base stack again and disables signup. Inspect only bounded, secret-free startup
diagnostics, for example:

```sh
docker compose --env-file .env.registration -f compose.yaml -f compose.registration.yaml ps -a
docker compose --env-file .env.registration -f compose.yaml -f compose.registration.yaml logs --tail=30 registration-setup registration-cleanup api
```

API startup verifies SMTP TLS/authentication/SMTPUTF8 without sending a message.
Submitting the form sends real email and, in the phone verification step, billable
SMS. Your browser must trust the local CA and support WebAuthn/passkeys. The email
link uses `https://localhost:8443`; open it in the same registering browser on this
computer, not on a phone where localhost refers to a different device. Actual
provider credentials, recipient delivery and relay policy must be verified with
your own configured services; copying the example does not establish delivery.

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
