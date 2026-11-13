#!/bin/sh
# Explicit development-only provisioning of one restricted, new local login.
set -eu
fail() { echo 'Registration cleanup setup failed; check local database access and the dedicated role configuration.' >&2; exit 1; }
[ "${APP_ENV:-}" = development ] && [ "${PGHOST:-}" = postgres ] && [ "${PGDATABASE:-}" = identity ] && [ "${PGUSER:-}" = identity ] || fail
password=${REGISTRATION_CLEANUP_PASSWORD:-}
case "$password" in ''|*[!A-Za-z0-9_-]*) echo 'Cleanup password must be 32..128 URL-safe characters.' >&2; exit 1;; esac
[ "${#password}" -ge 32 ] && [ "${#password}" -le 128 ] || fail
export PGCONNECT_TIMEOUT=5
exists=$(psql -X -v ON_ERROR_STOP=1 -Atc "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='identity_registration_cleanup')" 2>/dev/null) || fail
if [ "$exists" = t ]; then
  echo 'Existing cleanup role retained; the worker will verify credentials and exact privileges.'
  exit 0
fi
# No private value is interpolated into SQL or command arguments. psql's
# \password encrypts the secret before sending ALTER ROLE to PostgreSQL.
psql -X -v ON_ERROR_STOP=1 >/dev/null 2>&1 <<'SQL' || fail
BEGIN;
CREATE ROLE identity_registration_cleanup NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT USAGE ON SCHEMA public TO identity_registration_cleanup;
GRANT SELECT,DELETE ON public.registration_attempts TO identity_registration_cleanup;
GRANT SELECT ON public.legal_holds TO identity_registration_cleanup;
COMMIT;
SQL
printf '%s\n%s\n' "$password" "$password" | psql -X -v ON_ERROR_STOP=1 -c '\password identity_registration_cleanup' >/dev/null 2>&1 || fail
psql -X -v ON_ERROR_STOP=1 -c 'ALTER ROLE identity_registration_cleanup LOGIN' >/dev/null 2>&1 || fail
echo 'Restricted local registration cleanup role created.'
