#!/bin/sh
set -eu
[ "${APP_ENV:-}" = development ] || { echo 'Local entrypoint requires APP_ENV=development' >&2; exit 1; }
[ -f /run/local-keys/complete ] || { echo 'Local keys are incomplete; inspect init logs' >&2; exit 1; }
for key in ENVELOPE_MASTER_KEK ENVELOPE_BLIND_INDEX_PEPPER STEPUP_REPLAY_HMAC_KEY WEBAUTHN_MOCK_CHALLENGE_KEY OIDC_SIGNING_KEY_ACTIVE_PEM OIDC_SIGNING_KEY_NEXT_PEM; do
  [ -s "/run/local-keys/$key" ] || { echo "Missing local key file: $key" >&2; exit 1; }
  export "$key=$(cat "/run/local-keys/$key")"
done
exec /usr/local/bin/server "$@"
