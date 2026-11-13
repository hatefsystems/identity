#!/bin/sh
# Development only. Never source key material as shell code or print it.
set -eu
umask 077
keys=/run/local-keys
tls=/run/local-tls
fail() { echo 'Local initialization is incomplete or invalid. Restore the matching keys/TLS volumes; do not regenerate keys for retained data.' >&2; exit 1; }
validate() {
  for key in ENVELOPE_MASTER_KEK ENVELOPE_BLIND_INDEX_PEPPER STEPUP_REPLAY_HMAC_KEY WEBAUTHN_MOCK_CHALLENGE_KEY; do
    [ -s "$keys/$key" ] || fail
    [ "$(openssl base64 -d -A < "$keys/$key" | wc -c | tr -d ' ')" = 32 ] || fail
  done
  for key in OIDC_SIGNING_KEY_ACTIVE_PEM OIDC_SIGNING_KEY_NEXT_PEM; do
    openssl pkey -in "$keys/$key" -check -noout >/dev/null 2>&1 || fail
  done
  openssl verify -CAfile "$tls/ca.crt" -verify_hostname localhost "$tls/localhost.crt" >/dev/null 2>&1 || fail
  cert_public=$(openssl x509 -in "$tls/localhost.crt" -pubkey -noout)
  key_public=$(openssl pkey -in "$tls/localhost.key" -pubout)
  [ "$cert_public" = "$key_public" ] || fail
}
if [ -f "$keys/complete" ] && [ -f "$tls/complete" ]; then
  validate
  echo 'Existing local keys and TLS certificate verified.'
  exit 0
fi
# A partial prior attempt is evidence, not permission to overwrite secrets.
[ -z "$(ls -A "$keys")" ] && [ -z "$(ls -A "$tls")" ] || fail
for key in ENVELOPE_MASTER_KEK ENVELOPE_BLIND_INDEX_PEPPER STEPUP_REPLAY_HMAC_KEY WEBAUTHN_MOCK_CHALLENGE_KEY; do
  openssl rand -base64 32 | tr -d '\n' > "$keys/$key"
done
for key in OIDC_SIGNING_KEY_ACTIVE_PEM OIDC_SIGNING_KEY_NEXT_PEM; do
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$keys/$key"
done
openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -subj '/CN=Hatef local development CA' \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$tls/ca.key" -out "$tls/ca.crt" >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -subj '/CN=localhost' \
  -keyout "$tls/localhost.key" -out "$tls/localhost.csr" >/dev/null 2>&1
printf '%s\n' 'subjectAltName=DNS:localhost,IP:127.0.0.1' 'extendedKeyUsage=serverAuth' 'basicConstraints=critical,CA:FALSE' > "$tls/extensions"
openssl x509 -req -in "$tls/localhost.csr" -CA "$tls/ca.crt" -CAkey "$tls/ca.key" \
  -CAcreateserial -days 365 -extfile "$tls/extensions" -out "$tls/localhost.crt" >/dev/null 2>&1
validate
touch "$keys/complete" "$tls/complete"
chown -R 65532:65532 "$keys"
chmod 700 "$keys"
chmod 644 "$tls/ca.crt" "$tls/localhost.crt"
echo 'Local keys and TLS certificate initialized. Trust the exported ca.crt in your browser/OS.'
