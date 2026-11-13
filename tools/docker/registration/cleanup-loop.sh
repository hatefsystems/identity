#!/bin/sh
set -eu
marker=/tmp/registration-cleanup.last-success
if [ "${1:-}" = healthcheck ]; then
  last=$(cat "$marker" 2>/dev/null) || exit 1
  case "$last" in ''|*[!0-9]*) exit 1;; esac
  age=$(($(date +%s)-last))
  [ "$age" -ge 0 ] && [ "$age" -lt 120 ]
  exit $?
fi
[ "$#" -eq 0 ] && [ "${APP_ENV:-}" = development ] || exit 1
rm -f "$marker"
trap 'rm -f "$marker"; exit 0' TERM INT
/usr/local/bin/registration-cleanup check
while :; do
  /usr/local/bin/registration-cleanup once || { rm -f "$marker"; exit 1; }
  date +%s > "$marker"
  sleep 60 &
  wait "$!"
done
