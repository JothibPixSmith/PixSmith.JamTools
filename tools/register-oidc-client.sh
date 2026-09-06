#!/usr/bin/env bash
# Registers (or updates) the Jam Tools client on the PixSmith auth server.
#
# The auth server will not issue a code to a client it doesn't know about, so this
# has to run once before sign-in works. It is idempotent — safe to re-run after
# changing ports or scopes.
#
#   ADMIN_PASSWORD='Admin1234!' ./tools/register-oidc-client.sh
#
# Everything is overridable by environment variable; the defaults match a local
# docker-compose auth server and the "http" launch profile of this app.
set -euo pipefail

AUTH_BASE="${AUTH_BASE:-http://127.0.0.1:8080}"
APP_BASE="${APP_BASE:-http://localhost:5080}"

CLIENT_ID="${CLIENT_ID:-jamtools-web}"
CLIENT_SECRET="${CLIENT_SECRET:-jamtools-dev-secret}"

ADMIN_CLIENT_ID="${ADMIN_CLIENT_ID:-blazor-client}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin@pixsmith.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"

if [ -z "$ADMIN_PASSWORD" ]; then
  read -r -s -p "Auth server admin password for ${ADMIN_USERNAME}: " ADMIN_PASSWORD
  echo
fi

echo "→ Requesting an admin token from ${AUTH_BASE}"
TOKEN_RESPONSE=$(curl -sS --max-time 15 -X POST "${AUTH_BASE}/connect/token" \
  --data-urlencode "grant_type=password" \
  --data-urlencode "client_id=${ADMIN_CLIENT_ID}" \
  --data-urlencode "username=${ADMIN_USERNAME}" \
  --data-urlencode "password=${ADMIN_PASSWORD}" \
  --data-urlencode "scope=openid profile roles admin")

ACCESS_TOKEN=$(printf '%s' "$TOKEN_RESPONSE" | python3 -c \
  'import sys,json; print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null || true)

if [ -z "$ACCESS_TOKEN" ]; then
  echo "✗ Could not get an admin token. The server said:" >&2
  printf '%s\n' "$TOKEN_RESPONSE" >&2
  exit 1
fi
echo "  got a token (${#ACCESS_TOKEN} chars)"

read -r -d '' PAYLOAD <<JSON || true
{
  "clientId": "${CLIENT_ID}",
  "clientSecret": "${CLIENT_SECRET}",
  "displayName": "Jam Tools",
  "clientType": "confidential",
  "redirectUris": ["${APP_BASE}/signin-oidc"],
  "postLogoutRedirectUris": ["${APP_BASE}/signout-callback-oidc"],
  "scopes": ["openid", "profile", "email", "roles", "offline_access", "api"],
  "grantTypes": ["authorization_code", "refresh_token"]
}
JSON

EXISTS=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  "${AUTH_BASE}/api/admin/oidc-apps/${CLIENT_ID}")

if [ "$EXISTS" = "200" ]; then
  echo "→ '${CLIENT_ID}' already exists — updating it"
  METHOD=PUT
  URL="${AUTH_BASE}/api/admin/oidc-apps/${CLIENT_ID}"
else
  echo "→ Creating '${CLIENT_ID}'"
  METHOD=POST
  URL="${AUTH_BASE}/api/admin/oidc-apps"
fi

HTTP_CODE=$(curl -sS -o /tmp/jamtools-oidc-reg.out -w '%{http_code}' --max-time 15 \
  -X "$METHOD" "$URL" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
  echo "✓ Registered. Redirect URI: ${APP_BASE}/signin-oidc"
  echo
  echo "  Make sure the secret matches what the app sends:"
  echo "    Oidc:ClientSecret = ${CLIENT_SECRET}"
  echo "  (appsettings.Development.json, or: dotnet user-secrets set \"Oidc:ClientSecret\" \"${CLIENT_SECRET}\")"
else
  echo "✗ Registration failed (HTTP ${HTTP_CODE}):" >&2
  cat /tmp/jamtools-oidc-reg.out >&2
  echo >&2
  exit 1
fi
