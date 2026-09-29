#!/usr/bin/env bash
# Provisions Jam Tools on the PixSmith auth server.
#
# Registering the OIDC client is no longer enough. Under the tenant model, access to
# an application is inherited through a company:
#
#     Tenant ──subscribes to──> Application (OIDC client)
#        └────has member───────> User        ⟹ that user may use the app
#
# So this does three things, each idempotent:
#
#   1. register (or update) the "jamtools-web-local" client — one client per
#      DEPLOYMENT, not per application, so a leaked credential or a rotation is
#      contained to one environment
#   2. subscribe a tenancy to it          — POST /tenants/{id}/applications
#   3. make sure the signing-in user is a member of that tenancy
#
#   ADMIN_PASSWORD='…' ./tools/provision-app-access.sh
#
# ROTATE_SECRET=1 additionally resets the client secret to $CLIENT_SECRET — needed only
# when sign-in fails with invalid_client, since the stored secret is hashed and cannot be
# compared from here.
#
# Creating a *tenancy* is deliberately not done here: that endpoint requires an
# offline signature quorum (see the auth server's docs/TENANT-PROVISIONING.md). This
# script uses an existing tenancy — by default the "Default" one the backfill creates.
set -euo pipefail

AUTH_BASE="${AUTH_BASE:-http://127.0.0.1:8080}"
APP_BASE="${APP_BASE:-http://localhost:5080}"

CLIENT_ID="${CLIENT_ID:-jamtools-web-local}"

# How the app authenticates at the token endpoint.
#   private_key_jwt — the app signs an assertion; we register only its public key.
#                     Its JWKS is read from the running app, so no key material is
#                     copied by hand and the private half never leaves the app.
#   secret          — the shared secret below.
CLIENT_AUTH="${CLIENT_AUTH:-private_key_jwt}"
CLIENT_SECRET="${CLIENT_SECRET:-jamtools-dev-secret}"
APP_JWKS_URL="${APP_JWKS_URL:-${APP_BASE}/api/auth/client-jwks}"

# The app writes its public JWKS beside its signing key on startup, so this works whether
# or not Jam Tools is running right now — it only has to have been started once.
APP_JWKS_FILE="${APP_JWKS_FILE:-$(cd "$(dirname "$0")/.." && pwd)/PixSmith.Server.JamTools/keys/client-signing-key.jwks.json}"

# Which company gets Jam Tools. Matched on slug first, then name.
TENANT="${TENANT:-Default}"

ADMIN_CLIENT_ID="${ADMIN_CLIENT_ID:-blazor-client}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin@pixsmith.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"

# Who should be able to sign in to Jam Tools. Defaults to the admin themselves.
MEMBER_EMAIL="${MEMBER_EMAIL:-$ADMIN_USERNAME}"
MEMBER_ROLES="${MEMBER_ROLES:-Member}"

if [ -z "$ADMIN_PASSWORD" ]; then
  read -r -s -p "Auth server admin password for ${ADMIN_USERNAME}: " ADMIN_PASSWORD
  echo
fi

jsonq() { python3 -c "import sys,json$1"; }

# ── 1. the credential this client will be registered with ─
# Resolved before anything else: a missing signing key is a local problem and
# should not cost you a password prompt and an admin round trip to discover.
# ── ──────────────────────────
if [ "$CLIENT_AUTH" = "private_key_jwt" ]; then
  if [ -f "$APP_JWKS_FILE" ]; then
    echo "→ Reading this deployment's public JWKS from ${APP_JWKS_FILE}"
    JWKS=$(cat "$APP_JWKS_FILE")
  else
    echo "→ No JWKS file yet — asking the running app at ${APP_JWKS_URL}"
    JWKS=$(curl -sS --max-time 10 "$APP_JWKS_URL" 2>/dev/null || true)
  fi
  VALID=$(printf '%s' "$JWKS" | python3 -c '
import json, sys
try:
    keys = json.load(sys.stdin).get("keys") or []
except Exception:
    keys = []
private = [c for k in keys for c in ("d","p","q","dp","dq","qi","k") if c in k]
ok = bool(keys) and not private and all(k.get("use") == "sig" for k in keys)
print("yes" if ok else "no")')

  if [ "$VALID" != "yes" ]; then
    echo "✗ No usable signing key for this deployment." >&2
    echo >&2
    echo "  Looked for:" >&2
    echo "    file  ${APP_JWKS_FILE}" >&2
    echo "    url   ${APP_JWKS_URL}" >&2
    echo >&2
    echo "  The JAM TOOLS app generates its key on first start and writes the public half" >&2
    echo "  to that file (the auth server on :8080 is not what is needed here). Start it" >&2
    echo "  once, then re-run this script — it does not need to stay running:" >&2
    echo >&2
    echo "    dotnet run --project PixSmith.Server.JamTools --launch-profile http" >&2
    echo >&2
    echo "  If Oidc:ClientAuthentication is \"ClientSecret\", re-run with CLIENT_AUTH=secret" >&2
    echo "  instead. A key set carrying private components is refused by design." >&2
    exit 1
  fi
  KID=$(printf '%s' "$JWKS" | python3 -c 'import json,sys; print(json.load(sys.stdin)["keys"][0].get("kid",""))')
  echo "  ✓ public key ${KID:0:16}… (private half stays in the app)"

  # jsonWebKeySet carries raw JWKS JSON, so it has to be embedded as a JSON string.
  CREDENTIAL=$(JWKS="$JWKS" python3 -c '
import json, os
print("\"clientSecret\": null, \"jsonWebKeySet\": " + json.dumps(os.environ["JWKS"]))')
else
  echo "→ Using a shared client secret"
  CREDENTIAL="\"clientSecret\": \"${CLIENT_SECRET}\""
fi

# ── 2. admin token ────────────────────────────────────────────────────────────
echo "→ Requesting an admin token from ${AUTH_BASE}"
TOKEN_RESPONSE=$(curl -sS --max-time 15 -X POST "${AUTH_BASE}/connect/token" \
  --data-urlencode "grant_type=password" \
  --data-urlencode "client_id=${ADMIN_CLIENT_ID}" \
  --data-urlencode "username=${ADMIN_USERNAME}" \
  --data-urlencode "password=${ADMIN_PASSWORD}" \
  --data-urlencode "scope=openid profile roles admin")

ACCESS_TOKEN=$(printf '%s' "$TOKEN_RESPONSE" | jsonq '; print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null || true)
if [ -z "$ACCESS_TOKEN" ]; then
  echo "✗ Could not get an admin token. The server said:" >&2
  printf '%s\n' "$TOKEN_RESPONSE" >&2
  exit 1
fi
AUTH_HEADER="Authorization: Bearer ${ACCESS_TOKEN}"
echo "  got a token (${#ACCESS_TOKEN} chars)"

# ── 3. the OIDC client ────────────────────────────────────────────────────────
read -r -d '' CLIENT_PAYLOAD <<JSON || true
{
  "clientId": "${CLIENT_ID}",
  ${CREDENTIAL},
  "displayName": "Jam Tools (local)",
  "clientType": "confidential",
  "redirectUris": ["${APP_BASE}/signin-oidc"],
  "postLogoutRedirectUris": ["${APP_BASE}/signout-callback-oidc"],
  "scopes": ["openid", "profile", "email", "roles", "offline_access", "api"],
  "grantTypes": ["authorization_code", "refresh_token"]
}
JSON

# The update endpoint preserves the stored client secret (it reads the hash back via
# PopulateAsync and hands it straight to the descriptor), so editing a redirect URI no
# longer wipes the credential. Changing the secret is a separate, explicit operation:
# POST /oidc-apps/{clientId}/rotate-secret — because rotation breaks every deployment
# still using the old value, and that must never be a side effect of an edit.
CURRENT=$(curl -sS --max-time 15 -H "$AUTH_HEADER" "${AUTH_BASE}/api/admin/oidc-apps/${CLIENT_ID}")

# A 404 can come back as a JSON error body, so "parses as JSON" is not enough —
# require the clientId field an actual registration would carry.
EXISTS=$(printf '%s' "$CURRENT" | python3 -c '
import json, sys
try:
    app = json.load(sys.stdin)
    print("yes" if isinstance(app, dict) and app.get("clientId") else "no")
except Exception:
    print("no")')

if [ "$EXISTS" = "yes" ]; then
  MATCHES=$(printf '%s' "$CURRENT" | APP_BASE="$APP_BASE" python3 -c '
import json, os, sys
want = os.environ["APP_BASE"].rstrip("/") + "/signin-oidc"
try: app = json.load(sys.stdin)
except Exception: app = {}
uris = [str(u).rstrip("/") for u in (app.get("redirectUris") or [])]
print("yes" if want in uris else "no")')

  if [ "$MATCHES" = "yes" ]; then
    echo "→ Client '${CLIENT_ID}' already registered with the right redirect URI"
  else
    echo "→ Updating client '${CLIENT_ID}' (its existing credential is preserved)"
    # On update, an omitted jsonWebKeySet keeps the registered set and an omitted secret
    # keeps the stored one — so only send a key set when we have a fresh one to publish.
    if [ "$CLIENT_AUTH" = "private_key_jwt" ]; then
      UPDATE_CREDENTIAL=$(JWKS="$JWKS" python3 -c '
import json, os
print("\"jsonWebKeySet\": " + json.dumps(os.environ["JWKS"]) + ",")')
    else
      UPDATE_CREDENTIAL=""
    fi
    read -r -d '' UPDATE_PAYLOAD <<JSON || true
{
  "displayName": "Jam Tools (local)",
  ${UPDATE_CREDENTIAL}
  "redirectUris": ["${APP_BASE}/signin-oidc"],
  "postLogoutRedirectUris": ["${APP_BASE}/signout-callback-oidc"],
  "scopes": ["openid", "profile", "email", "roles", "offline_access", "api"],
  "grantTypes": ["authorization_code", "refresh_token"]
}
JSON
    CODE=$(curl -sS -o /tmp/jamtools-prov.out -w '%{http_code}' --max-time 15 -X PUT \
      "${AUTH_BASE}/api/admin/oidc-apps/${CLIENT_ID}" \
      -H "$AUTH_HEADER" -H "Content-Type: application/json" -d "$UPDATE_PAYLOAD")
    case "$CODE" in
      200|204) echo "  ✓ updated" ;;
      *) echo "✗ update failed (HTTP ${CODE}):" >&2; cat /tmp/jamtools-prov.out >&2; exit 1 ;;
    esac
  fi
else
  echo "→ Creating client '${CLIENT_ID}'"
  CODE=$(curl -sS -o /tmp/jamtools-prov.out -w '%{http_code}' --max-time 15 -X POST \
    "${AUTH_BASE}/api/admin/oidc-apps" \
    -H "$AUTH_HEADER" -H "Content-Type: application/json" -d "$CLIENT_PAYLOAD")
  case "$CODE" in
    200|201) echo "  ✓ created with the configured secret" ;;
    *) echo "✗ client registration failed (HTTP ${CODE}):" >&2; cat /tmp/jamtools-prov.out >&2; exit 1 ;;
  esac
fi

# The stored secret is hashed and unreadable, so this script cannot check whether it
# still matches Oidc:ClientSecret. Rotate explicitly when sign-in fails with
# invalid_client: ROTATE_SECRET=1 sets it to $CLIENT_SECRET.
if [ "${ROTATE_SECRET:-0}" = "1" ] && [ "$EXISTS" = "yes" ]; then
  echo "→ Rotating the client secret to the configured value"
  CODE=$(curl -sS -o /tmp/jamtools-prov.out -w '%{http_code}' --max-time 15 -X POST \
    "${AUTH_BASE}/api/admin/oidc-apps/${CLIENT_ID}/rotate-secret" \
    -H "$AUTH_HEADER" -H "Content-Type: application/json" \
    -d "{\"clientSecret\": \"${CLIENT_SECRET}\"}")
  case "$CODE" in
    200) echo "  ✓ rotated — every other deployment of this client must be updated too" ;;
    *) echo "✗ rotation failed (HTTP ${CODE}):" >&2; cat /tmp/jamtools-prov.out >&2; exit 1 ;;
  esac
fi

# ── 4. the tenancy ────────────────────────────────────────────────────────────
echo "→ Looking for tenancy '${TENANT}'"
TENANTS=$(curl -sS --max-time 15 -H "$AUTH_HEADER" "${AUTH_BASE}/api/admin/tenants")
TENANT_INFO=$(printf '%s' "$TENANTS" | TENANT="$TENANT" python3 -c '
import json, os, sys
want = os.environ["TENANT"].lower()
try: rows = json.load(sys.stdin)
except Exception: rows = []
if isinstance(rows, dict): rows = rows.get("items", rows.get("value", []))
hit = next((t for t in rows if str(t.get("slug","")).lower() == want), None) \
   or next((t for t in rows if str(t.get("name","")).lower() == want), None)
if hit:
    print("\t".join([str(hit["id"]), str(hit.get("slug") or ""), str(hit.get("isActive"))]))
else:
    names = ", ".join(str(t.get("name")) + " (" + str(t.get("slug")) + ")" for t in rows)
    print("\t\t")
    print("AVAILABLE: " + (names or "none"))
')
TENANT_ID=$(printf '%s' "$TENANT_INFO" | head -1 | cut -f1)
TENANT_SLUG=$(printf '%s' "$TENANT_INFO" | head -1 | cut -f2)

if [ -z "$TENANT_ID" ]; then
  echo "✗ No tenancy matched '${TENANT}'." >&2
  printf '%s\n' "$TENANT_INFO" | sed -n '2p' >&2
  echo "  Creating a tenancy needs an offline signature quorum — see the auth server's" >&2
  echo "  docs/TENANT-PROVISIONING.md. Re-run with TENANT=<slug> once one exists." >&2
  exit 1
fi
echo "  ✓ tenancy ${TENANT_SLUG} (${TENANT_ID})"

# ── 5. subscribe the tenancy to this application ──────────────────────────────
SUBSCRIBED=$(curl -sS --max-time 15 -H "$AUTH_HEADER" \
  "${AUTH_BASE}/api/admin/tenants/${TENANT_ID}/applications" \
  | CLIENT_ID="$CLIENT_ID" python3 -c '
import json, os, sys
try: rows = json.load(sys.stdin)
except Exception: rows = []
print("yes" if any(r.get("clientId") == os.environ["CLIENT_ID"] for r in rows) else "no")')

if [ "$SUBSCRIBED" = "yes" ]; then
  echo "→ Subscription already present — ensuring it is active"
  curl -sS -o /dev/null --max-time 15 -X PUT \
    "${AUTH_BASE}/api/admin/tenants/${TENANT_ID}/applications/${CLIENT_ID}" \
    -H "$AUTH_HEADER" -H "Content-Type: application/json" -d '{"isActive": true}' || true
else
  echo "→ Subscribing '${TENANT_SLUG}' to '${CLIENT_ID}'"
  CODE=$(curl -sS -o /tmp/jamtools-prov.out -w '%{http_code}' --max-time 15 -X POST \
    "${AUTH_BASE}/api/admin/tenants/${TENANT_ID}/applications" \
    -H "$AUTH_HEADER" -H "Content-Type: application/json" \
    -d "{\"clientId\": \"${CLIENT_ID}\"}")
  case "$CODE" in
    200|201) echo "  ✓ subscribed" ;;
    *) echo "✗ subscription failed (HTTP ${CODE}):" >&2; cat /tmp/jamtools-prov.out >&2; exit 1 ;;
  esac
fi

# ── 6. membership for the person who will sign in ─────────────────────────────
echo "→ Checking membership for ${MEMBER_EMAIL}"
USER_ID=$(curl -sS --max-time 15 -H "$AUTH_HEADER" "${AUTH_BASE}/api/admin/users?page=1&pageSize=200" \
  | MEMBER_EMAIL="$MEMBER_EMAIL" python3 -c '
import json, os, sys
want = os.environ["MEMBER_EMAIL"].lower()
try: data = json.load(sys.stdin)
except Exception: data = {}
rows = data.get("items") or data.get("users") or (data if isinstance(data, list) else [])
hit = next((u for u in rows if str(u.get("email","")).lower() == want
            or str(u.get("username","")).lower() == want), None)
print(hit["id"] if hit else "")')

if [ -z "$USER_ID" ]; then
  echo "  ! No user matched ${MEMBER_EMAIL} — skipping membership." >&2
else
  ALREADY=$(curl -sS --max-time 15 -H "$AUTH_HEADER" \
    "${AUTH_BASE}/api/admin/tenants/${TENANT_ID}/members" \
    | USER_ID="$USER_ID" python3 -c '
import json, os, sys
try: rows = json.load(sys.stdin)
except Exception: rows = []
print("yes" if any(str(r.get("userId")) == os.environ["USER_ID"] for r in rows) else "no")')

  if [ "$ALREADY" = "yes" ]; then
    echo "  ✓ already a member"
  else
    ROLES_JSON=$(MEMBER_ROLES="$MEMBER_ROLES" python3 -c '
import json, os; print(json.dumps([r.strip() for r in os.environ["MEMBER_ROLES"].split(",") if r.strip()]))')
    CODE=$(curl -sS -o /tmp/jamtools-prov.out -w '%{http_code}' --max-time 15 -X POST \
      "${AUTH_BASE}/api/admin/tenants/${TENANT_ID}/members" \
      -H "$AUTH_HEADER" -H "Content-Type: application/json" \
      -d "{\"userId\": \"${USER_ID}\", \"roles\": ${ROLES_JSON}}")
    case "$CODE" in
      200|201) echo "  ✓ added as a member (${MEMBER_ROLES})" ;;
      *) echo "  ! membership failed (HTTP ${CODE}):" >&2; cat /tmp/jamtools-prov.out >&2 ;;
    esac
  fi
fi

cat <<SUMMARY

✓ Provisioned.
    client       ${CLIENT_ID}
    redirect     ${APP_BASE}/signin-oidc
    tenancy      ${TENANT_SLUG} (${TENANT_ID})

  The app sends no "organization" parameter by default, so the auth server picks the
  company for a single-membership user. To pin Jam Tools to this one, set in
  appsettings.Development.json:

      "Oidc": { "Organization": "${TENANT_SLUG}" }

  Client authentication: ${CLIENT_AUTH}
SUMMARY

if [ "$CLIENT_AUTH" = "private_key_jwt" ]; then
  cat <<'KEYNOTE'
  The app signs its own assertions; the auth server holds only the public key, and there
  is no secret in any config file. Rolling the key is additive: register both, move the
  deployment, then re-register with only the new one.
KEYNOTE
else
  echo "  Check the secret matches:  Oidc:ClientSecret = ${CLIENT_SECRET}"
  echo "  (ROTATE_SECRET=1 resets it to that value.)"
fi
