#!/usr/bin/env bash

set -e

# This script parses vault's openapi spec and extracts only the parts relevant for c4ghtransit.

# Dependencies
# - realpath
# - curl
# - git
# - jq
# - running vault server with c4ghtransit plugin mounted under /c4ghtransit
# - RELEASE_VERSION environment variable with the c4ghtransit version

VAULT_ADDR=${VAULT_ADDR:-'http://127.0.0.1:8200'}
RELEASE_VERSION=${RELEASE_VERSION:-$(git describe --tags --abbrev=0 --dirty)}

# get the current folder
script_path=$(realpath "$0")
script_dir=$(dirname "$script_path")

#temp=$(mktemp)

vault_api="$(mktemp)"
paths="$(mktemp)"
schemas="$(mktemp)"
template="$(mktemp)"

cleanup() {
    rm "${vault_api}"
    rm "${paths}"
    rm "${schemas}"
    rm "${template}"
}

trap cleanup EXIT

# Wait for vault to be running
echo "Checking if Vault is running"
if ! wget --quiet --retry-connrefused --waitretry=1 --tries 10 --timeout=5 --spider "${VAULT_ADDR}/v1/sys/health?standbyok=true"; then
  echo "Vault doesn't seem to be running"
  exit 1
else
  echo "Vault is running"
fi

curl -sL -H "X-Vault-Token: devroot" "$VAULT_ADDR/v1/sys/internal/specs/openapi" > "$vault_api"

# extract c4ghtransit paths
jq -c '.paths | with_entries(select(.key | test("^/c4ghtransit"))) | {paths: .}' "$vault_api" > "$paths"

# extract c4ghtransit schemas
jq -c '.components.schemas | with_entries(select(.key | test("^C4ghtransit"))) | {components: {schemas: .}}' "$vault_api" > "$schemas"

cat << EOF > "${template}"
{
  "openapi": "3.0.2",
  "info": {
    "title": "c4ghtransit API",
    "description": "HTTP API of c4ghtransit Vault plugin. All API routes are prefixed with \`/v1/\`.",
    "version": "${RELEASE_VERSION}"
  }
}
EOF

# merge them all together
jq -s '.[0] * .[1] * .[2]' "${template}" "${paths}" "${schemas}" > "${script_dir}"/openapi.json

echo "openapi.json created!"