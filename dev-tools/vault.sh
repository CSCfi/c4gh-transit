#!/usr/bin/bash

set -e

# This script starts and configures a vault server in development mode with c4ghtransit plugin enabled
# and applies the pre-defined vault policy and role with pre-defined token

# The vault server replaces the bash process, so this script works well under a process manager

# Dependencies
# - vault

# get the current folder
SCRIPT=$(realpath "$0")
SCRIPT_DIR=$(dirname "$SCRIPT")

VAULT_ROLE=${VAULT_ROLE:-role}
VAULT_SECRET=${VAULT_SECRET:-role-secret-token}

function initVault {
    export VAULT_ADDR=${VAULT_ADDR:-'http://127.0.0.1:8200'}
    # wait for vault to be running
    wget --no-verbose --retry-connrefused --waitretry=1 --tries 10 --timeout=3 --spider "${VAULT_ADDR}/v1/sys/health?standbyok=true"
    vault login token=devroot
    vault auth enable approle
    vault secrets enable c4ghtransit
    vault policy write "$VAULT_ROLE" "$SCRIPT_DIR"/vault_policy.hcl
    vault write auth/approle/role/"$VAULT_ROLE" \
        secret_id_ttl=0 \
        secret_id_num_uses=0 \
        token_ttl=5m \
        token_max_ttl=5m \
        token_num_uses=0 \
        token_policies="$VAULT_ROLE" \
        role_id="$VAULT_ROLE"
    vault write -format=json -f auth/approle/role/"$VAULT_ROLE"/custom-secret-id secret_id="$VAULT_SECRET"
}

# update the code and build the plugin
cd "$(git rev-parse --show-toplevel)"
git pull
mkdir -p vault/plugins
go build -v -o vault/plugins/c4ghtransit c4ghtransit/cmd/c4ghtransit/main.go

# setup vault in the background, after the server is up
initVault 2>&1 &

# start vault server in development mode
VAULT_LOG_LEVEL=DEBUG exec vault server -dev -dev-plugin-dir=vault/plugins -dev-root-token-id=devroot
