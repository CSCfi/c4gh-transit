# Vault Transit plugin for crypt4gh files
**crypt4gh-vault-transit** is a plugin for **Hashicorp Vault** extending the
support of the existing **Vault transit** with proper support for crypt4gh
files. It adds key management by project/user level separation, whitelisted
download access by public key, automatic key generation for crypt4gh keys
along with some other changes related to the file type. Plugin tries to re-use
as much of the original plugin code as possible.

## Download built binaries

Each git tag triggers a release build that compiles and uploads binaries to configured binary repository.

There are compiled binaries available for x86_64 linux systems from `Artifactory`, where you can download the latest version.

Note that it requires authentication to download.

## Building
The binary must be build for the platform it will run in.
Even though that might be obvious, there is only Alpine official docker vault image, see [source](https://github.com/hashicorp/vault/blob/main/scripts/docker/Dockerfile).
And building locally in a development machine might not be compatible with the
official image, there to be wider compability diabling CGO is used in building.

Note: the docker images will not cache dependencies and build assets over subsequent builds with the configuration given below.

### Building for the local environment

```bash
mkdir -p vault/plugins
go build -v -o vault/plugins/c4ghtransit c4ghtransit/cmd/c4ghtransit/main.go
```

With the golang debian docker image
```
docker run --rm \
    -u $(id -u):$(id -g) \
    --env XDG_CACHE_HOME=/tmp \
    -v ${PWD}/:/c4ghtransit \
    -w /c4ghtransit \
    golang:bullseye \
    go build -v -o /c4ghtransit/vault/plugins/c4ghtransit /c4ghtransit/c4ghtransit/cmd/c4ghtransit/main.go
```

### Building for Alpine

With local environment, so the binary will be statically linked, and will use a golang implementation of the networking library.

    CGO_ENABLED=0 go build -tags netgo -a -v -o output/c4ghtransit-alpine c4ghtransit/cmd/c4ghtransit/main.go

With the golang docker alpine image
```
docker run --rm \
    -u $(id -u):$(id -g) \
    --env XDG_CACHE_HOME=/tmp \
    -v ${PWD}/:/c4ghtransit \
    -w /c4ghtransit \
    golang:1.21-alpine \
    go build -v -o /c4ghtransit/vault/plugins/c4ghtransit /c4ghtransit/c4ghtransit/cmd/c4ghtransit/main.go
```

## Running with the vault server

### In local environment
Install vault: https://developer.hashicorp.com/vault/downloads

Then run the script provided to start a vault server with the plugin enabled and configured.

    ./dev-tools/vault.sh

### With docker Alpine image

The commands below assume that the plugin binary exists at `./vault/plugins/c4ghtransit`

```
docker run --rm \
    --name=dev-vault \
    -e 'VAULT_DEV_ROOT_TOKEN_ID=devroot' \
    -e 'VAULT_LOCAL_CONFIG={"storage": {"file": {"path": "/vault/data"}}, "disable_mlock": true, "ui": true}' -p 8200:8200 \
    -v ${PWD}/vault/plugins:/vault/plugins \
    hashicorp/vault:latest \
    server -dev -dev-plugin-dir=/vault/plugins
```

## Usage
Login to dev server, and enable the plugin
```bash
export VAULT_ADDR='http://127.0.0.1:8200'
vault login token=devroot
vault secrets enable c4ghtransit
```

After this, you can e.g. create a new key with
```bash
vault write c4ghtransit/keys/test-user
```

### Updating Vault Plugin

see what version is currently running
```bash
vault secrets list -detailed
```

copy the new binary to plugins folder
```bash
mv c4ghtransit-<version> /vault/plugins-folder
chmod +x /vault/plugins-folder/c4ghtransit-<version>
chown vault:vault /vault/plugins-folder/c4ghtransit-<version>
```

Artifactory provides checksums for their binaries. Select a binary [from this page](https://sds-docker.artifactory.ci.csc.fi/artifactory/webapp/#/artifacts/browse/tree/General/sds-generic-local/c4gh-transit/c4ghtransit), find the checksum on the right-hand side, at the bottom under "Checksums".

Github Release also provides the artifacts for download.

Otherwise, calculate the checksum with `sha256sum c4ghtransit-<version>`.

register the plugin
```bash
vault plugin register -sha256=<checksum> -command=c4ghtransit-<version> -version=<version> secret c4ghtransit

vault secrets tune -plugin-version=<version> c4ghtransit

vault plugin reload -plugin c4ghtransit
vault secrets list -detailed
```
## Tests
There are acceptance and stress tests, which run in Docker. They can be run with

    go test -v ./c4ghtransit

## Docs
The `c4ghtransit` plugin is well documented, having its api documented using Vault's plugin SDK. There are different ways
to extract and visualize such information.

### Vault API Explorer
Vault provides API docs generated in the OpenAPI format. You can access it by opening
`http://localhost:8200/ui/vault/tools/api-explorer` in the browser.
Login with the token `devroot`. In the **filter** textbox, write `c4ghtransit` to see only endpoints of the plugin.

### C4ghtransit plugin OpenAPI JSON files
An OpenAPI json file can be generated by running `./dev-tools/generate_openapi.sh`.
The file will be at `dev-tools/openapi.json`. You can copy its contents into the
[Swagger editor](https://editor.swagger.io/) to visualize it.

### Vault API help
Vault API provide help docs at `http://127.0.0.1:8200/v1/c4ghtransit?help=1`

    $ curl -sL \
    -H "X-Vault-Token: devroot" \
    http://127.0.0.1:8200/v1/c4ghtransit?help=1 | jq

### Vault cli help
And the cli command [`path-help`](https://developer.hashicorp.com/vault/docs/commands/path-help)
can also be used to get information about each path.

## Licensing

`c4gh-transit` is licensed under MIT license.
Several sections that are licensed under MRL-2.0 have been flagged in the source code.

`SPDX-License-Identifier: MIT AND MPL-2.0`
