# Vault Transit plugin for crypt4gh files
**crypt4gh-vault-transit** is a plugin for **Hashicorp Vault** extending the
support of the existing **Vault transit** with proper support for crypt4gh
files. It adds key management by project/user level separation, whitelisted
download access by public key, automatic key generation for crypt4gh keys
along with some other changes related to the file type. Plugin tries to re-use
as much of the original plugin code as possible.

## Forking
Note that this repository contains code licensed under MPL-2.0, while code
written fully by **CSC – IT Center for Science** is typically licensed under
the MIT license. Sections licensed under MPL-2.0 have been separately flagged
in the source code, other parts are MIT licensed.

## Usage
To develop, local installation of `Vault` is required.

First build the module:
```bash
mkdir -p vault
mkdir -p vault/plugins
go build -v -o vault/plugins/c4ghtransit c4ghtransit/cmd/c4ghtransit/main.go
```

Then run a development server with the plugin
```bash
VAULT_LOG_LEVEL=DEBUG vault server -dev -dev-plugin-dir=vault/plugins -dev-root-token-id="devroot"
```

Login to dev server, and enable the plugin
```bash
vault login
vault secrets enable c4ghtransit
```

After this, you can e.g. create a new key with
```bash
vault write c4ghtransit/keys/test-user
```
