# Usage of c4gh-transit plugin

c4gh-transit is a plugin for Hashicorp Vault intended for storing crypt4gh encrypted file headers, and re-encrypting them with ephemeral encryption keys.

## Prerequisites 

[Hashicorp Vault](https://www.vaultproject.io/) installed and running, recommended latest version.

Select appropriate binary packed with the releases or build you a binary as indicated in [README](README.md)

## Installing

Copy the new binary to plugins folder
```bash
sudo mv c4ghtransit-<version> /vault/plugins-folder
sudo chmod 750 /vault/plugins-folder/c4ghtransit-<version>
sudo chown vault:vault /vault/plugins-folder/c4ghtransit-<version>
```   

Register and enable the plugin
```bash
vault plugin register -sha256=<checksum> -command=c4ghtransit-<version> -version=<version> secret c4ghtransit
vault secrets enable c4ghtransit
vault secrets list -detailed
```


## Updating Vault Plugin

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