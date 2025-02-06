# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Calendar Versioning](https://calver.org/).

## [Unreleased]

## [2025.2.0] - 2025-02-06

### Fixed

- dockerfile golang tag for 1.21 image

### Changed

- batch request supports the use of pattern `**`, which matches against any character

## [2024.02.2] - 2024-02-07

### Added

- add contribution guide
- github setup

### Changed

- bump to golang 1.21

## [2024.02.1] - 2024-02-01

### Changed

- update dependencies for vault-testing-stepwise v0.5.2

## [2024.02.0] - 2024-02-01

### Changed

- Update all non-major dependencies (merge commit)
- Update all non-major dependencies

## [2024.01.4] - 2024-01-24

### Added

- Add more details to API docs of keys, file and whitelist endpoints
- Add script to generate openapi.json
- Add a script to run vault locally

### Changed

- clean go.sum
- Compile openapi schema and link as asset
- correct function read which does write
- error strings should not be capitalized
- Expose binary as job artifact - also as release asset
- fix gofmt
- Improve README.md API docs section.
- rephrase must be in request body
- Update deprecated callback for paths

## [2024.01.3] - 2024-01-15

### Changed

- Update all non-major dependencies (merge commit)
- Update all non-major dependencies

## [2024.01.2] - 2024-01-02

### Fixed

- Fix release asset URL

## [2024.01.1] - 2024-01-02

### Fixed

- Fix URL for the release asset

## [2024.01.0] - 2024-01-02

### Added

- Add automated releases or merge request to the pipeline
- existencecheck required for create operations

### Changed

- Update all non-major dependencies
- Update all non-major dependencies
- Update module golang.org/x/crypto to v0.16.0
- Update all non-major dependencies
- update vault-testing and crypto

## [v0.7.3] - 2023-10-30

### Fixed

- fix typo in container name match disallowing underscore

## [v0.7.2] - 2023-10-23

### Added

- add tests to check sharing whitelist with allowed special characters

### Changed

- use correct string type in sharing path

## [v0.7.1] - 2023-10-13

### Added

- add tests for container name checks
- match containers with the pattern used in object storage

## [v0.7.0] - 2023-10-02

### Changed

- If key does not exist, create one automatically
- Move batch parameter to body by changing request to POST
- update crypt4gh to 1.8.2

## [v0.6.2] - 2023-07-24

### Added

- test delete operation for file and whitelist
- test sharing api that use delete parameters

### Changed

- update vault-testing-stepwise

## [v0.6.1] - 2023-07-17

### Added

- add jf command
- make use of jfrog commands to scan & upload

### Changed

- Update all non-major dependencies

## [v0.6.0] - 2023-07-11

### Added

- Add tests
- Include possibility to read headers in batches

### Fixed

- fix `readFile` with shared content
- Fix lint
- Fix path conflicts between listing containers and reading headers in batches. Fix error handling during batch reading.

### Removed

- Remove redundant log

### Changed

- Update module github.com/CSCfi/vault-testing-stepwise to v0.3.10
- move to CSCfi/vault-testing-stepwise v0.3.11

## [v0.5.0] - 2023-06-27

### Added

- add tests for sharing whitelist
- add whitelist check to files
- add shared access whitelist

### Fixed

- fix rebase mistake in file write

### Changed

- Update module golang.org/x/crypto to v0.10.0
- update README to reflect removal of second build in pipeline
- listing files in container should work
- modify the pipeline to produce one binary without compiler to no invoke the C compiler in build
- refine sharing whitelist

## [v0.4.1] - 2023-06-02

### Added

- Add details about the checksum calculation

### Changed

- Update module github.com/neicnordic/crypt4gh to v1.7.5
- Update module github.com/hashicorp/vault/sdk to v0.9.1
- Update module github.com/hashicorp/vault/api to v1.9.2

## [v0.4.0] - 2023-05-15

### Changed

- Update module golang.org/x/crypto to v0.9.0

## [v0.3.0] - 2023-05-02

### Added

- add tests for backup

### Fixed

- fix golangci-lint 1.52.2
- fix golang lint

### Changed

- Update module github.com/hashicorp/vault/api to v1.9.1
- Update module github.com/CSCfi/vault-testing-stepwise to v0.3.9

## [v0.3.0-alpha1] - 2023-04-20

### Added

- add listings for backup paths

## [v0.2.0] - 2023-04-20

### Added

- add 30m timeout to tests

### Fixed

- fix acceptance test tests

## [v0.1.5] - 2023-04-20

### Added

- Add acceptance test for header versioning
- Added header versioning, fixed whitelist backup, and added option to list whitelisted keys in a service.
- Document building and running the plugin with docker
- Link to the binary instead of path

### Changed

- Update module github.com/neicnordic/crypt4gh to v1.7.4
- update vault-testing-stepwise to v0.3.8
- user new testing api and newer image

## [v0.1.4] - 2023-04-03

### Added

- Add stress tests and path for rewrap

### Changed

- Update module github.com/hashicorp/go-hclog to v1.5.0

## [v0.1.3] - 2023-03-20

### Added

- Add renovate.json

### Changed

- Update module golang.org/x/crypto to v0.7.0
- Update module github.com/neicnordic/crypt4gh to v1.7.3

## [v0.1.2] - 2023-02-28

### Added

- dockerfile 1.20
- instructions to update vault plugin

### Changed

- update to vault testing with go 1.20
- update to go 1.20

## [v0.1.1] - 2023-02-21

### Update

- update vault crypto, api and sdk

## [v0.1.0] - 2023-02-21

### Added

- accept `/` in object names, add bucket awareness
- Add a new 'name' path parameter to the whitelist endpoint
- Add acceptance tests
- Add link to API docs to README.md
- add checksums to binary
- add checksums to binary
- add the licenses explicitly in the repository
- binary for vault needs installation
- build alpine binary
- correct path for artifact alpine
- Decided to not add c4ghtransit support at the moment
- File had incorrect field name 'name' in delete endpoint
- Headers and whitelisted keys can now be backed up and restored
- logging for all steps & name the plugin
- make use of ReEncryptHeader in golang crypt4gh
- more detailed gitignore for golang
- path files use MatchAllRegex
- proper build for binaries
- push binary to artifactory
- Refactor encrypt-decrypt into own functions
- refactor go.mod with tidy
- refine syntax gitlab-ci
- refine readme instructions
- remove ls for output
- Restoration of files is possible without force if the key in storage is the same as the one given as backup
- server plugin with multiplex enabled
- small fix to binary alpine

### Fixed

- fix upload path ci project name
- fix api call file
- fix syntax gitlabci
- fix some linting mises
- fix incorrect key usage in file ingestion and export

[Unreleased]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/2025.2.0...HEAD
[2025.2.0]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/2024.02.2...2025.2.0
[2024.02.2]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/2024.02.1...2024.02.2
[2024.02.1]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/2024.02.0...2024.02.1
[2024.02.0]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/2024.01.4...2024.02.0
[2024.01.4]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/2024.01.3...2024.01.4
[2024.01.3]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/2024.01.2...2024.01.3
[2024.01.2]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/2024.01.1...2024.01.2
[2024.01.1]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/2024.01.0...2024.01.1
[2024.01.0]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/v0.7.3...2024.01.0
[v0.7.3]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/v0.7.2...v0.7.3
[v0.7.2]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/v0.7.1...v0.7.2
[v0.7.1]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/v0.7.0...v0.7.1
[v0.7.0]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/v0.6.2...v0.7.0
[v0.6.2]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/v0.6.1...v0.6.2
[v0.6.1]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/v0.6.0...v0.6.1
[v0.6.0]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/v0.5.0...v0.6.0
[v0.5.0]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/v0.4.1...v0.5.0
[v0.4.1]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/v0.4.0...v0.4.1
[v0.4.0]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/v0.3.0...v0.4.0
[v0.3.0]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/v0.3.0-alpha1...v0.3.0
[v0.3.0-alpha1]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/v0.2.0...v0.3.0-alpha1
[v0.2.0]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/v0.1.5...v0.2.0
[v0.1.5]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/v0.1.4...v0.1.5
[v0.1.4]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/v0.1.3...v0.1.4
[v0.1.3]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/v0.1.2...v0.1.3
[v0.1.2]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/v0.1.1...v0.1.2
[v0.1.1]: https://gitlab.ci.csc.fi/sds-dev/c4gh-transit/compare/v0.1.0...v0.1.1
[v0.1.0]: https://github.com/CSCfi/c4gh-transit/releases/tag/v0.1.0
