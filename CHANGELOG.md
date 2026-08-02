# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project attempts to adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!--
## [${version}]

### Added - for new features
### Changed - for changes in existing functionality
### Deprecated - for soon-to-be removed features
### Removed - for now removed features
### Fixed - for any bug fixes
### Security - in case of vulnerabilities

[${version}]: https://github.com/joshuadavidthomas/go-selfupdate/releases/tag/v${version}
-->

## [Unreleased]

### Added

- Targeted stable-release installation with `CheckVersion` and an explicit `Config.AllowDowngrade` opt-in for reinstalls and downgrades.
- `Plan.AssetName` reports the release asset selected for the running platform.

## [0.1.0]

### Added

- Update discovery for exact stable GitHub Releases with platform-specific archives for Linux, macOS, and Windows on AMD64 and ARM64.
- Immutable update plans that pin release metadata, asset identity, executable identity, and provenance before installation.
- Cross-process installation locking and platform-specific executable replacement with committed-state reporting.
- Optional GitHub artifact attestation verification bound to the source repository, release tag, workflow, asset name, and digest.
- Streamed downloads with bounded archive extraction and download progress callbacks.
- Mandatory GitHub-provided SHA-256 verification for release assets and validation for malformed, oversized, duplicated, or redirected untrusted inputs.
- Executable identity revalidation immediately before replacement and non-executable staging until installation commits.
- Abandoned staging-file cleanup that preserves active concurrent installations.

[unreleased]: https://github.com/joshuadavidthomas/go-selfupdate/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/joshuadavidthomas/go-selfupdate/releases/tag/v0.1.0
