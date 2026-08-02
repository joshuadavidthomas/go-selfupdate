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

- Added update discovery for exact stable GitHub Releases with platform-specific archives for Linux, macOS, and Windows on AMD64 and ARM64.
- Added immutable update plans that pin release metadata, asset identity, executable identity, and provenance before installation.
- Added cross-process installation locking and platform-specific executable replacement with committed-state reporting.
- Added optional GitHub artifact attestation verification bound to the source repository, release tag, workflow, asset name, and digest.
- Added streamed downloads with bounded archive extraction and download progress callbacks.

### Security

- Require GitHub-provided SHA-256 digests for release assets and reject malformed, oversized, duplicated, or redirected untrusted inputs.
- Revalidate executable identity immediately before replacement and keep staged executables non-executable until installation commits.
- Reclaim abandoned staging files while preserving active concurrent installations.

[unreleased]: https://github.com/joshuadavidthomas/go-selfupdate/commits/main
