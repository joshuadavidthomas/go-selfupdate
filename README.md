# go-selfupdate

[![Go Reference](https://pkg.go.dev/badge/github.com/joshuadavidthomas/go-selfupdate.svg)](https://pkg.go.dev/github.com/joshuadavidthomas/go-selfupdate)

Package `selfupdate` checks a Go CLI's latest GitHub Release and replaces the running executable with a newer stable build.

It supports Linux, macOS, and Windows on `amd64` and `arm64`. Your CLI decides when to check, what to print, and whether a package manager owns the installation.

## Installation

```sh
go get github.com/joshuadavidthomas/go-selfupdate
```

The module requires Go 1.26.5 or later.

## Quick start

```go
updater, err := selfupdate.New(selfupdate.Config{
    Repository:     "owner/project",
    Command:        "project",
    CurrentVersion: version,
})
if err != nil {
    return err
}

plan, err := updater.Check(ctx)
if err != nil {
    return err
}
if !plan.VersionsComparable() {
    fmt.Printf("latest release: %s; current build %q cannot be compared\n",
        plan.AvailableVersion(), plan.CurrentVersion())
    return nil
}
if !plan.UpdateAvailable() {
    return nil
}

result, applyErr := updater.Apply(ctx, plan)
if result.Committed {
    fmt.Printf("installed %s at %s\n", result.Version, result.Executable)
    if result.CleanupPending {
        fmt.Println("Windows will retry removal of the old executable on a later update")
    }
}
if applyErr != nil {
    return applyErr
}
return nil
```

Inspect both values returned by `Apply`. A replacement can commit before a later durability or cleanup step fails, so `Result.Committed` may be true when the error is non-nil.

Development builds may call `Check`, but only an exact `vMAJOR.MINOR.PATCH` current version may call `Apply`. Check `VersionsComparable` before treating `UpdateAvailable() == false` as up to date.

See the [package documentation](https://pkg.go.dev/github.com/joshuadavidthomas/go-selfupdate) for configuration fields and exported types.

## Release requirements

The latest GitHub Release must have an exact stable tag such as `v1.2.3` and one matching archive for each supported platform:

```text
project_linux_amd64.tar.gz
project_linux_arm64.tar.gz
project_darwin_amd64.tar.gz
project_darwin_arm64.tar.gz
project_windows_amd64.zip
project_windows_arm64.zip
```

Replace `project` with the `Command` passed to `New`. A tar archive must contain a regular root file named after the command. A ZIP archive must contain the corresponding `.exe` file. Other archive members are ignored.

GitHub must report the selected asset's digest as `sha256:` followed by 64 lowercase hexadecimal digits. GitHub adds this digest when it receives the asset; no checksum file is needed.

### GoReleaser

This archive configuration produces the required names when `project_name` matches the command:

```yaml
archives:
  - name_template: "{{ .ProjectName }}_{{ .Os }}_{{ .Arch }}"
    format_overrides:
      - goos: windows
        formats: [zip]
```

GoReleaser can also write the checksum file used to attest every archive:

```yaml
checksum:
  name_template: checksums.txt
```

## Require GitHub artifact attestations

Attestation verification is opt in. Name the one workflow allowed to sign releases:

```go
updater, err := selfupdate.New(selfupdate.Config{
    Repository:     "owner/project",
    Command:        "project",
    CurrentVersion: version,
    Attestation: &selfupdate.AttestationPolicy{
        SignerWorkflow: ".github/workflows/release.yml",
    },
})
```

Omitting `Attestation` keeps the mandatory GitHub asset-digest check and makes no attestation request. Supplying it makes provenance mandatory: `Check` fails closed when it cannot fetch, parse, or verify a matching attestation. It never falls back to digest-only verification.

A release workflow can attest the files listed by GoReleaser's checksum file:

```yaml
permissions:
  id-token: write
  attestations: write
  contents: write

steps:
  - uses: goreleaser/goreleaser-action@v7
    with:
      args: release --clean
  - uses: actions/attest-build-provenance@v4
    with:
      subject-checksums: dist/checksums.txt
```

Attest before publishing the release. A client can observe a published asset before a later attestation exists and will reject that update. Use a draft release, create the attestations, then publish it; or keep publication in the same job after attestation succeeds.

Verification requires the exact repository, workflow file, release-tag ref, asset name, and SHA-256 digest. It also verifies the GitHub Actions issuer, Fulcio certificate and SCT, Rekor entry, in-toto Statement v1, and SLSA provenance v1 predicate type against Sigstore's public trust root. This blocks an asset uploaded without a valid run of the configured workflow and binds the selected bytes to that run. It does not validate every field in the provenance predicate, make the workflow safe, protect compromised repository admins or GitHub, review source code, or prove that the build inputs deserve trust.

The first attestation check fetches Sigstore TUF metadata with a 20-second deadline and no local TUF cache. A successful updater caches the verifier in memory for 24 hours. The TUF client may finish an in-flight refresh after the calling context is canceled. The package never sends `GitHubToken` to Sigstore.

## Package-managed installs

Homebrew, system package managers, and managed installers should update the files they own. Detect those installs before calling `Apply` and direct the user to the matching upgrade command.

The package leaves prompts, progress output, update schedules, install markers, caches, and downgrade policy to the CLI.

## How updates work

`Check` selects the exact platform archive and returns an opaque plan. The plan pins the release version, asset URL and digest, platform, executable path, and executable fingerprint. A plan belongs to the updater that created it.

`Apply` takes a cross-process lock and checks the path and fingerprint again. It downloads the pinned archive, verifies its SHA-256 digest, extracts the command executable, stages it beside the target, and checks the fingerprint once more before replacement. It rejects plans made for a locally changed executable and versions that are not strictly newer. A plan remains a snapshot of the release and attestation accepted by `Check`; `Apply` does not query GitHub again.

Unix replaces the target with one rename, then syncs the file and parent directory. Windows renames the old executable aside, installs the staged file, and restores the backup if installation fails. A running process may keep the old Windows executable open; in that case `CleanupPending` is true and a later update retries removal.

Cancellation stops ordinary work until replacement begins. The bounded Sigstore TUF refresh described above may finish in the background. Replacement, rollback, and cleanup run to completion once replacement starts.

## Security

The GitHub asset digest detects corruption and downloads that differ from the asset selected by `Check`. By itself it is not an independent publisher signature, so digest-only mode trusts GitHub, the repository, and anyone allowed to publish its releases. The optional attestation policy narrows publisher authority to one GitHub Actions workflow as described above.

The package bounds network and archive reads, accepts one exact regular archive member, resolves executable symlinks, locks across processes, uses random same-directory staging names, and checks for executable changes before installation.

On Windows, a process crash between renaming the old executable and installing the new one can leave only the hidden backup. Windows has no portable in-process operation that closes this gap while the executable is running.

## License

MIT
