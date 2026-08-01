## Commands

- `just build`: Build all packages
- `just test`: Run tests with the race detector
- `just coverage`: Run race-enabled tests with coverage
- `just fmt`: Format Go code
- `just lint`: Run all pre-commit hooks
- `just vet`: Run Go static analysis
- `just vuln`: Check dependencies for known vulnerabilities
- `just tidy`: Tidy `go.mod` and `go.sum`
- `just check`: Run the full local validation suite

## Validation

Run these after implementing changes:

- Tests: `just test`
- Lint and workflow checks: `just lint`
- Static analysis: `just vet`
- Vulnerabilities: `just vuln`
- Format: `just fmt`

## Architecture

- Module: `github.com/joshuadavidthomas/go-selfupdate`
- The root package owns update discovery, validation, download, and installation.
- Platform-specific locking and replacement live in files selected by Go build constraints.
- Callers own user interaction, update scheduling, and package-manager detection.

## Codebase patterns

- Thread `context.Context` through network and long-running work.
- Treat release metadata, archives, attestations, and filesystem state as untrusted input.
- Keep update plans immutable and revalidate executable identity before replacement.
- Preserve committed replacement state in returned results even when later cleanup fails.
- Keep platform behavior aligned and cover Windows-specific semantics with focused tests.
