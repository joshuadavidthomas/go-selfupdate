set unstable := true

[private]
default:
    @just --list

# Build the library
build *ARGS:
    go build {{ ARGS }} ./...

# Run tests with the race detector
test *ARGS:
    go test ./... -race {{ ARGS }}

# Run tests with coverage
coverage *ARGS:
    go test ./... -race -cover {{ ARGS }}

# Format Go source
fmt *ARGS='.':
    gofmt -w {{ ARGS }}

# Check Go source formatting
fmt-check:
    @test -z "$(gofmt -l .)" || { gofmt -l .; exit 1; }

# Run all pre-commit hooks
lint:
    pre-commit run --all-files

# Run static analysis
vet:
    go vet ./...

# Check dependencies for known vulnerabilities
vuln:
    govulncheck ./...

# Tidy go.mod and go.sum
tidy:
    go mod tidy

# Check module files without rewriting them
tidy-check:
    go mod tidy -diff

# Run all local checks
check: fmt-check test lint vet vuln tidy-check build
