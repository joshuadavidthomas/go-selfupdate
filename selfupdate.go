// Package selfupdate checks and installs stable GitHub releases of the running program.
package selfupdate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

const (
	defaultAPIBaseURL = "https://api.github.com"
	defaultTimeout    = 60 * time.Second
)

var (
	ownerPattern         = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$`)
	repositoryPattern    = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	commandPattern       = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$`)
	stableVersionPattern = regexp.MustCompile(`^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$`)
)

// AttestationPolicy identifies the GitHub Actions workflow allowed to sign
// release artifact attestations.
type AttestationPolicy struct {
	// SignerWorkflow is one repository-relative workflow path in the form
	// .github/workflows/<filename>.yml or .yaml.
	SignerWorkflow string
}

// Config identifies the release and the running program.
type Config struct {
	// Repository is the GitHub repository in owner/name form.
	Repository string
	// Command is the executable name and the prefix used for release assets.
	Command string
	// CurrentVersion is the running build's exact stable vMAJOR.MINOR.PATCH
	// version, or an opaque value for a development or unknown build. Opaque
	// versions support Check but cannot be installed over by Apply.
	CurrentVersion string
	// HTTPClient is the client used for GitHub API and asset requests. New uses
	// a shallow copy of a non-nil client. A nil client selects a default client
	// with a 60-second timeout.
	HTTPClient *http.Client
	// GitHubToken is an optional bearer token used only for GitHub API
	// requests. Asset, attestation bundle, and Sigstore trust downloads do not
	// include it.
	GitHubToken string
	// Attestation enables fail-closed GitHub Artifact Attestation verification.
	// A nil policy keeps digest-only verification and makes no attestation API
	// requests.
	Attestation *AttestationPolicy
}

// Updater checks and installs releases for one configured program.
type Updater struct {
	owner               string
	repository          string
	command             string
	currentVersion      string
	currentStable       bool
	httpClient          *http.Client
	githubToken         string
	attestationWorkflow string
	attestationVerifier attestationVerifier
	binding             [32]byte

	apiBaseURL            string
	attestationBundleHost string
	allowHTTP             bool
	goos                  string
	goarch                string
	executablePath        func() (string, error)
	beforeCommit          func()
	replace               func(string, string) (replacementResult, error)
}

// Plan is an immutable update decision returned by Check.
type Plan struct {
	updater          *Updater
	binding          [32]byte
	currentVersion   string
	availableVersion string
	comparable       bool
	updateAvailable  bool
	release          Release
	assetName        string
	assetURL         string
	archiveDigest    [sha256.Size]byte
	provenance       *provenanceRecord
	executable       string
	executableHash   [sha256.Size]byte
	goos             string
	goarch           string
}

// Release is a value snapshot of public GitHub release metadata.
type Release struct {
	// Version is the exact stable release tag.
	Version string
	// Name is the release's display name.
	Name string
	// Notes is the release's Markdown description.
	Notes string
	// URL is the public GitHub release page URL.
	URL string
	// PublishedAt is the GitHub publication time.
	PublishedAt time.Time
}

// Result reports the outcome of Apply. Committed is authoritative even when
// Apply also returns an error: replacement can commit before a later durability,
// cleanup, staged-file cleanup, or lock-release operation fails.
type Result struct {
	// Committed reports that the new executable replaced the old executable.
	// Callers must inspect it even when Apply returns a non-nil error.
	Committed bool
	// CleanupPending reports that Windows kept a random hidden backup because
	// the old executable is still open. A later Apply retries its removal.
	CleanupPending bool
	// PreviousVersion is the CurrentVersion supplied to New before a committed
	// replacement. It is empty when Committed is false.
	PreviousVersion string
	// Version is the installed release version. It is empty when Committed is
	// false.
	Version string
	// Executable is the resolved path replaced by Apply. It is empty when
	// Committed is false.
	Executable string
}

// New validates config and constructs an Updater.
func New(config Config) (*Updater, error) {
	owner, repository, err := parseRepository(config.Repository)
	if err != nil {
		return nil, err
	}
	command := strings.TrimSpace(config.Command)
	if command != config.Command || len(command) == 0 || len(command) > 100 || !commandPattern.MatchString(command) || command == "." || command == ".." {
		return nil, fmt.Errorf("selfupdate: invalid command %q", config.Command)
	}
	if err := validateCurrentVersion(config.CurrentVersion); err != nil {
		return nil, err
	}
	token := strings.TrimSpace(config.GitHubToken)
	if token != config.GitHubToken || strings.ContainsAny(token, "\r\n") {
		return nil, errors.New("selfupdate: GitHub token must not have surrounding whitespace or line breaks")
	}
	attestationWorkflow := ""
	if config.Attestation != nil {
		if err := validateAttestationWorkflow(config.Attestation.SignerWorkflow); err != nil {
			return nil, err
		}
		attestationWorkflow = config.Attestation.SignerWorkflow
	}

	client := &http.Client{Timeout: defaultTimeout}
	if config.HTTPClient != nil {
		copy := *config.HTTPClient
		client = &copy
	}

	u := &Updater{
		owner:                 owner,
		repository:            repository,
		command:               command,
		currentVersion:        config.CurrentVersion,
		currentStable:         isStableVersion(config.CurrentVersion),
		httpClient:            client,
		githubToken:           token,
		attestationWorkflow:   attestationWorkflow,
		attestationVerifier:   &sigstoreAttestationVerifier{},
		apiBaseURL:            defaultAPIBaseURL,
		attestationBundleHost: attestationBundleHost,
		goos:                  runtime.GOOS,
		goarch:                runtime.GOARCH,
		executablePath:        os.Executable,
		replace:               replaceExecutable,
	}
	if _, err := rand.Read(u.binding[:]); err != nil {
		return nil, fmt.Errorf("selfupdate: create updater identity: %w", err)
	}
	return u, nil
}

// Check fetches the latest GitHub release and returns an immutable plan.
func (u *Updater) Check(ctx context.Context) (*Plan, error) {
	if u == nil {
		return nil, errors.New("selfupdate: nil updater")
	}
	if ctx == nil {
		return nil, errors.New("selfupdate: nil context")
	}
	assetName, memberName, err := expectedNames(u.command, u.goos, u.goarch)
	if err != nil {
		return nil, err
	}

	release, asset, err := u.fetchLatestRelease(ctx, assetName)
	if err != nil {
		return nil, err
	}
	var provenance *provenanceRecord
	if u.attestationWorkflow != "" {
		provenance, err = u.verifyAttestation(ctx, release, asset)
		if err != nil {
			return nil, fmt.Errorf("selfupdate: verify artifact attestation: %w", err)
		}
	}
	executable, err := u.resolveExecutable()
	if err != nil {
		return nil, err
	}
	if executableName := filepath.Base(executable); executableName != memberName {
		return nil, fmt.Errorf("selfupdate: executable name %q does not match archive member %q", executableName, memberName)
	}
	executableHash, _, err := hashExecutable(ctx, executable)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	comparable := u.currentStable
	available := comparable && semver.Compare(u.currentVersion, release.Version) < 0
	return &Plan{
		updater:          u,
		binding:          u.binding,
		currentVersion:   u.currentVersion,
		availableVersion: release.Version,
		comparable:       comparable,
		updateAvailable:  available,
		release:          release,
		assetName:        asset.name,
		assetURL:         asset.downloadURL,
		archiveDigest:    asset.digest,
		provenance:       provenance,
		executable:       executable,
		executableHash:   executableHash,
		goos:             u.goos,
		goarch:           u.goarch,
	}, nil
}

// Apply verifies and installs the release described by plan. Result.Committed
// is authoritative even when the returned error is non-nil: replacement can
// commit before durability, cleanup, staged-file cleanup, or lock release fails.
func (u *Updater) Apply(ctx context.Context, plan *Plan) (result Result, returnErr error) {
	if u == nil {
		return Result{}, errors.New("selfupdate: nil updater")
	}
	if ctx == nil {
		return Result{}, errors.New("selfupdate: nil context")
	}
	if plan == nil {
		return Result{}, errors.New("selfupdate: nil plan")
	}
	if plan.updater != u || plan.binding != u.binding {
		return Result{}, errors.New("selfupdate: plan belongs to a different updater")
	}
	if !u.currentStable || !plan.comparable {
		return Result{}, fmt.Errorf("selfupdate: current version %q is not a stable version", u.currentVersion)
	}
	if !isStableVersion(plan.availableVersion) || semver.Compare(plan.currentVersion, plan.availableVersion) >= 0 || !plan.updateAvailable {
		return Result{}, fmt.Errorf("selfupdate: release %q is not strictly newer than %q", plan.availableVersion, plan.currentVersion)
	}
	if plan.goos != u.goos || plan.goarch != u.goarch {
		return Result{}, errors.New("selfupdate: plan platform does not match updater")
	}
	if u.attestationWorkflow != "" && (plan.provenance == nil || !plan.provenance.matches(u, plan)) {
		return Result{}, errors.New("selfupdate: plan has no matching verified provenance record")
	}

	target, err := u.resolveExecutable()
	if err != nil {
		return Result{}, err
	}
	if target != plan.executable {
		return Result{}, errors.New("selfupdate: executable path changed since Check")
	}
	lock, err := acquireFileLock(ctx, target+".selfupdate.lock")
	if err != nil {
		return Result{}, fmt.Errorf("selfupdate: lock executable: %w", err)
	}
	defer func() {
		if err := lock.release(); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("selfupdate: release executable lock: %w", err))
		}
	}()
	lockedTarget, err := u.resolveExecutable()
	if err != nil {
		return Result{}, err
	}
	if lockedTarget != plan.executable {
		return Result{}, errors.New("selfupdate: executable path changed since Check")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	cleanupPending, err := cleanupStaleBackups(target)
	if err != nil {
		return Result{}, fmt.Errorf("selfupdate: clean stale backups: %w", err)
	}
	currentHash, mode, err := hashExecutable(ctx, target)
	if err != nil {
		return Result{}, err
	}
	if currentHash != plan.executableHash {
		return Result{}, errors.New("selfupdate: executable changed since Check")
	}
	archiveBody, err := u.download(ctx, plan.assetURL, maxArchiveBytes, "release asset")
	if err != nil {
		return Result{}, err
	}
	archiveDigest := sha256.Sum256(archiveBody)
	if archiveDigest != plan.archiveDigest {
		return Result{}, fmt.Errorf("selfupdate: SHA-256 mismatch for %s", plan.assetName)
	}
	_, memberName, err := expectedNames(u.command, plan.goos, plan.goarch)
	if err != nil {
		return Result{}, err
	}
	binary, err := extractArchive(ctx, plan.assetName, archiveBody, memberName)
	if err != nil {
		return Result{}, fmt.Errorf("selfupdate: extract %s: %w", plan.assetName, err)
	}
	stage, err := stageExecutable(ctx, target, binary, mode)
	if err != nil {
		return Result{}, fmt.Errorf("selfupdate: stage executable: %w", err)
	}
	stageExists := true
	defer func() {
		if stageExists {
			if err := os.Remove(stage); err != nil && !errors.Is(err, os.ErrNotExist) {
				returnErr = errors.Join(returnErr, fmt.Errorf("selfupdate: remove staged executable: %w", err))
			}
		}
	}()

	currentHash, _, err = hashExecutable(ctx, target)
	if err != nil {
		return Result{}, err
	}
	if currentHash != plan.executableHash {
		return Result{}, errors.New("selfupdate: executable changed while the update was downloading")
	}
	if u.beforeCommit != nil {
		u.beforeCommit()
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	outcome, replaceErr := u.replace(stage, target)
	if !outcome.committed && replaceErr == nil {
		return Result{}, errors.New("selfupdate: replacement returned without committing")
	}
	if outcome.committed {
		stageExists = false
		result = Result{
			Committed:       true,
			CleanupPending:  cleanupPending || outcome.cleanupPending,
			PreviousVersion: plan.currentVersion,
			Version:         plan.availableVersion,
			Executable:      target,
		}
	}
	if replaceErr != nil {
		return result, fmt.Errorf("selfupdate: replace executable: %w", replaceErr)
	}
	return result, nil
}

// CurrentVersion returns the version supplied to New.
func (p *Plan) CurrentVersion() string {
	if p == nil {
		return ""
	}
	return p.currentVersion
}

// AvailableVersion returns the latest stable release version.
func (p *Plan) AvailableVersion() string {
	if p == nil {
		return ""
	}
	return p.availableVersion
}

// VersionsComparable reports whether CurrentVersion is an exact stable version
// that can be ordered against AvailableVersion. Development and unknown build
// versions are not comparable.
func (p *Plan) VersionsComparable() bool {
	return p != nil && p.comparable
}

// UpdateAvailable reports whether comparable versions show that the latest
// release is strictly newer. It returns false for incomparable versions, so
// callers must check VersionsComparable before treating false as up to date.
func (p *Plan) UpdateAvailable() bool {
	return p != nil && p.updateAvailable
}

// Release returns a copy of the release's public metadata.
func (p *Plan) Release() Release {
	if p == nil {
		return Release{}
	}
	return p.release
}

func parseRepository(value string) (string, string, error) {
	if value != strings.TrimSpace(value) || len(value) == 0 || len(value) > 141 || strings.Count(value, "/") != 1 {
		return "", "", fmt.Errorf("selfupdate: repository must be owner/repo, got %q", value)
	}
	parts := strings.SplitN(value, "/", 2)
	if len(parts[0]) > 39 || len(parts[1]) > 100 || !ownerPattern.MatchString(parts[0]) || !repositoryPattern.MatchString(parts[1]) || parts[0] == "." || parts[0] == ".." || parts[1] == "." || parts[1] == ".." {
		return "", "", fmt.Errorf("selfupdate: invalid repository %q", value)
	}
	return parts[0], parts[1], nil
}

func validateCurrentVersion(version string) error {
	if len(version) > 128 || strings.TrimSpace(version) != version || strings.ContainsAny(version, "\x00\r\n\t") {
		return fmt.Errorf("selfupdate: invalid current version %q", version)
	}
	if strings.HasPrefix(version, "v") && !isStableVersion(version) {
		return fmt.Errorf("selfupdate: version beginning with v must be exact vMAJOR.MINOR.PATCH, got %q", version)
	}
	return nil
}

func isStableVersion(version string) bool {
	return stableVersionPattern.MatchString(version) && semver.IsValid(version) && semver.Canonical(version) == version
}

func expectedNames(command, goos, goarch string) (string, string, error) {
	if goarch != "amd64" && goarch != "arm64" {
		return "", "", fmt.Errorf("selfupdate: unsupported architecture %q", goarch)
	}
	switch goos {
	case "linux", "darwin":
		return fmt.Sprintf("%s_%s_%s.tar.gz", command, goos, goarch), command, nil
	case "windows":
		return fmt.Sprintf("%s_windows_%s.zip", command, goarch), command + ".exe", nil
	default:
		return "", "", fmt.Errorf("selfupdate: unsupported operating system %q", goos)
	}
}

func (u *Updater) resolveExecutable() (string, error) {
	path, err := u.executablePath()
	if err != nil {
		return "", fmt.Errorf("selfupdate: locate executable: %w", err)
	}
	if path == "" || strings.ContainsRune(path, '\x00') {
		return "", errors.New("selfupdate: executable path is empty or invalid")
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("selfupdate: make executable path absolute: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("selfupdate: resolve executable symlinks: %w", err)
	}
	return resolved, nil
}

func hashExecutable(ctx context.Context, path string) ([sha256.Size]byte, os.FileMode, error) {
	var zero [sha256.Size]byte
	file, err := os.Open(path)
	if err != nil {
		return zero, 0, fmt.Errorf("selfupdate: open executable: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return zero, 0, fmt.Errorf("selfupdate: stat executable: %w", err)
	}
	if !info.Mode().IsRegular() {
		return zero, 0, errors.New("selfupdate: executable is not a regular file")
	}
	hash := sha256.New()
	if _, err := copyBounded(hash, &contextReader{ctx: ctx, reader: file}, maxBinaryBytes, "executable"); err != nil {
		return zero, 0, err
	}
	var sum [sha256.Size]byte
	copy(sum[:], hash.Sum(nil))
	return sum, info.Mode().Perm(), nil
}
