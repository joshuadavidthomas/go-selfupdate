package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/mod/semver"
)

type releaseFixture struct {
	tag          string
	assetName    string
	archive      []byte
	digest       *string
	nullDigest   bool
	omitDigest   bool
	omitAsset    bool
	duplicate    string
	metadataCode int
	metadataBody []byte
	draft        bool
	prerelease   bool
	archiveHook  func()
}

func TestNewValidation(t *testing.T) {
	t.Parallel()
	valid := Config{Repository: "owner/repo", Command: "tool", CurrentVersion: "v1.2.3"}
	if _, err := New(valid); err != nil {
		t.Fatalf("New(valid): %v", err)
	}
	dotRepository := valid
	dotRepository.Repository = "owner/.github"
	if _, err := New(dotRepository); err != nil {
		t.Fatalf("New(valid dot-prefixed repository): %v", err)
	}
	for _, test := range []struct {
		name   string
		change func(*Config)
	}{
		{"repository", func(c *Config) { c.Repository = "owner/repo/extra" }},
		{"command path", func(c *Config) { c.Command = "../tool" }},
		{"partial version", func(c *Config) { c.CurrentVersion = "v1.2" }},
		{"prerelease", func(c *Config) { c.CurrentVersion = "v1.2.3-rc.1" }},
		{"token newline", func(c *Config) { c.GitHubToken = "token\nother" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.change(&config)
			if _, err := New(config); err == nil {
				t.Fatal("New accepted invalid config")
			}
		})
	}
	for _, version := range []string{"", "dev", "unknown", "devel-abc123"} {
		config := valid
		config.CurrentVersion = version
		if _, err := New(config); err != nil {
			t.Errorf("New accepted unknown version %q: %v", version, err)
		}
	}
}

func TestNewRequiresAttestationVerifier(t *testing.T) {
	t.Parallel()
	_, err := New(Config{
		Repository:     "owner/repo",
		Command:        "tool",
		CurrentVersion: "v1.0.0",
		Attestation:    &AttestationPolicy{SignerWorkflow: ".github/workflows/release.yml"},
	})
	if err == nil || !strings.Contains(err.Error(), "requires a Verifier") {
		t.Fatalf("New error = %v, want error containing %q", err, "requires a Verifier")
	}
}

func TestCheckSelectsExactStableRelease(t *testing.T) {
	archive := makeTar(t, []archiveMember{{name: "tool", body: []byte("new")}})
	fixture := releaseFixture{tag: "v2.0.0", assetName: "tool_linux_amd64.tar.gz", archive: archive}
	u, server, _ := newTestUpdater(t, fixture, "v1.0.0")
	defer server.Close()

	plan, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if plan.CurrentVersion() != "v1.0.0" || plan.AvailableVersion() != "v2.0.0" || !plan.VersionsComparable() || !plan.UpdateAvailable() {
		t.Fatalf("unexpected plan: current=%q available=%q comparable=%v update=%v", plan.CurrentVersion(), plan.AvailableVersion(), plan.VersionsComparable(), plan.UpdateAvailable())
	}
	if plan.AssetName() != "tool_linux_amd64.tar.gz" {
		t.Fatalf("unexpected asset name %q", plan.AssetName())
	}
	if (*Plan)(nil).AssetName() != "" {
		t.Fatal("nil plan AssetName should be empty")
	}
	release := plan.Release()
	if release.Version != "v2.0.0" || release.Name != "Release v2.0.0" || release.Notes != "notes" || release.URL == "" || release.PublishedAt.IsZero() {
		t.Fatalf("unexpected release metadata: %#v", release)
	}
	release.Version = "v9.9.9"
	if plan.Release().Version != "v2.0.0" {
		t.Fatal("mutating a release snapshot changed the plan")
	}
}

func TestCheckRejectsExecutableNameThatDoesNotMatchArchiveMember(t *testing.T) {
	archive := makeTar(t, []archiveMember{{name: "tool", body: []byte("new")}})
	fixture := releaseFixture{tag: "v2.0.0", assetName: "tool_linux_amd64.tar.gz", archive: archive}
	u, server, target := newTestUpdater(t, fixture, "v1.0.0")
	defer server.Close()
	wrongTarget := filepath.Join(filepath.Dir(target), "other")
	if err := os.Rename(target, wrongTarget); err != nil {
		t.Fatal(err)
	}
	u.executablePath = func() (string, error) { return wrongTarget, nil }

	_, err := u.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), `executable name "other" does not match archive member "tool"`) {
		t.Fatalf("Check error = %v", err)
	}
}

func TestCheckVersionBehavior(t *testing.T) {
	archive := makeTar(t, []archiveMember{{name: "tool", body: []byte("new")}})
	for _, test := range []struct {
		name       string
		current    string
		comparable bool
		available  bool
	}{
		{"newer", "v1.0.0", true, true},
		{"equal", "v2.0.0", true, false},
		{"older release", "v3.0.0", true, false},
		{"development", "dev", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := releaseFixture{tag: "v2.0.0", assetName: "tool_linux_amd64.tar.gz", archive: archive}
			u, server, _ := newTestUpdater(t, fixture, test.current)
			defer server.Close()
			plan, err := u.Check(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if plan.VersionsComparable() != test.comparable || plan.UpdateAvailable() != test.available {
				t.Fatalf("comparable=%v available=%v", plan.VersionsComparable(), plan.UpdateAvailable())
			}
			if !test.available {
				if _, err := u.Apply(context.Background(), plan); err == nil {
					t.Fatal("Apply accepted a non-update")
				}
			}
		})
	}
}

func TestCheckVersionAppliesTargetedNewer(t *testing.T) {
	u, server, _ := newTestUpdater(t, releaseFixture{tag: "v2.0.0"}, "v1.0.0")
	defer server.Close()

	plan, err := u.CheckVersion(context.Background(), "v2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	result, err := u.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Committed || result.Version != "v2.0.0" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestApplyRejectsTargetedDowngradeWithoutOptIn(t *testing.T) {
	u, server, target := newTestUpdater(t, releaseFixture{tag: "v1.0.0"}, "v2.0.0")
	defer server.Close()

	plan, err := u.CheckVersion(context.Background(), "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	result, err := u.Apply(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "AllowDowngrade") {
		t.Fatalf("Apply error = %v, want AllowDowngrade error", err)
	}
	if result.Committed {
		t.Fatalf("unexpected committed result: %#v", result)
	}
	body, readErr := os.ReadFile(target)
	if readErr != nil || string(body) != "old" {
		t.Fatalf("target changed: body=%q err=%v", body, readErr)
	}
}

func TestApplyCommitsTargetedDowngradeWithOptIn(t *testing.T) {
	for _, test := range []struct {
		name    string
		current string
		target  string
	}{
		{name: "downgrade", current: "v2.0.0", target: "v1.0.0"},
		{name: "equal-version reinstall", current: "v1.0.0", target: "v1.0.0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			u, server, _ := newTestUpdater(t, releaseFixture{tag: test.target}, test.current)
			defer server.Close()
			u.allowDowngrade = true

			plan, err := u.CheckVersion(context.Background(), test.target)
			if err != nil {
				t.Fatal(err)
			}
			result, err := u.Apply(context.Background(), plan)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Committed || result.PreviousVersion != test.current || result.Version != test.target {
				t.Fatalf("unexpected result: %#v", result)
			}
			if test.name == "downgrade" && semver.Compare(result.PreviousVersion, result.Version) <= 0 {
				t.Fatalf("previous version %q is not greater than %q", result.PreviousVersion, result.Version)
			}
		})
	}
}

func TestAllowDowngradeDoesNotRelaxLatestPath(t *testing.T) {
	u, server, target := newTestUpdater(t, releaseFixture{tag: "v1.0.0"}, "v1.0.0")
	defer server.Close()
	u.allowDowngrade = true

	plan, err := u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result, err := u.Apply(context.Background(), plan)
	if err == nil {
		t.Fatal("Apply accepted a non-newer latest-path plan")
	}
	if result.Committed {
		t.Fatalf("unexpected committed result: %#v", result)
	}
	body, readErr := os.ReadFile(target)
	if readErr != nil || string(body) != "old" {
		t.Fatalf("target changed: body=%q err=%v", body, readErr)
	}
}

func TestCheckVersionRejectsPrereleaseFlaggedRelease(t *testing.T) {
	for _, test := range []struct {
		name    string
		fixture releaseFixture
		flag    string
	}{
		{name: "prerelease", fixture: releaseFixture{tag: "v2.0.0", prerelease: true}, flag: "prerelease"},
		{name: "draft", fixture: releaseFixture{tag: "v2.0.0", draft: true}, flag: "draft"},
	} {
		t.Run(test.name, func(t *testing.T) {
			u, server, _ := newTestUpdater(t, test.fixture, "v1.0.0")
			defer server.Close()
			_, err := u.CheckVersion(context.Background(), "v2.0.0")
			if err == nil || !strings.Contains(err.Error(), test.flag) {
				t.Fatalf("CheckVersion error = %v, want %q", err, test.flag)
			}
		})
	}
}

func TestCheckVersionValidatesInput(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}))
	defer server.Close()
	u := mustUpdater(t, "v1.0.0")
	u.apiBaseURL = server.URL
	u.allowHTTP = true
	for _, version := range []string{"1.2.3", "v1.2", "v1.2.3-rc1", "latest"} {
		if _, err := u.CheckVersion(context.Background(), version); err == nil {
			t.Errorf("CheckVersion accepted %q", version)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("invalid versions made %d HTTP requests", hits.Load())
	}

	mismatch, mismatchServer, _ := newTestUpdater(t, releaseFixture{tag: "v3.0.0"}, "v1.0.0")
	defer mismatchServer.Close()
	if _, err := mismatch.CheckVersion(context.Background(), "v2.0.0"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("tag mismatch error = %v", err)
	}
}

func TestApplyRejectsTargetedPlanOverDevelopmentBuild(t *testing.T) {
	u, server, _ := newTestUpdater(t, releaseFixture{tag: "v2.0.0"}, "dev")
	defer server.Close()
	u.allowDowngrade = true

	plan, err := u.CheckVersion(context.Background(), "v2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Apply(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "not a stable version") {
		t.Fatalf("Apply error = %v, want incomparable current-version error", err)
	}
}

func TestCheckRejectsMetadataAndAssets(t *testing.T) {
	archive := makeTar(t, []archiveMember{{name: "tool", body: []byte("new")}})
	for _, test := range []struct {
		name    string
		fixture releaseFixture
	}{
		{"status", releaseFixture{metadataCode: http.StatusBadGateway}},
		{"malformed JSON", releaseFixture{metadataBody: []byte(`{"tag_name":`)}},
		{"unstable tag", releaseFixture{tag: "v2.0.0-rc.1", assetName: "tool_linux_amd64.tar.gz", archive: archive}},
		{"tag without v", releaseFixture{tag: "2.0.0", assetName: "tool_linux_amd64.tar.gz", archive: archive}},
		{"missing exact asset", releaseFixture{tag: "v2.0.0", assetName: "tool_linux_amd64_v2.tar.gz", archive: archive}},
	} {
		t.Run(test.name, func(t *testing.T) {
			u, server, _ := newTestUpdater(t, test.fixture, "v1.0.0")
			defer server.Close()
			if _, err := u.Check(context.Background()); err == nil {
				t.Fatal("Check accepted invalid release")
			}
		})
	}
}

func TestCheckRejectsDuplicateArchiveWithoutDownload(t *testing.T) {
	var downloads atomic.Int32
	u, server, _ := newTestUpdater(t, releaseFixture{
		duplicate: "tool_linux_amd64.tar.gz",
		archiveHook: func() {
			downloads.Add(1)
		},
	}, "v1.0.0")
	defer server.Close()

	if _, err := u.Check(context.Background()); err == nil || !strings.Contains(err.Error(), "duplicate asset") {
		t.Fatalf("Check error = %v", err)
	}
	if downloads.Load() != 0 {
		t.Fatalf("archive downloads during Check = %d", downloads.Load())
	}
}

func TestCheckMetadataLimitAndCancellation(t *testing.T) {
	t.Run("limit", func(t *testing.T) {
		fixture := releaseFixture{metadataBody: bytes.Repeat([]byte("x"), int(maxMetadataBytes)+1)}
		u, server, _ := newTestUpdater(t, fixture, "v1.0.0")
		defer server.Close()
		if _, err := u.Check(context.Background()); err == nil || !strings.Contains(err.Error(), "limit") {
			t.Fatalf("Check error = %v", err)
		}
	})
	t.Run("cancellation", func(t *testing.T) {
		started := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(started)
			<-r.Context().Done()
		}))
		defer server.Close()
		u := mustUpdater(t, "v1.0.0")
		u.apiBaseURL = server.URL
		u.allowHTTP = true
		u.goos, u.goarch = "linux", "amd64"
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, err := u.Check(ctx)
			done <- err
		}()
		<-started
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Check error = %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Check did not stop after cancellation")
		}
	})
}

func TestApplyVerifiesAndReplacesOnlyCommand(t *testing.T) {
	archive := makeTar(t, []archiveMember{
		{name: "tool", body: []byte("new-command")},
		{name: "toold", body: []byte("daemon")},
	})
	fixture := releaseFixture{tag: "v2.0.0", assetName: "tool_linux_amd64.tar.gz", archive: archive}
	u, server, target := newTestUpdater(t, fixture, "v1.0.0")
	defer server.Close()
	resolvedTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o750); err != nil {
		t.Fatal(err)
	}
	plan, err := u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result, err := u.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "new-command" {
		t.Fatalf("installed %q", body)
	}
	if !result.Committed || result.PreviousVersion != "v1.0.0" || result.Version != "v2.0.0" || result.Executable != resolvedTarget {
		t.Fatalf("unexpected result: %#v", result)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o750 {
			t.Fatalf("mode = %o", info.Mode().Perm())
		}
	}
}

func TestStageExecutableModeAppliedAfterWrite(t *testing.T) {
	target := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(target, []byte("old"), 0o700); err != nil {
		t.Fatal(err)
	}
	body := makeTar(t, []archiveMember{{name: "tool", body: []byte("new-binary")}})
	archive, size := archiveFile(t, body)
	path, err := stageExecutable(context.Background(), target, 0o755, "tool_linux_amd64.tar.gz", archive, size, "tool")
	if err != nil {
		t.Fatalf("stageExecutable: %v", err)
	}
	defer func() { _ = os.Remove(path) }()

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o755 {
			t.Fatalf("mode = %o, want 0755", info.Mode().Perm())
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new-binary" {
		t.Fatalf("staged content = %q, want %q", got, "new-binary")
	}

	pattern := regexp.MustCompile(`^\.` + regexp.QuoteMeta(filepath.Base(target)) + `\.selfupdate-stage-[0-9a-f]{32}$`)
	if !pattern.MatchString(filepath.Base(path)) {
		t.Fatalf("stage name %q does not match %s", filepath.Base(path), pattern)
	}
}

func TestApplySweepsStaleStagedExecutables(t *testing.T) {
	archive := makeTar(t, []archiveMember{{name: "tool", body: []byte("new")}})
	fixture := releaseFixture{tag: "v2.0.0", assetName: "tool_linux_amd64.tar.gz", archive: archive}
	u, server, target := newTestUpdater(t, fixture, "v1.0.0")
	defer server.Close()
	directory := filepath.Dir(target)

	// Uppercase hex fails the lower-hex matcher; use "F" rather than "A" so the
	// name still differs from the matching fixture on case-insensitive
	// filesystems (macOS, Windows), where "a"*32 and "A"*32 would collide.
	matchingStage := filepath.Join(directory, ".tool.selfupdate-stage-"+strings.Repeat("a", 32))
	tooShortStage := filepath.Join(directory, ".tool.selfupdate-stage-abc")
	wrongCaseStage := filepath.Join(directory, ".tool.selfupdate-stage-"+strings.Repeat("F", 32))
	matchingArchive := filepath.Join(directory, ".tool.selfupdate-archive-"+strings.Repeat("a", 32))
	tooShortArchive := filepath.Join(directory, ".tool.selfupdate-archive-abc")
	wrongCaseArchive := filepath.Join(directory, ".tool.selfupdate-archive-"+strings.Repeat("F", 32))
	unrelated := filepath.Join(directory, ".tool.other")
	matching := []string{matchingStage, matchingArchive}
	nearMisses := []string{tooShortStage, wrongCaseStage, tooShortArchive, wrongCaseArchive, unrelated}
	for _, path := range append(append([]string{}, matching...), nearMisses...) {
		if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	plan, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if _, err := u.Apply(context.Background(), plan); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	for _, path := range matching {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale file %s still exists (stat err = %v)", path, err)
		}
	}
	for _, path := range nearMisses {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("near-miss %s was removed: %v", path, err)
		}
	}
}

func TestCleanupStaleStagesSkipsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinked stage names are a Unix-only concern")
	}
	for _, infix := range []string{"stage", "archive"} {
		t.Run(infix, func(t *testing.T) {
			directory := t.TempDir()
			target := filepath.Join(directory, "tool")

			victimDir := t.TempDir()
			victim := filepath.Join(victimDir, "victim")
			if err := os.WriteFile(victim, []byte("victim"), 0o600); err != nil {
				t.Fatal(err)
			}
			symlinkPath := filepath.Join(directory, ".tool.selfupdate-"+infix+"-"+strings.Repeat("a", 32))
			if err := os.Symlink(victim, symlinkPath); err != nil {
				t.Fatal(err)
			}

			if err := cleanupStaleFiles(target, infix); err != nil {
				t.Fatalf("cleanupStaleFiles: %v", err)
			}
			if _, err := os.Lstat(symlinkPath); err != nil {
				t.Fatalf("symlink removed: %v", err)
			}
			if _, err := os.Stat(victim); err != nil {
				t.Fatalf("victim removed: %v", err)
			}
		})
	}
}

func TestCheckRequiresCanonicalAssetDigest(t *testing.T) {
	archive := makeTar(t, []archiveMember{{name: "tool", body: []byte("new")}})
	archiveHash := sha256.Sum256(archive)
	valid := fmt.Sprintf("sha256:%x", archiveHash)
	for _, test := range []struct {
		name    string
		fixture releaseFixture
		valid   bool
	}{
		{"valid", releaseFixture{digest: stringPointer(valid)}, true},
		{"missing", releaseFixture{omitDigest: true}, false},
		{"null", releaseFixture{nullDigest: true}, false},
		{"empty", releaseFixture{digest: stringPointer("")}, false},
		{"uppercase hex", releaseFixture{digest: stringPointer("sha256:" + strings.Repeat("A", 64))}, false},
		{"malformed hex", releaseFixture{digest: stringPointer("sha256:" + strings.Repeat("g", 64))}, false},
		{"wrong length", releaseFixture{digest: stringPointer("sha256:" + strings.Repeat("0", 63))}, false},
		{"unsupported algorithm", releaseFixture{digest: stringPointer("sha512:" + strings.Repeat("0", 64))}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var downloads atomic.Int32
			fixture := test.fixture
			fixture.archive = archive
			fixture.archiveHook = func() { downloads.Add(1) }
			u, server, _ := newTestUpdater(t, fixture, "v1.0.0")
			defer server.Close()

			plan, err := u.Check(context.Background())
			if test.valid {
				if err != nil {
					t.Fatalf("Check: %v", err)
				}
				if plan.archiveDigest != archiveHash {
					t.Fatalf("plan digest = %x, want %x", plan.archiveDigest, archiveHash)
				}
			} else if err == nil {
				t.Fatal("Check accepted invalid asset digest")
			}
			if downloads.Load() != 0 {
				t.Fatalf("archive downloads during Check = %d", downloads.Load())
			}
		})
	}
}

func TestApplyRejectsAssetDigestMismatch(t *testing.T) {
	archive := makeTar(t, []archiveMember{{name: "tool", body: []byte("new")}})
	wrongDigest := "sha256:" + strings.Repeat("0", 64)
	var downloads atomic.Int32
	u, server, target := newTestUpdater(t, releaseFixture{
		archive: archive,
		digest:  &wrongDigest,
		archiveHook: func() {
			downloads.Add(1)
		},
	}, "v1.0.0")
	defer server.Close()

	plan, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if _, err := u.Apply(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("Apply error = %v", err)
	}
	if downloads.Load() != 1 {
		t.Fatalf("archive downloads = %d, want 1", downloads.Load())
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "old" {
		t.Fatalf("target changed to %q", body)
	}

	directory := filepath.Dir(target)
	stageMatches, err := filepath.Glob(filepath.Join(directory, ".tool.selfupdate-stage-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(stageMatches) != 0 {
		t.Fatalf("stage file created despite digest mismatch: %v", stageMatches)
	}
	archiveMatches, err := filepath.Glob(filepath.Join(directory, ".tool.selfupdate-archive-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(archiveMatches) != 0 {
		t.Fatalf("downloaded archive not cleaned up after digest mismatch: %v", archiveMatches)
	}
}

func TestApplyRejectsAssetRedirectOffAllowlist(t *testing.T) {
	u, server, target := newTestUpdater(t, releaseFixture{}, "v1.0.0")
	defer server.Close()

	plan, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}

	redirectingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/asset" {
			http.Redirect(w, r, "ftp://example.invalid/x", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	}))
	defer redirectingServer.Close()

	plan.assetURL = redirectingServer.URL + "/asset"

	if _, err := u.Apply(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "release asset") || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("Apply error = %v, want an error containing \"release asset\" and \"rejected\"", err)
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "old" {
		t.Fatalf("target changed to %q", body)
	}
}

func TestPlanBoundToUpdater(t *testing.T) {
	archive := makeTar(t, []archiveMember{{name: "tool", body: []byte("new")}})
	fixture := releaseFixture{tag: "v2.0.0", assetName: "tool_linux_amd64.tar.gz", archive: archive}
	first, server, _ := newTestUpdater(t, fixture, "v1.0.0")
	defer server.Close()
	plan, err := first.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second := mustUpdater(t, "v1.0.0")
	if _, err := second.Apply(context.Background(), plan); err == nil {
		t.Fatal("Apply accepted another updater's plan")
	}
	if _, err := first.Apply(context.Background(), nil); err == nil {
		t.Fatal("Apply accepted nil plan")
	}
}

func TestApplyRejectsStalePlanBeforeDownload(t *testing.T) {
	archive := makeTar(t, []archiveMember{{name: "tool", body: []byte("new")}})
	var downloads atomic.Int32
	u, server, target := newTestUpdater(t, releaseFixture{
		tag:       "v2.0.0",
		assetName: "tool_linux_amd64.tar.gz",
		archive:   archive,
		archiveHook: func() {
			downloads.Add(1)
		},
	}, "v1.0.0")
	defer server.Close()
	plan, err := u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("externally-installed-newer"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := u.Apply(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "changed since Check") {
		t.Fatalf("Apply error = %v", err)
	}
	if downloads.Load() != 0 {
		t.Fatalf("archive downloads = %d", downloads.Load())
	}
}

func TestLockWaitCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	first, err := acquireFileLock(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.release() }()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = acquireFileLock(ctx, path)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("acquireFileLock error = %v", err)
	}
}

func TestApplyCancellationWhileWaitingForLock(t *testing.T) {
	archive := makeTar(t, []archiveMember{{name: "tool", body: []byte("new")}})
	u, server, target := newTestUpdater(t, releaseFixture{tag: "v2.0.0", assetName: "tool_linux_amd64.tar.gz", archive: archive}, "v1.0.0")
	defer server.Close()
	plan, err := u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	lock, err := acquireFileLock(context.Background(), target+".selfupdate.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.release() }()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := u.Apply(ctx, plan); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Apply error = %v", err)
	}
}

func TestApplyCancellationImmediatelyBeforeCommit(t *testing.T) {
	archive := makeTar(t, []archiveMember{{name: "tool", body: []byte("new")}})
	u, server, target := newTestUpdater(t, releaseFixture{tag: "v2.0.0", assetName: "tool_linux_amd64.tar.gz", archive: archive}, "v1.0.0")
	defer server.Close()
	plan, err := u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	u.beforeCommit = cancel
	if _, err := u.Apply(ctx, plan); !errors.Is(err, context.Canceled) {
		t.Fatalf("Apply error = %v", err)
	}
	body, _ := os.ReadFile(target)
	if string(body) != "old" {
		t.Fatalf("target changed to %q", body)
	}
}

func TestApplyReturnsResultAfterPostCommitError(t *testing.T) {
	archive := makeTar(t, []archiveMember{{name: "tool", body: []byte("new")}})
	u, server, target := newTestUpdater(t, releaseFixture{tag: "v2.0.0", assetName: "tool_linux_amd64.tar.gz", archive: archive}, "v1.0.0")
	defer server.Close()
	resolvedTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	postCommitErr := errors.New("directory sync failed")
	u.replace = func(stage, target string) (replacementResult, error) {
		if err := os.Rename(stage, target); err != nil {
			return replacementResult{}, err
		}
		return replacementResult{committed: true}, postCommitErr
	}
	result, err := u.Apply(context.Background(), plan)
	if !errors.Is(err, postCommitErr) {
		t.Fatalf("Apply error = %v", err)
	}
	if !result.Committed || result.Executable != resolvedTarget || result.Version != "v2.0.0" {
		t.Fatalf("result = %#v", result)
	}
	body, _ := os.ReadFile(target)
	if string(body) != "new" {
		t.Fatalf("target = %q", body)
	}
}

func TestApplyReportsPendingPostCommitCleanup(t *testing.T) {
	archive := makeTar(t, []archiveMember{{name: "tool", body: []byte("new")}})
	u, server, _ := newTestUpdater(t, releaseFixture{tag: "v2.0.0", assetName: "tool_linux_amd64.tar.gz", archive: archive}, "v1.0.0")
	defer server.Close()
	plan, err := u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	u.replace = func(stage, target string) (replacementResult, error) {
		if err := os.Rename(stage, target); err != nil {
			return replacementResult{}, err
		}
		return replacementResult{committed: true, cleanupPending: true}, nil
	}
	result, err := u.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Committed || !result.CleanupPending {
		t.Fatalf("result = %#v", result)
	}
}

func TestApplyDetectsExecutableChangeDuringDownload(t *testing.T) {
	archive := makeTar(t, []archiveMember{{name: "tool", body: []byte("new")}})
	fixture := releaseFixture{tag: "v2.0.0", assetName: "tool_linux_amd64.tar.gz", archive: archive}
	_, server, target := newTestUpdater(t, fixture, "v1.0.0")
	defer server.Close()
	fixture.archiveHook = func() {
		if err := os.WriteFile(target, []byte("changed"), 0o700); err != nil {
			t.Errorf("change target: %v", err)
		}
	}
	// The handler captured a pointer-equivalent closure only through its fixture value,
	// so install the hook directly with a fresh server.
	server.Close()
	u, server, target := newTestUpdater(t, releaseFixture{
		tag:       "v2.0.0",
		assetName: "tool_linux_amd64.tar.gz",
		archive:   archive,
		archiveHook: func() {
			_ = os.WriteFile(target, []byte("changed"), 0o700)
		},
	}, "v1.0.0")
	defer server.Close()
	plan, err := u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.Apply(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("Apply error = %v", err)
	}
}

// newDownloadTimingTestUpdater builds a fixture whose /asset handler is fully
// caller-controlled, so tests can delay, stall, or block the archive transfer
// to exercise download timing behavior.
func newDownloadTimingTestUpdater(t *testing.T, archive []byte, assetHandler http.HandlerFunc) (*Updater, *httptest.Server, string) {
	t.Helper()
	archiveHash := sha256.Sum256(archive)
	digest := fmt.Sprintf("sha256:%x", archiveHash)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/repo/releases/latest":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": "v2.0.0", "name": "Release v2.0.0", "body": "notes",
				"html_url": server.URL + "/release", "published_at": "2026-01-02T03:04:05Z",
				"assets": []map[string]any{{
					"name": "tool_linux_amd64.tar.gz", "browser_download_url": server.URL + "/asset",
					"size": len(archive), "digest": digest,
				}},
			})
		case "/asset":
			assetHandler(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	target := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(target, []byte("old"), 0o700); err != nil {
		t.Fatal(err)
	}
	u := mustUpdater(t, "v1.0.0")
	u.apiBaseURL = server.URL
	u.allowHTTP = true
	u.goos, u.goarch = "linux", "amd64"
	u.executablePath = func() (string, error) { return target, nil }
	return u, server, target
}

func TestApplyDownloadsSlowerThanClientTimeout(t *testing.T) {
	archive := makeTar(t, []archiveMember{{name: "tool", body: []byte("new")}})
	u, _, target := newDownloadTimingTestUpdater(t, archive, func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Errorf("ResponseWriter does not support Flush")
			return
		}
		half := len(archive) / 2
		if _, err := w.Write(archive[:half]); err != nil {
			return
		}
		flusher.Flush()
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write(archive[half:])
	})
	u.httpClient.Timeout = 200 * time.Millisecond

	plan, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if _, err := u.Apply(context.Background(), plan); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "new" {
		t.Fatalf("installed %q", body)
	}
}

func TestApplyDownloadStallAborts(t *testing.T) {
	archive := makeTar(t, []archiveMember{{name: "tool", body: []byte("new")}})
	block := make(chan struct{})
	u, _, target := newDownloadTimingTestUpdater(t, archive, func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Errorf("ResponseWriter does not support Flush")
			return
		}
		half := len(archive) / 2
		if _, err := w.Write(archive[:half]); err != nil {
			return
		}
		flusher.Flush()
		<-block
	})
	// Registered after newDownloadTimingTestUpdater's t.Cleanup(server.Close), so
	// LIFO cleanup order closes block (unblocking the handler) before closing the
	// server; otherwise Close blocks up to 5s waiting for the active connection.
	t.Cleanup(func() { close(block) })
	u.downloadIdleTimeout = 100 * time.Millisecond

	plan, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := u.Apply(context.Background(), plan)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || (!errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context")) {
			t.Fatalf("Apply error = %v, want context.Canceled or a \"context\" error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Apply did not stop after the idle timeout")
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "old" {
		t.Fatalf("target changed to %q", body)
	}
}

func TestApplyDownloadHonorsCallerCancellation(t *testing.T) {
	archive := makeTar(t, []archiveMember{{name: "tool", body: []byte("new")}})
	started := make(chan struct{})
	block := make(chan struct{})
	u, _, _ := newDownloadTimingTestUpdater(t, archive, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		close(started)
		<-block
	})
	// Registered after newDownloadTimingTestUpdater's t.Cleanup(server.Close), so
	// LIFO cleanup order closes block (unblocking the handler) before closing the
	// server; otherwise Close blocks up to 5s waiting for the active connection.
	t.Cleanup(func() { close(block) })

	plan, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := u.Apply(ctx, plan)
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Apply error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Apply did not stop after caller cancellation")
	}
}

func TestApplyReportsDownloadProgress(t *testing.T) {
	archive := makeTar(t, []archiveMember{{name: "tool", body: []byte("new-command-body")}})
	fixture := releaseFixture{tag: "v2.0.0", assetName: "tool_linux_amd64.tar.gz", archive: archive}
	u, server, _ := newTestUpdater(t, fixture, "v1.0.0")
	defer server.Close()

	type sample struct{ received, total int64 }
	var mu sync.Mutex
	var samples []sample
	u.downloadProgress = func(received, total int64) {
		mu.Lock()
		samples = append(samples, sample{received, total})
		mu.Unlock()
	}

	plan, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}

	mu.Lock()
	afterCheck := len(samples)
	mu.Unlock()
	if afterCheck != 0 {
		t.Fatalf("progress calls observed during Check = %d, want 0", afterCheck)
	}

	if _, err := u.Apply(context.Background(), plan); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(samples) == 0 {
		t.Fatal("no progress calls during Apply")
	}
	var previous int64
	for _, s := range samples {
		if s.received < previous {
			t.Fatalf("received went backwards: %d then %d", previous, s.received)
		}
		if s.total != int64(len(archive)) {
			t.Fatalf("total = %d, want %d", s.total, len(archive))
		}
		previous = s.received
	}
	if samples[len(samples)-1].received != int64(len(archive)) {
		t.Fatalf("final received = %d, want %d", samples[len(samples)-1].received, len(archive))
	}
}

func TestDownloadToFile(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		content := bytes.Repeat([]byte("x"), 1024)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(content)
		}))
		defer server.Close()

		u := mustUpdater(t, "v1.0.0")
		u.allowHTTP = true
		file, err := os.CreateTemp(t.TempDir(), "archive-*")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = file.Close() }()

		digest, err := u.downloadToFile(context.Background(), server.URL+"/asset", int64(len(content)), "release asset", 0, file)
		if err != nil {
			t.Fatalf("downloadToFile: %v", err)
		}
		want := sha256.Sum256(content)
		if digest != want {
			t.Fatalf("digest = %x, want %x", digest, want)
		}
		got, err := os.ReadFile(file.Name())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, content) {
			t.Fatalf("file contents = %d bytes, want %d bytes matching the served archive", len(got), len(content))
		}
	})

	t.Run("oversize rejection", func(t *testing.T) {
		content := bytes.Repeat([]byte("x"), 1025)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Write in two flushed chunks so the server cannot compute
			// Content-Length up front; this forces the post-copy
			// written-bytes check (rather than the earlier Content-Length
			// check) to be the one that rejects the oversized body.
			flusher, _ := w.(http.Flusher)
			_, _ = w.Write(content[:1])
			if flusher != nil {
				flusher.Flush()
			}
			_, _ = w.Write(content[1:])
		}))
		defer server.Close()

		u := mustUpdater(t, "v1.0.0")
		u.allowHTTP = true
		file, err := os.CreateTemp(t.TempDir(), "archive-*")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = file.Close() }()

		_, err = u.downloadToFile(context.Background(), server.URL+"/asset", 1024, "release asset", 0, file)
		if err == nil || !strings.Contains(err.Error(), "exceeds the 1024-byte limit") {
			t.Fatalf("downloadToFile error = %v, want a byte-limit error", err)
		}
	})

	t.Run("non-2xx", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "not found here", http.StatusNotFound)
		}))
		defer server.Close()

		u := mustUpdater(t, "v1.0.0")
		u.allowHTTP = true
		file, err := os.CreateTemp(t.TempDir(), "archive-*")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = file.Close() }()

		_, err = u.downloadToFile(context.Background(), server.URL+"/asset", 1024, "release asset", 0, file)
		if err == nil || !strings.Contains(err.Error(), "HTTP 404") || !strings.Contains(err.Error(), "not found here") {
			t.Fatalf("downloadToFile error = %v, want an HTTP 404 error mentioning the response body", err)
		}
	})
}

func TestConcurrentApplyUsesFileLock(t *testing.T) {
	archive := makeTar(t, []archiveMember{{name: "tool", body: []byte("new")}})
	var active atomic.Int32
	var maximum atomic.Int32
	fixture := releaseFixture{
		tag:       "v2.0.0",
		assetName: "tool_linux_amd64.tar.gz",
		archive:   archive,
		archiveHook: func() {
			current := active.Add(1)
			for {
				old := maximum.Load()
				if current <= old || maximum.CompareAndSwap(old, current) {
					break
				}
			}
			time.Sleep(75 * time.Millisecond)
			active.Add(-1)
		},
	}
	first, server, target := newTestUpdater(t, fixture, "v1.0.0")
	defer server.Close()
	second := mustUpdater(t, "v1.0.0")
	second.apiBaseURL, second.allowHTTP = server.URL, true
	second.goos, second.goarch = "linux", "amd64"
	second.executablePath = func() (string, error) { return target, nil }
	firstPlan, err := first.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	secondPlan, err := second.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	errorsSeen := make(chan error, 2)
	for _, item := range []struct {
		u *Updater
		p *Plan
	}{{first, firstPlan}, {second, secondPlan}} {
		wait.Add(1)
		go func(updater *Updater, plan *Plan) {
			defer wait.Done()
			_, err := updater.Apply(context.Background(), plan)
			errorsSeen <- err
		}(item.u, item.p)
	}
	wait.Wait()
	close(errorsSeen)
	succeeded, stale := 0, 0
	for err := range errorsSeen {
		if err == nil {
			succeeded++
		} else if strings.Contains(err.Error(), "changed since Check") {
			stale++
		} else {
			t.Errorf("Apply: %v", err)
		}
	}
	if succeeded != 1 || stale != 1 {
		t.Fatalf("succeeded=%d stale=%d", succeeded, stale)
	}
	if maximum.Load() != 1 {
		t.Fatalf("maximum concurrent archive downloads = %d", maximum.Load())
	}
}

func TestValidateURLProductionAllowlist(t *testing.T) {
	t.Parallel()
	u := &Updater{}
	for _, test := range []struct {
		name    string
		rawURL  string
		api     bool
		wantErr string
	}{
		{"api ok", "https://api.github.com/repos/o/r/releases/latest", true, ""},
		{"release ok", "https://github.com/o/r/releases/download/v1/x.tar.gz", false, ""},
		{"api host case insensitive", "https://API.GITHUB.COM/x", true, ""},
		{"api on release host", "https://github.com/x", true, "api.github.com"},
		{"release on api host", "https://api.github.com/x", false, "github.com"},
		{"release on unrelated host", "https://evil.example/x", false, "github.com"},
		{"api on suffix-matching host", "https://api.github.com.evil.example/x", true, "api.github.com"},
		{"plain http rejected", "http://github.com/x", false, "HTTPS"},
		{"pinned host with port ok", "https://github.com:443/x", false, ""},
		{"credentials rejected", "https://user@github.com/x", false, "credentials"},
		{"fragment rejected", "https://github.com/x#frag", false, "fragment"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := u.validateURL(test.rawURL, test.api)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("validateURL(%q, %v) = %v, want nil", test.rawURL, test.api, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validateURL(%q, %v) = %v, want error containing %q", test.rawURL, test.api, err, test.wantErr)
			}
		})
	}

	t.Run("allowHTTP escape hatch", func(t *testing.T) {
		allowed := &Updater{allowHTTP: true}
		if err := allowed.validateURL("http://127.0.0.1:8080/x", true); err != nil {
			t.Fatalf("validateURL with allowHTTP = %v, want nil", err)
		}
	})
}

func TestAssetRedirectAllowed(t *testing.T) {
	t.Parallel()
	u := &Updater{}
	for _, test := range []struct {
		name    string
		target  string
		wantErr string
	}{
		{"objects host ok", "https://objects.githubusercontent.com/x", ""},
		{"release-assets host ok", "https://release-assets.githubusercontent.com/x", ""},
		{"github.com asset ok", "https://github.com/o/r/releases/download/v1/x", ""},
		{"bare githubusercontent host ok", "https://githubusercontent.com/x", ""},
		{"unrelated host rejected", "https://evil.example/x", "untrusted host"},
		{"suffix without dot rejected", "https://evilgithubusercontent.com/x", "untrusted host"},
		{"http downgrade rejected", "http://objects.githubusercontent.com/x", "rejected"},
		{"non-default port rejected", "https://objects.githubusercontent.com:8443/x", "rejected"},
		{"credentials rejected", "https://user@objects.githubusercontent.com/x", "rejected"},
	} {
		t.Run(test.name, func(t *testing.T) {
			target, err := url.Parse(test.target)
			if err != nil {
				t.Fatal(err)
			}
			gotErr := u.assetRedirectAllowed(target)
			if test.wantErr == "" {
				if gotErr != nil {
					t.Fatalf("assetRedirectAllowed(%q) = %v, want nil", test.target, gotErr)
				}
				return
			}
			if gotErr == nil || !strings.Contains(gotErr.Error(), test.wantErr) {
				t.Fatalf("assetRedirectAllowed(%q) = %v, want error containing %q", test.target, gotErr, test.wantErr)
			}
		})
	}

	t.Run("allowHTTP escape hatch", func(t *testing.T) {
		allowed := &Updater{allowHTTP: true}
		target, err := url.Parse("http://127.0.0.1:9999/x")
		if err != nil {
			t.Fatal(err)
		}
		if err := allowed.assetRedirectAllowed(target); err != nil {
			t.Fatalf("assetRedirectAllowed with allowHTTP = %v, want nil", err)
		}
	})
}

func TestNewCopiesHTTPClient(t *testing.T) {
	t.Parallel()
	original := &http.Client{Timeout: 5 * time.Second}
	u, err := New(Config{Repository: "owner/repo", Command: "tool", CurrentVersion: "v1.0.0", HTTPClient: original})
	if err != nil {
		t.Fatal(err)
	}
	if u.httpClient == original {
		t.Fatal("New must copy the caller-supplied HTTP client, not reuse the pointer")
	}
	if u.httpClient.Timeout != 5*time.Second {
		t.Fatalf("u.httpClient.Timeout = %v, want 5s", u.httpClient.Timeout)
	}
	original.Timeout = 10 * time.Second
	if u.httpClient.Timeout != 5*time.Second {
		t.Fatalf("u.httpClient.Timeout changed after mutating caller's client: %v", u.httpClient.Timeout)
	}

	defaultClient := mustUpdater(t, "v1.0.0")
	if defaultClient.httpClient.Timeout != 60*time.Second {
		t.Fatalf("default u.httpClient.Timeout = %v, want 60s", defaultClient.httpClient.Timeout)
	}
}

// archiveFile writes body to a temp file for tests exercising the streaming
// extraction signatures, which take an *os.File (as production callers do,
// after downloadToFile) rather than a []byte. Buffering the archive bytes in
// a test fixture is fine; only production code must avoid buffering the full
// archive.
func archiveFile(t *testing.T, body []byte) (*os.File, int64) {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "archive-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	if _, err := file.Write(body); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	return file, int64(len(body))
}

func TestExtractTarGzRejectsOversizedExpansion(t *testing.T) {
	t.Parallel()
	// extractTarGzContext bounds the decompressed stream with a LimitedReader
	// of N = maxExpanded+1. Depending on where the budget runs out, the
	// rejection surfaces one of two ways:
	//   - mid-entry: a member larger than the budget makes tar.Reader's
	//     internal skip-to-next-header logic drain the LimitedReader before
	//     it finds the next header, surfacing io.ErrUnexpectedEOF.
	//   - block boundary: a member that consumes exactly N bytes (512-byte
	//     header + padded data) leaves the LimitedReader at N==0 right as the
	//     next Next() call cleanly hits EOF, so the loop breaks normally and
	//     the explicit post-loop "expanded archive exceeds" backstop fires.
	t.Run("mid-entry exhaustion", func(t *testing.T) {
		t.Parallel()
		limit := int64(4096)
		body := makeTar(t, []archiveMember{{name: "filler", body: make([]byte, limit+1024)}})
		archive, _ := archiveFile(t, body)
		var destination bytes.Buffer
		written, err := extractTarGzContext(context.Background(), archive, "tool", limit, &destination)
		if written != 0 {
			t.Fatalf("extractTarGzContext wrote %d bytes, want 0", written)
		}
		if err == nil || !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("extractTarGzContext error = %v, want io.ErrUnexpectedEOF", err)
		}
	})

	t.Run("block-boundary backstop", func(t *testing.T) {
		t.Parallel()
		limit := int64(1535) // 512-byte header + 1024-byte data = 1536 = limit+1
		body := makeTar(t, []archiveMember{{name: "filler", body: make([]byte, 1024)}})
		archive, _ := archiveFile(t, body)
		var destination bytes.Buffer
		written, err := extractTarGzContext(context.Background(), archive, "tool", limit, &destination)
		if written != 0 {
			t.Fatalf("extractTarGzContext wrote %d bytes, want 0", written)
		}
		if err == nil || !strings.Contains(err.Error(), "expanded archive exceeds") {
			t.Fatalf("extractTarGzContext error = %v, want \"expanded archive exceeds\"", err)
		}
	})
}

func TestExtractTarGzStrictMember(t *testing.T) {
	for _, test := range []struct {
		name    string
		members []archiveMember
		want    string
		ok      bool
	}{
		{"command and daemon", []archiveMember{{name: "tool", body: []byte("command")}, {name: "toold", body: []byte("daemon")}}, "command", true},
		{"missing", []archiveMember{{name: "toold", body: []byte("daemon")}}, "", false},
		{"nested", []archiveMember{{name: "bin/tool", body: []byte("command")}}, "", false},
		{"symlink", []archiveMember{{name: "tool", kind: tar.TypeSymlink}}, "", false},
		{"duplicate", []archiveMember{{name: "tool", body: []byte("one")}, {name: "tool", body: []byte("two")}}, "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := makeTar(t, test.members)
			archive, size := archiveFile(t, body)
			var destination bytes.Buffer
			written, err := extractArchive(context.Background(), "tool_linux_amd64.tar.gz", archive, size, "tool", &destination)
			if test.ok && (err != nil || destination.String() != test.want || written != int64(len(test.want))) {
				t.Fatalf("extract = %q (written=%d), %v", destination.String(), written, err)
			}
			if !test.ok && err == nil {
				t.Fatalf("extract accepted archive: %q", destination.String())
			}
		})
	}
}

func TestExtractZIPStrictMember(t *testing.T) {
	for _, test := range []struct {
		name    string
		members []zipMember
		want    string
		ok      bool
	}{
		{"command and daemon", []zipMember{{name: "tool.exe", body: []byte("command")}, {name: "toold.exe", body: []byte("daemon")}}, "command", true},
		{"missing", []zipMember{{name: "toold.exe", body: []byte("daemon")}}, "", false},
		{"nested", []zipMember{{name: "bin/tool.exe", body: []byte("command")}}, "", false},
		{"symlink", []zipMember{{name: "tool.exe", body: []byte("target"), mode: os.ModeSymlink | 0o777}}, "", false},
		{"duplicate", []zipMember{{name: "tool.exe", body: []byte("one")}, {name: "tool.exe", body: []byte("two")}}, "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := makeZIP(t, test.members)
			archive, size := archiveFile(t, body)
			var destination bytes.Buffer
			written, err := extractArchive(context.Background(), "tool_windows_amd64.zip", archive, size, "tool.exe", &destination)
			if test.ok && (err != nil || destination.String() != test.want || written != int64(len(test.want))) {
				t.Fatalf("extract = %q (written=%d), %v", destination.String(), written, err)
			}
			if !test.ok && err == nil {
				t.Fatalf("extract accepted archive: %q", destination.String())
			}
		})
	}

	t.Run("unsupported archive name", func(t *testing.T) {
		body := makeZIP(t, []zipMember{{name: "tool.exe", body: []byte("command")}})
		archive, size := archiveFile(t, body)
		var destination bytes.Buffer
		_, err := extractArchive(context.Background(), "tool_windows_amd64.rar", archive, size, "tool.exe", &destination)
		if err == nil || !strings.Contains(err.Error(), "unsupported archive name") {
			t.Fatalf("extractArchive error = %v, want \"unsupported archive name\"", err)
		}
	})
}

func TestExtractZIPRejectsExcessiveEntries(t *testing.T) {
	// Built directly with zip.Store (not the shared makeZIP helper, which
	// hardcodes zip.Deflate) so that setting up thousands of tiny entries
	// stays fast: per-entry deflate compressor initialization dominated this
	// fixture's construction time when measured with Deflate.
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for i := 0; i < maxZIPEntries+1; i++ {
		header := &zip.FileHeader{Name: fmt.Sprintf("file%d", i), Method: zip.Store}
		if _, err := writer.CreateHeader(header); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	archive, size := archiveFile(t, output.Bytes())
	var destination bytes.Buffer
	_, err := extractArchive(context.Background(), "tool_windows_amd64.zip", archive, size, "tool.exe", &destination)
	if err == nil || !strings.Contains(err.Error(), "entries") {
		t.Fatalf("extractArchive error = %v, want an error mentioning entries", err)
	}
}

type archiveMember struct {
	name string
	body []byte
	kind byte
}

func makeTar(t *testing.T, members []archiveMember) []byte {
	t.Helper()
	var output bytes.Buffer
	gzipWriter := gzip.NewWriter(&output)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, member := range members {
		kind := member.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		header := &tar.Header{Name: member.name, Mode: 0o755, Size: int64(len(member.body)), Typeflag: kind}
		if kind == tar.TypeSymlink {
			header.Linkname = "other"
			header.Size = 0
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if len(member.body) > 0 && kind == tar.TypeReg {
			if _, err := tarWriter.Write(member.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

type zipMember struct {
	name string
	body []byte
	mode os.FileMode
}

func makeZIP(t *testing.T, members []zipMember) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for _, member := range members {
		header := &zip.FileHeader{Name: member.name, Method: zip.Deflate}
		mode := member.mode
		if mode == 0 {
			mode = 0o755
		}
		header.SetMode(mode)
		entry, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(member.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func newTestUpdater(t *testing.T, fixture releaseFixture, current string) (*Updater, *httptest.Server, string) {
	t.Helper()
	if fixture.tag == "" {
		fixture.tag = "v2.0.0"
	}
	if fixture.assetName == "" {
		fixture.assetName = "tool_linux_amd64.tar.gz"
	}
	if fixture.archive == nil {
		fixture.archive = makeTar(t, []archiveMember{{name: "tool", body: []byte("new")}})
	}
	archiveHash := sha256.Sum256(fixture.archive)
	defaultDigest := fmt.Sprintf("sha256:%x", archiveHash)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/owner/repo/releases/latest" || strings.HasPrefix(r.URL.Path, "/repos/owner/repo/releases/tags/") {
			if fixture.metadataCode != 0 {
				http.Error(w, "metadata failed", fixture.metadataCode)
				return
			}
			if fixture.metadataBody != nil {
				_, _ = w.Write(fixture.metadataBody)
				return
			}
			assets := make([]map[string]any, 0, 2)
			asset := map[string]any{"name": fixture.assetName, "browser_download_url": server.URL + "/asset", "size": len(fixture.archive)}
			if !fixture.omitDigest {
				switch {
				case fixture.nullDigest:
					asset["digest"] = nil
				case fixture.digest != nil:
					asset["digest"] = *fixture.digest
				default:
					asset["digest"] = defaultDigest
				}
			}
			if !fixture.omitAsset {
				assets = append(assets, asset)
			}
			if fixture.duplicate != "" {
				duplicate := map[string]any{"name": fixture.duplicate, "browser_download_url": server.URL + "/asset", "size": len(fixture.archive), "digest": defaultDigest}
				assets = append(assets, duplicate)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": fixture.tag, "name": "Release " + fixture.tag, "body": "notes",
				"html_url": server.URL + "/release", "published_at": "2026-01-02T03:04:05Z",
				"draft": fixture.draft, "prerelease": fixture.prerelease, "assets": assets,
			})
			return
		}
		switch r.URL.Path {
		case "/asset":
			if fixture.archiveHook != nil {
				fixture.archiveHook()
			}
			_, _ = w.Write(fixture.archive)
		default:
			http.NotFound(w, r)
		}
	}))
	target := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(target, []byte("old"), 0o700); err != nil {
		t.Fatal(err)
	}
	u := mustUpdater(t, current)
	u.apiBaseURL = server.URL
	u.allowHTTP = true
	u.goos, u.goarch = "linux", "amd64"
	u.executablePath = func() (string, error) { return target, nil }
	return u, server, target
}

func stringPointer(value string) *string {
	return &value
}

func mustUpdater(t *testing.T, current string) *Updater {
	t.Helper()
	u, err := New(Config{Repository: "owner/repo", Command: "tool", CurrentVersion: current})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestExpectedNames(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		goos, arch, asset, member string
	}{
		{"linux", "amd64", "tool_linux_amd64.tar.gz", "tool"},
		{"darwin", "arm64", "tool_darwin_arm64.tar.gz", "tool"},
		{"windows", "amd64", "tool_windows_amd64.zip", "tool.exe"},
	} {
		asset, member, err := expectedNames("tool", test.goos, test.arch)
		if err != nil || asset != test.asset || member != test.member {
			t.Errorf("expectedNames(%s/%s) = %q, %q, %v", test.goos, test.arch, asset, member, err)
		}
	}
	if _, _, err := expectedNames("tool", "linux", "386"); err == nil {
		t.Error("accepted 386")
	}
	if _, _, err := expectedNames("tool", "freebsd", "amd64"); err == nil {
		t.Error("accepted freebsd")
	}
}

func TestRollbackErrorUnwrap(t *testing.T) {
	updateErr := errors.New("update")
	rollbackErr := errors.New("rollback")
	err := &RollbackError{TargetPath: "target", BackupPath: "backup", UpdateErr: updateErr, RollbackErr: rollbackErr}
	if !errors.Is(err, updateErr) || !errors.Is(err, rollbackErr) || !strings.Contains(err.Error(), "target") {
		t.Fatalf("unexpected RollbackError: %v", err)
	}
}

func ExampleUpdater() {
	updater, err := New(Config{Repository: "owner/project", Command: "project", CurrentVersion: "v1.2.3"})
	if err != nil {
		panic(err)
	}
	plan, err := updater.Check(context.Background())
	if err != nil {
		panic(err)
	}
	fmt.Println(plan.AvailableVersion(), plan.UpdateAvailable())
}
