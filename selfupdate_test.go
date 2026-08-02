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
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
		got, err := extractTarGzContext(context.Background(), body, "tool", limit)
		if got != nil {
			t.Fatalf("extractTarGzContext returned data %q, want nil", got)
		}
		if err == nil || !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("extractTarGzContext error = %v, want io.ErrUnexpectedEOF", err)
		}
	})

	t.Run("block-boundary backstop", func(t *testing.T) {
		t.Parallel()
		limit := int64(1535) // 512-byte header + 1024-byte data = 1536 = limit+1
		body := makeTar(t, []archiveMember{{name: "filler", body: make([]byte, 1024)}})
		got, err := extractTarGzContext(context.Background(), body, "tool", limit)
		if got != nil {
			t.Fatalf("extractTarGzContext returned data %q, want nil", got)
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
			got, err := extractArchive(context.Background(), "tool_linux_amd64.tar.gz", body, "tool")
			if test.ok && (err != nil || string(got) != test.want) {
				t.Fatalf("extract = %q, %v", got, err)
			}
			if !test.ok && err == nil {
				t.Fatalf("extract accepted archive: %q", got)
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
			got, err := extractArchive(context.Background(), "tool_windows_amd64.zip", body, "tool.exe")
			if test.ok && (err != nil || string(got) != test.want) {
				t.Fatalf("extract = %q, %v", got, err)
			}
			if !test.ok && err == nil {
				t.Fatalf("extract accepted archive: %q", got)
			}
		})
	}

	t.Run("unsupported archive name", func(t *testing.T) {
		body := makeZIP(t, []zipMember{{name: "tool.exe", body: []byte("command")}})
		_, err := extractArchive(context.Background(), "tool_windows_amd64.rar", body, "tool.exe")
		if err == nil || !strings.Contains(err.Error(), "unsupported archive name") {
			t.Fatalf("extractArchive error = %v, want \"unsupported archive name\"", err)
		}
	})
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
		switch r.URL.Path {
		case "/repos/owner/repo/releases/latest":
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
				"html_url": server.URL + "/release", "published_at": "2026-01-02T03:04:05Z", "assets": assets,
			})
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
