package selfupdate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RollbackError reports both a failed Windows installation step and the failed
// attempt to put the original executable back.
type RollbackError struct {
	TargetPath  string
	BackupPath  string
	UpdateErr   error
	RollbackErr error
}

// Error implements error.
func (e *RollbackError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("selfupdate: update %s from backup %s failed: %v; rollback failed: %v", e.TargetPath, e.BackupPath, e.UpdateErr, e.RollbackErr)
}

// Unwrap exposes both the update and rollback failures.
func (e *RollbackError) Unwrap() []error {
	if e == nil {
		return nil
	}
	return []error{e.UpdateErr, e.RollbackErr}
}

type replacementResult struct {
	committed      bool
	cleanupPending bool
}

const stageRandomLength = 32

// createRandomFile creates a new, exclusively-owned file in target's
// directory named "."+base(target)+"."+infix+"-"+<32 lowercase hex>, mode
// 0600. It is the shared pattern behind stage and archive temp files: a
// crypto-random suffix collision-checked with O_EXCL, retried up to 10 times.
func createRandomFile(target, infix string, flags int) (*os.File, error) {
	var random [16]byte
	for attempts := 0; attempts < 10; attempts++ {
		if _, err := rand.Read(random[:]); err != nil {
			return nil, fmt.Errorf("create random %s name: %w", infix, err)
		}
		candidate := filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".selfupdate-"+infix+"-"+hex.EncodeToString(random[:]))
		file, err := os.OpenFile(candidate, os.O_CREATE|os.O_EXCL|flags, 0o600)
		if err == nil {
			return file, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("could not create a unique %s name", infix)
}

func createStageFile(target string) (*os.File, error) {
	return createRandomFile(target, "stage", os.O_WRONLY)
}

// createArchiveFile creates the quarantined temp file that downloadToFile
// streams the release archive into: same directory, mode, and crypto-random
// naming discipline as the stage file, so both are swept by cleanupStaleFiles
// if a process is killed mid-update. Unlike the write-only stage file, it
// needs O_RDWR: downloadToFile writes it, then stageExecutable reads it back
// to extract the staged member after the digest check passes.
func createArchiveFile(target string) (*os.File, error) {
	return createRandomFile(target, "archive", os.O_RDWR)
}

func isLowerHex(value string) bool {
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

// cleanupStaleFiles removes files left behind by a process killed between
// staging/downloading and replacement: names matching
// "."+base(target)+".selfupdate-"+infix+"-"+<32 lower hex>, regular files
// only (symlinks and directories are left alone). It is called for both the
// "stage" and "archive" infixes from the same Apply site, under the
// cross-process lock that already guards staging and downloading, so a sweep
// cannot race a live operation in a lock-honoring process.
func cleanupStaleFiles(target, infix string) error {
	directory := filepath.Dir(target)
	prefix := "." + filepath.Base(target) + ".selfupdate-" + infix + "-"
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || len(name) != len(prefix)+stageRandomLength || !isLowerHex(name[len(prefix):]) {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
			continue
		}
		if err := os.Remove(filepath.Join(directory, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func cleanupStaleStages(target string) error {
	return cleanupStaleFiles(target, "stage")
}

func cleanupStaleArchives(target string) error {
	return cleanupStaleFiles(target, "archive")
}

// stageExecutable extracts memberName from archive directly into a new stage
// file beside target, so the extracted binary is never buffered in memory.
// archiveSize is required by the ZIP central-directory reader and ignored for
// tar.gz. The stage file is chmodded only after every byte has been written
// and synced (plan 005's ordering), so it is never executable-but-partial.
func stageExecutable(ctx context.Context, target string, mode os.FileMode, assetName string, archive *os.File, archiveSize int64, memberName string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	directory := filepath.Dir(target)
	file, err := createStageFile(target)
	if err != nil {
		return "", err
	}
	path := file.Name()
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	written, err := extractArchive(ctx, assetName, archive, archiveSize, memberName, file)
	if err != nil {
		return "", err
	}
	if written <= 0 {
		return "", errors.New("refusing to stage an empty executable")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Chmod(mode.Perm()); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := syncDirectory(directory); err != nil {
		return "", err
	}
	remove = false
	return path, nil
}
