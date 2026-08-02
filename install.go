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

func createStageFile(target string) (*os.File, error) {
	var random [16]byte
	for attempts := 0; attempts < 10; attempts++ {
		if _, err := rand.Read(random[:]); err != nil {
			return nil, fmt.Errorf("create random stage name: %w", err)
		}
		candidate := filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".selfupdate-stage-"+hex.EncodeToString(random[:]))
		file, err := os.OpenFile(candidate, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			return file, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	return nil, errors.New("could not create a unique stage name")
}

func isLowerHex(value string) bool {
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func cleanupStaleStages(target string) error {
	directory := filepath.Dir(target)
	prefix := "." + filepath.Base(target) + ".selfupdate-stage-"
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

func stageExecutable(ctx context.Context, target string, binary []byte, mode os.FileMode) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if len(binary) == 0 {
		return "", errors.New("refusing to stage an empty executable")
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
	written := 0
	for written < len(binary) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		end := min(written+(1<<20), len(binary))
		count, err := file.Write(binary[written:end])
		if err != nil {
			return "", err
		}
		if count == 0 {
			return "", errors.New("short write while staging executable")
		}
		written += count
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
