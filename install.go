package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

func stageExecutable(ctx context.Context, target string, binary []byte, mode os.FileMode) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if len(binary) == 0 {
		return "", errors.New("refusing to stage an empty executable")
	}
	directory := filepath.Dir(target)
	prefix := "." + filepath.Base(target) + ".selfupdate-"
	file, err := os.CreateTemp(directory, prefix)
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
	if err := file.Chmod(mode.Perm()); err != nil {
		return "", err
	}
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
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := syncDirectory(directory); err != nil {
		return "", err
	}
	remove = false
	return path, nil
}
