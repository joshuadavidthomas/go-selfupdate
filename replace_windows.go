//go:build windows

package selfupdate

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

const backupRandomLength = 32

func replaceExecutable(stage, target string) (replacementResult, error) {
	backup, err := randomBackupPath(target)
	if err != nil {
		return replacementResult{}, err
	}
	if err := os.Rename(target, backup); err != nil {
		return replacementResult{}, fmt.Errorf("move current executable aside: %w", err)
	}
	if err := hideFile(backup); err != nil {
		return replacementResult{}, rollbackWindows(target, backup, fmt.Errorf("hide backup: %w", err))
	}
	if err := os.Rename(stage, target); err != nil {
		return replacementResult{}, rollbackWindows(target, backup, fmt.Errorf("install staged executable: %w", err))
	}
	result := replacementResult{committed: true}
	if err := removeBackup(backup); err != nil {
		if isPendingCleanupError(err) {
			result.cleanupPending = true
			return result, nil
		}
		return result, fmt.Errorf("remove installed executable backup %s: %w", backup, err)
	}
	return result, nil
}

func rollbackWindows(target, backup string, updateErr error) error {
	return rollbackWindowsWith(target, backup, updateErr, os.Rename, clearHidden)
}

func rollbackWindowsWith(target, backup string, updateErr error, rename func(string, string) error, clear func(string) error) error {
	if err := rename(backup, target); err != nil {
		return &RollbackError{
			TargetPath:  target,
			BackupPath:  backup,
			UpdateErr:   updateErr,
			RollbackErr: fmt.Errorf("restore backup: %w", err),
		}
	}
	if err := clear(target); err != nil {
		return &RollbackError{
			TargetPath:  target,
			BackupPath:  backup,
			UpdateErr:   updateErr,
			RollbackErr: fmt.Errorf("clear restored target hidden attribute: %w", err),
		}
	}
	return updateErr
}

func cleanupStaleBackups(target string) (bool, error) {
	directory := filepath.Dir(target)
	prefix := "." + filepath.Base(target) + ".selfupdate-backup-"
	entries, err := os.ReadDir(directory)
	if err != nil {
		return false, err
	}
	pending := false
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || len(name) != len(prefix)+backupRandomLength || !isLowerHex(name[len(prefix):]) {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
			continue
		}
		path := filepath.Join(directory, name)
		if err := removeBackup(path); err != nil {
			if isPendingCleanupError(err) {
				pending = true
				continue
			}
			return pending, err
		}
	}
	return pending, nil
}

func randomBackupPath(target string) (string, error) {
	var random [16]byte
	for attempts := 0; attempts < 10; attempts++ {
		if _, err := rand.Read(random[:]); err != nil {
			return "", fmt.Errorf("create random backup name: %w", err)
		}
		candidate := filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".selfupdate-backup-"+hex.EncodeToString(random[:]))
		_, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			return candidate, nil
		}
		if err != nil {
			return "", fmt.Errorf("check backup name: %w", err)
		}
	}
	return "", errors.New("could not create a unique backup name")
}

func isLowerHex(value string) bool {
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func isPendingCleanupError(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED)
}

func hideFile(path string) error {
	return updateHidden(path, true)
}

func clearHidden(path string) error {
	return updateHidden(path, false)
}

func removeBackup(path string) error {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(pointer)
	if err != nil {
		return err
	}
	if attributes&windows.FILE_ATTRIBUTE_READONLY != 0 {
		if err := windows.SetFileAttributes(pointer, attributes&^windows.FILE_ATTRIBUTE_READONLY); err != nil {
			return err
		}
	}
	return os.Remove(path)
}

func updateHidden(path string, hidden bool) error {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(pointer)
	if err != nil {
		return err
	}
	if hidden {
		attributes |= windows.FILE_ATTRIBUTE_HIDDEN
	} else {
		attributes &^= windows.FILE_ATTRIBUTE_HIDDEN
	}
	return windows.SetFileAttributes(pointer, attributes)
}

func syncDirectory(string) error {
	return nil
}
