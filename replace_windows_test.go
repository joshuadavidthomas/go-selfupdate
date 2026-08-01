//go:build windows

package selfupdate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsReplacementOfNonRunningFile(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "tool.exe")
	stage := filepath.Join(directory, "stage.exe")
	if err := os.WriteFile(target, []byte("old"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stage, []byte("new"), 0o700); err != nil {
		t.Fatal(err)
	}
	result, err := replaceExecutable(stage, target)
	if err != nil {
		t.Fatal(err)
	}
	if !result.committed || result.cleanupPending {
		t.Fatalf("result = %#v", result)
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "new" {
		t.Fatalf("target = %q", body)
	}
}

func TestWindowsReplacementRemovesReadOnlyBackup(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "tool.exe")
	stage := filepath.Join(directory, "stage.exe")
	if err := os.WriteFile(target, []byte("old"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setReadOnly(target); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stage, []byte("new"), 0o700); err != nil {
		t.Fatal(err)
	}
	result, err := replaceExecutable(stage, target)
	if err != nil {
		t.Fatal(err)
	}
	if !result.committed || result.cleanupPending {
		t.Fatalf("result = %#v", result)
	}
	matches, err := filepath.Glob(filepath.Join(directory, ".tool.exe.selfupdate-backup-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("backups = %q", matches)
	}
}

func TestWindowsRollbackRestoresVisibleTarget(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "tool.exe")
	backup := filepath.Join(directory, ".tool.exe.selfupdate-backup-0123456789abcdef0123456789abcdef")
	if err := os.WriteFile(backup, []byte("old"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := hideFile(backup); err != nil {
		t.Fatal(err)
	}
	updateErr := errors.New("install failed")
	if err := rollbackWindows(target, backup, updateErr); !errors.Is(err, updateErr) {
		t.Fatalf("rollbackWindows error = %v", err)
	}
	pointer, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal(err)
	}
	attributes, err := windows.GetFileAttributes(pointer)
	if err != nil {
		t.Fatal(err)
	}
	if attributes&windows.FILE_ATTRIBUTE_HIDDEN != 0 {
		t.Fatal("restored target is hidden")
	}
}

func TestWindowsRollbackDoesNotAlterTargetWhenRestoreFails(t *testing.T) {
	updateErr := errors.New("install failed")
	renameErr := errors.New("rename failed")
	clearCalled := false
	err := rollbackWindowsWith(
		"target.exe",
		"backup.exe",
		updateErr,
		func(string, string) error { return renameErr },
		func(string) error {
			clearCalled = true
			return nil
		},
	)
	if clearCalled {
		t.Fatal("clear called for a target that was not restored")
	}
	if !errors.Is(err, updateErr) || !errors.Is(err, renameErr) {
		t.Fatalf("rollbackWindowsWith error = %v", err)
	}
	var rollbackErr *RollbackError
	if !errors.As(err, &rollbackErr) {
		t.Fatalf("error type = %T", err)
	}
}

func TestWindowsRollbackReportsVisibilityFailureAfterRestore(t *testing.T) {
	updateErr := errors.New("install failed")
	attributeErr := errors.New("attribute failed")
	var calls []string
	err := rollbackWindowsWith(
		"target.exe",
		"backup.exe",
		updateErr,
		func(oldPath, newPath string) error {
			calls = append(calls, "rename "+oldPath+" "+newPath)
			return nil
		},
		func(path string) error {
			calls = append(calls, "clear "+path)
			return attributeErr
		},
	)
	if len(calls) != 2 || calls[0] != "rename backup.exe target.exe" || calls[1] != "clear target.exe" {
		t.Fatalf("calls = %q", calls)
	}
	if !errors.Is(err, updateErr) || !errors.Is(err, attributeErr) {
		t.Fatalf("rollbackWindowsWith error = %v", err)
	}
	var rollbackErr *RollbackError
	if !errors.As(err, &rollbackErr) {
		t.Fatalf("error type = %T", err)
	}
}

func TestWindowsCleansReadOnlyStaleBackup(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "tool.exe")
	backup := filepath.Join(directory, ".tool.exe.selfupdate-backup-0123456789abcdef0123456789abcdef")
	if err := os.WriteFile(backup, []byte("old"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setReadOnly(backup); err != nil {
		t.Fatal(err)
	}
	pending, err := cleanupStaleBackups(target)
	if err != nil {
		t.Fatal(err)
	}
	if pending {
		t.Fatal("cleanup unexpectedly pending")
	}
	if _, err := os.Stat(backup); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup still exists: %v", err)
	}
}

func TestWindowsCleansOnlyOwnedBackupNames(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "tool.exe")
	owned := filepath.Join(directory, ".tool.exe.selfupdate-backup-0123456789abcdef0123456789abcdef")
	unowned := filepath.Join(directory, ".tool.exe.selfupdate-backup-not-ours")
	for _, path := range []string{owned, unowned} {
		if err := os.WriteFile(path, []byte("backup"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := cleanupStaleBackups(target)
	if err != nil {
		t.Fatal(err)
	}
	if pending {
		t.Fatal("cleanup unexpectedly pending")
	}
	if _, err := os.Stat(owned); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned backup still exists: %v", err)
	}
	if _, err := os.Stat(unowned); err != nil {
		t.Fatalf("unowned file was removed: %v", err)
	}
}

func setReadOnly(path string) error {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(pointer)
	if err != nil {
		return err
	}
	return windows.SetFileAttributes(pointer, attributes|windows.FILE_ATTRIBUTE_READONLY)
}
