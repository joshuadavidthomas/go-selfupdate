//go:build !windows

package selfupdate

import (
	"os"
	"path/filepath"
)

func replaceExecutable(stage, target string) (replacementResult, error) {
	if err := os.Rename(stage, target); err != nil {
		return replacementResult{}, err
	}
	result := replacementResult{committed: true}
	if err := syncDirectory(filepath.Dir(target)); err != nil {
		return result, err
	}
	return result, nil
}

func cleanupStaleBackups(string) (bool, error) {
	return false, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}
