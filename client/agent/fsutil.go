package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// writeFileAtomic replaces path with data, readable only by the owner. It
// writes a temporary file in the same directory, flushes it to disk and
// renames it over path, so a crash leaves either the old or the new file.
func writeFileAtomic(path string, data []byte) error {
	return writeFileModeAtomic(path, data, 0)
}

// writeFileModeAtomic replaces path with data, applying mode before renaming
// when mode is non-zero.
func writeFileModeAtomic(path string, data []byte, mode os.FileMode) (err error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if mode != 0 {
		if err := f.Chmod(mode); err != nil {
			_ = f.Close()
			return fmt.Errorf("chmod %s: %w", filepath.Base(path), err)
		}
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("flush %s: %w", filepath.Base(path), err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace %s: %w", filepath.Base(path), err)
	}
	syncDir(dir)
	return nil
}

// syncDir flushes a directory entry change to disk where the platform
// supports it. It is best effort.
func syncDir(dir string) {
	if runtime.GOOS == "windows" {
		return
	}
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// isTempFile reports whether name is a leftover of writeFileAtomic.
func isTempFile(name string) bool {
	return len(name) > 4 && name[0] == '.' && name[len(name)-4:] == ".tmp"
}
