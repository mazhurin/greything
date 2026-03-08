package storage

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// FilesystemAdapter implements StorageAdapter using the local filesystem.
type FilesystemAdapter struct {
	basePath string
	mu       sync.RWMutex
}

// NewFilesystemAdapter creates a new filesystem-based storage adapter.
func NewFilesystemAdapter(basePath string) (*FilesystemAdapter, error) {
	// Ensure base directory exists
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, err
	}
	return &FilesystemAdapter{basePath: basePath}, nil
}

// keyToPath converts a storage key to a filesystem path.
// Key format: {userId}/{hash} or {userId}/{hash}.meta
func (f *FilesystemAdapter) keyToPath(key string) string {
	return filepath.Join(f.basePath, key)
}

// Get retrieves blob bytes by key.
func (f *FilesystemAdapter) Get(key string) ([]byte, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	path := f.keyToPath(key)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	return data, err
}

// Put stores blob bytes at key.
func (f *FilesystemAdapter) Put(key string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	path := f.keyToPath(key)

	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Write atomically: write to temp file, then rename
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}

	return os.Rename(tmpPath, path)
}

// Delete removes blob at key.
func (f *FilesystemAdapter) Delete(key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	path := f.keyToPath(key)
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return ErrNotFound
	}
	return err
}

// Exists checks if blob exists at key.
func (f *FilesystemAdapter) Exists(key string) (bool, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	path := f.keyToPath(key)
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// List returns all keys with given prefix.
func (f *FilesystemAdapter) List(prefix string) ([]string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	var keys []string
	prefixPath := f.keyToPath(prefix)

	err := filepath.WalkDir(prefixPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil // prefix doesn't exist, return empty list
			}
			return err
		}
		if !d.IsDir() {
			// Convert path back to key
			relPath, err := filepath.Rel(f.basePath, path)
			if err != nil {
				return err
			}
			keys = append(keys, relPath)
		}
		return nil
	})

	return keys, err
}

// Size returns total bytes used by keys with given prefix.
func (f *FilesystemAdapter) Size(prefix string) (int64, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	var total int64
	prefixPath := f.keyToPath(prefix)

	err := filepath.WalkDir(prefixPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil // prefix doesn't exist, size is 0
			}
			return err
		}
		if !d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			total += info.Size()
		}
		return nil
	})

	return total, err
}

// ListUsers returns all user IDs (top-level directories).
func (f *FilesystemAdapter) ListUsers() ([]string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	entries, err := os.ReadDir(f.basePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var users []string
	for _, entry := range entries {
		if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
			users = append(users, entry.Name())
		}
	}
	return users, nil
}
