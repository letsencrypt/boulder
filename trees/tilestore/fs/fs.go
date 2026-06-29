// Package fs stores tilestore objects as files under a root directory.
package fs

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/letsencrypt/boulder/trees/tilestore"
)

// Backend is a tilestore.Backend that stores each object as a file under a root
// directory. It does not sanitize keys, so they must be trusted input: a key
// with ".." or an absolute path would escape root. A Store builds the only keys
// it sees.
type Backend struct {
	root string
}

// New returns a filesystem Backend rooted at dir.
func New(dir string) *Backend {
	return &Backend{root: dir}
}

func (b *Backend) path(key string) string {
	return filepath.Join(b.root, filepath.FromSlash(key))
}

// Get reads the file for key, returning tilestore.ErrNotExist if it is absent.
func (b *Backend) Get(ctx context.Context, key string) ([]byte, error) {
	data, err := os.ReadFile(b.path(key))
	if errors.Is(err, os.ErrNotExist) {
		return nil, tilestore.ErrNotExist
	}
	return data, err
}

// Put writes data to the file for key, creating parent directories. The write is
// atomic, so a reader never sees a partially written object.
func (b *Backend) Put(ctx context.Context, key string, data []byte) error {
	dest := b.path(key)
	dir := filepath.Dir(dest)
	err := os.MkdirAll(dir, 0o755)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	// Best-effort cleanup if we return before the rename.
	defer os.Remove(tmp.Name())

	_, err = tmp.Write(data)
	if err != nil {
		tmp.Close()
		return err
	}
	err = tmp.Close()
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dest)
}

var _ tilestore.Backend = (*Backend)(nil)
