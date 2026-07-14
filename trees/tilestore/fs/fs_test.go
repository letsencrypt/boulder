package fs_test

import (
	"errors"
	"testing"

	"github.com/letsencrypt/boulder/trees/tilestore"
	"github.com/letsencrypt/boulder/trees/tilestore/fs"
)

func TestRoundTripAndOverwrite(t *testing.T) {
	b := fs.New(t.TempDir())

	_, err := b.Get(t.Context(), "example.com%2Flog/tile/0/000")
	if !errors.Is(err, tilestore.ErrNotExist) {
		t.Fatalf("Get of a missing key = %v, want ErrNotExist", err)
	}

	// A nested key creates its parent directories.
	err = b.Put(t.Context(), "example.com%2Flog/tile/0/000", []byte("first"))
	if err != nil {
		t.Fatalf("Put: %s", err)
	}
	got, err := b.Get(t.Context(), "example.com%2Flog/tile/0/000")
	if err != nil || string(got) != "first" {
		t.Fatalf("Get = (%q, %v), want (\"first\", nil)", got, err)
	}

	// Put overwrites.
	err = b.Put(t.Context(), "example.com%2Flog/tile/0/000", []byte("second"))
	if err != nil {
		t.Fatalf("Put overwrite: %s", err)
	}
	got, err = b.Get(t.Context(), "example.com%2Flog/tile/0/000")
	if err != nil || string(got) != "second" {
		t.Fatalf("Get after overwrite = (%q, %v), want (\"second\", nil)", got, err)
	}
}
