package goodkey

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestKnown(t *testing.T) {
	wk := &weakKeys{suffixes: make(map[[10]byte]struct{})}
	err := wk.addSuffix("200352313bc059445190")
	test.AssertNotError(t, err, "weakKeys.addSuffix failed")
	test.Assert(t, wk.Known([]byte("asd")), "weakKeys.Known failed to find suffix that has been added")
	test.Assert(t, !wk.Known([]byte("ASD")), "weakKeys.Known found a suffix that has not been added")
}

func TestLoadKeys(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "weak-keys")
	test.AssertNotError(t, err, "Failed to create temporary directory")
	tempPath := filepath.Join(tempDir, "a.json")
	err = ioutil.WriteFile(tempPath, []byte("[\"200352313bc059445190\"]"), os.ModePerm)
	test.AssertNotError(t, err, "Failed to create temporary file")

	wk, err := loadSuffixes(tempPath)
	test.AssertNotError(t, err, "Failed to load suffixes from directory")
	test.Assert(t, wk.Known([]byte("asd")), "weakKeys.Known failed to find suffix that has been added")
}
