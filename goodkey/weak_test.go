package goodkey

import (
	"crypto/rsa"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestKnown(t *testing.T) {
	testKey := rsa.PublicKey{N: big.NewInt(1337)}
	otherKey := rsa.PublicKey{N: big.NewInt(2020)}

	wk := &weakKeys{suffixes: make(map[truncatedHash]struct{})}
	err := wk.addSuffix("72526dffb55a71b6e407")
	// ffded93275143b51c90c72526dffb55a71b6e407
	test.AssertNotError(t, err, "weakKeys.addSuffix failed")
	test.Assert(t, wk.Known(&testKey), "weakKeys.Known failed to find suffix that has been added")
	test.Assert(t, !wk.Known(&otherKey), "weakKeys.Known found a suffix that has not been added")
}

func TestLoadKeys(t *testing.T) {
	testKey := rsa.PublicKey{
		N: big.NewInt(1337),
	}
	tempDir, err := ioutil.TempDir("", "weak-keys")
	test.AssertNotError(t, err, "Failed to create temporary directory")
	tempPath := filepath.Join(tempDir, "a.json")
	err = ioutil.WriteFile(tempPath, []byte("[\"72526dffb55a71b6e407\"]"), os.ModePerm)
	test.AssertNotError(t, err, "Failed to create temporary file")

	wk, err := loadSuffixes(tempPath)
	test.AssertNotError(t, err, "Failed to load suffixes from directory")
	test.Assert(t, wk.Known(&testKey), "weakKeys.Known failed to find suffix that has been added")
}
