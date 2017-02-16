package goodkey

import (
	"crypto/sha1"
	"encoding/hex"
	"io/ioutil"
	"path/filepath"
	"strings"
)

type weakKeys struct {
	suffixes map[[10]byte]struct{}
}

func loadSuffixes(dir string) (*weakKeys, error) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	wk := &weakKeys{suffixes: make(map[[10]byte]struct{})}
	for _, fh := range files {
		if fh.IsDir() {
			continue
		}
		f, err := ioutil.ReadFile(filepath.Join(dir, fh.Name()))
		if err != nil {
			return nil, err
		}
		for _, l := range strings.Split(string(f), "\n") {
			if strings.HasPrefix(l, "#") {
				continue
			}
			err := wk.addSuffix(l)
			if err != nil {
				return nil, err
			}
		}
	}
	return wk, nil
}

func (wk *weakKeys) addSuffix(str string) error {
	var suffix [10]byte
	decoded, err := hex.DecodeString(str)
	if err != nil {
		return err
	}
	copy(suffix[:], decoded)
	wk.suffixes[suffix] = struct{}{}
	return nil
}

func (wk *weakKeys) Known(der []byte) bool {
	hash := sha1.Sum(der)
	var suffix [10]byte
	copy(suffix[:], hash[10:])
	_, present := wk.suffixes[suffix]
	return present
}
