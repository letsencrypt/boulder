package goodkey

import (
	"crypto"
	"errors"
	"io/ioutil"

	"github.com/letsencrypt/boulder/core"

	yaml "gopkg.in/yaml.v2"
)

// blockedKeys is a type for maintaining a map of Base64 encoded SHA256 hashes
// of SubjectPublicKeyInfo's that should be considered blocked.
// blockedKeys are created by using loadBlockedKeysList.
type blockedKeys map[string]bool

// blocked checks if the given public key is considered administratively
// blocked based on a Base64 encoded SHA256 hash of the SubjectPublicKeyInfo.
// Important: blocked should not be called except on a blockedKeys instance
// returned from loadBlockedKeysList.
// function should not be used until after `loadBlockedKeysList` has returned.
func (b blockedKeys) blocked(key crypto.PublicKey) (bool, error) {
	hash, err := core.KeyDigest(key)
	if err != nil {
		// the bool result should be ignored when err is != nil but to be on the
		// paranoid side return true anyway so that a key we can't compute the
		// digest for will always be blocked even if a caller foolishly discards the
		// err result.
		return true, err
	}
	return b[hash], nil
}

// loadBlockedKeysList creates a blockedKeys object that can be used to check if
// a key is blocked. It creates a lookup map from a list of Base64 encoded
// SHA256 hashes of SubjectPublicKeyInfo's in the input YAML file
// with the expected format:
//
// ```
// blocked:
//   - cuwGhNNI6nfob5aqY90e7BleU6l7rfxku4X3UTJ3Z7M=
//   <snipped>
//   - Qebc1V3SkX3izkYRGNJilm9Bcuvf0oox4U2Rn+b4JOE=
// ```
//
// If no hashes are found in the input YAML an error is returned.
func loadBlockedKeysList(filename string) (*blockedKeys, error) {
	yamlBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var list struct {
		BlockedHashes []string `yaml:"blocked"`
	}
	if err := yaml.Unmarshal(yamlBytes, &list); err != nil {
		return nil, err
	}

	if len(list.BlockedHashes) == 0 {
		return nil, errors.New("no blocked hashes in YAML")
	}

	blockedKeys := make(blockedKeys, len(list.BlockedHashes))
	for _, hash := range list.BlockedHashes {
		blockedKeys[hash] = true
	}
	return &blockedKeys, nil
}
