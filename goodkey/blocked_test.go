package goodkey

import (
	"crypto"
	"io/ioutil"
	"os"
	"testing"

	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/web"
	yaml "gopkg.in/yaml.v2"
)

func TestBlockedKeys(t *testing.T) {
	// Start with an empty list
	var inList struct {
		BlockedHashes []string `yaml:"blocked"`
	}

	yamlList, err := yaml.Marshal(&inList)
	test.AssertNotError(t, err, "error marshaling test blockedKeys list")

	yamlListFile, err := ioutil.TempFile("", "test-blocked-keys-list.*.yaml")
	test.AssertNotError(t, err, "error creating test blockedKeys yaml file")
	defer os.Remove(yamlListFile.Name())

	err = ioutil.WriteFile(yamlListFile.Name(), yamlList, 0640)
	test.AssertNotError(t, err, "error writing test blockedKeys yaml file")

	// Trying to load it should error
	_, err = loadBlockedKeysList(yamlListFile.Name())
	test.AssertError(t, err, "expected error loading empty blockedKeys yaml file")

	// Load some test certs/keys - see ../test/block-a-key/test/README.txt
	// for more information.
	testCertA, err := core.LoadCert("../test/block-a-key/test/test.rsa.cert.pem")
	test.AssertNotError(t, err, "error loading test.rsa.cert.pem")
	testCertB, err := core.LoadCert("../test/block-a-key/test/test.ecdsa.cert.pem")
	test.AssertNotError(t, err, "error loading test.ecdsa.cert.pem")
	testJWKA, err := web.LoadJWK("../test/block-a-key/test/test.rsa.jwk.json")
	test.AssertNotError(t, err, "error loading test.rsa.jwk.pem")
	testJWKB, err := web.LoadJWK("../test/block-a-key/test/test.ecdsa.jwk.json")
	test.AssertNotError(t, err, "error loading test.ecdsa.jwk.pem")

	// All of the above should be blocked
	blockedKeys := []crypto.PublicKey{
		testCertA.PublicKey,
		testCertB.PublicKey,
		testJWKA.Key,
		testJWKB.Key,
	}

	// Now use a populated list - these values match the base64 digest of the
	// public keys in the test certs/JWKs
	inList.BlockedHashes = []string{
		"cuwGhNNI6nfob5aqY90e7BleU6l7rfxku4X3UTJ3Z7M=",
		"Qebc1V3SkX3izkYRGNJilm9Bcuvf0oox4U2Rn+b4JOE=",
	}

	yamlList, err = yaml.Marshal(&inList)
	test.AssertNotError(t, err, "error marshaling test blockedKeys list")

	yamlListFile, err = ioutil.TempFile("", "test-blocked-keys-list.*.yaml")
	test.AssertNotError(t, err, "error creating test blockedKeys yaml file")
	defer os.Remove(yamlListFile.Name())

	err = ioutil.WriteFile(yamlListFile.Name(), yamlList, 0640)
	test.AssertNotError(t, err, "error writing test blockedKeys yaml file")

	// Trying to load it should not error
	outList, err := loadBlockedKeysList(yamlListFile.Name())
	test.AssertNotError(t, err, "unexpected error loading empty blockedKeys yaml file")

	// Create a test policy that doesn't reference the blocked list
	testingPolicy := &KeyPolicy{
		AllowRSA:           true,
		AllowECDSANISTP256: true,
		AllowECDSANISTP384: true,
	}

	// All of the test keys should not be considered blocked
	for _, k := range blockedKeys {
		err := testingPolicy.GoodKey(k)
		test.AssertNotError(t, err, "test key was blocked by key policy without block list")
	}

	// Now update the key policy with the blocked list
	testingPolicy.blockedList = outList

	// Now all of the test keys should be considered blocked, and with the correct
	// type of error.
	for _, k := range blockedKeys {
		err := testingPolicy.GoodKey(k)
		test.AssertError(t, err, "test key was not blocked by key policy with block list")
		test.Assert(t, berrors.Is(err, berrors.BadPublicKey), "err was not BadPublicKey error")
	}
}
