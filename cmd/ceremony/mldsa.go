package main

import (
	"crypto/mldsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/letsencrypt/boulder/strictyaml"
)

// keyfileConfig is similar to keyConfig, except that it doesn't need a PKCS#11
// config and does need a path to output the private key file. It only produces
// ML-DSA-44 keys.
type keyfileConfig struct {
	CeremonyType string       `yaml:"ceremony-type"`
	Key          keyGenConfig `yaml:"key"`
	Outputs      struct {
		PublicKeyPath  string `yaml:"public-key-path"`
		PrivateKeyPath string `yaml:"private-key-path"`
	} `yaml:"outputs"`
}

func (kc keyfileConfig) validate() error {
	// Key gen fields
	err := kc.Key.validate()
	if err != nil {
		return err
	}

	// Output fields
	err = checkOutputFile(kc.Outputs.PublicKeyPath, "public-key-path")
	if err != nil {
		return err
	}
	err = checkOutputFile(kc.Outputs.PrivateKeyPath, "private-key-path")
	if err != nil {
		return err
	}

	// One extra check for safety
	if kc.Key.Type != "mldsa" || kc.Key.MLDSAParameterSet != "ML-DSA-44" {
		return fmt.Errorf("staging-mldsa-keyfile-no-hsm ceremony must only be used for ML-DSA-44 keys")
	}

	return nil
}

// keyfileCeremony is like keyCeremony, except that it generates the key in
// memory instead of on an HSM, and it writes the private key to a file.
//
// This is DANGEROUS. Do not use it unless you know exactly what you're doing.
// It is not acceptable for use in production environments. It exists solely
// for use in integration test and staging environments, where software HSMs
// do not yet have support for ML-DSA key generation and signing operations.
func keyfileCeremony(configBytes []byte) error {
	var config keyfileConfig
	err := strictyaml.Unmarshal(configBytes, &config)
	if err != nil {
		return fmt.Errorf("failed to parse config: %s", err)
	}

	err = config.validate()
	if err != nil {
		return fmt.Errorf("failed to validate config: %s", err)
	}

	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		return err
	}

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	privKeyFile, err := os.OpenFile(config.Outputs.PrivateKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer privKeyFile.Close()

	err = pem.Encode(privKeyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
	if err != nil {
		return err
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(key.PublicKey())
	if err != nil {
		return err
	}

	pubKeyFile, err := os.OpenFile(config.Outputs.PublicKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer pubKeyFile.Close()

	err = pem.Encode(pubKeyFile, &pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})
	if err != nil {
		return err
	}

	return nil
}
