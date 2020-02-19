package main

import "testing"

func TestValidateConfig(t *testing.T) {
	cases := []struct {
		name          string
		config        ceremonyConfig
		expectedError string
	}{
		{
			name:          "no pkcs11-module",
			config:        ceremonyConfig{},
			expectedError: "pkcs11-module is required",
		},
		{
			name: "no key-label",
			config: ceremonyConfig{
				PKCS11Module: "asd",
			},
			expectedError: "key-label is required",
		},
		{
			name: "invalid ceremony-type",
			config: ceremonyConfig{
				PKCS11Module: "asd",
				KeyLabel:     "label",
				CeremonyType: "doop",
			},
			expectedError: "ceremony-type can only be 'root', 'intermediate', or 'key'",
		},
		// root tests
		{
			name: "root: key-id present",
			config: ceremonyConfig{
				PKCS11Module: "asd",
				CeremonyType: "root",
				KeyLabel:     "label",
				KeyID:        "bad-id",
			},
			expectedError: "key-id is not used for root ceremonies",
		},
		{
			name: "root: no key-type",
			config: ceremonyConfig{
				PKCS11Module: "asd",
				CeremonyType: "root",
				KeyLabel:     "label",
			},
			expectedError: "key-type is required",
		},
		{
			name: "root: bad key-type",
			config: ceremonyConfig{
				PKCS11Module: "asd",
				CeremonyType: "root",
				KeyLabel:     "label",
				KeyType:      "bad",
			},
			expectedError: "key-type can only be 'rsa' or 'ecdsa'",
		},
		{
			name: "root: rsa key-type with invalid rsa-mod-length",
			config: ceremonyConfig{
				PKCS11Module: "asd",
				CeremonyType: "root",
				KeyLabel:     "label",
				KeyType:      "rsa",
				RSAModLength: 1337,
			},
			expectedError: "rsa-mod-length can only be 2048 or 4096",
		},
		{
			name: "root: rsa key-type with ecdsa-curve",
			config: ceremonyConfig{
				PKCS11Module: "asd",
				CeremonyType: "root",
				KeyLabel:     "label",
				KeyType:      "rsa",
				RSAModLength: 2048,
				ECDSACurve:   "mhm",
			},
			expectedError: "if key-type = \"rsa\" then ecdsa-curve is not used",
		},
		{
			name: "root: ecdsa key-type with no ecdsa-curve",
			config: ceremonyConfig{
				PKCS11Module: "asd",
				CeremonyType: "root",
				KeyLabel:     "label",
				KeyType:      "ecdsa",
			},
			expectedError: "if key-type = \"ecdsa\" then ecdsa-curve is required",
		},
		{
			name: "root: no public-key-path",
			config: ceremonyConfig{
				PKCS11Module: "asd",
				CeremonyType: "root",
				KeyLabel:     "label",
				KeyType:      "rsa",
				RSAModLength: 2048,
			},
			expectedError: "public-key-path is required",
		},
		{
			name: "root: no certificate-path",
			config: ceremonyConfig{
				PKCS11Module:  "asd",
				CeremonyType:  "root",
				KeyLabel:      "label",
				KeyType:       "rsa",
				RSAModLength:  2048,
				PublicKeyPath: "path",
			},
			expectedError: "certificate-path is required",
		},
		{
			name: "root: issuer-path present",
			config: ceremonyConfig{
				PKCS11Module:    "asd",
				CeremonyType:    "root",
				KeyLabel:        "label",
				KeyType:         "rsa",
				RSAModLength:    2048,
				PublicKeyPath:   "path",
				CertificatePath: "path",
				IssuerPath:      "bad path",
			},
			expectedError: "issuer-path is not used for root ceremonies",
		},
		{
			name: "root: no certificate-profile",
			config: ceremonyConfig{
				PKCS11Module:    "asd",
				CeremonyType:    "root",
				KeyLabel:        "label",
				KeyType:         "rsa",
				RSAModLength:    2048,
				PublicKeyPath:   "path",
				CertificatePath: "path",
			},
			expectedError: "certificate-profile is required",
		},
		{
			name: "root: bad certificate-profile",
			config: ceremonyConfig{
				PKCS11Module:       "asd",
				CeremonyType:       "root",
				KeyLabel:           "label",
				KeyType:            "rsa",
				RSAModLength:       2048,
				PublicKeyPath:      "path",
				CertificatePath:    "path",
				CertificateProfile: &certProfile{},
			},
			expectedError: "invalid certificate-profile: not-before is required",
		},
		// intermediate tests
		{
			name: "intermediate: no key-id",
			config: ceremonyConfig{
				PKCS11Module: "asd",
				CeremonyType: "intermediate",
				KeyLabel:     "label",
			},
			expectedError: "key-id is required",
		},
		{
			name: "intermediate: key-type present",
			config: ceremonyConfig{
				PKCS11Module: "asd",
				CeremonyType: "intermediate",
				KeyLabel:     "label",
				KeyID:        "ffff",
				KeyType:      "rsa",
			},
			expectedError: "key-type is not used for intermediate ceremonies",
		},
		{
			name: "intermediate: ecdsa-curve present",
			config: ceremonyConfig{
				PKCS11Module: "asd",
				CeremonyType: "intermediate",
				KeyLabel:     "label",
				KeyID:        "ffff",
				ECDSACurve:   "p-256",
			},
			expectedError: "ecdsa-curve is not used for intermediate ceremonies",
		},
		{
			name: "intermediate: no public-key-path",
			config: ceremonyConfig{
				PKCS11Module: "asd",
				CeremonyType: "intermediate",
				KeyLabel:     "label",
				KeyID:        "ffff",
			},
			expectedError: "public-key-path is required",
		},
		{
			name: "intermediate: no certificate-path",
			config: ceremonyConfig{
				PKCS11Module:  "asd",
				CeremonyType:  "intermediate",
				KeyLabel:      "label",
				KeyID:         "ffff",
				PublicKeyPath: "path",
			},
			expectedError: "certificate-path is required",
		},
		{
			name: "intermediate: no issuer-path",
			config: ceremonyConfig{
				PKCS11Module:    "asd",
				CeremonyType:    "intermediate",
				KeyLabel:        "label",
				KeyID:           "ffff",
				PublicKeyPath:   "path",
				CertificatePath: "path",
			},
			expectedError: "issuer-path is required",
		},
		{
			name: "intermediate: no certificate-profile",
			config: ceremonyConfig{
				PKCS11Module:    "asd",
				CeremonyType:    "intermediate",
				KeyLabel:        "label",
				KeyID:           "ffff",
				PublicKeyPath:   "path",
				CertificatePath: "path",
				IssuerPath:      "path",
			},
			expectedError: "certificate-profile is required",
		},
		{
			name: "intermediate: bad certificate-profile",
			config: ceremonyConfig{
				PKCS11Module:       "asd",
				CeremonyType:       "intermediate",
				KeyLabel:           "label",
				KeyID:              "ffff",
				PublicKeyPath:      "path",
				CertificatePath:    "path",
				IssuerPath:         "path",
				CertificateProfile: &certProfile{},
			},
			expectedError: "invalid certificate-profile: not-before is required",
		},
		// key tests
		{
			name: "key: key-id present",
			config: ceremonyConfig{
				PKCS11Module: "asd",
				CeremonyType: "key",
				KeyLabel:     "label",
				KeyID:        "bad-id",
			},
			expectedError: "key-id is not used for key ceremonies",
		},
		{
			name: "key: no key-type",
			config: ceremonyConfig{
				PKCS11Module: "asd",
				CeremonyType: "key",
				KeyLabel:     "label",
			},
			expectedError: "key-type is required",
		},
		{
			name: "key: bad key-type",
			config: ceremonyConfig{
				PKCS11Module: "asd",
				CeremonyType: "key",
				KeyLabel:     "label",
				KeyType:      "bad",
			},
			expectedError: "key-type can only be 'rsa' or 'ecdsa'",
		},
		{
			name: "key: rsa key-type with invalid rsa-mod-length",
			config: ceremonyConfig{
				PKCS11Module: "asd",
				CeremonyType: "root",
				KeyLabel:     "label",
				KeyType:      "rsa",
				RSAModLength: 1337,
			},
			expectedError: "rsa-mod-length can only be 2048 or 4096",
		},
		{
			name: "key: rsa key-type with ecdsa-curve",
			config: ceremonyConfig{
				PKCS11Module: "asd",
				CeremonyType: "key",
				KeyLabel:     "label",
				KeyType:      "rsa",
				RSAModLength: 2048,
				ECDSACurve:   "mhm",
			},
			expectedError: "if key-type = \"rsa\" then ecdsa-curve is not used",
		},
		{
			name: "key: ecdsa key-type with no ecdsa-curve",
			config: ceremonyConfig{
				PKCS11Module: "asd",
				CeremonyType: "key",
				KeyLabel:     "label",
				KeyType:      "ecdsa",
			},
			expectedError: "if key-type = \"ecdsa\" then ecdsa-curve is required",
		},
		{
			name: "key: no public-key-path",
			config: ceremonyConfig{
				PKCS11Module: "asd",
				CeremonyType: "key",
				KeyLabel:     "label",
				KeyType:      "rsa",
				RSAModLength: 2048,
			},
			expectedError: "public-key-path is required",
		},
		{
			name: "key: issuer-path present",
			config: ceremonyConfig{
				PKCS11Module:  "asd",
				CeremonyType:  "key",
				KeyLabel:      "label",
				KeyType:       "rsa",
				RSAModLength:  2048,
				PublicKeyPath: "path",
				IssuerPath:    "path",
			},
			expectedError: "issuer-path is not used for key ceremonies",
		},
		{
			name: "key: certificate-path present",
			config: ceremonyConfig{
				PKCS11Module:    "asd",
				CeremonyType:    "key",
				KeyLabel:        "label",
				KeyType:         "rsa",
				RSAModLength:    2048,
				PublicKeyPath:   "path",
				CertificatePath: "path",
			},
			expectedError: "certificate-path is not used for key ceremonies",
		},
		{
			name: "key: certificate-profile present",
			config: ceremonyConfig{
				PKCS11Module:       "asd",
				CeremonyType:       "key",
				KeyLabel:           "label",
				KeyType:            "rsa",
				RSAModLength:       2048,
				PublicKeyPath:      "path",
				CertificateProfile: &certProfile{},
			},
			expectedError: "certificate-profile is not used for key ceremonies",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()
			if err != nil {
				if err.Error() != tc.expectedError {
					t.Fatalf("Validate returned an unexpected error: wanted %q, got %q", tc.expectedError, err)
				}
			}
		})
	}
}
