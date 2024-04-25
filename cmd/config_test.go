package cmd

import (
	"crypto/tls"
	"testing"

	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/test"
)

func TestDBConfigURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		conf     DBConfig
		expected string
	}{
		{
			// Test with one config file that has no trailing newline
			conf:     DBConfig{DBConnectFile: "testdata/test_dburl"},
			expected: "test@tcp(testhost:3306)/testDB?readTimeout=800ms&writeTimeout=800ms",
		},
		{
			// Test with a config file that *has* a trailing newline
			conf:     DBConfig{DBConnectFile: "testdata/test_dburl_newline"},
			expected: "test@tcp(testhost:3306)/testDB?readTimeout=800ms&writeTimeout=800ms",
		},
	}

	for _, tc := range tests {
		url, err := tc.conf.URL()
		test.AssertNotError(t, err, "Failed calling URL() on DBConfig")
		test.AssertEquals(t, url, tc.expected)
	}
}

func TestPasswordConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		pc       PasswordConfig
		expected string
	}{
		{pc: PasswordConfig{}, expected: ""},
		{pc: PasswordConfig{PasswordFile: "testdata/test_secret"}, expected: "secret"},
	}

	for _, tc := range tests {
		password, err := tc.pc.Pass()
		test.AssertNotError(t, err, "Failed to retrieve password")
		test.AssertEquals(t, password, tc.expected)
	}
}

func TestTLSConfigLoad(t *testing.T) {
	t.Parallel()
	null := "/dev/null"
	nonExistent := "[nonexistent]"
	cert := "../test/hierarchy/int-e2.cert.pem"
	key := "../test/hierarchy/int-e2.key.pem"
	caCertOne := "../test/hierarchy/root-x1.cert.pem"
	caCertMultiple := "../test/hierarchy/multiple-roots.cert.pem"
	caCertDuplicate := "../test/hierarchy/duplicate-roots.cert.pem"

	testCases := []struct {
		name                  string
		expectedErrSubstr     string
		expectedRootStoreSize int
		expectedCipherSuites  []string
		expectedClientAuth    string
		testConf              TLSConfig
	}{
		{
			name:              "Empty cert",
			expectedErrSubstr: "nil CertFile in TLSConfig",
			testConf:          TLSConfig{"", null, null, "", nil},
		},
		{
			name:              "Empty key",
			expectedErrSubstr: "nil KeyFile in TLSConfig",
			testConf:          TLSConfig{null, "", null, "", nil},
		},
		{
			name:              "Empty root",
			expectedErrSubstr: "nil CACertFile",
			testConf:          TLSConfig{null, null, "", "", nil},
		},
		{
			name:              "Could not parse cert",
			expectedErrSubstr: "failed to find any PEM data",
			testConf:          TLSConfig{null, key, caCertOne, "", nil},
		},
		{
			name:              "Could not parse key",
			expectedErrSubstr: "failed to find any PEM data",
			testConf:          TLSConfig{cert, null, caCertOne, "", nil},
		},
		{
			name:              "Could not parse root",
			expectedErrSubstr: "parsing CA certs",
			testConf:          TLSConfig{cert, key, null, "", nil},
		},
		{
			name:              "Invalid cert location",
			expectedErrSubstr: "no such file or directory",
			testConf:          TLSConfig{nonExistent, key, caCertOne, "", nil},
		},
		{
			name:              "Invalid key location",
			expectedErrSubstr: "no such file or directory",
			testConf:          TLSConfig{cert, nonExistent, caCertOne, "", nil},
		},
		{
			name:              "Invalid root location",
			expectedErrSubstr: "no such file or directory",
			testConf:          TLSConfig{cert, key, nonExistent, "", nil},
		},
		{
			name:                  "Valid config with one root",
			testConf:              TLSConfig{cert, key, caCertOne, "", nil},
			expectedRootStoreSize: 1,
		},
		{
			name:                  "Valid config with two roots",
			testConf:              TLSConfig{cert, key, caCertMultiple, "", nil},
			expectedRootStoreSize: 2,
		},
		{
			name:                  "Valid config with duplicate roots",
			testConf:              TLSConfig{cert, key, caCertDuplicate, "", nil},
			expectedRootStoreSize: 1,
		},
		{
			name:                  "Valid config with alternate ClientAuth",
			testConf:              TLSConfig{cert, key, caCertDuplicate, "NoClientCert", nil},
			expectedRootStoreSize: 1,
			expectedClientAuth:    "NoClientCert",
		},
		{
			name:                  "Valid config with alternate CipherSuite",
			testConf:              TLSConfig{cert, key, caCertDuplicate, "", []string{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"}},
			expectedRootStoreSize: 1,
			expectedCipherSuites:  []string{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
		},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			conf, err := tc.testConf.Load(metrics.NoopRegisterer)
			if tc.expectedErrSubstr == "" {
				if tc.expectedCipherSuites == nil {
					// This default is set by makeCipherSuitesFromConfig()
					tc.expectedCipherSuites = []string{"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"}
				}
				if tc.expectedClientAuth == "" {
					// This default is set by makeClientAuthFromConfig()
					tc.expectedClientAuth = "RequireAndVerifyClientCert"
				}

				test.AssertNotError(t, err, "Should not have errored, but did")

				// We are not using SystemCertPool, we are manually defining our
				// own.
				test.AssertEquals(t, len(conf.RootCAs.Subjects()), tc.expectedRootStoreSize)
				test.AssertEquals(t, len(conf.ClientCAs.Subjects()), tc.expectedRootStoreSize)
				test.AssertEquals(t, conf.ClientAuth.String(), tc.expectedClientAuth)
				test.AssertEquals(t, len(conf.CipherSuites), len(tc.expectedCipherSuites))
				for idx, cs := range conf.CipherSuites {
					test.AssertEquals(t, tls.CipherSuiteName(cs), tc.expectedCipherSuites[idx])
				}
			} else {
				test.AssertError(t, err, "Expected an error but received none")
				test.AssertContains(t, err.Error(), tc.expectedErrSubstr)
			}
		})
	}
}
