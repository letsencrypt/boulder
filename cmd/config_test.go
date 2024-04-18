package cmd

import (
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
		testConf              TLSConfig
	}{
		{
			name:              "Empty cert",
			expectedErrSubstr: "nil CertFile in TLSConfig",
			testConf:          TLSConfig{"", null, null},
		},
		{
			name:              "Empty key",
			expectedErrSubstr: "nil KeyFile in TLSConfig",
			testConf:          TLSConfig{null, "", null},
		},
		{
			name:              "Empty root",
			expectedErrSubstr: "nil CACertFile",
			testConf:          TLSConfig{null, null, ""},
		},
		{
			name:              "Could not parse cert",
			expectedErrSubstr: "failed to find any PEM data",
			testConf:          TLSConfig{null, key, caCertOne},
		},
		{
			name:              "Could not parse key",
			expectedErrSubstr: "failed to find any PEM data",
			testConf:          TLSConfig{cert, null, caCertOne},
		},
		{
			name:              "Could not parse root",
			expectedErrSubstr: "parsing CA certs",
			testConf:          TLSConfig{cert, key, null},
		},
		{
			name:              "Invalid cert location",
			expectedErrSubstr: "no such file or directory",
			testConf:          TLSConfig{nonExistent, key, caCertOne},
		},
		{
			name:              "Invalid key location",
			expectedErrSubstr: "no such file or directory",
			testConf:          TLSConfig{cert, nonExistent, caCertOne},
		},
		{
			name:              "Invalid root location",
			expectedErrSubstr: "no such file or directory",
			testConf:          TLSConfig{cert, key, nonExistent},
		},
		{
			name:                  "Valid config with one root",
			testConf:              TLSConfig{cert, key, caCertOne},
			expectedRootStoreSize: 1,
		},
		{
			name:                  "Valid config with two roots",
			testConf:              TLSConfig{cert, key, caCertMultiple},
			expectedRootStoreSize: 2,
		},
		{
			name:                  "Valid config with duplicate roots",
			testConf:              TLSConfig{cert, key, caCertDuplicate},
			expectedRootStoreSize: 1,
		},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			conf, err := tc.testConf.Load(metrics.NoopRegisterer)
			if tc.expectedErrSubstr == "" {
				test.AssertNotError(t, err, "Should not have errored, but did")
				// We are not using SystemCertPool, we are manually defining our
				// own.
				test.AssertEquals(t, len(conf.RootCAs.Subjects()), tc.expectedRootStoreSize)
				test.AssertEquals(t, len(conf.ClientCAs.Subjects()), tc.expectedRootStoreSize)
			} else {
				test.AssertError(t, err, "Expected an error but received none")
				test.AssertContains(t, err.Error(), tc.expectedErrSubstr)
			}
		})
	}
}
