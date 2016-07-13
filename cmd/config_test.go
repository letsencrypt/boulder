package cmd

import (
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestDBConfigURL(t *testing.T) {
	tests := []struct {
		conf     DBConfig
		expected string
	}{
		{
			// Test with one config file that has no trailing newline
			conf:     DBConfig{DBConnectFile: "testdata/test_dburl"},
			expected: "mysql+tcp://test@testhost:3306/testDB?readTimeout=800ms&writeTimeout=800ms",
		},
		{
			// Test with a config file that *has* a trailing newline
			conf:     DBConfig{DBConnectFile: "testdata/test_dburl_newline"},
			expected: "mysql+tcp://test@testhost:3306/testDB?readTimeout=800ms&writeTimeout=800ms",
		},
	}

	for _, tc := range tests {
		url, err := tc.conf.URL()
		test.AssertNotError(t, err, "Failed calling URL() on DBConfig")
		test.AssertEquals(t, url, tc.expected)
	}
}

func TestPasswordConfig(t *testing.T) {
	tests := []struct {
		pc       PasswordConfig
		expected string
	}{
		{pc: PasswordConfig{}, expected: ""},
		{pc: PasswordConfig{Password: "config"}, expected: "config"},
		{pc: PasswordConfig{Password: "config", PasswordFile: "testdata/test_secret"}, expected: "secret"},
		{pc: PasswordConfig{PasswordFile: "testdata/test_secret"}, expected: "secret"},
	}

	for _, tc := range tests {
		password, err := tc.pc.Pass()
		test.AssertNotError(t, err, "Failed to retrieve password")
		test.AssertEquals(t, password, tc.expected)
	}
}
