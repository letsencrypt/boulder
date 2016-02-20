package cmd

import (
	"testing"

	"github.com/letsencrypt/boulder/test"
)

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
