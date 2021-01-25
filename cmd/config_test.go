package cmd

import (
	"regexp"
	"strings"
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

func TestGetMaxOpenConns(t *testing.T) {
	tests := []struct {
		conf     DBConfig
		expected int
	}{
		{
			// Test with config that contains both fields with different values
			conf:     DBConfig{MaxDBConns: 1, MaxOpenConns: 100},
			expected: 100,
		},
		{
			// Test with config that contains only MaxDBConns
			conf:     DBConfig{MaxDBConns: 100},
			expected: 100,
		},
		{
			// Test with config that contains only MaxOpenConns
			conf:     DBConfig{MaxOpenConns: 1},
			expected: 1,
		},
		{
			// Test with config that contains neither field
			conf:     DBConfig{},
			expected: 0,
		},
	}

	for _, tc := range tests {
		maxOpenConns := tc.conf.GetMaxOpenConns()
		test.AssertEquals(t, maxOpenConns, tc.expected)
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

func TestTLSConfigLoad(t *testing.T) {
	null := "/dev/null"
	nonExistent := "[nonexistent]"
	cert := "testdata/cert.pem"
	key := "testdata/key.pem"
	caCert := "testdata/minica.pem"
	testCases := []struct {
		TLSConfig
		want string
	}{
		{TLSConfig{nil, &null, &null}, "nil CertFile in TLSConfig"},
		{TLSConfig{&null, nil, &null}, "nil KeyFile in TLSConfig"},
		{TLSConfig{&null, &null, nil}, "nil CACertFile in TLSConfig"},
		{TLSConfig{&nonExistent, &key, &caCert}, "loading key pair.*no such file or directory"},
		{TLSConfig{&cert, &nonExistent, &caCert}, "loading key pair.*no such file or directory"},
		{TLSConfig{&cert, &key, &nonExistent}, "reading CA cert from.*no such file or directory"},
		{TLSConfig{&null, &key, &caCert}, "loading key pair.*failed to find any PEM data"},
		{TLSConfig{&cert, &null, &caCert}, "loading key pair.*failed to find any PEM data"},
		{TLSConfig{&cert, &key, &null}, "parsing CA certs"},
	}
	for _, tc := range testCases {
		var title [3]string
		if tc.CertFile == nil {
			title[0] = "nil"
		} else {
			title[0] = *tc.CertFile
		}
		if tc.KeyFile == nil {
			title[1] = "nil"
		} else {
			title[1] = *tc.KeyFile
		}
		if tc.CACertFile == nil {
			title[2] = "nil"
		} else {
			title[2] = *tc.CACertFile
		}
		t.Run(strings.Join(title[:], "_"), func(t *testing.T) {
			_, err := tc.TLSConfig.Load()
			if err == nil {
				t.Errorf("got no error")
			}
			if matched, _ := regexp.MatchString(tc.want, err.Error()); !matched {
				t.Errorf("got error %q, wanted %q", err, tc.want)
			}
		})
	}
}
