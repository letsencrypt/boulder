package cmd

import (
	"regexp"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/metrics"
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

func TestPasswordConfig(t *testing.T) {
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
	null := "/dev/null"
	nonExistent := "[nonexistent]"
	cert := "testdata/cert.pem"
	key := "testdata/key.pem"
	caCert := "testdata/minica.pem"

	testCases := []struct {
		TLSConfig
		want string
	}{
		{TLSConfig{"", null, null}, "nil CertFile in TLSConfig"},
		{TLSConfig{null, "", null}, "nil KeyFile in TLSConfig"},
		{TLSConfig{null, null, ""}, "nil CACertFile in TLSConfig"},
		{TLSConfig{nonExistent, key, caCert}, "loading key pair.*no such file or directory"},
		{TLSConfig{cert, nonExistent, caCert}, "loading key pair.*no such file or directory"},
		{TLSConfig{cert, key, nonExistent}, "reading CA cert from.*no such file or directory"},
		{TLSConfig{null, key, caCert}, "loading key pair.*failed to find any PEM data"},
		{TLSConfig{cert, null, caCert}, "loading key pair.*failed to find any PEM data"},
		{TLSConfig{cert, key, null}, "parsing CA certs"},
	}
	for _, tc := range testCases {
		var title [3]string
		if tc.CertFile == "" {
			title[0] = "nil"
		} else {
			title[0] = tc.CertFile
		}
		if tc.KeyFile == "" {
			title[1] = "nil"
		} else {
			title[1] = tc.KeyFile
		}
		if tc.CACertFile == "" {
			title[2] = "nil"
		} else {
			title[2] = tc.CACertFile
		}
		t.Run(strings.Join(title[:], "_"), func(t *testing.T) {
			_, err := tc.TLSConfig.Load(metrics.NoopRegisterer)
			if err == nil {
				t.Errorf("got no error")
			}
			if matched, _ := regexp.MatchString(tc.want, err.Error()); !matched {
				t.Errorf("got error %q, wanted %q", err, tc.want)
			}
		})
	}
}
