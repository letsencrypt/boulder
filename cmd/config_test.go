package cmd

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestDBConfigURL(t *testing.T) {
	tests := []struct {
		description string
		conf        DBConfig
		expected    string
	}{
		{
			description: "Test with one config file that has no trailing newline",
			conf:        DBConfig{DBConnectFile: "testdata/test_dburl"},
			expected:    "mysql+tcp://test@testhost:3306/testDB?readTimeout=800ms&writeTimeout=800ms",
		},
		{
			description: "Test with a config file that *has* a trailing newline",
			conf:        DBConfig{DBConnectFile: "testdata/test_dburl_newline"},
			expected:    "mysql+tcp://test@testhost:3306/testDB?readTimeout=800ms&writeTimeout=800ms",
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			url, err := tc.conf.URL()
			test.AssertNotError(t, err, "Failed calling URL() on DBConfig")
			if url != tc.expected {
				t.Errorf("got %q, expected %q", url, tc.expected)
			}
		})
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
		t.Run(fmt.Sprintf("%q password", tc.expected), func(t *testing.T) {
			password, err := tc.pc.Pass()
			test.AssertNotError(t, err, "Failed to retrieve password")
			if password != tc.expected {
				t.Errorf("got %q, expected %q", password, tc.expected)
			}
		})
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
