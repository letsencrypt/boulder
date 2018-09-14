package cmd

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jmhodges/clock"
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

func TestTemporalSetup(t *testing.T) {
	for _, tc := range []struct {
		ts  TemporalSet
		err string
	}{
		{
			ts:  TemporalSet{},
			err: "Name cannot be empty",
		},
		{
			ts: TemporalSet{
				Name: "temporal set",
			},
			err: "temporal set contains no shards",
		},
		{
			ts: TemporalSet{
				Name: "temporal set",
				Shards: []TemporalLogDescription{
					{
						WindowStart: time.Time{},
						WindowEnd:   time.Time{},
					},
				},
			},
			err: "WindowStart must be before WindowEnd",
		},
		{
			ts: TemporalSet{
				Name: "temporal set",
				Shards: []TemporalLogDescription{
					{
						WindowStart: time.Time{}.Add(time.Hour),
						WindowEnd:   time.Time{},
					},
				},
			},
			err: "WindowStart must be before WindowEnd",
		},
		{
			ts: TemporalSet{
				Name: "temporal set",
				Shards: []TemporalLogDescription{
					{
						WindowStart: time.Time{},
						WindowEnd:   time.Time{}.Add(time.Hour),
					},
				},
			},
			err: "",
		},
	} {
		err := tc.ts.Setup()
		if err != nil && tc.err != err.Error() {
			t.Errorf("got error %q, wanted %q", err, tc.err)
		} else if err == nil && tc.err != "" {
			t.Errorf("unexpected error %q", err)
		}
	}
}

func TestLogInfo(t *testing.T) {
	ld := LogDescription{
		URI: "basic-uri",
		Key: "basic-key",
	}
	uri, key, err := ld.Info(time.Time{})
	test.AssertNotError(t, err, "Info failed")
	test.AssertEquals(t, uri, ld.URI)
	test.AssertEquals(t, key, ld.Key)

	fc := clock.NewFake()
	ld.TemporalSet = &TemporalSet{}
	uri, key, err = ld.Info(fc.Now())
	test.AssertError(t, err, "Info should fail with a TemporalSet with no viable shards")
	ld.TemporalSet.Shards = []TemporalLogDescription{{WindowStart: fc.Now().Add(time.Hour), WindowEnd: fc.Now().Add(time.Hour * 2)}}
	uri, key, err = ld.Info(fc.Now())
	test.AssertError(t, err, "Info should fail with a TemporalSet with no viable shards")

	fc.Add(time.Hour * 4)
	now := fc.Now()
	ld.TemporalSet.Shards = []TemporalLogDescription{
		{
			WindowStart: now.Add(time.Hour * -4),
			WindowEnd:   now.Add(time.Hour * -2),
			URI:         "a",
			Key:         "a",
		},
		{
			WindowStart: now.Add(time.Hour * -2),
			WindowEnd:   now.Add(time.Hour * 2),
			URI:         "b",
			Key:         "b",
		},
		{
			WindowStart: now.Add(time.Hour * 2),
			WindowEnd:   now.Add(time.Hour * 4),
			URI:         "c",
			Key:         "c",
		},
	}
	uri, key, err = ld.Info(now)
	test.AssertNotError(t, err, "Info failed")
	test.AssertEquals(t, uri, "b")
	test.AssertEquals(t, key, "b")
}
