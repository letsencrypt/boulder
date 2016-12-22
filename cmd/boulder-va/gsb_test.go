package main

import (
	"testing"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/test"
)

func TestConfigCheck(t *testing.T) {

	testcases := []struct {
		conf     *cmd.GoogleSafeBrowsingConfig
		expected error
	}{
		{
			conf:     nil,
			expected: NilConfigErr,
		},
		{
			conf: &cmd.GoogleSafeBrowsingConfig{
				APIKey: "",
			},
			expected: EmptyAPIKeyErr,
		},
		{
			conf: &cmd.GoogleSafeBrowsingConfig{
				APIKey:  "you are the keymaster!",
				DataDir: "",
			},
			expected: EmptyDataDirErr,
		},
		{
			conf: &cmd.GoogleSafeBrowsingConfig{
				APIKey:  "you are the keymaster!",
				DataDir: "/distrust/everything/i/say/i/am/telling/the/truth",
			},
			expected: MissingDataDirErr,
		},
		{
			conf: &cmd.GoogleSafeBrowsingConfig{
				APIKey:  "you are the keymaster!",
				DataDir: "./",
			},
			expected: nil,
		},
	}

	for _, tc := range testcases {
		result := configCheck(tc.conf)
		test.AssertEquals(t, result, tc.expected)
	}
}
