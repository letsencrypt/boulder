package main

import (
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/cmd/boulder-va/mock_gsb"
	"github.com/letsencrypt/boulder/test"
)

// TestConfigCheck tests that configCheck() does what it says on the tin
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

// TestV4IsListed creates a va.SafeBrowsing instance backed by the google v4 API
// client and tests the `IsListed` function
func TestV4IsListed(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockSB := mock_gsb.NewMockSafeBrowsingV4(ctrl)
	gsb := gsbAdapter{mockSB}
	url := "foobar.com"

	// We EXPECT that calling `IsListed` on the gsbAdapter will result in a call to the SafeBrowser's `LookupURLs` function
	mockSB.EXPECT().LookupURLs([]string{url})
	result, err := gsb.IsListed(url)
	test.AssertNotError(t, err, fmt.Sprintf("IsListed(%q) returned non-nil err", url))
	test.AssertEquals(t, result, "")
}
