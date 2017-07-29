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
	testCases := []struct {
		conf     *cmd.GoogleSafeBrowsingConfig
		expected error
	}{
		{
			nil, NilConfigErr,
		},
		{
			&cmd.GoogleSafeBrowsingConfig{
				APIKey: "",
			},
			EmptyAPIKeyErr,
		},
		{
			&cmd.GoogleSafeBrowsingConfig{
				APIKey:  "you are the keymaster!",
				DataDir: "",
			},
			EmptyDataDirErr,
		},
		{
			&cmd.GoogleSafeBrowsingConfig{
				APIKey:  "you are the keymaster!",
				DataDir: "/distrust/everything/i/say/i/am/telling/the/truth",
			},
			MissingDataDirErr,
		},
		{
			&cmd.GoogleSafeBrowsingConfig{
				APIKey:  "you are the keymaster!",
				DataDir: "./",
			},
			nil,
		},
	}

	for _, tc := range testCases {
		var description string
		if tc.expected == nil {
			description = "nil"
		} else {
			description = tc.expected.Error()
		}
		t.Run(fmt.Sprintf("Error case: \"%q\"", description), func(t *testing.T) {
			result := configCheck(tc.conf)
			if result != tc.expected {
				// NOTE: These should probably look more like `tc.expected.Error()`,
				//  but if we use that and one of the values is `nil`, the test fails
				//  AND we get a runtime error.
				t.Errorf("Expected %v, but got %v", tc.expected, result)
			}
		})
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
