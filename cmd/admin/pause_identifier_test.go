package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestReadingPauseCSVFiles(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		data        []string
		errorSubstr string
	}{
		{
			name:        "No data in file",
			data:        nil,
			errorSubstr: "were nil",
		},
		{
			name: "valid",
			data: []string{"1,dns,example.com"},
		},
		{
			name: "valid with duplicates",
			data: []string{"1,dns,example.com,example.net", "2,dns,example.org", "1,dns,example.com,example.net", "1,dns,example.com,example.net", "3,dns,example.gov", "3,dns,example.gov"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			a := admin{}
			csvFile := filepath.Join(t.TempDir(), t.Name()+".csv")
			err := os.WriteFile(csvFile, []byte(strings.Join(testCase.data, "\n")), os.ModeAppend)
			test.AssertNotError(t, err, "could not write temporary file")

			_, err = a.readPausedAccountFile(csvFile)
			if testCase.errorSubstr == "" {
				test.AssertNotError(t, err, "no error expected, but received one")
			} else {
				test.AssertError(t, err, "expected error, but received none")
			}
			//test.AssertDeepEquals(t, data, pairs)

		})
	}
}

func TestPausingSingle(t *testing.T) {
	t.Parallel()
	// a := admin{}
}
