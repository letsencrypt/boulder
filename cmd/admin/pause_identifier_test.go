package main

import (
	"os"
	"path"
	"strings"
	"testing"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/test"
)

func TestReadingPauseCSVFiles(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name            string
		data            []string
		expectedRecords int
	}{
		{
			name: "No data in file",
			data: nil,
		},
		{
			name:            "valid",
			data:            []string{"1,dns,example.com"},
			expectedRecords: 1,
		},
		{
			name:            "valid with duplicates",
			data:            []string{"1,dns,example.com,example.net", "2,dns,example.org", "1,dns,example.com,example.net", "1,dns,example.com,example.net", "3,dns,example.gov", "3,dns,example.gov"},
			expectedRecords: 6,
		},
		{
			name: "invalid just commas",
			data: []string{",,,"},
		},
		{
			name: "invalid only contains accountID",
			data: []string{"1"},
		},
		{
			name: "invalid only contains accountID and identifierType",
			data: []string{"1,dns"},
		},
		{
			name: "invalid missing identifierType",
			data: []string{"1,,example.com"},
		},
		{
			name: "invalid accountID isnt an int",
			data: []string{"blorple"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			//t.Parallel()
			log := blog.NewMock()
			a := admin{log: log}

			csvFile := path.Join(t.TempDir(), path.Base(t.Name()+".csv"))
			err := os.WriteFile(csvFile, []byte(strings.Join(testCase.data, "\n")), os.ModePerm)
			test.AssertNotError(t, err, "could not write temporary file")

			parsedData, err := a.readPausedAccountFile(csvFile)
			test.AssertNotError(t, err, "no error expected, but received one")
			test.AssertEquals(t, len(parsedData), testCase.expectedRecords)
		})
	}
}
