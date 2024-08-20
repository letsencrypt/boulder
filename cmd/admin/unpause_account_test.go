package main

import (
	"os"
	"path"
	"strings"
	"testing"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/test"
)

func TestReadingUnpauseAccountFile(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		data           []string
		expectedRegIDs int
	}{
		{
			name: "No data in file",
			data: nil,
		},
		{
			name:           "valid",
			data:           []string{"1"},
			expectedRegIDs: 1,
		},
		{
			name:           "valid with duplicates",
			data:           []string{"1", "2", "1", "3", "3"},
			expectedRegIDs: 5,
		},
		{
			name:           "valid with empty lines and duplicates",
			data:           []string{"1", "\n", "6", "6", "6"},
			expectedRegIDs: 4,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			log := blog.NewMock()
			a := admin{log: log}

			file := path.Join(t.TempDir(), path.Base(t.Name()+".txt"))
			err := os.WriteFile(file, []byte(strings.Join(testCase.data, "\n")), os.ModePerm)
			test.AssertNotError(t, err, "could not write temporary file")

			regIDs, err := a.readUnpauseAccountFile(file)
			test.AssertNotError(t, err, "no error expected, but received one")
			test.AssertEquals(t, len(regIDs), testCase.expectedRegIDs)
		})
	}
}
