package main

import (
	"context"
	"os"
	"path"
	"strings"
	"testing"

	blog "github.com/letsencrypt/boulder/log"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/test"
	"google.golang.org/grpc"
)

// mockSAPaused is a mock which records the PauseRequest it received, and
// returns the number of identifiers as a PauseIdentifiersResponse. It does not
// maintain state of repaused identifiers.
type mockSAPaused struct {
	sapb.StorageAuthorityClient
	reqs []*sapb.PauseRequest
}

func (msa *mockSAPaused) PauseIdentifiers(ctx context.Context, in *sapb.PauseRequest, _ ...grpc.CallOption) (*sapb.PauseIdentifiersResponse, error) {
	msa.reqs = append(msa.reqs, in)

	return &sapb.PauseIdentifiersResponse{Paused: int64(len(in.Identifiers))}, nil
}

func TestPausingIdentifiers(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name            string
		data            []string
		expectedRecords int
		expectErr       bool
	}{
		{
			name:      "No data in file",
			data:      nil,
			expectErr: true,
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
			name:      "invalid just commas",
			data:      []string{",,,"},
			expectErr: true,
		},
		{
			name:      "invalid only contains accountID",
			data:      []string{"1"},
			expectErr: true,
		},
		{
			name:      "invalid only contains accountID and identifierType",
			data:      []string{"1,dns"},
			expectErr: true,
		},
		{
			name:      "invalid missing identifierType",
			data:      []string{"1,,example.com"},
			expectErr: true,
		},
		{
			name:      "invalid accountID isnt an int",
			data:      []string{"blorple"},
			expectErr: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			log := blog.NewMock()
			a := admin{sac: &mockSAPaused{}, log: log}

			csvFile := path.Join(t.TempDir(), path.Base(t.Name()+".csv"))
			err := os.WriteFile(csvFile, []byte(strings.Join(testCase.data, "\n")), os.ModePerm)
			test.AssertNotError(t, err, "could not write temporary file")

			parsedData, err := a.readPausedAccountFile(csvFile)
			test.AssertNotError(t, err, "no error expected, but received one")
			test.AssertEquals(t, len(parsedData), testCase.expectedRecords)

			responses, err := a.pauseIdentifiers(context.TODO(), parsedData)
			if testCase.expectErr {
				test.AssertError(t, err, "should not have been able to pause identifiers, but did")
			} else {
				test.AssertNotError(t, err, "could not pause identifiers")
			}
			test.AssertEquals(t, len(responses), testCase.expectedRecords)
		})
	}
}
