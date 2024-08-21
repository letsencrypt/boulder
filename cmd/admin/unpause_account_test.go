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
type mockSAUnpause struct {
	sapb.StorageAuthorityClient
	regIDCounter map[int64]int64
}

func (msa *mockSAUnpause) UnpauseAccount(ctx context.Context, in *sapb.RegistrationID, _ ...grpc.CallOption) (*sapb.Count, error) {
	if _, ok := msa.regIDCounter[in.Id]; ok {
		msa.regIDCounter[in.Id] += 1
	}

	return &sapb.Count{Count: msa.regIDCounter[in.Id]}, nil
}

func TestUnpausingAccounts(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		data           []string
		expectedRegIDs int
		expectErr      bool
	}{
		{
			name:      "No data in file",
			data:      nil,
			expectErr: true,
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
			a := admin{sac: &mockSAUnpause{}, log: log}

			file := path.Join(t.TempDir(), path.Base(t.Name()+".txt"))
			err := os.WriteFile(file, []byte(strings.Join(testCase.data, "\n")), os.ModePerm)
			test.AssertNotError(t, err, "could not write temporary file")

			regIDs, err := a.readUnpauseAccountFile(file)
			test.AssertNotError(t, err, "no error expected, but received one")
			test.AssertEquals(t, len(regIDs), testCase.expectedRegIDs)

			count, err := a.unpauseAccounts(context.TODO(), regIDs)
			if testCase.expectErr {
				test.AssertError(t, err, "should not have been able to unpause accounts, but did")
			} else {
				test.AssertNotError(t, err, "could not unpause accounts")
			}
			test.AssertEquals(t, len(count), testCase.expectedRegIDs)
		})
	}
}
