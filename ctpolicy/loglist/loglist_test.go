package loglist

import (
	"fmt"
	"testing"

	"github.com/letsencrypt/boulder/ctpolicy/ctconfig"
	"github.com/letsencrypt/boulder/ctpolicy/loglist/generated"
	"github.com/letsencrypt/boulder/test"
)

func TestNewHelper(t *testing.T) {
	type testCase struct {
		// The purpose to which the test log list will be put.
		purp purpose
		// The state that the log in the test log list is in.
		state generated.LogListSchemaJsonOperatorsElemLogsElemState
		// Whether or not the log in the test log list matches a wanted log ID.
		matches bool
		// Whether the resulting list should have any entries or not.
		expectEmpty bool
	}

	testCases := make([]testCase, 0, 3*5*2)

	for _, purp := range []purpose{Issuance, Informational, Validation} {
		for _, state := range []generated.LogListSchemaJsonOperatorsElemLogsElemState{
			{Pending: &generated.State{}},
			{Qualified: &generated.State{}},
			{Usable: &generated.State{}},
			{Readonly: &generated.State{}},
			{Retired: &generated.State{}},
		} {
			for _, matches := range []bool{true, false} {
				tc := testCase{
					purp:    purp,
					state:   state,
					matches: matches,
				}

				if !matches {
					tc.expectEmpty = true
				} else if state.Retired != nil {
					tc.expectEmpty = true
				} else if state.Readonly != nil && purp != Validation {
					tc.expectEmpty = true
				} else if state.Qualified != nil && purp != Informational {
					tc.expectEmpty = true
				} else if state.Pending != nil && purp != Informational {
					tc.expectEmpty = true
				}

				testCases = append(testCases, tc)
			}
		}
	}

	for i, tc := range testCases {
		i := i
		tc := tc
		t.Run(fmt.Sprintf("%d/%d", i, len(testCases)), func(t *testing.T) {
			t.Parallel()

			base := embedOnce{
				LogListSchemaJson: generated.LogListSchemaJson{
					Operators: []generated.LogListSchemaJsonOperatorsElem{
						{
							Logs: []generated.LogListSchemaJsonOperatorsElemLogsElem{
								{
									Url:   "https://example.com/ct",
									Key:   "base64key",
									LogId: "base64id",
									State: &tc.state,
								},
							},
						},
					},
				},
			}

			id := ctconfig.LogID{ID: "base64id"}
			if !tc.matches {
				id.ID = "other-base64id"
			}

			actual, err := newHelper(&base, []ctconfig.LogID{id}, tc.purp)
			test.AssertNotError(t, err, "loglist.New() shouldn't have failed")

			if tc.expectEmpty {
				test.AssertEquals(t, len(actual), 0)
			} else {
				test.AssertEquals(t, len(actual), 1)
			}
		})
	}
}
