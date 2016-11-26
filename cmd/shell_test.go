package cmd

import (
	"encoding/json"
	"testing"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/test"
)

var (
	validPAConfig = []byte(`{
  "dbConnect": "dummyDBConnect",
  "enforcePolicyWhitelist": false,
  "challenges": { "http-01": true }
}`)
	invalidPAConfig = []byte(`{
  "dbConnect": "dummyDBConnect",
  "enforcePolicyWhitelist": false,
  "challenges": { "nonsense": true }
}`)
	noChallengesPAConfig = []byte(`{
  "dbConnect": "dummyDBConnect",
  "enforcePolicyWhitelist": false
}`)

	emptyChallengesPAConfig = []byte(`{
  "dbConnect": "dummyDBConnect",
  "enforcePolicyWhitelist": false,
  "challenges": {}
}`)
)

func TestPAConfigUnmarshal(t *testing.T) {
	var pc1 PAConfig
	err := json.Unmarshal(validPAConfig, &pc1)
	test.AssertNotError(t, err, "Failed to unmarshal PAConfig")
	test.AssertNotError(t, pc1.CheckChallenges(), "Flagged valid challenges as bad")

	var pc2 PAConfig
	err = json.Unmarshal(invalidPAConfig, &pc2)
	test.AssertNotError(t, err, "Failed to unmarshal PAConfig")
	test.AssertError(t, pc2.CheckChallenges(), "Considered invalid challenges as good")

	var pc3 PAConfig
	err = json.Unmarshal(noChallengesPAConfig, &pc3)
	test.AssertNotError(t, err, "Failed to unmarshal PAConfig")
	test.AssertError(t, pc3.CheckChallenges(), "Disallow empty challenges map")

	var pc4 PAConfig
	err = json.Unmarshal(emptyChallengesPAConfig, &pc4)
	test.AssertNotError(t, err, "Failed to unmarshal PAConfig")
	test.AssertError(t, pc4.CheckChallenges(), "Disallow empty challenges map")
}

func TestMysqlLogger(t *testing.T) {
	log := blog.UseMock()
	mysqlLogger := mysqlLogger{log}

	testCases := []struct {
		args     []interface{}
		expected string
	}{
		{
			[]interface{}{nil},
			`ERR: [AUDIT] [mysql] <nil>`,
		},
		{
			[]interface{}{""},
			`ERR: [AUDIT] [mysql] `,
		},
		{
			[]interface{}{"Sup ", 12345, " Sup sup"},
			`ERR: [AUDIT] [mysql] Sup 12345 Sup sup`,
		},
	}

	for _, tc := range testCases {
		mysqlLogger.Print(tc.args...)
		logged := log.GetAll()
		test.AssertEquals(t, len(logged), 1)
		test.AssertEquals(t, logged[0], tc.expected)
		log.Clear()
	}
}
