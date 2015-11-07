package cmd

import (
	"encoding/json"
	"testing"

	"github.com/letsencrypt/boulder/test"
)

var (
	validPAConfig = []byte(`{
  "dbConnect": "dummyDBConnect",
  "enforcePolicyWhitelist": false,
  "challenges": { "simpleHttp": true }
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
)

func TestPAConfigUnmarshal(t *testing.T) {
	var pc PAConfig

	err := json.Unmarshal(validPAConfig, &pc)
	test.AssertNotError(t, err, "Failed to unmarshal valid PAConfig")

	err = json.Unmarshal(invalidPAConfig, &pc)
	test.AssertError(t, err, "Failed to reject invalid PAConfig")

	err = json.Unmarshal(noChallengesPAConfig, &pc)
	test.AssertNotError(t, err, "Failed to unmarshal valid PAConfig")
	test.Assert(t, len(pc.Challenges) == 4, "Incorrect number of challenges in default set")
}
