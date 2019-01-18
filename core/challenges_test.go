package core

import (
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestNewChallenge(t *testing.T) {
	challenge := newChallenge(ChallengeTypeDNS01, "")
	test.Assert(t, challenge.Token != "", "token is not set")
	challenge = newChallenge(ChallengeTypeDNS01, "asd")
	test.Assert(t, challenge.Token == "asd", "token is not set")
}
