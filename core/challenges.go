package core

func newChallenge(challengeType string) Challenge {
	return Challenge{
		Type:   challengeType,
		Status: StatusPending,
		Token:  NewToken(),
	}
}

// HTTPChallenge01 constructs a random http-01 challenge
func HTTPChallenge01() Challenge {
	return newChallenge(ChallengeTypeHTTP01)
}

// TLSSNIChallenge01 constructs a random tls-sni-01 challenge
func TLSSNIChallenge01() Challenge {
	return newChallenge(ChallengeTypeTLSSNI01)
}

// TLSSNIChallenge02 constructs a random tls-sni-02 challenge
func TLSSNIChallenge02() Challenge {
	return newChallenge(ChallengeTypeTLSSNI02)
}

// DNSChallenge01 constructs a random dns-01 challenge
func DNSChallenge01() Challenge {
	return newChallenge(ChallengeTypeDNS01)
}
