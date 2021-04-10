package ca

import (
	"sync"

	"gopkg.in/yaml.v2"
)

// ecdsaAllowedList acts as a container for a `regIDsMap` and a mutex.
// This allows for `regIDsMap` to be updated safely when list changes
// (e.g. due to a reload of the allowed list file).
type ecdsaAllowedList struct {
	sync.RWMutex

	// List of Registration IDs for which ECDSA issuance is allowed. If
	// an account is in this allowlist *and* requests issuance for an
	// ECDSA key *and* an ECDSA issuer is configured in the CA, then the
	// certificate will be issued from that ECDSA issuer.
	//
	// This is temporary, and will be used for testing and slow roll-out
	// of ECDSA issuance, but will then be removed.
	regIDsMap map[int64]bool
}

// load unmarshals a list of allowed registration IDs from YAML as bytes
// (typically read from disk by a reloader) and updates the `regIDsMap`
// with the resulting list.
func (e *ecdsaAllowedList) load(contents []byte) error {
	var regIDsList []int64
	err := yaml.Unmarshal(contents, &regIDsList)
	if err != nil {
		return err
	}

	e.Lock()
	newRegIDsMap := make(map[int64]bool)
	for _, regID := range regIDsList {
		newRegIDsMap[regID] = true
	}
	e.regIDsMap = newRegIDsMap
	e.Unlock()
	return nil
}

// regIDAllowed checks if a given registration ID is on the ECDSA
// allowed list.
func (e *ecdsaAllowedList) regIDAllowed(regID int64) bool {
	e.RLock()
	defer e.RUnlock()
	return e.regIDsMap[regID]
}

func newECDSAAllowedList() ecdsaAllowedList {
	return ecdsaAllowedList{regIDsMap: map[int64]bool{}}
}
