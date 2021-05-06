package ca

import (
	"io/ioutil"
	"sync"

	"github.com/letsencrypt/boulder/reloader"
	"gopkg.in/yaml.v2"
)

// ECDSAAllowList acts as a container for a `regIDsMap` and a mutex.
// This allows for `regIDsMap` to be updated safely when list changes
// (e.g. due to a reload of the ECDSA allow list file).
type ECDSAAllowList struct {
	sync.RWMutex

	// List of Registration IDs for which ECDSA issuance is allowed. If
	// an account is in this allowlist *and* requests issuance for an
	// ECDSA key *and* an ECDSA issuer is configured in the CA, then the
	// certificate will be issued from that ECDSA issuer.
	//
	// This is temporary, and will be used for testing and slow roll-out
	// of ECDSA issuance, but will then be removed.
	regIDsMap map[int64]bool
	reloader  *reloader.Reloader
}

// Update is an exported method that replaces the inner `regIDsMap` with
// the contents of an allow list (YAML) as bytes, typically read from
// disk by a reloader.
func (e *ECDSAAllowList) Update(contents []byte) error {
	newRegIDsMap, err := unmarshalAllowList(contents)
	if err != nil {
		return err
	}
	e.Lock()
	defer e.Unlock()
	e.regIDsMap = newRegIDsMap
	return nil
}

// regIDAllowed checks if a given registration ID is on the ECDSA
// allow list.
func (e *ECDSAAllowList) regIDAllowed(regID int64) bool {
	e.RLock()
	defer e.RUnlock()
	return e.regIDsMap[regID]
}

// Stop stops an active reloader.
func (e *ECDSAAllowList) Stop() {
	e.Lock()
	defer e.Unlock()
	if e.reloader != nil {
		e.reloader.Stop()
	}
}

func unmarshalAllowList(contents []byte) (map[int64]bool, error) {
	var regIDs []int64
	err := yaml.Unmarshal(contents, &regIDs)
	if err != nil {
		return nil, err
	}
	return makeRegIDsMap(regIDs), nil
}

func makeRegIDsMap(regIDs []int64) map[int64]bool {
	regIDsMap := make(map[int64]bool)
	for _, regID := range regIDs {
		regIDsMap[regID] = true
	}
	return regIDsMap
}

// NewECDSAAllowListFromFile is exported to allow boulder-ca to
func NewECDSAAllowListFromFile(filename string, reloader *reloader.Reloader) (*ECDSAAllowList, error) {
	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	regIDsMap, err := unmarshalAllowList(contents)
	if err != nil {
		return nil, err
	}
	return &ECDSAAllowList{regIDsMap: regIDsMap, reloader: reloader}, nil
}

// NewECDSAAllowListFromConfig is exported to allow boulder-ca to set
// the inner `regIDsMap` with using a list of allowed registration IDs
// received in the CA config JSON.
//
// TODO(#5394): This is deprecated and exists to support deployability
// until `ECDSAAllowedAccounts` is replaced by `ECDSAAllowListFilename`
// in all staging and production configs.
func NewECDSAAllowListFromConfig(regIDs []int64) (*ECDSAAllowList, error) {
	regIDsMap := makeRegIDsMap(regIDs)
	return &ECDSAAllowList{regIDsMap: regIDsMap, reloader: nil}, nil
}
