package ca

import (
	"io/ioutil"
	"sync"

	"github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/reloader"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v2"
)

// ECDSAAllowList acts as a container for a `regIDsMap` and a mutex.
// This allows `regIDsMap` to be updated safely when the list changes.
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
	logger    log.Logger
	metric    *prometheus.GaugeVec
}

// Update is an exported method, typically specified as a callback to a
// file reloader, that replaces the inner `regIDsMap` with the contents
// of a YAML list (as bytes)
func (e *ECDSAAllowList) Update(contents []byte) error {
	newRegIDsMap, err := unmarshalAllowList(contents)
	if err != nil {
		return err
	}
	e.Lock()
	defer e.Unlock()
	e.regIDsMap = newRegIDsMap
	// nil check for testing purposes
	if e.metric != nil {
		e.metric.WithLabelValues("succeeded").Set(float64(len(e.regIDsMap)))
	}
	return nil
}

// UpdateErr is an exported method, typically specified as a callback to
// a file reloader, that records failed ecdsa allow list reload attempts
func (e *ECDSAAllowList) UpdateErr(err error) {
	e.logger.Errf("error reloading ECDSA allowed list: %s", err)
	e.RLock()
	defer e.RUnlock()
	// nil check for testing purposes
	if e.metric != nil {
		e.metric.WithLabelValues("failed").Set(float64(len(e.regIDsMap)))
	}
}

// regIDAllowed checks if ECDSA issuance is permitted for the specified
// Registration ID.
func (e *ECDSAAllowList) regIDAllowed(regID int64) bool {
	e.RLock()
	defer e.RUnlock()
	return e.regIDsMap[regID]
}

// Stop stops an active allow list reloader.
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
func NewECDSAAllowListFromFile(filename string, reloader *reloader.Reloader, logger log.Logger, metric *prometheus.GaugeVec) (*ECDSAAllowList, int, error) {
	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, 0, err
	}
	regIDsMap, err := unmarshalAllowList(contents)
	if err != nil {
		return nil, 0, err
	}
	return &ECDSAAllowList{regIDsMap: regIDsMap, reloader: reloader, logger: logger, metric: metric}, len(regIDsMap), nil
}

// NewECDSAAllowListFromConfig is exported to allow boulder-ca to set
// the inner `regIDsMap` from a list of registration IDs received in the
// CA config JSON.
//
// TODO(#5394): This is deprecated and exists to support deployability
// until `ECDSAAllowedAccounts` is replaced by `ECDSAAllowListFilename`
// in all staging and production configs.
func NewECDSAAllowListFromConfig(regIDs []int64) (*ECDSAAllowList, error) {
	regIDsMap := makeRegIDsMap(regIDs)
	return &ECDSAAllowList{regIDsMap: regIDsMap, reloader: nil, logger: nil, metric: nil}, nil
}
