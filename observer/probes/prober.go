package observer

import (
	"fmt"
	"time"

	"github.com/letsencrypt/boulder/cmd"
)

const (
	initProb = "Error while initializing probes"
)

var (
	// Registry is the central registry for prober Configurer types
	Registry = make(map[string]Configurer)
)

// Prober is the expected interface for all Prober types
type Prober interface {
	Name() string
	Type() string
	Do(time.Duration) (bool, time.Duration)
}

// Configurer is the expected interface for Prober Configurer types
type Configurer interface {
	UnmarshalSettings([]byte) (Configurer, error)
	Validate() error
	AsProbe() Prober
}

// GetProbeConf returns the probe configurer specified by name from
// `observer.Registry`
func GetProbeConf(kind string, s map[string]interface{}) (Configurer, error) {
	if _, ok := Registry[kind]; ok {
		return Registry[kind], nil
	}
	return nil, fmt.Errorf("%s is not a registered probe type", kind)
}

// Register is called in every prober's `init()` function and adds the
// probe configurer to `observer.Registry`
func Register(kind string, c Configurer) {
	if _, ok := Registry[kind]; ok {
		cmd.FailOnError(
			fmt.Errorf("configurer: %s has already been added", kind), initProb)
	}
	Registry[kind] = c
}
