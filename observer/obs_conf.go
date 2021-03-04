package observer

import (
	"errors"
	"fmt"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	p "github.com/letsencrypt/boulder/observer/probes"
)

var (
	errNewObsNoMons = errors.New("observer config is invalid, 0 monitors configured")
	errNewObsEmpty  = errors.New("observer config is empty")
)

// ObsConf is exported to receive yaml configuration
type ObsConf struct {
	Syslog    cmd.SyslogConfig `yaml:"syslog"`
	DebugAddr string           `yaml:"debugaddr"`
	Modules   []p.Configurer   `yaml:"modules"`
	MonConfs  []*MonConf       `yaml:"monitors"`
}

func (n *ObsConf) validateMonConfs() ([]error, bool) {
	var validationErrs []error
	for _, m := range n.MonConfs {
		err := m.validate()
		if err != nil {
			validationErrs = append(validationErrs, err)
		}
	}

	// all configured monitors are invalid, cannot continue
	if len(n.MonConfs) == len(validationErrs) {
		return validationErrs, false
	}
	return validationErrs, true
}

// Validate normalizes and validates the observer config as well as each
// monitor config. If no valid monitor configs remain, Validate will
// return an error indicating that observer cannot be started. In all
// instances the the rationale for invalidating a monitor will logged to
// stderr
func (n *ObsConf) Validate(log blog.Logger) error {
	if n == nil {
		return errNewObsEmpty
	}

	if len(n.MonConfs) == 0 {
		return errNewObsNoMons
	}

	logErrs := func(errs []error, lenMons int) {
		log.Errf("%d of %d monitors failed validation", len(errs), lenMons)
		for _, err := range errs {
			log.Errf("invalid monitor: %s", err)
		}
	}

	errs, ok := n.validateMonConfs()

	// if no valid mons remain, log validation errors, and return in
	// error
	if len(errs) != 0 && !ok {
		logErrs(errs, len(n.MonConfs))
		return fmt.Errorf("no valid mons, cannot continue")
	}

	// if at least 1 valid monitor remains, only log validation errors
	if len(errs) != 0 && ok {
		logErrs(errs, len(n.MonConfs))
	}
	return nil
}
