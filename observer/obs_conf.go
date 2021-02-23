package observer

import (
	"errors"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/observer/plugins"
)

var (
	errNewObsNoMons  = errors.New("observer config is invalid, 0 monitors configured")
	errNewObsEmpty   = errors.New("observer config is empty")
	errNewObsInvalid = errors.New("observer config is invalid")
)

// ObsConf is exported to receive the supplied observer config
type ObsConf struct {
	Syslog    cmd.SyslogConfig `yaml:"syslog"`
	DebugAddr string           `yaml:"debugAddr"`
	Modules   []plugins.Conf   `yaml:"modules"`
	Timeout   int              `yaml:"timeout"`
	NewMons   []MonConf        `yaml:"monitors"`
}

func (n *ObsConf) validateMonConfs() error {
	i := 0
	for _, m := range n.NewMons {
		if !m.Enabled {
			continue
		}
		err := m.validate()
		if err != nil {
			return err
		}
		n.NewMons[i] = m
		i++
	}
	n.NewMons = n.NewMons[:i]
	return nil
}

// Validate normalizes and validates the received monitor config
func (n *ObsConf) Validate() error {
	if n == nil {
		return errNewObsEmpty
	}
	if n.DebugAddr == "" {
		return errNewObsInvalid
	}
	err := n.validateMonConfs()
	if err != nil {
		return err
	}
	if len(n.NewMons) == 0 {
		return errNewObsNoMons
	}
	return nil
}
