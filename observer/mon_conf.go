package observer

import (
	"fmt"
	"strings"

	"github.com/letsencrypt/boulder/cmd"
	p "github.com/letsencrypt/boulder/observer/probes"
	"gopkg.in/yaml.v2"
)

type settings map[string]interface{}

// MonConf is exported to receive yaml configuration
type MonConf struct {
	Valid    bool
	Period   cmd.ConfigDuration `yaml:"period"`
	Timeout  int                `yaml:"timeout"`
	Kind     string             `yaml:"type"`
	Settings settings           `yaml:"settings"`
}

func (c MonConf) normalize() {
	c.Kind = strings.ToLower(c.Kind)
}

func (c MonConf) unmashalProbeSettings() (p.Configurer, error) {
	probeConf, err := p.GetProbeConf(c.Kind, c.Settings)
	if err != nil {
		return nil, err
	}
	s, _ := yaml.Marshal(c.Settings)
	probeConf, err = probeConf.UnmarshalSettings(s)
	if err != nil {
		return nil, err
	}
	return probeConf, nil
}

// validate normalizes and validates the received monitor config
func (c *MonConf) validate() error {
	c.normalize()
	probeConf, err := c.unmashalProbeSettings()
	if err != nil {
		return err
	}
	err = probeConf.Validate()
	if err != nil {
		return fmt.Errorf(
			"failed to validate: %s prober with settings: %+v due to: %w",
			c.Kind, probeConf, err)
	}
	c.Valid = true
	return nil
}

func (c MonConf) getProber() p.Prober {
	probeConf, _ := c.unmashalProbeSettings()
	return probeConf.AsProbe()
}
