package observer

import (
	"fmt"
	"strings"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/observer/probers"
	"gopkg.in/yaml.v2"
)

// MonConf is exported to receive YAML configuration in `ObsConf`.
type MonConf struct {
	Period   cmd.ConfigDuration `yaml:"period"`
	Timeout  int                `yaml:"timeout"`
	Kind     string             `yaml:"kind"`
	Settings probers.Settings   `yaml:"settings"`
}

// unmarshalProbeSettings attempts to unmarshal the value of the
// `Settings` field to the `Configurer` type specified by the `Kind`
// field.
func (c MonConf) unmarshalProbeSettings() (probers.Configurer, error) {
	kind := strings.Trim(strings.ToLower(c.Kind), " ")
	configurer, err := probers.GetConfigurer(kind, c.Settings)
	if err != nil {
		return nil, err
	}
	s, _ := yaml.Marshal(c.Settings)
	configurer, err = configurer.UnmarshalSettings(s)
	if err != nil {
		return nil, err
	}
	return configurer, nil
}

// validate ensures the received `MonConf` is valid by calling
// `Validate` method of the `Configurer`type specified by the `Kind`
// field.
func (c *MonConf) validate() error {
	configurer, err := c.unmarshalProbeSettings()
	if err != nil {
		return err
	}

	err = configurer.Validate()
	if err != nil {
		return fmt.Errorf(
			"failed to validate: %s configurer with settings: %+v due to: %w",
			c.Kind, c.Settings, err)
	}
	return nil
}

func (c MonConf) makeProber() probers.Prober {
	probeConf, _ := c.unmarshalProbeSettings()
	return probeConf.MakeProber()
}
