package observer

import (
	"errors"
	"fmt"
	"strings"

	"github.com/letsencrypt/boulder/observer/plugins"
)

var (
	errNewMonEmpty   = errors.New("monitor config is empty")
	errNewMonInvalid = errors.New("monitor config is invalid")
)

// MonConf is exported to receive the supplied monitor config
type MonConf struct {
	Enabled  bool                   `yaml:"enabled"`
	Period   int                    `yaml:"period"`
	Timeout  int                    `yaml:"timeout"`
	Plugin   plugins.Info           `yaml:"plugin"`
	Settings map[string]interface{} `yaml:"settings"`
}

func (c MonConf) normalize() {
	c.Plugin.Name = strings.ToLower(c.Plugin.Name)
	c.Plugin.Path = strings.ToLower(c.Plugin.Path)
}

// validate normalizes and validates the received monitor config
func (c MonConf) validate() error {
	c.normalize()
	pluginConf, err := plugins.GetPluginConf(c.Settings, c.Plugin.Path, c.Plugin.Name)
	if err != nil {
		if err != nil {
			return fmt.Errorf("failed to get plugin: %w", err)
		}
	}
	err = pluginConf.Validate()
	if err != nil {
		return fmt.Errorf("failed to validate plugin settings: %w", err)
	}
	return nil
}
