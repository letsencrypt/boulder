package plugins

import (
	"fmt"
	"plugin"
	"time"

	"gopkg.in/yaml.v2"
)

// Plugin is the expected interface for probe plugins
type Plugin interface {
	Do(time.Time, time.Duration) (bool, time.Duration)
}

// Conf is the expected interface for plugin config data
type Conf interface {
	FromSettings([]byte) (Conf, error)
	GetMonitorName() string
	Validate() error
	AsProbe() Plugin
}

// Info contains the name of the plugin and the path where it can be
// loaded from
type Info struct {
	Name string `yaml:"name"`
	Path string `yaml:"path"`
}

// GetPluginConf performs a lookup for the probe plugin specified in the
// `MonConf` and returns the specified `ProbeConf` by calling it's
// `FromSettings` method
func GetPluginConf(s map[string]interface{}, path, name string) (Conf, error) {
	settings, _ := yaml.Marshal(s)
	plugin, err := plugin.Open(path)
	if err != nil {
		return nil, fmt.Errorf("couldn't load plugin file: %q due to error: %w", path, err)
	}

	symProbeConf, err := plugin.Lookup(name)
	if err != nil {
		return nil, fmt.Errorf(
			"plugin: %q not in file: %q due to error: %w", name, path, err)
	}

	var probeConf Conf
	probeConf, ok := symProbeConf.(Conf)
	if !ok {
		return nil, fmt.Errorf(
			"plugin: %q in file: %q does not satisfy the PluginConf interface",
			name, path)
	}
	return probeConf.FromSettings(settings)
}
