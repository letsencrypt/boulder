package main

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/letsencrypt/boulder/observer/plugins"
	"gopkg.in/yaml.v2"
)

var (
	errNewMonHTTPEmpty   = errors.New("monitor HTTP config is empty")
	errNewMonHTTPInvalid = errors.New("monitor HTTP config is invalid")
)

// HTTP is the exported name of the HTTP probe
var HTTP Conf

// Conf is exported to receive the supplied probe config
type Conf struct {
	URL   string `yaml:"url"`
	RCode int    `yaml:"rcode"`
}

func (c Conf) normalize() {
	c.URL = strings.ToLower(c.URL)
}

// Validate normalizes and validates the received probe config
func (c Conf) Validate() error {
	c.normalize()
	_, err := url.ParseRequestURI(c.URL)
	if err != nil {
		return errNewMonHTTPInvalid
	}
	return nil
}

// GetMonitorName returns a name that uniquely identifies the monitor
func (c Conf) GetMonitorName() string {
	return fmt.Sprintf("%s-%d", c.URL, c.RCode)
}

// FromSettings returns the supplied settings as an `Observer.PluginConf`
func (c Conf) FromSettings(settings []byte) (plugins.Conf, error) {
	err := yaml.Unmarshal(settings, &c)
	if err != nil {
		return nil, fmt.Errorf("couldn't unmarshal settings for http plugin: %w", err)
	}
	return c, nil
}

// AsProbe returns the NewHTTP object as an HTTP probe
func (c Conf) AsProbe() plugins.Plugin {
	url, _ := url.Parse(c.URL)
	return Probe{URL: *url, RCode: c.RCode}
}
