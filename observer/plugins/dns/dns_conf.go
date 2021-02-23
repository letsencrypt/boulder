package main

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/letsencrypt/boulder/observer/plugins"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v2"
)

var (
	errNewMonDNSEmpty   = errors.New("monitor DNS config is empty")
	errNewMonDNSInvalid = errors.New("monitor DNS config is invalid")

	validQprotos = []string{"udp", "tcp"}
	validQtypes  = map[string]uint16{"A": 1, "TXT": 16, "AAAA": 28, "CAA": 257}
)

// DNS is the exported name of the DNS probe plugin
var DNS Conf

// Conf is exported to receive the supplied probe config
type Conf struct {
	QProto   string `yaml:"qproto"`
	QRecurse bool   `yaml:"qrecurse"`
	QName    string `yaml:"qname"`
	QServer  string `yaml:"qserver"`
	QType    string `yaml:"qtype"`
}

func (c Conf) normalize() {
	c.QProto = strings.ToLower(c.QProto)
	c.QName = strings.ToLower(c.QName)
	c.QServer = strings.ToLower(c.QServer)
	c.QType = strings.ToLower(c.QType)
}

// Validate normalizes and validates the received probe config
func (c Conf) Validate() error {
	c.normalize()
	qprotoValid := func() bool {
		for _, i := range validQprotos {
			if c.QProto == i {
				return true
			}
		}
		return false
	}()
	if !qprotoValid {
		return fmt.Errorf("Invalid qproto: %w", errNewMonDNSInvalid)
	}
	if !dns.IsFqdn(dns.Fqdn(c.QName)) {
		return fmt.Errorf("Invalid qname: %w", errNewMonDNSInvalid)
	}
	if net.ParseIP(c.QServer) == nil {
		if !dns.IsFqdn(dns.Fqdn(c.QServer)) {
			return fmt.Errorf("Invalid qserver: %w", errNewMonDNSInvalid)
		}
	}
	qtypeValid := func() bool {
		for i := range validQtypes {
			if c.QType == i {
				return true
			}
		}
		return false
	}()
	if !qtypeValid {
		return fmt.Errorf("Invalid qtype: %w", errNewMonDNSInvalid)
	}

	return nil
}

// GetMonitorName returns a name that uniquely identifies the monitor
func (c Conf) GetMonitorName() string {
	return fmt.Sprintf("%s-%s-%s-%s", c.QProto, c.QServer, c.QName, c.QType)
}

// FromSettings returns the supplied settings as an `Observer.PluginConf`
func (c Conf) FromSettings(settings []byte) (plugins.Conf, error) {
	var conf Conf
	err := yaml.Unmarshal(settings, &conf)
	if err != nil {
		return nil, fmt.Errorf("couldn't unmarshal settings for dns plugin: %w", err)
	}
	return conf, nil
}

// AsProbe returns the `Conf` object as a DNS probe
func (c Conf) AsProbe() plugins.Plugin {
	return Probe{
		QProto:   c.QProto,
		QRecurse: c.QRecurse,
		QName:    c.QName,
		QServer:  c.QServer,
		QType:    validQtypes[c.QType],
	}
}
