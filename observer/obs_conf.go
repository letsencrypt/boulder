package observer

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"github.com/letsencrypt/boulder/cmd"
)

var addrExp = regexp.MustCompile("^:([1-9][0-9]{0,4})$")

// ObsConf is exported to receive YAML configuration.
type ObsConf struct {
	Syslog    cmd.SyslogConfig `yaml:"syslog"`
	DebugAddr string           `yaml:"debugaddr"`
	MonConfs  []*MonConf       `yaml:"monitors"`
}

// validateSyslog ensures the the `Syslog` field received by `ObsConf`
// contains valid log levels.
func (c *ObsConf) validateSyslog() error {
	stdout := c.Syslog.StdoutLevel
	syslog := c.Syslog.SyslogLevel
	if stdout < 0 || stdout > 7 || syslog < 0 || syslog > 7 {
		return fmt.Errorf(
			"invalid `syslog`, %q, log level must be 0-7", c.Syslog)
	}
	return nil
}

// validateDebugAddr ensures the `debugAddr` received by `ObsConf` is
// properly formatted and a valid port.
func (c *ObsConf) validateDebugAddr() error {
	if !addrExp.MatchString(c.DebugAddr) {
		return fmt.Errorf(
			"invalid `debugaddr`, %q, not expected format", c.DebugAddr)
	}
	addrExpMatches := addrExp.FindAllStringSubmatch(c.DebugAddr, -1)
	port, _ := strconv.Atoi(addrExpMatches[0][1])
	if port <= 0 || port > 65535 {
		return fmt.Errorf(
			"invalid `debugaddr`, %q, is not a valid port", port)
	}
	return nil
}

// validateMonConfs calls the validate method for each `MonConf`. If a
// validation error is encountered, this is appended to a slice of
// errors. If no valid `MonConf` remain, the slice of errors is returned
// along with and error indicating that Observer should not be started.
func (c *ObsConf) validateMonConfs() ([]error, error) {
	if len(c.MonConfs) == 0 {
		return nil, errors.New("no monitors provided")
	}

	var errs []error
	for _, m := range c.MonConfs {
		err := m.validate()
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(c.MonConfs) == len(errs) {
		return errs, fmt.Errorf("no valid monitors, cannot continue")
	}
	return errs, nil
}

// validate ensures the configuration received by `ObsConf` is valid.
func (c *ObsConf) validate() error {
	err := c.validateSyslog()
	if err != nil {
		return err
	}

	err = c.validateDebugAddr()
	if err != nil {
		return err
	}

	return nil
}
