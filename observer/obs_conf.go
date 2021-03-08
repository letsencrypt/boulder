package observer

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"github.com/letsencrypt/boulder/cmd"
)

// ObsConf is exported to receive yaml configuration
type ObsConf struct {
	Syslog    cmd.SyslogConfig `yaml:"syslog"`
	DebugAddr string           `yaml:"debugaddr"`
	MonConfs  []*MonConf       `yaml:"monitors"`
}

// validateSyslog ensures the the `Syslog` received by `ObsConf`
// contains valid loglevels
func (c *ObsConf) validateSyslog() error {

	if (c.Syslog.StdoutLevel > 7) || (c.Syslog.SyslogLevel > 7) {
		return fmt.Errorf(
			"invalid `syslog`, %q, log level cannot exceed 7", c.Syslog)
	}
	return nil
}

// validateDebugAddr ensures the `debugAddr` received by `ObsConf`
// is properly formatted and a valid port
func (c *ObsConf) validateDebugAddr() error {
	addrExp := regexp.MustCompile("^:([[:digit:]]{1,5})$")
	if !addrExp.MatchString(c.DebugAddr) {
		return fmt.Errorf(
			"invalid `debugaddr`, %q, not expected format", c.DebugAddr)
	}
	addrExpMatches := addrExp.FindAllStringSubmatch(c.DebugAddr, -1)
	port, _ := strconv.Atoi(addrExpMatches[0][1])
	if !(port > 0 && port < 65535) {
		return fmt.Errorf(
			"invalid `debugaddr`, %q, is not a valid port", port)
	}
	return nil
}

// validateMonConfs calls the validate method for each `MonConf`. If a
// valiation error is encountered, this is appended to a slice of
// errors. If no valid `MonConf` remain, the slice of errors is returned
// along with `false`, indicating that observer should not start
func (c *ObsConf) validateMonConfs() ([]error, bool) {
	// failed to provide any monitors
	if len(c.MonConfs) == 0 {
		return []error{errors.New("no monitors provided")}, false
	}

	var errs []error
	for _, m := range c.MonConfs {
		err := m.validate()
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(c.MonConfs) == len(errs) {
		// all configured monitors are invalid, cannot continue
		return errs, false
	}
	return errs, true
}

// validate normalizes then validates the config received the `ObsConf`
// and each of it's `MonConf`. If no valid `MonConf` remain, an error
// indicating that Observer cannot be started is returned. In all
// instances the rationale for invalidating a 'MonConf' will logged to
// stderr
func (c *ObsConf) validate() error {

	// validate `syslog`
	err := c.validateSyslog()
	if err != nil {
		return err
	}

	// validate `debugaddr`
	err = c.validateDebugAddr()
	if err != nil {
		return err
	}

	return nil
}
