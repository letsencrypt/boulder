package observer

import (
	"errors"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	p "github.com/letsencrypt/boulder/observer/probers"
	_ "github.com/letsencrypt/boulder/observer/probers/mock"
)

const (
	dbzErrMsg = "over 9000"
)

var dbzErr = errors.New(dbzErrMsg)

var validMonSettings = p.Settings{"valid": true, "pname": "foo", "pkind": "bar"}
var invalidMonSettings = p.Settings{"valid": false, "errmsg": dbzErrMsg, "pname": "foo", "pkind": "bar"}

var cfgSyslog = cmd.SyslogConfig{StdoutLevel: 6, SyslogLevel: 6}
var cfgDur = cmd.ConfigDuration{Duration: time.Second * 5}

var validMonConf = &MonConf{cfgDur, 10, "MockConf", validMonSettings, true}
var invalidMonConf = &MonConf{cfgDur, 10, "MockConf", invalidMonSettings, false}

func TestObsConf_validateMonConfs(t *testing.T) {
	type fields struct {
		Syslog    cmd.SyslogConfig
		DebugAddr string
		MonConfs  []*MonConf
	}
	tests := []struct {
		name   string
		fields fields
		errs   []error
		ok     bool
	}{
		// valid
		{"1 valid", fields{cfgSyslog, ":9090", []*MonConf{validMonConf}}, []error{}, true},
		{"1 valid, 1 invalid", fields{
			cfgSyslog, ":9090", []*MonConf{validMonConf, invalidMonConf}}, []error{dbzErr}, true},
		{"1 invalid, 2 invalid", fields{
			cfgSyslog, ":9090", []*MonConf{validMonConf, invalidMonConf, invalidMonConf}}, []error{dbzErr, dbzErr}, true},
		// invalid
		{"no valid mons", fields{cfgSyslog, ":9090", []*MonConf{invalidMonConf}}, []error{dbzErr}, false},
		{"no mons at all", fields{cfgSyslog, ":9090", []*MonConf{}}, []error{errors.New("no monitors provided")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ObsConf{
				Syslog:    tt.fields.Syslog,
				DebugAddr: tt.fields.DebugAddr,
				MonConfs:  tt.fields.MonConfs,
			}
			errs, ok := c.validateMonConfs()
			if len(errs) != len(tt.errs) {
				t.Errorf("ObsConf.validateMonConfs() errs = %d, want %d", len(errs), len(tt.errs))
				t.Log(errs)
			}
			if ok != tt.ok {
				t.Errorf("ObsConf.validateMonConfs() ok = %v, want %v", ok, tt.ok)
			}
		})
	}
}

func TestObsConf_ValidateDebugAddr(t *testing.T) {
	type fields struct {
		DebugAddr string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		// valid
		{"valid", fields{":8080"}, false},
		// invalid
		{"out of range high", fields{":65536"}, true},
		{"out of range low", fields{":0"}, true},
		{"not even a port", fields{":foo"}, true},
		{"missing :", fields{"foo"}, true},
		{"missing port", fields{"foo:"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ObsConf{
				DebugAddr: tt.fields.DebugAddr,
			}
			if err := c.validateDebugAddr(); (err != nil) != tt.wantErr {
				t.Errorf("ObsConf.ValidateDebugAddr() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestObsConf_validateSyslog(t *testing.T) {
	type fields struct {
		Syslog cmd.SyslogConfig
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		// valid
		{"valid", fields{cmd.SyslogConfig{StdoutLevel: 6, SyslogLevel: 6}}, false},
		// invalid
		{"both too high", fields{cmd.SyslogConfig{StdoutLevel: 9, SyslogLevel: 9}}, true},
		{"stdout too high", fields{cmd.SyslogConfig{StdoutLevel: 9, SyslogLevel: 6}}, true},
		{"stderr too high", fields{cmd.SyslogConfig{StdoutLevel: 6, SyslogLevel: 9}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ObsConf{
				Syslog: tt.fields.Syslog,
			}
			if err := c.validateSyslog(); (err != nil) != tt.wantErr {
				t.Errorf("ObsConf.validateSyslog() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
