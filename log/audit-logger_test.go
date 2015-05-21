// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package log

import (
	"errors"
	"log/syslog"
	"testing"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/test"
)

func TestConstruction(t *testing.T) {
	t.Parallel()
	writer, err := syslog.New(syslog.LOG_EMERG|syslog.LOG_KERN, "tag")
	test.AssertNotError(t, err, "Could not construct syslog object")

	stats, _ := statsd.NewNoopClient(nil)
	_, err = NewAuditLogger(writer, stats)
	test.AssertNotError(t, err, "Could not construct audit logger")
}

func TestSingleton(t *testing.T) {
	t.Parallel()
	log1 := GetAuditLogger()
	test.AssertNotNil(t, log1, "Logger shouldn't be nil")

	log2 := GetAuditLogger()
	test.AssertEquals(t, log1, log2)

	writer, err := syslog.New(syslog.LOG_EMERG|syslog.LOG_KERN, "tag")
	test.AssertNotError(t, err, "Could not construct syslog object")

	stats, _ := statsd.NewNoopClient(nil)
	log3, err := NewAuditLogger(writer, stats)
	test.AssertNotError(t, err, "Could not construct audit logger")

	// Should not work
	err = SetAuditLogger(log3)
	test.AssertError(t, err, "Can't re-set")

	// Verify no change
	log4 := GetAuditLogger()

	// Verify that log4 != log3
	test.AssertNotEquals(t, log4, log3)

	// Verify that log4 == log2 == log1
	test.AssertEquals(t, log4, log2)
	test.AssertEquals(t, log4, log1)
}

func TestDial(t *testing.T) {
	t.Parallel()
	stats, _ := statsd.NewNoopClient(nil)
	_, err := Dial("", "", "tag", stats)
	test.AssertNotError(t, err, "Could not construct audit logger")
}

func TestDialError(t *testing.T) {
	t.Parallel()
	stats, _ := statsd.NewNoopClient(nil)
	_, err := Dial("_fail", "_fail", "tag", stats)
	test.AssertError(t, err, "Audit Logger should have failed")
}

func TestConstructionNil(t *testing.T) {
	t.Parallel()
	stats, _ := statsd.NewNoopClient(nil)
	_, err := NewAuditLogger(nil, stats)
	test.AssertError(t, err, "Nil shouldn't be permitted.")
}

func TestEmit(t *testing.T) {
	t.Parallel()
	writer, err := syslog.New(syslog.LOG_EMERG|syslog.LOG_KERN, "tag")
	test.AssertNotError(t, err, "Could not construct syslog object")

	stats, _ := statsd.NewNoopClient(nil)
	audit, err := NewAuditLogger(writer, stats)
	test.AssertNotError(t, err, "Could not construct audit logger")

	audit.Audit("test message")
}

func TestEmitEmpty(t *testing.T) {
	t.Parallel()
	writer, err := syslog.New(syslog.LOG_EMERG|syslog.LOG_KERN, "tag")
	test.AssertNotError(t, err, "Could not construct syslog object")

	stats, _ := statsd.NewNoopClient(nil)
	audit, err := NewAuditLogger(writer, stats)
	test.AssertNotError(t, err, "Could not construct audit logger")

	audit.Audit("")
}

func TestEmitErrors(t *testing.T) {
	t.Parallel()
	stats, _ := statsd.NewNoopClient(nil)
	audit, _ := Dial("", "", "tag", stats)

	audit.AuditErr(errors.New("Error Audit"))
	audit.WarningErr(errors.New("Warning Audit"))
}

func TestSyslogMethods(t *testing.T) {
	t.Parallel()
	// Write all logs to UDP on a high port so as to not bother the system
	// which is running the test, particularly for Emerg()
	writer, err := syslog.Dial("udp", "127.0.0.1:65530", syslog.LOG_INFO|syslog.LOG_LOCAL0, "")
	test.AssertNotError(t, err, "Could not construct syslog object")

	stats, _ := statsd.NewNoopClient(nil)
	audit, err := NewAuditLogger(writer, stats)
	test.AssertNotError(t, err, "Could not construct audit logger")

	audit.Audit("audit-logger_test.go: audit-notice")
	audit.Crit("audit-logger_test.go: critical")
	audit.Debug("audit-logger_test.go: debug")
	audit.Emerg("audit-logger_test.go: emerg")
	audit.Err("audit-logger_test.go: err")
	audit.Info("audit-logger_test.go: info")
	audit.Notice("audit-logger_test.go: notice")
	audit.Warning("audit-logger_test.go: warning")
	audit.Alert("audit-logger_test.go: alert")
}

func TestPanic(t *testing.T) {
	t.Parallel()
	stats, _ := statsd.NewNoopClient(nil)
	audit, _ := Dial("", "", "tag", stats)
	defer audit.AuditPanic()
	panic("Test panic")
	// Can't assert anything here or golint gets angry
}

func TestAuditObject(t *testing.T) {
	t.Parallel()
	stats, _ := statsd.NewNoopClient(nil)
	audit, _ := Dial("", "", "tag", stats)

	// Test a simple object
	err := audit.AuditObject("Prefix", "String")
	test.AssertNotError(t, err, "Simple objects should be serializable")

	// Test a system object
	err = audit.AuditObject("Prefix", t)
	test.AssertNotError(t, err, "System objects should be serializable")

	// Test a complex object
	type validObj struct {
		A string
		B string
	}
	var valid = validObj{A: "B", B: "C"}
	err = audit.AuditObject("Prefix", valid)
	test.AssertNotError(t, err, "Complex objects should be serializable")

	type invalidObj struct {
		A chan string
	}

	var invalid = invalidObj{A: make(chan string)}
	err = audit.AuditObject("Prefix", invalid)
	test.AssertError(t, err, "Invalid objects should fail serialization")

}

func TestEmergencyExit(t *testing.T) {
	t.Parallel()
	// Write all logs to UDP on a high port so as to not bother the system
	// which is running the test, particularly for Emerg()
	writer, err := syslog.Dial("udp", "127.0.0.1:65530", syslog.LOG_INFO|syslog.LOG_LOCAL0, "")
	test.AssertNotError(t, err, "Could not construct syslog object")

	stats, _ := statsd.NewNoopClient(nil)
	audit, err := NewAuditLogger(writer, stats)
	test.AssertNotError(t, err, "Could not construct audit logger")

	called := false

	audit.SetEmergencyExitFunc(func() { called = true })
	audit.EmergencyExit("Emergency!")
	test.AssertEquals(t, called, true)
}
