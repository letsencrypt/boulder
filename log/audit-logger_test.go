// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package log

import (
	"errors"
	"fmt"
	"log/syslog"
	"net"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/test"
)

const stdoutLevel = 7

func setup(t *testing.T) *AuditLogger {
	// Write all logs to UDP on a high port so as to not bother the system
	// which is running the test, particularly for Emerg()
	writer, err := syslog.Dial("udp", "127.0.0.1:65530", syslog.LOG_INFO|syslog.LOG_LOCAL0, "")
	test.AssertNotError(t, err, "Could not construct syslog object")

	stats, _ := statsd.NewNoopClient(nil)
	audit, err := NewAuditLogger(writer, stats, stdoutLevel)
	test.AssertNotError(t, err, "Could not construct syslog object")
	return audit
}

func TestConstruction(t *testing.T) {
	t.Parallel()
	_ = setup(t)
}

func TestSingleton(t *testing.T) {
	t.Parallel()
	log1 := GetAuditLogger()
	test.AssertNotNil(t, log1, "Logger shouldn't be nil")

	log2 := GetAuditLogger()
	test.AssertEquals(t, log1, log2)

	audit := setup(t)

	// Should not work
	err := SetAuditLogger(audit)
	test.AssertError(t, err, "Can't re-set")

	// Verify no change
	log4 := GetAuditLogger()

	// Verify that log4 != log3
	test.AssertNotEquals(t, log4, audit)

	// Verify that log4 == log2 == log1
	test.AssertEquals(t, log4, log2)
	test.AssertEquals(t, log4, log1)
}

func TestConstructionNil(t *testing.T) {
	t.Parallel()
	stats, _ := statsd.NewNoopClient(nil)
	_, err := NewAuditLogger(nil, stats, stdoutLevel)
	test.AssertError(t, err, "Nil shouldn't be permitted.")
}

func TestEmit(t *testing.T) {
	t.Parallel()
	log := setup(t)

	log.AuditNotice("test message")
}

func TestEmitEmpty(t *testing.T) {
	t.Parallel()
	log := setup(t)

	log.AuditNotice("")
}

func TestEmitErrors(t *testing.T) {
	t.Parallel()
	audit := setup(t)

	audit.AuditErr(errors.New("Error Audit"))
	audit.WarningErr(errors.New("Warning Audit"))
}

func TestSyslogMethods(t *testing.T) {
	t.Parallel()
	audit := setup(t)

	audit.AuditNotice("audit-logger_test.go: audit-notice")
	audit.AuditErr(errors.New("audit-logger_test.go: audit-err"))
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
	audit := setup(t)
	defer audit.AuditPanic()
	panic("Test panic")
	// Can't assert anything here or golint gets angry
}

func TestAuditObject(t *testing.T) {
	t.Parallel()
	audit := setup(t)

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
	audit := setup(t)

	called := false

	audit.SetEmergencyExitFunc(func() { called = true })
	audit.EmergencyExit("Emergency!")
	test.AssertEquals(t, called, true)
}

func TestUnknownLoggingLevel(t *testing.T) {
	t.Parallel()
	audit := setup(t)
	err := audit.logAtLevel(1000, "string")
	test.AssertError(t, err, "Should have been unknown.")
}

func TestTransmission(t *testing.T) {
	t.Parallel()

	l, err := newUDPListener("127.0.0.1:0")
	test.AssertNotError(t, err, "Failed to open log server")
	defer l.Close()

	stats, _ := statsd.NewNoopClient(nil)
	fmt.Printf("Going to %s\n", l.LocalAddr().String())
	writer, err := syslog.Dial("udp", l.LocalAddr().String(), syslog.LOG_INFO|syslog.LOG_LOCAL0, "")
	test.AssertNotError(t, err, "Failed to find connect to log server")

	audit, err := NewAuditLogger(writer, stats, stdoutLevel)
	test.AssertNotError(t, err, "Failed to construct audit logger")

	data := make([]byte, 128)

	audit.AuditNotice("audit-logger_test.go: audit-notice")
	_, _, err = l.ReadFrom(data)
	test.AssertNotError(t, err, "Failed to find packet")

	audit.AuditErr(errors.New("audit-logger_test.go: audit-err"))
	_, _, err = l.ReadFrom(data)
	test.AssertNotError(t, err, "Failed to find packet")

	audit.Crit("audit-logger_test.go: critical")
	_, _, err = l.ReadFrom(data)
	test.AssertNotError(t, err, "Failed to find packet")

	audit.Debug("audit-logger_test.go: debug")
	_, _, err = l.ReadFrom(data)
	test.AssertNotError(t, err, "Failed to find packet")

	audit.Emerg("audit-logger_test.go: emerg")
	_, _, err = l.ReadFrom(data)
	test.AssertNotError(t, err, "Failed to find packet")

	audit.Err("audit-logger_test.go: err")
	_, _, err = l.ReadFrom(data)
	test.AssertNotError(t, err, "Failed to find packet")

	audit.Info("audit-logger_test.go: info")
	_, _, err = l.ReadFrom(data)
	test.AssertNotError(t, err, "Failed to find packet")

	audit.Notice("audit-logger_test.go: notice")
	_, _, err = l.ReadFrom(data)
	test.AssertNotError(t, err, "Failed to find packet")

	audit.Warning("audit-logger_test.go: warning")
	_, _, err = l.ReadFrom(data)
	test.AssertNotError(t, err, "Failed to find packet")

	audit.Alert("audit-logger_test.go: alert")
	_, _, err = l.ReadFrom(data)
	test.AssertNotError(t, err, "Failed to find packet")
}

func newUDPListener(addr string) (*net.UDPConn, error) {
	l, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	l.SetDeadline(time.Now().Add(100 * time.Millisecond))
	l.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	l.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	return l.(*net.UDPConn), nil
}
