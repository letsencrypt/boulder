// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package log

import (
	"errors"
	"log/syslog"
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestConstruction(t *testing.T) {
	writer, err := syslog.New(syslog.LOG_EMERG|syslog.LOG_KERN, "tag")
	test.AssertNotError(t, err, "Could not construct syslog object")

	_, err = NewAuditLogger(writer)
	test.AssertNotError(t, err, "Could not construct audit logger")
}

func TestDial(t *testing.T) {
	_, err := Dial("", "", "tag")
	test.AssertNotError(t, err, "Could not construct audit logger")
}

func TestDialError(t *testing.T) {
	_, err := Dial("_fail", "_fail", "tag")
	test.AssertError(t, err, "Audit Logger should have failed")
}

func TestConstructionNil(t *testing.T) {
	_, err := NewAuditLogger(nil)
	test.AssertError(t, err, "Nil shouldn't be permitted.")
}

func TestEmit(t *testing.T) {
	writer, err := syslog.New(syslog.LOG_EMERG|syslog.LOG_KERN, "tag")
	test.AssertNotError(t, err, "Could not construct syslog object")

	audit, err := NewAuditLogger(writer)
	test.AssertNotError(t, err, "Could not construct audit logger")

	audit.Audit("test message")
}

func TestEmitEmpty(t *testing.T) {
	writer, err := syslog.New(syslog.LOG_EMERG|syslog.LOG_KERN, "tag")
	test.AssertNotError(t, err, "Could not construct syslog object")

	audit, err := NewAuditLogger(writer)
	test.AssertNotError(t, err, "Could not construct audit logger")

	audit.Audit("")
}

func TestEmitErrors(t *testing.T) {
	audit, _ := Dial("", "", "tag")

	audit.AuditErr(errors.New("Error Audit"))
	audit.WarningErr(errors.New("Warning Audit"))
}

func TestSyslogMethods(t *testing.T) {
	writer, err := syslog.New(syslog.LOG_EMERG|syslog.LOG_KERN, "tag")
	test.AssertNotError(t, err, "Could not construct syslog object")

	audit, err := NewAuditLogger(writer)
	test.AssertNotError(t, err, "Could not construct audit logger")

	audit.Audit("audit-logger_test.go: audit-notice")
	audit.Crit("audit-logger_test.go: critical")
	audit.Debug("audit-logger_test.go: debug")
	// Don't test Emerg... it sends a wall to the host OS.
	// audit.Emerg("audit-logger_test.go: emerg")
	audit.Err("audit-logger_test.go: err")
	audit.Info("audit-logger_test.go: info")
	audit.Notice("audit-logger_test.go: notice")
	audit.Warning("audit-logger_test.go: warning")
}
