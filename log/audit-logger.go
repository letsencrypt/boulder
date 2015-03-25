// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package log

import (
	"errors"
	"fmt"
	"log/syslog"
)

// The constant used to identify audit-specific messages
const auditTag = "[AUDIT]"

// AuditLogger is a System Logger with additional audit-specific methods.
// In addition to all the standard syslog.Writer methods from
// http://golang.org/pkg/log/syslog/#Writer, you can also call
//   auditLogger.Audit(msg string)
// to send a message as an audit event.
type AuditLogger struct {
	*syslog.Writer
}

// Dial establishes a connection to the log daemon by passing through
// the parameters to the syslog.Dial method.
// See http://golang.org/pkg/log/syslog/#Dial
func Dial(network, raddr string, tag string) (*AuditLogger, error) {
	syslogger, err := syslog.Dial(network, raddr, syslog.LOG_INFO|syslog.LOG_LOCAL0, tag)
	if err != nil {
		return nil, err
	}
	return NewAuditLogger(syslogger)
}

// NewAuditLogger constructs an Audit Logger that decorates a normal
// System Logger. All methods in log/syslog continue to work.
func NewAuditLogger(log *syslog.Writer) (*AuditLogger, error) {
	if log == nil {
		return nil, errors.New("Attempted to use a nil System Logger.")
	}
	return &AuditLogger{log}, nil
}

// Audit sends a NOTICE-severity message that is prefixed with the
// audit tag, for special handling at the upstream system logger.
func (log *AuditLogger) Audit(msg string) (err error) {
	err = log.Notice(fmt.Sprintf("%s %s", auditTag, msg))
	return
}

// Audit can format an error for auditing; it does so at ERR level.
func (log *AuditLogger) AuditErr(msg error) (err error) {
	err = log.Err(fmt.Sprintf("%s %s", auditTag, msg))
	return
}

// Warning formats an error for the Warn level.
func (log *AuditLogger) WarningErr(msg error) (err error) {
	err = log.Warning(fmt.Sprintf("%s", msg))
	return
}
