// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package log

import (
	"errors"
	"fmt"
	"log/syslog"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
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
	Stats statsd.Statter
}

// TestLogger returns an AuditLogger, required to initialize many components
func TestLogger() (logger *AuditLogger) {
	stats, _ := statsd.NewNoopClient(nil)
	// Audit logger
	logger, _ = Dial("", "", "tag", stats)
	return
}

// Dial establishes a connection to the log daemon by passing through
// the parameters to the syslog.Dial method.
// See http://golang.org/pkg/log/syslog/#Dial
func Dial(network, raddr string, tag string, stats statsd.Statter) (*AuditLogger, error) {
	syslogger, err := syslog.Dial(network, raddr, syslog.LOG_INFO|syslog.LOG_LOCAL0, tag)
	if err != nil {
		return nil, err
	}
	return NewAuditLogger(syslogger, stats)
}

// NewAuditLogger constructs an Audit Logger that decorates a normal
// System Logger. All methods in log/syslog continue to work.
func NewAuditLogger(log *syslog.Writer, stats statsd.Statter) (*AuditLogger, error) {
	if log == nil {
		return nil, errors.New("Attempted to use a nil System Logger.")
	}
	return &AuditLogger{log, stats}, nil
}

// Audit sends a NOTICE-severity message that is prefixed with the
// audit tag, for special handling at the upstream system logger.
func (log *AuditLogger) Audit(msg string) (err error) {
	fmt.Println(msg)
	err = log.Notice(fmt.Sprintf("%s %s", auditTag, msg))

	log.Stats.Inc("Logging.Audit", 1, 1.0)

	return
}

// Audit can format an error for auditing; it does so at ERR level.
func (log *AuditLogger) AuditErr(msg error) (err error) {
	fmt.Println(msg)
	err = log.Err(fmt.Sprintf("%s %s", auditTag, msg))

	log.Stats.Inc("Logging.Audit", 1, 1.0)

	return
}

func (log *AuditLogger) auditAtLevel(level, msg string) (err error) {
	fmt.Println(msg)
	log.Stats.Inc(level, 1, 1, 0)
	text := fmt.Sprintf("%s %s", auditTag, msg)
	switch level {
	case "Logging.Alert":
		err = log.Writer.Alert(text)
	case "Logging.Crit":
		err = log.Writer.Crit(text)
	case "Logging.Debug":
		err = log.Writer.Debug(text)
	case "Logging.Emerg":
		err = log.Writer.Emerg(text)
	case "Logging.Err":
		err = log.Writer.Err(text)
	case "Logging.Info":
		err = log.Writer.Info(text)
	case "Logging.Warning":
		err = log.Writer.Warning(text)
	}
	return
}

// To catch panics in executables, this method should be added
// in a defer statement as early as possible
func (log *AuditLogger) AuditPanic() {
	if err := recover(); err != nil {
		log.Audit(fmt.Sprintf("Panic: %v", err))
	}
}

// Warning formats an error for the Warn level.
func (log *AuditLogger) WarningErr(msg error) (err error) {
	fmt.Println(msg)
	err = log.Warning(fmt.Sprintf("%s", msg))

	return
}

func (log *AuditLogger) Alert(msg string) (err error) {
	fmt.Println(msg)
	log.Stats.Inc("Logging.Alert", 1, 1.0)
	return log.Writer.Alert(msg)
}

// Crit-level messages are automatically marked for audit
func (log *AuditLogger) Crit(msg string) (err error) {
	return log.auditAtLevel("Logging.Crit", msg)
}

func (log *AuditLogger) Debug(msg string) (err error) {
	fmt.Println(msg)
	log.Stats.Inc("Logging.Debug", 1, 1.0)
	return log.Writer.Debug(msg)
}

// Emerg-level messages are automatically marked for audit
func (log *AuditLogger) Emerg(msg string) (err error) {
	return log.auditAtLevel("Logging.Emerg", msg)
}

// Err-level messages are automatically marked for audit
func (log *AuditLogger) Err(msg string) (err error) {
	return log.auditAtLevel("Logging.Err", msg)
}

func (log *AuditLogger) Info(msg string) (err error) {
	fmt.Println(msg)
	log.Stats.Inc("Logging.Info", 1, 1.0)
	return log.Writer.Info(msg)
}

func (log *AuditLogger) Warning(msg string) (err error) {
	fmt.Println(msg)
	log.Stats.Inc("Logging.Warning", 1, 1.0)
	return log.Writer.Warning(msg)
}

func (log *AuditLogger) Notice(msg string) (err error) {
	fmt.Println(msg)
	log.Stats.Inc("Logging.Notice", 1, 1.0)
	return log.Writer.Notice(msg)
}
