// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package log

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/syslog"
	"os"
	"sync"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
)

// singleton defines the object of a Singleton pattern
type singleton struct {
	once sync.Once
	log  *AuditLogger
}

// _Singleton is the single AuditLogger entity in memory
var _Singleton singleton

// The constant used to identify audit-specific messages
const auditTag = "[AUDIT]"

// Constant used to indicate an emergency exit to the executor
const emergencyReturnValue = 13

// exitFunction closes the running system
type exitFunction func()

// Default to calling os.Exit()
func defaultEmergencyExit() {
	os.Exit(emergencyReturnValue)
}

// AuditLogger is a System Logger with additional audit-specific methods.
// In addition to all the standard syslog.Writer methods from
// http://golang.org/pkg/log/syslog/#Writer, you can also call
//   auditLogger.Audit(msg string)
// to send a message as an audit event.
type AuditLogger struct {
	*syslog.Writer
	Stats        statsd.Statter
	exitFunction exitFunction
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
	audit := &AuditLogger{
		log,
		stats,
		defaultEmergencyExit,
	}
	return audit, nil
}

// initializeAuditLogger should only be used in unit tests. Failures in this
// method are unlikely as the defaults are safe, and they are also
// of minimal consequence during unit testing -- logs get printed to stdout
// even if syslog is missing.
func initializeAuditLogger() {
	stats, _ := statsd.NewNoopClient(nil)
	audit, _ := Dial("", "", "default", stats)
	audit.Notice("Using default logging configuration.")

	SetAuditLogger(audit)
}

// SetAuditLogger configures the singleton audit logger. This method
// must only be called once, and before calling GetAuditLogger the
// first time.
func SetAuditLogger(logger *AuditLogger) (err error) {
	if _Singleton.log != nil {
		err = errors.New("You may not call SetAuditLogger after it has already been implicitly or explicitly set.")
		_Singleton.log.WarningErr(err)
	} else {
		_Singleton.log = logger
	}
	return
}

// GetAuditLogger obtains the singleton audit logger. If SetAuditLogger
// has not been called first, this method initializes with basic defaults.
// The basic defaults cannot error, and subequent access to an already-set
// AuditLogger also cannot error, so this method is error-safe.
func GetAuditLogger() *AuditLogger {
	_Singleton.once.Do(func() {
		if _Singleton.log == nil {
			initializeAuditLogger()
		}
	})

	return _Singleton.log
}

// Log the provided message at the appropriate level, writing to
// both stdout and the Logger, as well as informing statsd.
func (log *AuditLogger) logAtLevel(level, msg string) (err error) {
	fmt.Printf("%s\n", msg)
	log.Stats.Inc(level, 1, 1.0)

	switch level {
	case "Logging.Alert":
		err = log.Writer.Alert(msg)
	case "Logging.Crit":
		err = log.Writer.Crit(msg)
	case "Logging.Debug":
		err = log.Writer.Debug(msg)
	case "Logging.Emerg":
		err = log.Writer.Emerg(msg)
	case "Logging.Err":
		err = log.Writer.Err(msg)
	case "Logging.Info":
		err = log.Writer.Info(msg)
	case "Logging.Warning":
		err = log.Writer.Warning(msg)
	}
	return
}

// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
func (log *AuditLogger) auditAtLevel(level, msg string) (err error) {
	// Submit a separate counter that marks an Audit event
	log.Stats.Inc("Logging.Audit", 1, 1.0)

	text := fmt.Sprintf("%s %s", auditTag, msg)
	return log.logAtLevel(level, text)
}

// AuditPanic catches panicking executables. This method should be added
// in a defer statement as early as possible
// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
func (log *AuditLogger) AuditPanic() {
	if err := recover(); err != nil {
		log.Audit(fmt.Sprintf("Panic: %v", err))
	}
}

// WarningErr formats an error for the Warn level.
func (log *AuditLogger) WarningErr(msg error) (err error) {
	return log.logAtLevel("Logging.Warning", msg.Error())
}

// Alert level messages pass through normally.
func (log *AuditLogger) Alert(msg string) (err error) {
	return log.logAtLevel("Logging.Alert", msg)
}

// Crit level messages are automatically marked for audit
func (log *AuditLogger) Crit(msg string) (err error) {
	return log.auditAtLevel("Logging.Crit", msg)
}

// Debug level messages pass through normally.
func (log *AuditLogger) Debug(msg string) (err error) {
	return log.logAtLevel("Logging.Debug", msg)
}

// Emerg level messages are automatically marked for audit
func (log *AuditLogger) Emerg(msg string) (err error) {
	return log.auditAtLevel("Logging.Emerg", msg)
}

// Err level messages are automatically marked for audit
func (log *AuditLogger) Err(msg string) (err error) {
	return log.auditAtLevel("Logging.Err", msg)
}

// Info level messages pass through normally.
func (log *AuditLogger) Info(msg string) (err error) {
	return log.logAtLevel("Logging.Info", msg)
}

// Warning level messages pass through normally.
func (log *AuditLogger) Warning(msg string) (err error) {
	return log.logAtLevel("Logging.Warning", msg)
}

// Notice level messages pass through normally.
func (log *AuditLogger) Notice(msg string) (err error) {
	return log.logAtLevel("Logging.Notice", msg)
}

// Audit sends a NOTICE-severity message that is prefixed with the
// audit tag, for special handling at the upstream system logger.
func (log *AuditLogger) Audit(msg string) (err error) {
	return log.auditAtLevel("Logging.Notice", msg)
}

// AuditObject sends a NOTICE-severity JSON-serialized object message that is prefixed
// with the audit tag, for special handling at the upstream system logger.
func (log *AuditLogger) AuditObject(msg string, obj interface{}) (err error) {
	jsonLogEvent, logErr := json.Marshal(obj)
	if logErr != nil {
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		log.auditAtLevel("Logging.Err", fmt.Sprintf("%s - logEvent could not be serialized. Raw: %+v", msg, obj))
		return logErr
	}

	return log.auditAtLevel("Logging.Notice", fmt.Sprintf("%s - %s", msg, jsonLogEvent))
}

// AuditErr can format an error for auditing; it does so at ERR level.
// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
func (log *AuditLogger) AuditErr(msg error) (err error) {
	return log.auditAtLevel("Logging.Err", msg.Error())
}

// SetEmergencyExitFunc changes the systems' behavior on an emergency exit.
func (log *AuditLogger) SetEmergencyExitFunc(exit exitFunction) {
	log.exitFunction = exit
}

// EmergencyExit triggers an immediate Boulder shutdown in the event of serious
// errors. This function will provide the necessary housekeeping.
// Currently, make an emergency log entry and exit; the Activity Monitor
// should notice the Emerg level event and shut down all components.
// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
func (log *AuditLogger) EmergencyExit(msg string) {
	log.auditAtLevel("Logging.Emerg", msg)
	log.exitFunction()
}
