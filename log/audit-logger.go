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
	"path"
	"runtime"
	"strings"
	"sync"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
)

// A SyslogWriter logs messages with explicit priority levels. It is
// implemented by a logging back-end like syslog.Writer or
// mocks.SyslogWriter.
type SyslogWriter interface {
	Close() error
	Alert(m string) error
	Crit(m string) error
	Debug(m string) error
	Emerg(m string) error
	Err(m string) error
	Info(m string) error
	Notice(m string) error
	Warning(m string) error
}

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

// AuditLogger implements SyslogWriter, and has additional
// audit-specific methods, like Audit(), for indicating which messages
// should be classified as audit events.
type AuditLogger struct {
	SyslogWriter
	Stats          statsd.Statter
	exitFunction   exitFunction
	stdoutLogLevel int
	clk            clock.Clock
}

const defaultPriority = syslog.LOG_INFO | syslog.LOG_LOCAL0

// NewAuditLogger returns a new AuditLogger that uses the given
// SyslogWriter as a backend.
func NewAuditLogger(log SyslogWriter, stats statsd.Statter, stdoutLogLevel int) (*AuditLogger, error) {
	if log == nil {
		return nil, errors.New("Attempted to use a nil System Logger.")
	}
	audit := &AuditLogger{
		log,
		stats,
		defaultEmergencyExit,
		stdoutLogLevel,
		clock.Default(),
	}
	return audit, nil
}

// initializeAuditLogger should only be used in unit tests.
func initializeAuditLogger() {
	stats, err := statsd.NewNoopClient(nil)
	if err != nil {
		panic(err)
	}
	syslogger, err := syslog.Dial("", "", defaultPriority, "test")
	if err != nil {
		panic(err)
	}
	audit, err := NewAuditLogger(syslogger, stats, int(syslog.LOG_DEBUG))
	if err != nil {
		panic(err)
	}

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
// The basic defaults cannot error, and subsequent access to an already-set
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
func (log *AuditLogger) logAtLevel(level syslog.Priority, msg string) error {
	var name, color string
	var err error

	const red = "\033[31m"
	const yellow = "\033[33m"

	switch level {
	case syslog.LOG_ALERT:
		err = log.SyslogWriter.Alert(msg)
		name = "ALERT"
		color = red
	case syslog.LOG_CRIT:
		err = log.SyslogWriter.Crit(msg)
		name = "CRIT"
		color = red
	case syslog.LOG_DEBUG:
		err = log.SyslogWriter.Debug(msg)
		name = "DEBUG"
	case syslog.LOG_EMERG:
		err = log.SyslogWriter.Emerg(msg)
		name = "EMERG"
		color = red
	case syslog.LOG_ERR:
		err = log.SyslogWriter.Err(msg)
		name = "ERR"
		color = red
	case syslog.LOG_INFO:
		err = log.SyslogWriter.Info(msg)
		name = "INFO"
	case syslog.LOG_WARNING:
		err = log.SyslogWriter.Warning(msg)
		name = "WARNING"
		color = yellow
	case syslog.LOG_NOTICE:
		err = log.SyslogWriter.Notice(msg)
		name = "NOTICE"
	default:
		err = fmt.Errorf("Unknown logging level: %d", int(level))
	}

	var reset string
	if color != "" {
		reset = "\033[0m"
	}

	if int(level) <= log.stdoutLogLevel {
		fmt.Printf("%s%s %s %s %s%s\n",
			color,
			log.clk.Now().Format("15:04:05"),
			path.Base(os.Args[0]),
			name,
			msg,
			reset)
	}
	return err
}

// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
func (log *AuditLogger) auditAtLevel(level syslog.Priority, msg string) (err error) {
	// Submit a separate counter that marks an Audit event
	log.Stats.Inc("Logging.Audit", 1, 1.0)

	text := fmt.Sprintf("%s %s", auditTag, msg)
	return log.logAtLevel(level, text)
}

// Return short format caller info for panic events, skipping to before the
// panic handler.
func caller(level int) string {
	_, file, line, _ := runtime.Caller(level)
	splits := strings.Split(file, "/")
	filename := splits[len(splits)-1]
	return fmt.Sprintf("%s:%d:", filename, line)
}

// AuditPanic catches panicking executables. This method should be added
// in a defer statement as early as possible
// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
func (log *AuditLogger) AuditPanic() {
	if err := recover(); err != nil {
		buf := make([]byte, 8192)
		log.AuditErr(fmt.Errorf("Panic caused by err: %s", err))

		runtime.Stack(buf, false)
		log.AuditErr(fmt.Errorf("Stack Trace (Current frame) %s", buf))

		runtime.Stack(buf, true)
		log.Warning(fmt.Sprintf("Stack Trace (All frames): %s", buf))
	}
}

// WarningErr formats an error for the Warn level.
func (log *AuditLogger) WarningErr(msg error) (err error) {
	return log.logAtLevel(syslog.LOG_WARNING, msg.Error())
}

// Alert level messages pass through normally.
func (log *AuditLogger) Alert(msg string) (err error) {
	return log.logAtLevel(syslog.LOG_ALERT, msg)
}

// Crit level messages are automatically marked for audit
func (log *AuditLogger) Crit(msg string) (err error) {
	return log.auditAtLevel(syslog.LOG_CRIT, msg)
}

// Debug level messages pass through normally.
func (log *AuditLogger) Debug(msg string) (err error) {
	return log.logAtLevel(syslog.LOG_DEBUG, msg)
}

// Emerg level messages are automatically marked for audit
func (log *AuditLogger) Emerg(msg string) (err error) {
	return log.auditAtLevel(syslog.LOG_EMERG, msg)
}

// Err level messages are automatically marked for audit
func (log *AuditLogger) Err(msg string) (err error) {
	return log.auditAtLevel(syslog.LOG_ERR, msg)
}

// Info level messages pass through normally.
func (log *AuditLogger) Info(msg string) (err error) {
	return log.logAtLevel(syslog.LOG_INFO, msg)
}

// Warning level messages pass through normally.
func (log *AuditLogger) Warning(msg string) (err error) {
	return log.logAtLevel(syslog.LOG_WARNING, msg)
}

// Notice level messages pass through normally.
func (log *AuditLogger) Notice(msg string) (err error) {
	return log.logAtLevel(syslog.LOG_NOTICE, msg)
}

// AuditNotice sends a NOTICE-severity message that is prefixed with the
// audit tag, for special handling at the upstream system logger.
func (log *AuditLogger) AuditNotice(msg string) (err error) {
	return log.auditAtLevel(syslog.LOG_NOTICE, msg)
}

func (log *AuditLogger) formatObjectMessage(msg string, obj interface{}) (string, error) {
	jsonObj, err := json.Marshal(obj)
	if err != nil {
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		log.auditAtLevel(syslog.LOG_ERR, fmt.Sprintf("Object could not be serialized to JSON. Raw: %+v", obj))
		return "", err
	}

	return fmt.Sprintf("%s JSON=%s", msg, jsonObj), nil
}

// AuditObject sends a NOTICE-severity JSON-serialized object message that is prefixed
// with the audit tag, for special handling at the upstream system logger.
func (log *AuditLogger) AuditObject(msg string, obj interface{}) (err error) {
	formattedEvent, logErr := log.formatObjectMessage(msg, obj)
	if logErr != nil {
		return logErr
	}

	return log.auditAtLevel(syslog.LOG_NOTICE, formattedEvent)
}

// InfoObject sends an INFO-severity JSON-serialized object message.
func (log *AuditLogger) InfoObject(msg string, obj interface{}) (err error) {
	formattedEvent, logErr := log.formatObjectMessage(msg, obj)
	if logErr != nil {
		return logErr
	}

	return log.logAtLevel(syslog.LOG_INFO, formattedEvent)
}

// AuditErr can format an error for auditing; it does so at ERR level.
// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
func (log *AuditLogger) AuditErr(msg error) (err error) {
	return log.auditAtLevel(syslog.LOG_ERR, msg.Error())
}

// SetEmergencyExitFunc changes the systems' behavior on an emergency exit.
func (log *AuditLogger) SetEmergencyExitFunc(exit exitFunction) {
	log.exitFunction = exit
}

// EmergencyExit triggers an immediate Boulder shutdown in the event of serious
// errors. This function will provide the necessary housekeeping.
// Currently, make an emergency log entry and exit.
// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
func (log *AuditLogger) EmergencyExit(msg string) {
	log.auditAtLevel(syslog.LOG_EMERG, msg)
	log.exitFunction()
}
