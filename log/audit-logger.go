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
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
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

// NewAuditLogger returns a new AuditLogger that uses the given
// SyslogWriter as a backend.
func NewAuditLogger(log SyslogWriter, stats statsd.Statter) (*AuditLogger, error) {
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

// initializeAuditLogger should only be used in unit tests.
func initializeAuditLogger() {
	stats, err := statsd.NewNoopClient(nil)
	if err != nil {
		panic(err)
	}
	audit, err := Dial("", "", "default", stats)
	if err != nil {
		panic(err)
	}
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
	fmt.Printf("%s %s\n", time.Now().Format("2006/01/02 15:04:05"), msg)
	log.Stats.Inc(level, 1, 1.0)

	switch level {
	case "Logging.Alert":
		err = log.SyslogWriter.Alert(msg)
	case "Logging.Crit":
		err = log.SyslogWriter.Crit(msg)
	case "Logging.Debug":
		err = log.SyslogWriter.Debug(msg)
	case "Logging.Emerg":
		err = log.SyslogWriter.Emerg(msg)
	case "Logging.Err":
		err = log.SyslogWriter.Err(msg)
	case "Logging.Info":
		err = log.SyslogWriter.Info(msg)
	case "Logging.Warning":
		err = log.SyslogWriter.Warning(msg)
	case "Logging.Notice":
		err = log.SyslogWriter.Notice(msg)
	default:
		err = fmt.Errorf("Unknown logging level: %s", level)
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
		log.Audit(fmt.Sprintf("Panic caused by err: %s", err))

		runtime.Stack(buf, false)
		log.Audit(fmt.Sprintf("Stack Trace (Current frame) %s", buf))

		runtime.Stack(buf, true)
		log.Warning(fmt.Sprintf("Stack Trace (All frames): %s", buf))
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

func (log *AuditLogger) formatObjectMessage(msg string, obj interface{}) (string, error) {
	jsonObj, err := json.Marshal(obj)
	if err != nil {
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		log.auditAtLevel("Logging.Err", fmt.Sprintf("Object could not be serialized to JSON. Raw: %+v", obj))
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

	return log.auditAtLevel("Logging.Notice", formattedEvent)
}

// InfoObject sends a INFO-severity JSON-serialized object message.
func (log *AuditLogger) InfoObject(msg string, obj interface{}) (err error) {
	formattedEvent, logErr := log.formatObjectMessage(msg, obj)
	if logErr != nil {
		return logErr
	}

	return log.logAtLevel("Logging.Info", formattedEvent)
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
