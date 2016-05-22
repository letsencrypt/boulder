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

	"github.com/jmhodges/clock"
)

// A Logger logs messages with explicit priority levels. It is
// implemented by a logging back-end as provided by New() or
// NewMock().
type Logger interface {
	Err(m string)
	Warning(m string)
	Info(m string)
	Debug(m string)
	AuditPanic()
	AuditInfo(string)
	AuditObject(string, interface{})
	AuditErr(error)
}

// impl implements Logger.
type impl struct {
	w writer
}

// singleton defines the object of a Singleton pattern
type singleton struct {
	once sync.Once
	log  Logger
}

// _Singleton is the single impl entity in memory
var _Singleton singleton

// The constant used to identify audit-specific messages
const auditTag = "[AUDIT]"

const syslogDefaultFacility = syslog.LOG_LOCAL0

// New returns a new Logger that uses the given syslog.Writer as a backend.
func New(syslogNetwork, syslogAddr, syslogTag string, stdoutLogLevel int) (Logger, error) {
	syslogIsStdout := false
	logForTerminal := false
	if syslogNetwork == "" {
		if syslogAddr != "" {
			return nil, fmt.Errorf(
				"syslog address must be empty when network is empty while %s was given", syslogAddr)
		}
		if s := os.Getenv("STDOUT_LOG"); s != "" {
			syslogIsStdout = true
			if s == "terminal" {
				logForTerminal = true
			} else if s != "plain" {
				return nil, fmt.Errorf(
					"STDOUT_LOG must be either plain or terminal while %s was given", s)
			}
		}
	}
	if syslogTag == "" {
		syslogTag = path.Base(os.Args[0])
	}

	var syslogger *syslog.Writer
	var stdoutLog *stdoutLog
	var err error
	if syslogIsStdout {
		// When we log to stdout, use stdoutLogLevel above error
		// as a hint to show colors.
		stdoutLog = newStdoutLog(syslogTag, 7, logForTerminal)
	} else {
		if stdoutLogLevel >= int(syslog.LOG_ERR) {
			// Always format as if for terminal when stdout log is an
			// extra log beyond syslog.
			stdoutLog = newStdoutLog(syslogTag, stdoutLogLevel, true)
		}
		syslogger, err = syslog.Dial(
			syslogNetwork,
			syslogAddr,
			syslogDefaultFacility|syslog.LOG_INFO, // default, overridden by log calls
			syslogTag)
	}
	if err != nil {
		return nil, err
	}
	return &impl{
		&bothWriter{syslogger, stdoutLog},
	}, nil
}

// initialize should only be used in unit tests.
func initialize() {
	logger, err := New("", "", "test", int(syslog.LOG_DEBUG))
	if err != nil {
		panic(err)
	}

	_ = Set(logger)
}

// Set configures the singleton Logger. This method
// must only be called once, and before calling Get the
// first time.
func Set(logger Logger) (err error) {
	if _Singleton.log != nil {
		err = errors.New("You may not call Set after it has already been implicitly or explicitly set.")
		_Singleton.log.Warning(err.Error())
	} else {
		_Singleton.log = logger
	}
	return
}

// Get obtains the singleton Logger. If Set has not been called first, this
// method initializes with basic defaults.  The basic defaults cannot error, and
// subsequent access to an already-set Logger also cannot error, so this method is
// error-safe.
func Get() Logger {
	_Singleton.once.Do(func() {
		if _Singleton.log == nil {
			initialize()
		}
	})

	return _Singleton.log
}

type writer interface {
	logAtLevel(syslog.Priority, string)
}

// bothWriter implements writer and writes to both syslog and stdout.
type bothWriter struct {
	syslog    *syslog.Writer
	stdoutLog *stdoutLog
}

// Log the provided message at the appropriate level, writing to
// both stdout and the Logger, as well as informing statsd.
func (w *bothWriter) logAtLevel(level syslog.Priority, msg string) {
	if w.syslog != nil {
		var err error
		switch level {
		case syslog.LOG_ERR:
			err = w.syslog.Err(msg)
		case syslog.LOG_WARNING:
			err = w.syslog.Warning(msg)
		case syslog.LOG_INFO:
			err = w.syslog.Info(msg)
		case syslog.LOG_DEBUG:
			err = w.syslog.Debug(msg)
		default:
			err = w.syslog.Err(fmt.Sprintf("%s (unknown logging level: %d)", msg, int(level)))
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write to syslog: %s (%s)", msg, err)
		}
	}
	if w.stdoutLog != nil {
		w.stdoutLog.logAtLevel(level, msg)
	}
}

// Implement writer to log to stdout
type stdoutLog struct {
	tag         string
	stdoutLevel int
	forTerminal bool
	clk         clock.Clock
}

func newStdoutLog(tag string, stdoutLogLevel int, forTerminal bool) *stdoutLog {
	slog := &stdoutLog{tag, stdoutLogLevel, forTerminal, nil}
	if forTerminal {
		slog.clk = clock.Default()
	}
	return slog
}

func (slog *stdoutLog) logAtLevel(level syslog.Priority, msg string) {
	if int(level) > slog.stdoutLevel {
		return
	}

	var prefix string
	switch level {
	case syslog.LOG_ERR:
		prefix = "E"
	case syslog.LOG_WARNING:
		prefix = "W"
	case syslog.LOG_INFO:
		prefix = "I"
	case syslog.LOG_DEBUG:
		prefix = "D"
	default:
		msg = fmt.Sprintf("%s (unknown logging level: %d)", msg, int(level))
		level = syslog.LOG_ERR
		prefix = "E"
	}

	var reset string
	if slog.forTerminal {
		const red = "\033[31m\033[1m"
		const yellow = "\033[33m"
		color := ""
		if level <= syslog.LOG_ERR {
			color = red
		} else if level <= syslog.LOG_WARNING {
			color = yellow
		}
		if color != "" {
			reset = "\033[0m"
		}
		prefix = color + prefix + slog.clk.Now().Format("150405")
	} else {
		// Use the standard syslog reporting of facility and level
		prefix = fmt.Sprintf("<%d> %s", int(syslogDefaultFacility|level), prefix)
	}

	fmt.Printf("%s %s %s%s\n",
		prefix,
		slog.tag,
		msg,
		reset)
}

// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
func (log *impl) auditAtLevel(level syslog.Priority, msg string) {
	text := fmt.Sprintf("%s %s", auditTag, msg)
	log.w.logAtLevel(level, text)
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
func (log *impl) AuditPanic() {
	if err := recover(); err != nil {
		buf := make([]byte, 8192)
		log.AuditErr(fmt.Errorf("Panic caused by err: %s", err))

		runtime.Stack(buf, false)
		log.AuditErr(fmt.Errorf("Stack Trace (Current frame) %s", buf))

		runtime.Stack(buf, true)
		log.Warning(fmt.Sprintf("Stack Trace (All frames): %s", buf))
	}
}

// Err level messages are always marked with the audit tag, for special handling
// at the upstream system logger.
func (log *impl) Err(msg string) {
	log.auditAtLevel(syslog.LOG_ERR, msg)
}

// Warning level messages pass through normally.
func (log *impl) Warning(msg string) {
	log.w.logAtLevel(syslog.LOG_WARNING, msg)
}

// Info level messages pass through normally.
func (log *impl) Info(msg string) {
	log.w.logAtLevel(syslog.LOG_INFO, msg)
}

// Debug level messages pass through normally.
func (log *impl) Debug(msg string) {
	log.w.logAtLevel(syslog.LOG_DEBUG, msg)
}

// AuditInfo sends an INFO-severity message that is prefixed with the
// audit tag, for special handling at the upstream system logger.
func (log *impl) AuditInfo(msg string) {
	log.auditAtLevel(syslog.LOG_INFO, msg)
}

// AuditObject sends an INFO-severity JSON-serialized object message that is prefixed
// with the audit tag, for special handling at the upstream system logger.
func (log *impl) AuditObject(msg string, obj interface{}) {
	jsonObj, err := json.Marshal(obj)
	if err != nil {
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		log.auditAtLevel(syslog.LOG_ERR, fmt.Sprintf("Object could not be serialized to JSON. Raw: %+v", obj))
		return
	}

	log.auditAtLevel(syslog.LOG_INFO, fmt.Sprintf("%s JSON=%s", msg, jsonObj))
}

// AuditErr can format an error for auditing; it does so at ERR level.
// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
func (log *impl) AuditErr(msg error) {
	log.auditAtLevel(syslog.LOG_ERR, msg.Error())
}
