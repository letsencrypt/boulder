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
	AuditErr(string)
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

// New returns a new Logger that uses the given syslog.Writer as a backend.
func New(log *syslog.Writer, stdoutLogLevel int, syslogLogLevel int) (Logger, error) {
	if log == nil {
		return nil, errors.New("Attempted to use a nil System Logger.")
	}
	return &impl{
		&bothWriter{log, stdoutLogLevel, syslogLogLevel, clock.Default()},
	}, nil
}

// initialize should only be used in unit tests.
func initialize() {
	// defaultPriority is never used because we always use specific priority-based
	// logging methods.
	const defaultPriority = syslog.LOG_INFO | syslog.LOG_LOCAL0
	syslogger, err := syslog.Dial("", "", defaultPriority, "test")
	if err != nil {
		panic(err)
	}
	logger, err := New(syslogger, int(syslog.LOG_DEBUG), int(syslog.LOG_DEBUG))
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
	*syslog.Writer
	stdoutLevel int
	syslogLevel int
	clk         clock.Clock
}

// Log the provided message at the appropriate level, writing to
// both stdout and the Logger, as well as informing statsd.
func (w *bothWriter) logAtLevel(level syslog.Priority, msg string) {
	var prefix string
	var err error

	const red = "\033[31m\033[1m"
	const yellow = "\033[33m"

	switch syslogAllowed := int(level) <= w.syslogLevel; level {
	case syslog.LOG_ERR:
		if syslogAllowed {
			err = w.Err(msg)
		}
		prefix = red + "E"
	case syslog.LOG_WARNING:
		if syslogAllowed {
			err = w.Warning(msg)
		}
		prefix = yellow + "W"
	case syslog.LOG_INFO:
		if syslogAllowed {
			err = w.Info(msg)
		}
		prefix = "I"
	case syslog.LOG_DEBUG:
		if syslogAllowed {
			err = w.Debug(msg)
		}
		prefix = "D"
	default:
		err = w.Err(fmt.Sprintf("%s (unknown logging level: %d)", msg, int(level)))
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write to syslog: %s (%s)", msg, err)
	}

	var reset string
	if strings.HasPrefix(prefix, "\033") {
		reset = "\033[0m"
	}

	if int(level) <= w.stdoutLevel {
		fmt.Printf("%s%s %s %s%s\n",
			prefix,
			w.clk.Now().Format("150405"),
			path.Base(os.Args[0]),
			msg,
			reset)
	}
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
		log.AuditErr(fmt.Sprintf("Panic caused by err: %s", err))

		runtime.Stack(buf, false)
		log.AuditErr(fmt.Sprintf("Stack Trace (Current frame) %s", buf))

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
func (log *impl) AuditErr(msg string) {
	log.auditAtLevel(syslog.LOG_ERR, msg)
}
