package errors

import (
	"fmt"
	"sync"
)

//go:generate stringer -type=Priority

// Priority defines how an error should be threaded
type Priority int

// Priorities that can be used to create and list errors
const (
	Unknown Priority = iota
	Debug
	Info
	Notice
	Warning
	Error
	Critical
	Alert
	Emergency
)

// Config defines the error configuration, currently no configuration options
// are available.
type Config struct {
}

// Err contains a single error
type Err struct {
	p   Priority
	msg string
}

// Priority returns the priority of this error
func (e Err) Priority() Priority {
	return e.p
}

// String returns the message of this error
func (e Err) Error() string {
	return e.msg
}

// Errors contains a list of Error
type Errors struct {
	err    []Err
	config *Config
	p      Priority
	m      sync.Mutex
}

// New creates an empty error container
func New(c *Config) *Errors {
	return &Errors{config: c}
}

// IsError returns true on one or more errors
func (e *Errors) IsError() bool {
	if len(e.err) > 0 {
		return true
	}
	return false
}

// Priority returns the priority of this error
func (e *Errors) Priority() Priority {
	return e.p
}

// List returns all errors of a given priority, if no priority is given all
// errors are returned.
func (e *Errors) List(p ...Priority) []Err {
	if len(p) == 0 {
		return e.err
	}

	// filter errors to given priorities
	var l []Err
	for _, e := range e.err {
		for _, priority := range p {
			if e.p == priority {
				l = append(l, e)
			}
		}
	}
	return l
}

// Append add all Errors to existing Errors
func (e *Errors) Append(err *Errors) error {
	if err == nil {
		return nil
	}

	e.m.Lock()

	// append Errors at the end of the current list
	e.err = append(e.err, err.err...)

	// set highest priority
	if err.p > e.p {
		e.p = err.p
	}

	e.m.Unlock()
	return nil
}

// Emerg log an error with severity Emergency
func (e *Errors) Emerg(format string, a ...interface{}) error {
	return e.add(Emergency, format, a...)
}

// Alert log an error with severity Alert
func (e *Errors) Alert(format string, a ...interface{}) error {
	return e.add(Alert, format, a...)
}

// Crit log an error with severity Critical
func (e *Errors) Crit(format string, a ...interface{}) error {
	return e.add(Critical, format, a...)
}

// Err log an error with severity Error
func (e *Errors) Err(format string, a ...interface{}) error {
	return e.add(Error, format, a...)
}

// Warning log an error with severity Warning
func (e *Errors) Warning(format string, a ...interface{}) error {
	return e.add(Warning, format, a...)
}

// Notice log an error with severity Notice
func (e *Errors) Notice(format string, a ...interface{}) error {
	return e.add(Notice, format, a...)
}

// Info log an error with severity Info
func (e *Errors) Info(format string, a ...interface{}) error {
	return e.add(Info, format, a...)
}

// Debug log an error with severity Debug
func (e *Errors) Debug(format string, a ...interface{}) error {
	return e.add(Debug, format, a...)
}

func (e *Errors) add(p Priority, format string, a ...interface{}) error {
	// no error in request
	if len(format) == 0 && len(a) == 0 {
		return nil
	}

	e.m.Lock()

	msg := format
	if len(a) > 0 {
		msg = fmt.Sprintf(format, a...)
	}

	// add this priority to the end of the list
	e.err = append(e.err, Err{
		p:   p,
		msg: msg,
	})

	// set highest priority in this list
	if p > e.p {
		e.p = p
	}

	e.m.Unlock()
	return nil
}
