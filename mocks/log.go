// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mocks

import (
	"log/syslog"
	"regexp"

	blog "github.com/letsencrypt/boulder/log"
)

// SyslogWriter implements the blog.SyslogWriter interface. It
// stores all logged messages in a buffer for inspection by test
// functions (via GetAll()) instead of sending them to syslog.
type SyslogWriter struct {
	logged    []*LogMessage
	msgChan   chan<- *LogMessage
	getChan   <-chan []*LogMessage
	clearChan chan<- struct{}
	closeChan chan<- struct{}
}

// LogMessage is a log entry that has been sent to a SyslogWriter.
type LogMessage struct {
	Priority syslog.Priority // aka Log level
	Message  string          // content of log message
}

var levelName = map[syslog.Priority]string{
	syslog.LOG_EMERG:   "EMERG",
	syslog.LOG_ALERT:   "ALERT",
	syslog.LOG_CRIT:    "CRIT",
	syslog.LOG_ERR:     "ERR",
	syslog.LOG_WARNING: "WARNING",
	syslog.LOG_NOTICE:  "NOTICE",
	syslog.LOG_INFO:    "INFO",
	syslog.LOG_DEBUG:   "DEBUG",
}

func (lm *LogMessage) String() string {
	return levelName[lm.Priority&7] + ": " + lm.Message
}

// UseMockLog changes the SyslogWriter used by the current singleton
// audit logger to a new mock logger, and returns the mock. Example:
//
//	var log = mocks.UseMockLog()
//	func TestFoo(t *testing.T) {
//		log.Clear()
//		// ...
//		Assert(t, len(log.GetAll()) > 0, "Should have logged something")
//	}
func UseMockLog() *SyslogWriter {
	sw := NewSyslogWriter()
	blog.GetAuditLogger().SyslogWriter = sw
	return sw
}

// NewSyslogWriter returns a new SyslogWriter.
func NewSyslogWriter() *SyslogWriter {
	msgChan := make(chan *LogMessage)
	getChan := make(chan []*LogMessage)
	clearChan := make(chan struct{})
	closeChan := make(chan struct{})
	msw := &SyslogWriter{
		logged:    []*LogMessage{},
		msgChan:   msgChan,
		getChan:   getChan,
		clearChan: clearChan,
		closeChan: closeChan,
	}
	go func() {
		for {
			select {
			case logMsg := <-msgChan:
				msw.logged = append(msw.logged, logMsg)
			case getChan <- msw.logged:
			case <-clearChan:
				msw.logged = []*LogMessage{}
			case <-closeChan:
				close(getChan)
				return
			}
		}
	}()
	return msw
}

func (msw *SyslogWriter) write(m string, priority syslog.Priority) error {
	msw.msgChan <- &LogMessage{Message: m, Priority: priority}
	return nil
}

// GetAll returns all LogMessages logged (since the last call to
// Clear(), if applicable).
//
// The caller must not modify the returned slice or its elements.
func (msw *SyslogWriter) GetAll() []*LogMessage {
	return <-msw.getChan
}

// GetAllMatching returns all LogMessages logged (since the last
// Clear()) whose text matches the given regexp. The regexp is
// accepted as a string and compiled on the fly, because convenience
// is more important than performance.
//
// The caller must not modify the elements of the returned slice.
func (msw *SyslogWriter) GetAllMatching(reString string) (matches []*LogMessage) {
	re := regexp.MustCompile(reString)
	for _, logMsg := range <-msw.getChan {
		if re.MatchString(logMsg.String()) {
			matches = append(matches, logMsg)
		}
	}
	return
}

// Clear resets the log buffer.
func (msw *SyslogWriter) Clear() {
	msw.clearChan <- struct{}{}
}

// Close releases resources. No other methods may be called after this.
func (msw *SyslogWriter) Close() error {
	msw.closeChan <- struct{}{}
	return nil
}

// Alert logs at LOG_ALERT
func (msw *SyslogWriter) Alert(m string) error {
	return msw.write(m, syslog.LOG_ALERT)
}

// Crit logs at LOG_CRIT
func (msw *SyslogWriter) Crit(m string) error {
	return msw.write(m, syslog.LOG_CRIT)
}

// Debug logs at LOG_DEBUG
func (msw *SyslogWriter) Debug(m string) error {
	return msw.write(m, syslog.LOG_DEBUG)
}

// Emerg logs at LOG_EMERG
func (msw *SyslogWriter) Emerg(m string) error {
	return msw.write(m, syslog.LOG_EMERG)
}

// Err logs at LOG_ERR
func (msw *SyslogWriter) Err(m string) error {
	return msw.write(m, syslog.LOG_ERR)
}

// Info logs at LOG_INFO
func (msw *SyslogWriter) Info(m string) error {
	return msw.write(m, syslog.LOG_INFO)
}

// Notice logs at LOG_NOTICE
func (msw *SyslogWriter) Notice(m string) error {
	return msw.write(m, syslog.LOG_NOTICE)
}

// Warning logs at LOG_WARNING
func (msw *SyslogWriter) Warning(m string) error {
	return msw.write(m, syslog.LOG_WARNING)
}
