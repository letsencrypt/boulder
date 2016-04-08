// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package log

import (
	"log/syslog"
	"regexp"
)

func UseMock() *Mock {
	m := NewMock()
	_ = Set(m)
	return m
}

func NewMock() *Mock {
	return &Mock{impl{newMockWriter()}}
}

type Mock struct {
	impl
}

// Mock implements the writer interface. It
// stores all logged messages in a buffer for inspection by test
// functions (via GetAll()) instead of sending them to syslog.
type mockWriter struct {
	logged    []*LogMessage
	msgChan   chan<- *LogMessage
	getChan   <-chan []*LogMessage
	clearChan chan<- struct{}
	closeChan chan<- struct{}
}

// LogMessage is a log entry that has been sent to a Mock.
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

func (w *mockWriter) logAtLevel(p syslog.Priority, msg string) {
	w.msgChan <- &LogMessage{Message: msg, Priority: p}
}

// newMockWriter returns a new mockWriter
func newMockWriter() *mockWriter {
	msgChan := make(chan *LogMessage)
	getChan := make(chan []*LogMessage)
	clearChan := make(chan struct{})
	closeChan := make(chan struct{})
	w := &mockWriter{
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
				w.logged = append(w.logged, logMsg)
			case getChan <- w.logged:
			case <-clearChan:
				w.logged = []*LogMessage{}
			case <-closeChan:
				close(getChan)
				return
			}
		}
	}()
	return w
}

// GetAll returns all LogMessages logged (since the last call to
// Clear(), if applicable).
//
// The caller must not modify the returned slice or its elements.
func (m *Mock) GetAll() []*LogMessage {
	w := m.w.(*mockWriter)
	return <-w.getChan
}

// GetAllMatching returns all LogMessages logged (since the last
// Clear()) whose text matches the given regexp. The regexp is
// accepted as a string and compiled on the fly, because convenience
// is more important than performance.
//
// The caller must not modify the elements of the returned slice.
func (m *Mock) GetAllMatching(reString string) (matches []*LogMessage) {
	w := m.w.(*mockWriter)
	re := regexp.MustCompile(reString)
	for _, logMsg := range <-w.getChan {
		if re.MatchString(logMsg.String()) {
			matches = append(matches, logMsg)
		}
	}
	return matches
}

// Clear resets the log buffer.
func (m *Mock) Clear() {
	w := m.w.(*mockWriter)
	w.clearChan <- struct{}{}
}
