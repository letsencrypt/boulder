// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package analysisengine

import (
	"log/syslog"
	"testing"

	"github.com/letsencrypt/boulder/log"
	"github.com/streadway/amqp"
)

func TestNewLoggingAnalysisEngine(t *testing.T) {
	writer, _ := syslog.New(syslog.LOG_EMERG|syslog.LOG_KERN, "tag")
	log, _ := log.NewAuditLogger(writer)
	ae := NewLoggingAnalysisEngine(log)

	// Trivially check an empty mock message
	d := &amqp.Delivery{}
	ae.ProcessMessage(*d)

	// Nothing to assert
}

type MockAck struct {
	// json.Marshall cannot represent a chan, so this will break
	// the json.Marshal attempt in ProcessMessage and let us get
	// coverage there.
	JsonBreaker chan bool
}

func (m *MockAck) Ack(tag uint64, multiple bool) error {
	return nil
}
func (m *MockAck) Nack(tag uint64, multiple bool, requeue bool) error {
	return nil
}
func (m *MockAck) Reject(tag uint64, requeue bool) error {
	return nil
}

func TestAnalysisEngineBadMessage(t *testing.T) {
	writer, _ := syslog.New(syslog.LOG_EMERG|syslog.LOG_KERN, "tag")
	log, _ := log.NewAuditLogger(writer)
	ae := NewLoggingAnalysisEngine(log)

	// Trivially check an empty mock message
	d := &amqp.Delivery{Acknowledger: &MockAck{}}
	ae.ProcessMessage(*d)

	// Nothing to assert
}
