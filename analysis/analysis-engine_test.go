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
