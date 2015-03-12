// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package analysisengine

import (
	"github.com/letsencrypt/boulder/log"
	"github.com/streadway/amqp"
)

// This file analyzes messages obtained from the Message Broker to determine
// whether the system as a whole is functioning correctly.

// Interface all Analysis Engines share
type AnalysisEngine interface {
	ProcessMessage(amqp.Delivery)
}

// An Analysis Engine that just logs to the JSON Logger.
type LoggingAnalysisEngine struct {
	jsonLogger *log.JSONLogger
}

func (eng *LoggingAnalysisEngine) ProcessMessage(delivery amqp.Delivery) {
	// Send the entire message contents to the syslog server for debugging.
	eng.jsonLogger.Debug("Message contents", delivery)
}

// Construct a new Analysis Engine.
func NewLoggingAnalysisEngine(logger *log.JSONLogger) AnalysisEngine {
	return &LoggingAnalysisEngine{jsonLogger: logger}
}
