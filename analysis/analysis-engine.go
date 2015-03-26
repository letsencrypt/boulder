// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package analysisengine

import (
	blog "github.com/letsencrypt/boulder/log"

	"encoding/json"
	"fmt"
	"github.com/streadway/amqp"
)

// This file analyzes messages obtained from the Message Broker to determine
// whether the system as a whole is functioning correctly.

// Interface all Analysis Engines share
type AnalysisEngine interface {
	ProcessMessage(amqp.Delivery) (err error)
}

// An Analysis Engine that just logs to the JSON Logger.
type LoggingAnalysisEngine struct {
	log *blog.AuditLogger
}

func (eng *LoggingAnalysisEngine) ProcessMessage(delivery amqp.Delivery) (err error) {
	// Send the entire message contents to the syslog server for debugging.
	encoded, err := json.Marshal(delivery)

	if err != nil {
		return
	}

	err = eng.log.Debug(fmt.Sprintf("MONITOR: %s", encoded))
	return
}

// Construct a new Analysis Engine.
func NewLoggingAnalysisEngine(logger *blog.AuditLogger) AnalysisEngine {
	logger.Notice("Analysis Engine Starting")

	return &LoggingAnalysisEngine{log: logger}
}
