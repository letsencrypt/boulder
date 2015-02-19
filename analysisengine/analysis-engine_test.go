// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package analysisengine

import (
  "github.com/letsencrypt/boulder"
  "github.com/streadway/amqp"
  "testing"
)


func TestNewLoggingAnalysisEngine(t *testing.T) {
  log := boulder.NewJsonLogger("newEngine")
  ae  := NewLoggingAnalysisEngine(log)

  // Trivially check an empty mock message
  d := &amqp.Delivery{}
  ae.ProcessMessage(*d)

  // Nothing to assert
}