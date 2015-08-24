// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package metrics

import (
	"sync"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/streadway/amqp"

	"github.com/letsencrypt/boulder/test"
)

func TestRPCMonitor(t *testing.T) {
	stats, _ := statsd.NewNoopClient(nil)
	rm := RPCMonitor{
		stats:           stats,
		deliveryTimings: make(map[string]time.Time),
		dtMu:            &sync.Mutex{},
	}

	rm.add("test-a")
	test.AssertEquals(t, rm.size(), 1)
	test.Assert(t, time.Now().After(rm.get("test-a")), "Delivery time was in the future")
	rm.delete("test-a")
	test.AssertEquals(t, rm.size(), 0)
	// Wait for test-b to timeout and manually call cleanup
	rm.add("test-b")
	time.Sleep(time.Second * 10)
	test.AssertEquals(t, int(rm.cleanup()), 1)
	test.AssertEquals(t, rm.size(), 0)

	rm.TimeDelivery(amqp.Delivery{
		CorrelationId: "a",
		ReplyTo:       "b",
	})
	test.AssertEquals(t, rm.size(), 1)
	rm.TimeDelivery(amqp.Delivery{
		CorrelationId: "a",
		RoutingKey:    "b",
		Body:          []byte("{}"),
	})
	test.AssertEquals(t, rm.size(), 0)
}
