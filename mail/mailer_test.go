// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package mail

import (
	"io"
	"math/big"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/test"
)

type fakeSource struct{}

func (f fakeSource) Int(reader io.Reader, max *big.Int) (*big.Int, error) {
	return big.NewInt(1991), nil
}

func TestGenerateMessage(t *testing.T) {
	fc := clock.NewFake()
	m := MailerImpl{From: "send@email.com", clk: fc, csprgSource: fakeSource{}}
	messageBytes, err := m.generateMessage([]string{"recv@email.com"}, "test subject", "this is the body\n")
	test.AssertNotError(t, err, "Failed to generate email body")
	message := string(messageBytes)
	fields := strings.Split(message, "\r\n")
	test.AssertEquals(t, len(fields), 8)
	test.AssertEquals(t, fields[0], "To: \"recv@email.com\"")
	test.AssertEquals(t, fields[1], "From: send@email.com")
	test.AssertEquals(t, fields[2], "Subject: test subject")
	test.AssertEquals(t, fields[3], "Date: Thu Jan 1 1970 00:00:00 +0000")
	test.AssertEquals(t, fields[4], "Message-Id: <19700101T000000.1991.send@email.com>")
	test.AssertEquals(t, fields[5], "")
	test.AssertEquals(t, fields[6], "this is the body\\n")
	test.AssertEquals(t, fields[7], "")
}
