// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sa

import (
	"net"
	"testing"
)

func TestIncrementIP(t *testing.T) {
	testCases := []struct {
		ip       string
		index    int
		expected string
	}{
		{"0.0.0.0", 15, "0.0.0.1"},
		{"0.0.0.255", 15, "0.0.1.0"},
		{"127.0.0.1", 15, "127.0.0.2"},
		{"1.2.3.4", 14, "1.2.4.4"},
		{"::1", 15, "::2"},
		{"2002:1001:4008::", 15, "2002:1001:4008::1"},
		{"2002:1001:4008::", 5, "2002:1001:4009::"},
	}
	for _, tc := range testCases {
		ip := net.ParseIP(tc.ip).To16()
		incrementIP(&ip, tc.index)
		expectedIP := net.ParseIP(tc.expected)
		if !ip.Equal(expectedIP) {
			t.Errorf("Expected incrementIP(%s, %d) to be %s, instead got %s",
				tc.ip, tc.index, expectedIP, ip.String())
		}
	}
}

func TestIPRange(t *testing.T) {
	testCases := []struct {
		ip            string
		expectedBegin string
		expectedEnd   string
	}{
		{"28.45.45.28", "28.45.45.28", "28.45.45.29"},
		{"2002:1001:4008::", "2002:1001:4008::", "2002:1001:4009::"},
	}
	for _, tc := range testCases {
		ip := net.ParseIP(tc.ip)
		expectedBegin := net.ParseIP(tc.expectedBegin)
		expectedEnd := net.ParseIP(tc.expectedEnd)
		actualBegin, actualEnd := ipRange(ip)
		if !expectedBegin.Equal(actualBegin) || !expectedEnd.Equal(actualEnd) {
			t.Errorf("Expected ipRange(%s) to be (%s, %s), got (%s, %s)",
				tc.ip, tc.expectedBegin, tc.expectedEnd, actualBegin, actualEnd)
		}
	}
}
