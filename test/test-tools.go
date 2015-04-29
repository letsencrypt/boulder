// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package test

import (
	"bytes"
	"fmt"
	"strings"
	"runtime"
	"testing"
	"encoding/base64"
)

// Return short format caller info for printing errors, so errors don't all
// appear to come from test-tools.go.
func caller() string {
	_, file, line, _ := runtime.Caller(2)
	splits := strings.Split(file, "/")
	filename := splits[len(splits) - 1]
	return fmt.Sprintf("%s:%d:", filename, line)
}

func Assert(t *testing.T, result bool, message string) {
	if !result {
		t.Error(caller(), message)
	}
}

func AssertNotError(t *testing.T, err error, message string) {
	if err != nil {
		t.Error(caller(), message, ":", err)
	}
}

func AssertError(t *testing.T, err error, message string) {
	if err == nil {
		t.Error(caller(), message, ":", err)
	}
}

func AssertEquals(t *testing.T, one string, two string) {
	if one != two {
		t.Errorf("%s String [%s] != [%s]", caller(), one, two)
	}
}

func AssertByteEquals(t *testing.T, one []byte, two []byte) {
	if !bytes.Equal(one, two) {
		t.Errorf("%s Byte [%s] != [%s]",
			caller(),
			base64.StdEncoding.EncodeToString(one),
			base64.StdEncoding.EncodeToString(two))
	}
}
func AssertContains(t *testing.T, haystack string, needle string) {
	if !strings.Contains(haystack, needle) {
		t.Errorf("%s String [%s] does not contain [%s]", caller(), haystack, needle)
	}
}

func AssertSeverity(t *testing.T, data string, severity int) {
	expected := fmt.Sprintf("\"severity\":%d", severity)
	AssertContains(t, data, expected)
}
