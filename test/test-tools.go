// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package test

import (
	"fmt"
	"strings"
	"testing"
)

func Assert(t *testing.T, result bool, message string) {
	if !result {
		t.Error(message)
	}
}

func AssertNotError(t *testing.T, err error, message string) {
	if err != nil {
		t.Error(message, err)
	}
}

func AssertEquals(t *testing.T, one string, two string) {
	if one != two {
		t.Errorf("String [%s] != [%s]", one, two)
	}
}

func AssertContains(t *testing.T, haystack string, needle string) {
	if !strings.Contains(haystack, needle) {
		t.Errorf("String [%s] does not contain [%s]", haystack, needle)
	}
}

func AssertSeverity(t *testing.T, data string, severity int) {
	expected := fmt.Sprintf("\"severity\":%d", severity)
	AssertContains(t, data, expected)
}
