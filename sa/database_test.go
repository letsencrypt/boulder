// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sa

import (
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestInvalidDSN(t *testing.T) {
	_, err := NewDbMap("invalid")
	test.AssertError(t, err, "DB connect string missing the slash separating the database name")
}
