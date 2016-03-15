// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sa

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestInvalidDSN(t *testing.T) {
	_, err := NewDbMap("invalid")
	test.AssertError(t, err, "DB connect string missing the slash separating the database name")
}

var errExpected = errors.New("expected")

func TestNewDbMap(t *testing.T) {
	const mysqlConnectURL = "mysql+tcp://policy:password@localhost:3306/boulder_policy_integration?readTimeout=800ms&writeTimeout=800ms"
	const expectedTransformed = "policy:password@tcp(localhost:3306)/boulder_policy_integration?clientFoundRows=true&parseTime=true&readTimeout=800ms&strict=true&writeTimeout=800ms"

	oldSQLOpen := sqlOpen
	defer func() {
		sqlOpen = oldSQLOpen
	}()
	sqlOpen = func(dbType, connectString string) (*sql.DB, error) {
		if connectString != expectedTransformed {
			t.Errorf("incorrect connection string mangling, got %v", connectString)
		}
		return nil, errExpected
	}

	dbMap, err := NewDbMap(mysqlConnectURL)
	if err != errExpected {
		t.Errorf("got incorrect error: %v", err)
	}
	if dbMap != nil {
		t.Errorf("expected nil, got %v", dbMap)
	}

}
