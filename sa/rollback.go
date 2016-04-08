// Copyright 2016 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sa

import (
	"fmt"
	gorp "github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"
)

// RollbackError is a combination of a database error and the error, if any,
// encountered while trying to rollback the transaction.
type RollbackError struct {
	Err         error
	RollbackErr error
}

// Error implements the error interface
func (re *RollbackError) Error() string {
	if re.RollbackErr == nil {
		return re.Err.Error()
	}
	return fmt.Sprintf("%s (also, while rolling back: %s)", re.Err, re.RollbackErr)
}

// Rollback rolls back the provided transaction (if err is non-nil) and wraps
// the error, if any, of the rollback into a RollbackError.
//
// If err is nil, the error (if any) from the rollback is returned without
// wrapping.
//
//   err = sa.Rollback(tx, err)
func Rollback(tx *gorp.Transaction, err error) error {
	if err == nil {
		return tx.Rollback()
	}
	return &RollbackError{
		Err:         err,
		RollbackErr: tx.Rollback(),
	}
}
