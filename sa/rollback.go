// Copyright 2016 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sa

import (
	"fmt"

	"gopkg.in/go-gorp/gorp.v2"
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
// The err parameter must be non-nil.
//
//   err = sa.Rollback(tx, err)
func Rollback(tx *gorp.Transaction, err error) error {
	return &RollbackError{
		Err:         err,
		RollbackErr: tx.Rollback(),
	}
}
