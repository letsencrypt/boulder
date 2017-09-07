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

// Rollback rolls back the provided transaction. If the rollback fails for any
// reason a `RollbackError` error is returned wrapping the original error. If no
// rollback error occurs then the original error is returned.
func Rollback(tx *gorp.Transaction, err error) error {
	if txErr := tx.Rollback(); txErr != nil {
		return &RollbackError{
			Err:         err,
			RollbackErr: txErr,
		}
	}
	return err
}
