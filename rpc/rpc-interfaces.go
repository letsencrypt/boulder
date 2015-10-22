// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package rpc

import (
	"time"
)

// Client describes the functions an RPC Client performs
type Client interface {
	SetTimeout(time.Duration)
	DispatchSync(string, []byte) ([]byte, error)
}

// Server describes the functions an RPC Server performs
type Server interface {
	Handle(string, func([]byte) ([]byte, error))
}
