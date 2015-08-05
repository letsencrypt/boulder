// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package rpc

import (
	"time"
)

// client describes the functions an RPC Client performs
type client interface {
	SetTimeout(time.Duration)
	Dispatch(string, []byte) chan []byte
	DispatchSync(string, []byte) ([]byte, error)
}

// server describes the functions an RPC Server performs
type server interface {
	Handle(string, func([]byte) ([]byte, error))
}
