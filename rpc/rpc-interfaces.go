// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package rpc

import (
	"time"
)

// RPCClient describes the functions an RPC Client performs
type RPCClient interface {
	SetTimeout(time.Duration)
	Dispatch(string, []byte) chan []byte
	DispatchSync(string, []byte) ([]byte, error)
	SyncDispatchWithTimeout(string, []byte, time.Duration) ([]byte, error)
}

// RPCServer describes the functions an RPC Server performs
type RPCServer interface {
	Handle(string, func([]byte) ([]byte, error))
}
