// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"github.com/letsencrypt/boulder/test"
	"testing"
)

func TestValidNonce(t *testing.T) {
	ns := NewNonceService()
	n := ns.Nonce()
	test.Assert(t, ns.Valid(n), "Did not recognize fresh nonce")
}

func TestAlreadyUsed(t *testing.T) {
	ns := NewNonceService()
	n := ns.Nonce()
	test.Assert(t, ns.Valid(n), "Did not recognize fresh nonce")
	test.Assert(t, !ns.Valid(n), "Recognized the same nonce twice")
}

func TestRejectMalformed(t *testing.T) {
	ns := NewNonceService()
	n := ns.Nonce()
	test.Assert(t, !ns.Valid("asdf"+n), "Accepted an invalid nonce")
}

func TestRejectUnknown(t *testing.T) {
	ns1 := NewNonceService()
	ns2 := NewNonceService()
	n := ns1.Nonce()
	test.Assert(t, !ns2.Valid(n), "Accepted a foreign nonce")
}

func TestRejectTooLate(t *testing.T) {
	ns := NewNonceService()

	ns.latest = 2
	n := ns.Nonce()
	ns.latest = 1
	test.Assert(t, !ns.Valid(n), "Accepted a nonce with a too-high counter")
}

func TestRejectTooEarly(t *testing.T) {
	ns := NewNonceService()
	ns.maxUsed = 2

	n0 := ns.Nonce()
	n1 := ns.Nonce()
	n2 := ns.Nonce()
	n3 := ns.Nonce()

	test.Assert(t, ns.Valid(n3), "Rejected a valid nonce")
	test.Assert(t, ns.Valid(n2), "Rejected a valid nonce")
	test.Assert(t, ns.Valid(n1), "Rejected a valid nonce")
	test.Assert(t, !ns.Valid(n0), "Accepted a nonce that we should have forgotten")
}
