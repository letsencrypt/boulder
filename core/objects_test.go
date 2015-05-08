// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestSanityCheck(t *testing.T) {
	chall := Challenge{Type: ChallengeTypeSimpleHTTPS, Status: StatusValid}
	test.Assert(t, !chall.IsSane(false), "IsSane should be false")
	chall.Status = StatusPending
	test.Assert(t, !chall.IsSane(false), "IsSane should be false")
	chall.R = "bad"
	chall.S = "bad"
	chall.Nonce = "bad"
	test.Assert(t, !chall.IsSane(false), "IsSane should be false")
	chall = Challenge{Type: ChallengeTypeSimpleHTTPS, Path: "bad", Status: StatusPending}
	test.Assert(t, !chall.IsSane(false), "IsSane should be false")
	chall.Path = ""
	test.Assert(t, !chall.IsSane(true), "IsSane should be false")
	chall.Token = ""
	test.Assert(t, !chall.IsSane(false), "IsSane should be false")
	chall.Token = "notlongenough"
	test.Assert(t, !chall.IsSane(false), "IsSane should be false")
	chall.Token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ+PCt92wr+o!"
	test.Assert(t, !chall.IsSane(false), "IsSane should be false")
	chall.Token = "KQqLsiS5j0CONR_eUXTUSUDNVaHODtc-0pD6ACif7U4"
	test.Assert(t, chall.IsSane(false), "IsSane should be true")

	chall = Challenge{Type: ChallengeTypeDVSNI, Status: StatusPending}
	chall.Path = "bad"
	chall.Token = "bad"
	test.Assert(t, !chall.IsSane(false), "IsSane should be false")
	chall = Challenge{Type: ChallengeTypeDVSNI, Status: StatusPending}
	test.Assert(t, !chall.IsSane(false), "IsSane should be false")
	chall.Nonce = "wutwut"
	test.Assert(t, !chall.IsSane(false), "IsSane should be false")
	chall.Nonce = "!2345678901234567890123456789012"
	test.Assert(t, !chall.IsSane(false), "IsSane should be false")
	chall.Nonce = "12345678901234567890123456789012"
	test.Assert(t, !chall.IsSane(false), "IsSane should be false")
	chall.R = "notlongenough"
	test.Assert(t, !chall.IsSane(false), "IsSane should be false")
	chall.R = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ+PCt92wr+o!"
	test.Assert(t, !chall.IsSane(false), "IsSane should be false")
	chall.R = "KQqLsiS5j0CONR_eUXTUSUDNVaHODtc-0pD6ACif7U4"
	test.Assert(t, chall.IsSane(false), "IsSane should be true")
	chall.S = "anything"
	test.Assert(t, !chall.IsSane(false), "IsSane should be false")
	test.Assert(t, !chall.IsSane(true), "IsSane should be false")
	chall.S = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ+PCt92wr+o!"
	test.Assert(t, !chall.IsSane(true), "IsSane should be false")
	chall.S = "KQqLsiS5j0CONR_eUXTUSUDNVaHODtc-0pD6ACif7U4"
	test.Assert(t, chall.IsSane(true), "IsSane should be true")
}