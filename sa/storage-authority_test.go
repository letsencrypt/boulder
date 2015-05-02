// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sa

import (
	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/mattn/go-sqlite3"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/test"
	"io/ioutil"
	"testing"
)

func TestAddCertificate(t *testing.T) {
	sa, err := NewSQLStorageAuthority("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create SA")
	}
	if err = sa.InitTables(); err != nil {
		t.Fatalf("Failed to create SA")
	}

	// An example cert taken from EFF's website
	certDER, err := ioutil.ReadFile("www.eff.org.der")
	test.AssertNotError(t, err, "Couldn't read example cert DER")

	digest, err := sa.AddCertificate(certDER)
	test.AssertNotError(t, err, "Couldn't add www.eff.org.der")
	test.AssertEquals(t, digest, "qWoItDZmR4P9eFbeYgXXP3SR4ApnkQj8x4LsB_ORKBo")

	// Example cert serial is 0x21bd4, so a prefix of all zeroes should fetch it.
	retrievedDER, err := sa.GetCertificateByShortSerial("0000000000000000")
	test.AssertNotError(t, err, "Couldn't get www.eff.org.der by short serial")
	test.AssertByteEquals(t, certDER, retrievedDER)

	retrievedDER, err = sa.GetCertificate("00000000000000000000000000021bd4")
	test.AssertNotError(t, err, "Couldn't get www.eff.org.der by full serial")
	test.AssertByteEquals(t, certDER, retrievedDER)

	certificateStatus, err := sa.GetCertificateStatus("00000000000000000000000000021bd4")
	test.AssertNotError(t, err, "Couldn't get status for www.eff.org.der")
	test.Assert(t, !certificateStatus.SubscriberApproved, "SubscriberApproved should be false")
	test.Assert(t, certificateStatus.Status == core.OCSPStatusGood, "OCSP Status should be good")
	test.Assert(t, certificateStatus.OCSPLastUpdated.IsZero(), "OCSPLastUpdated should be nil")

	// Test cert generated locally by Boulder / CFSSL, serial "ff00000000000002238054509817da5a"
	certDER2, err := ioutil.ReadFile("test-cert.der")
	test.AssertNotError(t, err, "Couldn't read example cert DER")

	digest2, err := sa.AddCertificate(certDER2)
	test.AssertNotError(t, err, "Couldn't add test-cert.der")
	test.AssertEquals(t, digest2, "CMVYqWzyqUW7pfBF2CxL0Uk6I0Upsk7p4EWSnd_vYx4")

	// Example cert serial is 0x21bd4, so a prefix of all zeroes should fetch it.
	retrievedDER2, err := sa.GetCertificateByShortSerial("ff00000000000002")
	test.AssertNotError(t, err, "Couldn't get test-cert.der")
	test.AssertByteEquals(t, certDER2, retrievedDER2)

	retrievedDER2, err = sa.GetCertificate("ff00000000000002238054509817da5a")
	test.AssertNotError(t, err, "Couldn't get test-cert.der")
	test.AssertByteEquals(t, certDER2, retrievedDER2)

	certificateStatus2, err := sa.GetCertificateStatus("ff00000000000002238054509817da5a")
	test.AssertNotError(t, err, "Couldn't get status for test-cert.der")
	test.Assert(t, !certificateStatus2.SubscriberApproved, "SubscriberApproved should be false")
	test.Assert(t, certificateStatus2.Status == core.OCSPStatusGood, "OCSP Status should be good")
	test.Assert(t, certificateStatus2.OCSPLastUpdated.IsZero(), "OCSPLastUpdated should be nil")
}

// TestGetCertificateByShortSerial tests some failure conditions for GetCertificate.
// Success conditions are tested above in TestAddCertificate.
func TestGetCertificateByShortSerial(t *testing.T) {
	sa, err := NewSQLStorageAuthority("sqlite3", ":memory:")
	test.AssertNotError(t, err, "Failed to create SA")
	sa.InitTables()

	_, err = sa.GetCertificateByShortSerial("")
	test.AssertError(t, err, "Should've failed on empty serial")

	_, err = sa.GetCertificateByShortSerial("01020304050607080102030405060708")
	test.AssertError(t, err, "Should've failed on too-long serial")
}
