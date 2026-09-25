package mtcb

import (
	"crypto"
	"crypto/x509"
	"testing"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/trees/entry"
	"github.com/letsencrypt/boulder/trees/proof"
)

func TestSplitMTCSerial(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		serial           uint64
		expectLogNum     uint16
		expectEntryIndex uint64
	}{
		{name: "log one", serial: 1<<entryIndexBits | 5, expectLogNum: 1, expectEntryIndex: 5},
		{name: "max values", serial: 0xffffffffffffffff, expectLogNum: 0xffff, expectEntryIndex: 1<<entryIndexBits - 1},
		{name: "high bit set", serial: 0x8000<<entryIndexBits | 1, expectLogNum: 0x8000, expectEntryIndex: 1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			logNum, entryIndex := splitMTCSerial(tc.serial)
			test.AssertEquals(t, logNum, tc.expectLogNum)
			test.AssertEquals(t, entryIndex, tc.expectEntryIndex)
		})
	}
}

func TestBuildCertificate(t *testing.T) {
	t.Parallel()

	orig, err := core.LoadCert("../test/hierarchy/ee-e1.cert.pem")
	test.AssertNotError(t, err, "loading test cert")

	mtcle, err := entry.FromX509(orig.Raw, crypto.SHA256)
	test.AssertNotError(t, err, "building log entry")

	tbs, err := mtcle.ToTBSCertificate(1<<entryIndexBits|7, orig.RawSubjectPublicKeyInfo, crypto.SHA256)
	test.AssertNotError(t, err, "building tbsCertificate")

	sig := proof.MTCProof{
		Start:          0,
		End:            8,
		InclusionProof: []tlog.Hash{{1}, {2}, {3}},
		Signatures: []*proof.SubtreeSignature{
			{CosignerID: []byte("44947.4.1"), Signature: []byte("mtca sig")},
			{CosignerID: []byte("mirror.example"), Signature: []byte("mirror sig")},
		},
	}
	expectSig, err := sig.Marshal()
	test.AssertNotError(t, err, "marshalling proof")

	certBytes, err := buildCertificate(tbs, &sig)
	test.AssertNotError(t, err, "building certificate")

	cert, err := x509.ParseCertificate(certBytes)
	test.AssertNotError(t, err, "parsing built certificate")

	test.AssertByteEquals(t, cert.RawTBSCertificate, tbs)
	test.AssertByteEquals(t, cert.Signature, expectSig)
	test.AssertByteEquals(t, cert.RawSubject, orig.RawSubject)
	test.AssertEquals(t, cert.SerialNumber.Uint64(), uint64(1<<entryIndexBits|7))
}
