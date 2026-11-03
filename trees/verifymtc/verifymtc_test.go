package verifymtc

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/core/reloid"
	"github.com/letsencrypt/boulder/must"
	"github.com/letsencrypt/boulder/privatekey"
	"github.com/letsencrypt/boulder/trees/cosigned"
	"github.com/letsencrypt/boulder/trees/entry"
	"github.com/letsencrypt/boulder/trees/issuancelog"
	"github.com/letsencrypt/boulder/trees/proof"
	"github.com/letsencrypt/boulder/trees/subtree"
)

// certInputs are used to build a standalone certificate. They can be tweaked
// to generate a standalone certificate that is wrong in various ways.
type certInputs struct {
	mtcle  *entry.MTCLogEntry
	spki   []byte
	serial uint64
	proof  proof.MTCProof

	// If non-empty, use this signature algorithm instead of correct one.
	// Must be same length as correct one to avoid re-encoding.
	sigAlg []byte
	// If non-nil, use this as the certificate's signature instead of the
	// marshaled proof.
	rawProof []byte
}

// Stand-in for mtcb.GetStandalone: build a standalone certificate from its
// parts (which may be flawed).
func mkStandalone(t *testing.T, in *certInputs) []byte {
	t.Helper()
	tbs, err := in.mtcle.ToTBSCertificate(in.serial, in.spki, crypto.SHA256)
	if err != nil {
		t.Fatalf("ToTBSCertificate: %s", err)
	}

	sigAlg := proof.SigAlgEncoded()
	if len(in.sigAlg) > 0 {
		tbs = bytes.Replace(tbs, sigAlg, in.sigAlg, 1)
		sigAlg = in.sigAlg
	}

	sigBytes, err := in.proof.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %s", err)
	}
	if in.rawProof != nil {
		sigBytes = in.rawProof
	}
	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(tbs)
		b.AddBytes(sigAlg)
		b.AddASN1BitString(sigBytes)
	})
	certDER, err := b.Bytes()
	if err != nil {
		t.Fatalf("serializing certificate: %s", err)
	}
	return certDER
}

// mtcSerial returns the serial of the entry at index in the given log. Unlike
// core.EncodeMTCSerial, it allows log number zero.
func mtcSerial(logNumber uint16, index int64) uint64 {
	return uint64(logNumber)<<48 | uint64(index) //nolint:gosec // G115: test indexes are small and non-negative
}

// newIssuer returns a self-signed issuer certificate with the given rawSubject.
func newIssuer(t *testing.T, rawSubject []byte) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %s", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		RawSubject:   rawSubject,
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2026, 1, 8, 0, 0, 0, 0, time.UTC),
		IsCA:         true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %s", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %s", err)
	}
	return cert
}

// mkMTCLE makes an MTCLogEntry with issuer matching the given raw subject.
func mkMTCLE(t *testing.T, issuerSubject []byte, dnsName string) (*entry.MTCLogEntry, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %s", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{dnsName},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2026, 1, 8, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	parent := &x509.Certificate{RawSubject: issuerSubject}
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %s", err)
	}

	mtcle, err := entry.FromX509(certDER, crypto.SHA256)
	if err != nil {
		t.Fatalf("FromX509: %s", err)
	}

	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}

	return mtcle, spki
}

// testMTCA is the MTCA from test/certs/mtpki, operating log number 5.
type testMTCA struct {
	cert    *x509.Certificate
	logID   *issuancelog.ID
	privKey crypto.Signer
}

func loadMTCA(t *testing.T) *testMTCA {
	t.Helper()
	cert, err := core.LoadCert("../../test/certs/mtpki/mtca1.cert.pem")
	if err != nil {
		t.Fatalf("LoadCert: %s", err)
	}
	mtcaID, err := issuancelog.MTCAID(cert)
	if err != nil {
		t.Fatalf("MTCAID: %s", err)
	}
	logID, err := issuancelog.Config{CAID: mtcaID.String(), LogNumber: 5}.Load()
	if err != nil {
		t.Fatalf("Load: %s", err)
	}
	privKey, _, err := privatekey.Load("../../test/certs/mtpki/mtca1.key.pem")
	if err != nil {
		t.Fatalf("privatekey.Load: %s", err)
	}
	return &testMTCA{
		cert:    cert,
		logID:   logID,
		privKey: privKey,
	}
}

// newBasicInputs returns the inputs to a valid standalone certificate for
// entry 3 in mtca's log (number 5), proven against the signed subtree [0, 6).
func newBasicInputs(t *testing.T, mtca *testMTCA) *certInputs {
	t.Helper()
	mtcle, spki := mkMTCLE(t, mtca.cert.RawSubject, "example.com")

	mtcleMarshaled, err := mtcle.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// Since we're not testing proof-building (that belongs in the `subtree`
	// package), we take a shortcut building our inclusion proof and assume
	// every neighbor node has a hash of 0x07, then calculate the subtree hash
	// based on that. Then the test cases can munge the correct proof in various
	// ways to make sure validation fails.
	//
	// An inclusion proof for entry index 3 in the subtree [0, 6) has 3 entries.
	const entryIndex, subtreeStart, subtreeEnd = 3, 0, 6
	inclusionProof := []tlog.Hash{{0x07}, {0x07}, {0x07}}
	subtreeHash, err := subtree.HashFromProof(tlog.RecordHash(mtcleMarshaled), inclusionProof,
		entryIndex, subtreeStart, subtreeEnd)
	if err != nil {
		t.Fatal(err)
	}

	msg, err := (&cosigned.Message{
		CosignerName: mtca.logID.CACosignerName(),
		LogOrigin:    mtca.logID.Origin(),
		Start:        subtreeStart,
		End:          subtreeEnd,
		SubtreeHash:  subtreeHash,
	}).Marshal()
	if err != nil {
		t.Fatalf("cosigned.Message.Marshal(): %s", err)
	}

	sig, err := mtca.privKey.Sign(nil, msg, nil)
	if err != nil {
		t.Fatalf("signing: %s", err)
	}

	return &certInputs{
		mtcle:  mtcle,
		spki:   spki,
		serial: mtcSerial(mtca.logID.LogNumber(), entryIndex),
		proof: proof.MTCProof{
			Start:          subtreeStart,
			End:            subtreeEnd,
			InclusionProof: inclusionProof,
			Signatures: []*proof.SubtreeSignature{
				{CosignerID: mtca.logID.CAID().Bytes(), Signature: sig},
			},
		}}
}

func TestStandalone(t *testing.T) {
	t.Parallel()

	mirrorOID := must.Do(reloid.FromString("32473.9"))

	mtca := loadMTCA(t)
	mismatchedKeyIssuer := newIssuer(t, mtca.cert.RawSubject)
	mismatchedSubjectIssuer := newIssuer(t, nil)

	testCases := []struct {
		name string
		// issuer is used to validate the cert; defaults to mtca.cert.
		modify func(s *certInputs, issuer **x509.Certificate)
		// wantErr is a substring of the expected error, or empty for success.
		wantErr string
	}{
		{
			name:   "valid",
			modify: func(*certInputs, **x509.Certificate) {},
		},
		{
			name: "valid with unrecognized mirror signature",
			modify: func(s *certInputs, _ **x509.Certificate) {
				s.proof.Signatures = append(s.proof.Signatures,
					&proof.SubtreeSignature{CosignerID: mirrorOID.Bytes(), Signature: []byte("mirror sig")})
			},
		},
		{
			name: "issuer subject does not match",
			modify: func(_ *certInputs, issuer **x509.Certificate) {
				*issuer = mismatchedSubjectIssuer
			},
			wantErr: "does not match issuer's subject",
		},
		{
			name: "issuer key is not ML-DSA",
			modify: func(_ *certInputs, issuer **x509.Certificate) {
				*issuer = mismatchedKeyIssuer
			},
			wantErr: "unsupported pubkey type",
		},
		{
			name: "serial has log number zero",
			modify: func(s *certInputs, _ **x509.Certificate) {
				s.serial = mtcSerial(0, 3)
			},
			wantErr: "log number is zero",
		},
		{
			name: "malformed MTCProof",
			modify: func(s *certInputs, _ **x509.Certificate) {
				s.rawProof = []byte{0}
			},
			wantErr: "unmarshaling MTCProof",
		},
		{
			name: "signature algorithm is not MTCProof",
			modify: func(s *certInputs, _ **x509.Certificate) {
				s.sigAlg = proof.SigAlgEncoded()
				s.sigAlg[len(s.sigAlg)-1] = 99
			},
			wantErr: "cert.RawSignatureAlgorithm",
		},
		{
			name: "landmark-relative certificate",
			modify: func(s *certInputs, _ **x509.Certificate) {
				s.proof.Signatures = nil
			},
			wantErr: "no signatures",
		},
		{
			name: "MTCProof extensions",
			modify: func(s *certInputs, _ **x509.Certificate) {
				s.proof.Extensions = []byte{0, 1, 0, 0}
			},
			wantErr: "unrecognized extensions",
		},
		{
			name: "no signature by the CA",
			modify: func(s *certInputs, _ **x509.Certificate) {
				s.proof.Signatures = []*proof.SubtreeSignature{
					{CosignerID: mirrorOID.Bytes(), Signature: []byte("mirror sig")},
				}
			},
			wantErr: "none were by CA",
		},
		{
			name: "corrupted CA signature",
			modify: func(s *certInputs, _ **x509.Certificate) {
				s.proof.Signatures[0].Signature[0] ^= 1
			},
			wantErr: "invalid signature",
		},
		{
			name: "serial in a different log",
			modify: func(s *certInputs, _ **x509.Certificate) {
				s.serial = mtcSerial(6, 3)
			},
			wantErr: "invalid signature",
		},
		{
			name: "serial for a different entry",
			modify: func(s *certInputs, _ **x509.Certificate) {
				s.serial = mtcSerial(5, 2)
			},
			wantErr: "invalid signature",
		},
		{
			name: "serial outside the subtree",
			modify: func(s *certInputs, _ **x509.Certificate) {
				s.serial = mtcSerial(5, 6)
			},
			wantErr: "evaluating subtree inclusion proof",
		},
		{
			name: "tampered inclusion proof",
			modify: func(s *certInputs, _ **x509.Certificate) {
				s.proof.InclusionProof[0][0] ^= 1
			},
			wantErr: "invalid signature",
		},
		{
			name: "truncated inclusion proof",
			modify: func(s *certInputs, _ **x509.Certificate) {
				s.proof.InclusionProof = s.proof.InclusionProof[:len(s.proof.InclusionProof)-1]
			},
			wantErr: "evaluating subtree inclusion proof",
		},
		{
			name: "inclusion proof with an extra hash",
			modify: func(s *certInputs, _ **x509.Certificate) {
				s.proof.InclusionProof = append(s.proof.InclusionProof, tlog.Hash{0x07})
			},
			wantErr: "too many hashes",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			issuer := mtca.cert
			inputs := newBasicInputs(t, mtca)
			tc.modify(inputs, &issuer)
			result := mkStandalone(t, inputs)

			err := Standalone(result, issuer)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Standalone: %s", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Standalone: got nil error, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Standalone: got %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestStandaloneUnparsable(t *testing.T) {
	t.Parallel()
	err := Standalone([]byte("not a certificate"), loadMTCA(t).cert)
	if err == nil {
		t.Fatal("Standalone: got nil error, want error")
	}
	if !strings.Contains(err.Error(), "x509.ParseCertificate") {
		t.Errorf("Standalone: got %q, want it to contain %q", err, "x509.ParseCertificate")
	}
}

// TestStandaloneOversizeSerial checks that Standalone rejects a serial that
// doesn't fit in a uint64.
func TestStandaloneOversizeSerial(t *testing.T) {
	t.Parallel()
	mtca := loadMTCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %s", err)
	}
	template := &x509.Certificate{
		SerialNumber: new(big.Int).Lsh(big.NewInt(1), 64),
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2026, 1, 8, 0, 0, 0, 0, time.UTC),
	}
	parent := &x509.Certificate{RawSubject: mtca.cert.RawSubject}
	// Since the appropriate check comes pretty early on we can use a
	// not-very-realistic certificate and still hit the error check we want.
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent,
		key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %s", err)
	}

	err = Standalone(certDER, mtca.cert)
	if err == nil {
		t.Fatal("Standalone: got nil error, want error")
	}
	if !strings.Contains(err.Error(), "not representable as a uint64") {
		t.Errorf("Standalone: got %q, want it to contain %q", err, "not representable as a uint64")
	}
}
