package entry

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/trees/proof"
)

// testCertB64 contains an example certificate generated from
// test/certs/ipki/wfe.boulder/cert.pem.
const testCertB64 = `
MIIB4TCCAWegAwIBAgIIJuDkMteShO8wCgYIKoZIzj0EAwMwIDEeMBwGA1UEAxMV
bWluaWNhIHJvb3QgY2EgNGU0YjFkMB4XDTI2MDYyOTA1NDUyNloXDTI4MDcyOTA1
NDUyNlowFjEUMBIGA1UEAxMLd2ZlLmJvdWxkZXIwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAATLkY1wBrGl9+jhR4+HSycRv5kvVV8LUO3xY1styu8+q9kaSi03wrdH7LUf
rJkRE6S60XzVXkeqL9N//jOXFsaM9JbsbeHFRoAx+mBEV68Vu69dblxtXIAKNlMM
5dav5XOjeDB2MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYI
KwYBBQUHAwIwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBSA+ZfinkHdxJDZuRo1
zJ7mHOmaCDAWBgNVHREEDzANggt3ZmUuYm91bGRlcjAKBggqhkjOPQQDAwNoADBl
AjEApE8cwaAQ6hnGtUM/TWAb54E5/29ZVy5E/UY8mEzoE021pl3tq1fEof5qz5n/
KrL4AjAuEpVOjRrRWWMnRJxd05Pfxq7gZmxgwppjnE9JZ9P6WRP7ZWqZcc9p8YLM
YhKuXQo=`

// testSPKIB64 contains the SubjectPublicKeyInfo from testCertB64.
const testSPKIB64 = `
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEy5GNcAaxpffo4UePh0snEb+ZL1VfC1Dt
8WNbLcrvPqvZGkotN8K3R+y1H6yZEROkutF81V5Hqi/Tf/4zlxbGjPSW7G3hxUaA
MfpgRFevFbuvXW5cbVyACjZTDOXWr+Vz`

// mustDecodeB64 decodes a base64 string that may contain embedded newlines.
func mustDecodeB64(t *testing.T, in string) []byte {
	t.Helper()
	out, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(in, "\n", ""))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestFromX509(t *testing.T) {
	input := mustDecodeB64(t, testCertB64)

	mtcle, err := FromX509(input, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	if mtcle.typ != typeTBSCertEntry {
		t.Errorf("mtcle.Type: got %d, want tbs_cert_entry (1)", mtcle.typ)
	}

	expectedOutput, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(`
oAMCAQIwIDEeMBwGA1UEAxMVbWluaWNhIHJvb3QgY2EgNGU0YjFkMB4XDTI2MDYy
OTA1NDUyNloXDTI4MDcyOTA1NDUyNlowFjEUMBIGA1UEAxMLd2ZlLmJvdWxkZXIw
EAYHKoZIzj0CAQYFK4EEACIEIMSLH5h0zn2wLKskA7HQxGB55+KVdq5YxDrrIAhg
9ZkJo3gwdjAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsG
AQUFBwMCMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUgPmX4p5B3cSQ2bkaNcye
5hzpmggwFgYDVR0RBA8wDYILd2ZlLmJvdWxkZXI=
`, "\n", ""))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(mtcle.value, expectedOutput) {
		t.Errorf("FromX509(): got %s, want %s",
			base64.StdEncoding.EncodeToString(mtcle.value),
			base64.StdEncoding.EncodeToString(expectedOutput))
	}
}

func TestToMTC(t *testing.T) {
	input := mustDecodeB64(t, testCertB64)
	spki := mustDecodeB64(t, testSPKIB64)

	mtcle, err := FromX509(input, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	sig := proof.MTCProof{
		Start: 123,
		End:   456,
		InclusionProof: []tlog.Hash{
			{1, 2, 3, 4, 5, 6, 7, 8, 9},
		},
	}

	out, err := mtcle.ToMTC(123, spki, crypto.SHA256, sig)
	if err != nil {
		t.Fatal(err)
	}

	// Rather than comparing against golden bytes, check the output
	// structurally: it must be a well-formed X.509 certificate whose issuer,
	// validity, subject, SPKI, and extensions match the original certificate,
	// with the caller-provided serial and signature.
	cert, err := x509.ParseCertificate(out)
	if err != nil {
		t.Fatalf("parsing ToMTC() output: %s", err)
	}
	orig, err := x509.ParseCertificate(input)
	if err != nil {
		t.Fatal(err)
	}

	if cert.SerialNumber.Cmp(big.NewInt(123)) != 0 {
		t.Errorf("serialNumber: got %v, want 123", cert.SerialNumber)
	}
	if !bytes.Equal(cert.RawIssuer, orig.RawIssuer) {
		t.Errorf("issuer: got %x, want %x", cert.RawIssuer, orig.RawIssuer)
	}
	if !cert.NotBefore.Equal(orig.NotBefore) || !cert.NotAfter.Equal(orig.NotAfter) {
		t.Errorf("validity: got %s/%s, want %s/%s",
			cert.NotBefore, cert.NotAfter, orig.NotBefore, orig.NotAfter)
	}
	if !bytes.Equal(cert.RawSubject, orig.RawSubject) {
		t.Errorf("subject: got %x, want %x", cert.RawSubject, orig.RawSubject)
	}
	if !bytes.Equal(cert.RawSubjectPublicKeyInfo, spki) {
		t.Errorf("subjectPublicKeyInfo: got %x, want %x", cert.RawSubjectPublicKeyInfo, spki)
	}
	if !reflect.DeepEqual(cert.Extensions, orig.Extensions) {
		t.Errorf("extensions: got %v, want %v", cert.Extensions, orig.Extensions)
	}

	// The signature must be the marshaled MTCProof.
	sigBytes, err := sig.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cert.Signature, sigBytes) {
		t.Errorf("signature: got %x, want %x", cert.Signature, sigBytes)
	}

	// Both the TBSCertificate signature field and the Certificate
	// signatureAlgorithm field must be the experimental id-alg-mtcProof
	// AlgorithmIdentifier (1.3.6.1.4.1.44363.47.0) with parameters omitted.
	// x509.ParseCertificate already checks that the two are equal.
	sigAlg := proof.SigAlgEncoded()
	if got := bytes.Count(out, sigAlg); got != 2 {
		t.Errorf("id-alg-mtcProof AlgorithmIdentifier: found %d copies, want 2", got)
	}
}

func TestToMTCMalformed(t *testing.T) {
	input := mustDecodeB64(t, testCertB64)
	spki := mustDecodeB64(t, testSPKIB64)

	valid, err := FromX509(input, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	// mutatedTBS returns a tbs_cert_entry whose TBSCertificateLogEntry bytes
	// are a copy of the valid entry's, transformed by f.
	mutatedTBS := func(f func([]byte) []byte) *MTCLogEntry {
		return &MTCLogEntry{
			typ:   typeTBSCertEntry,
			value: f(bytes.Clone(valid.value)),
		}
	}

	// mutatedSPKI returns a copy of spki with the byte at index i flipped.
	mutatedSPKI := func(i int) []byte {
		out := bytes.Clone(spki)
		out[i] ^= 0xff
		return out
	}

	type testCase struct {
		name  string
		mtcle *MTCLogEntry
		spki  []byte
		hash  crypto.Hash
	}

	testCases := []testCase{
		{"null entry", &MTCLogEntry{}, spki, crypto.SHA256},
		{"truncated TBS", mutatedTBS(func(v []byte) []byte { return v[:len(v)-2] }), spki, crypto.SHA256},
		{"trailing byte in TBS", mutatedTBS(func(v []byte) []byte { return append(v, 0) }), spki, crypto.SHA256},
		// The version is the first field of the TBSCertificateLogEntry,
		// encoded as a0 03 02 01 02; overwrite the value byte (v2 not v3).
		{"wrong version", mutatedTBS(func(v []byte) []byte { v[4] = 1; return v }), spki, crypto.SHA256},
		{"empty SPKI", valid, nil, crypto.SHA256},
		{"truncated SPKI", valid, spki[:8], crypto.SHA256},
		// Index 8 is inside the id-ecPublicKey OID within the SPKI's
		// AlgorithmIdentifier, so it must fail the algorithm comparison.
		{"SPKI with different algorithm", valid, mutatedSPKI(8), crypto.SHA256},
		// The last byte is inside the public key BIT STRING, so the
		// AlgorithmIdentifiers match but the hash must not.
		{"SPKI with different key", valid, mutatedSPKI(len(spki) - 1), crypto.SHA256},
		{"wrong hash function", valid, spki, crypto.SHA384},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.mtcle.ToMTC(123, tc.spki, tc.hash, proof.MTCProof{})
			if err == nil {
				t.Errorf("ToMTC(): got nil err, want error")
			}
		})
	}

	// serialNumber must be a positive integer (RFC 5280 4.1.2.2).
	if _, err := valid.ToMTC(0, spki, crypto.SHA256, proof.MTCProof{}); err == nil {
		t.Errorf("ToMTC() with zero serial: got nil err, want error")
	}
}

func TestFromX509Malformed(t *testing.T) {
	valid := mustDecodeB64(t, testCertB64)

	shortValid := valid[:len(valid)-2]
	longValid := append(valid, 0)

	wrongVersion := bytes.Clone(valid)
	copy(wrongVersion[10:13], []byte{2, 1, 1})

	type testCase struct {
		name, hex string
	}
	testCases := []testCase{
		{"empty", ""},
		{"tag only", "30"},
		{"nothing inside", "300100"},
		{"too short", hex.EncodeToString(shortValid)},
		{"too long", hex.EncodeToString(longValid)},
		{"wrong version", hex.EncodeToString(wrongVersion)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			val, err := hex.DecodeString(tc.hex)
			if err != nil {
				t.Fatal(err)
			}
			_, err = FromX509(val, crypto.SHA256)
			if err == nil {
				t.Errorf("FromX509(): got nil err, want error")
			}
		})
	}
}

func TestMarshalMTCLE(t *testing.T) {
	invalidType := MTCLogEntry{
		typ: 99,
	}
	_, err := invalidType.Marshal()
	if err == nil {
		t.Errorf("invalid type: got nil err, want error")
	}

	nonEmptyNullEntry := MTCLogEntry{
		typ:   typeNullEntry,
		value: []byte("abc"),
	}
	_, err = nonEmptyNullEntry.Marshal()
	if err == nil {
		t.Errorf("non-empty null_entry: got nil err, want error")
	}

	validNullEntry := MTCLogEntry{
		typ: typeNullEntry,
	}
	output, err := validNullEntry.Marshal()
	if err != nil {
		t.Errorf("marshaling valid null_entry: %s", err)
	}
	expected := []byte{0, 0, 0, 0}
	if !bytes.Equal(output, expected) {
		t.Errorf("marshaling valid null_entry: got %x, want %x", output, expected)
	}

	validTBSCertificateLogEntry := MTCLogEntry{
		typ:   typeTBSCertEntry,
		value: []byte("abc"),
	}
	output, err = validTBSCertificateLogEntry.Marshal()
	if err != nil {
		t.Errorf("marshaling valid tbs_cert_entry: %s", err)
	}
	expected = []byte{0, 0, 0, 1, 'a', 'b', 'c'}
	if !bytes.Equal(output, expected) {
		t.Errorf("marshaling valid tbs_cert_entry: got %x, want %x", output, expected)
	}
}

func TestUnmarshalMTCLE(t *testing.T) {
	type testCase struct {
		name      string
		input     string
		expectErr bool
		expectVal *MTCLogEntry
	}

	testCases := []testCase{
		{"valid TBS", "00000001616263", false, &MTCLogEntry{
			typ:   typeTBSCertEntry,
			value: []byte("abc"),
		}},
		{"valid null_entry", "00000000", false, &MTCLogEntry{
			typ: typeNullEntry,
		}},
		{"too short", "000000", true, nil},
		{"way too short", "00", true, nil},
		{"way way too short", "", true, nil},
		{"null_entry with value", "0000000099", true, nil},
		{"invalid type", "00000102616263", true, nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			val, err := hex.DecodeString(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			mtcle, err := unmarshalMTCLE(val)
			if tc.expectErr && err == nil {
				t.Errorf("expected error")
			}
			if tc.expectVal != nil {
				if err != nil {
					t.Fatalf("Unmarshal(): %s", err)
				}
				if !bytes.Equal(mtcle.extensions, tc.expectVal.extensions) {
					t.Errorf("Unmarshal() extensions: got %#v, want %#v", mtcle.extensions, tc.expectVal.extensions)
				}
				if mtcle.typ != tc.expectVal.typ {
					t.Errorf("Unmarshal() type: got %#v, want %#v", mtcle.typ, tc.expectVal.typ)
				}
				if !bytes.Equal(mtcle.value, tc.expectVal.value) {
					t.Errorf("Unmarshal() value: got %#v, want %#v", mtcle.value, tc.expectVal.value)
				}
			}
		})
	}
}

func TestBundleBuildAndRead(t *testing.T) {
	var buf []byte
	bb := NewBundleBuilder(buf)

	bb.Add(&MTCLogEntry{})

	for range 10 {
		bb.Add(&MTCLogEntry{
			typ:   typeTBSCertEntry,
			value: []byte{0x55, 0x55, 0x55, 0x55, 0x55},
		})
	}

	tile, err := bb.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	br := NewBundleReader(tile)

	mtcle, raw, err := br.ReadEntry()
	if err != nil {
		t.Fatal(err)
	}
	if mtcle.typ != typeNullEntry {
		t.Errorf("mtcle.Type: got %d, want %d", mtcle.typ, typeNullEntry)
	}
	if len(mtcle.extensions) != 0 {
		t.Errorf("mtcle.Extensions: got %v, want nil", mtcle.extensions)
	}
	if len(mtcle.value) != 0 {
		t.Errorf("mtcle.Value: got %v, want nil", mtcle.value)
	}
	expected := []byte{0, 0, 0, 0}
	if !bytes.Equal(raw, expected) {
		t.Errorf("raw mtcle: got %x, want %x", raw, expected)
	}

	for range 10 {
		mtcle, raw, err := br.ReadEntry()
		if err != nil {
			t.Fatal(err)
		}
		if mtcle.typ != typeTBSCertEntry {
			t.Errorf("mtcle.Type: got %d, want %d", mtcle.typ, typeTBSCertEntry)
		}
		if len(mtcle.extensions) != 0 {
			t.Errorf("mtcle.Extensions: got %v, want nil", mtcle.extensions)
		}
		wantValue := []byte{0x55, 0x55, 0x55, 0x55, 0x55}
		if !bytes.Equal(mtcle.value, wantValue) {
			t.Errorf("mtcle.Value: got %x, want %x", mtcle.value, wantValue)
		}
		wantMTCLEBytes := append([]byte{0, 0, 0, 1}, wantValue...)
		if !bytes.Equal(raw, wantMTCLEBytes) {
			t.Errorf("raw MTCLogEntry: got %x, want %x", raw, expected)
		}
	}
}

func TestBundleReaderSuccess(t *testing.T) {
	br := NewBundleReader(nil)
	entry, entryBytes, err := br.ReadEntry()
	if err != nil && !errors.Is(err, io.EOF) {
		t.Error(err)
	}
	if entry != nil {
		t.Errorf("empty reader: got %v, want nil entry", entry)
	}
	if len(entryBytes) != 0 {
		t.Errorf("empty reader: got %x, want empty bytes", entryBytes)
	}

	// - 9 bytes of data
	// - empty extensions (0000);
	// - type = TBSCertificateLogEntry (0001)
	// - fake TBSCertificateLogEntry (5 bytes of 55)
	input, err := hex.DecodeString("0009000000015555555555")
	if err != nil {
		t.Fatal(err)
	}

	br = NewBundleReader(input)
	_, _, err = br.ReadEntry()
	if err != nil {
		t.Error(err)
	}
	_, _, err = br.ReadEntry()
	if !errors.Is(err, io.EOF) {
		t.Errorf("second read on a 1-element bundle: want EOF, got %v", err)
	}

	br = NewBundleReader(bytes.Repeat(input, 256))
	var count int64
	for count = 0; ; count++ {
		_, _, err := br.ReadEntry()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatal(err)
		}
	}

	if count != 256 {
		t.Errorf("reading many bundles: got %d values, want %d", count, 256)
	}
}

func TestBundleReaderMalformed(t *testing.T) {
	type testCase struct {
		name, input string
	}

	testCases := []testCase{
		{"short length", "09"},
		{"short body", "0001"},
		{"max length, short body", "FFFF"},
		{"two records, short length on second", "0001FF09"},
		{"two records, short body on second", "0001FF0001"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			in, err := hex.DecodeString(tc.input)
			if err != nil {
				t.Fatal(err)
			}

			br := NewBundleReader(in)
			for {
				_, _, err = br.ReadEntry()
				if err != nil {
					if errors.Is(err, io.EOF) {
						t.Error("got nil error, want error")
					}
					break
				}
			}
		})
	}
}
