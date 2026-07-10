//go:build go1.27

package entry

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/zmap/zcrypto/cryptobyte"
	"github.com/zmap/zcrypto/cryptobyte/asn1"
)

func TestTBSCertificateLogEntryFromX509(t *testing.T) {
	// Bytes from an example generated test/certs/ipki/wfe.boulder/cert.pem
	input, err := base64.StdEncoding.DecodeString(strings.Replace(`
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
YhKuXQo=`, "\n", "", -1))
	if err != nil {
		t.Fatal(err)
	}

	output, err := TBSCertificateLogEntryFromX509(input, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	expectedOutput, err := base64.StdEncoding.DecodeString(strings.Replace(`
oAWgAwIBAjAiMCAxHjAcBgNVBAMTFW1pbmljYSByb290IGNhIDRlNGIxZDAgMB4X
DTI2MDYyOTA1NDUyNloXDTI4MDcyOTA1NDUyNlowGDAWMRQwEgYDVQQDEwt3ZmUu
Ym91bGRlcjAQBgcqhkjOPQIBBgUrgQQAIgQgxIsfmHTOfbAsqyQDsdDEYHnn4pV2
rljEOusgCGD1mQmjeDB2MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEF
BQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBSA+ZfinkHd
xJDZuRo1zJ7mHOmaCDAWBgNVHREEDzANggt3ZmUuYm91bGRlcg==
`, "\n", "", -1))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(output, expectedOutput) {
		// Since TBSCertificateLogEntry is encoded as DER without a tag or length,
		// it's not readily parseable by off-the-shelf DER parsers like lapo.it/asn1js.
		// For convenience of investigating, wrap both values in a SEQUENCE before output.
		t.Errorf("sequenceWrap(TBSCertificateLogEntryFromX509()): got %s, want %s",
			base64.StdEncoding.EncodeToString(sequenceWrap(output)),
			base64.StdEncoding.EncodeToString(sequenceWrap(expectedOutput)))
	}
}

func TestMerkleTreeCertEntryMarshal(t *testing.T) {
	invalidType := MerkleTreeCertEntry{
		Type: 99,
	}
	_, err := invalidType.Marshal()
	if err == nil {
		t.Errorf("invalid type: got nil err, want error")
	}

	nonEmptyNullEntry := MerkleTreeCertEntry{
		Type:  TYPE_NULL_ENTRY,
		Value: []byte("abc"),
	}
	_, err = nonEmptyNullEntry.Marshal()
	if err == nil {
		t.Errorf("non-empty null_entry: got nil err, want error")
	}

	validNullEntry := MerkleTreeCertEntry{
		Type: TYPE_NULL_ENTRY,
	}
	output, err := validNullEntry.Marshal()
	if err != nil {
		t.Errorf("marshaling valid null_entry: %s", err)
	}
	expected := []byte{0, 0, 0, 0}
	if !bytes.Equal(output, expected) {
		t.Errorf("marshaling valid null_entry: got %x, want %x", output, expected)
	}

	validTBSCertificateLogEntry := MerkleTreeCertEntry{
		Type:  TYPE_TBS_CERT_ENTRY,
		Value: []byte("abc"),
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

func TestMerkleTreeCertEntryUnmarshal(t *testing.T) {
	type testCase struct {
		name      string
		input     string
		expectErr bool
		expectVal *MerkleTreeCertEntry
	}

	testCases := []testCase{
		{"valid TBS", "00000001616263", false, &MerkleTreeCertEntry{
			Type:  TYPE_TBS_CERT_ENTRY,
			Value: []byte("abc"),
		}},
		{"valid null_entry", "00000000", false, &MerkleTreeCertEntry{
			Type: TYPE_NULL_ENTRY,
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
			mtce, err := Unmarshal(val)
			if tc.expectErr && err == nil {
				t.Errorf("expected error")
			}
			if tc.expectVal != nil {
				if err != nil {
					t.Fatalf("Unmarshal(): %s", err)
				}
				if !bytes.Equal(mtce.Extensions, tc.expectVal.Extensions) {
					t.Errorf("Unmarshal() extensions: got %#v, want %#v", mtce.Extensions, tc.expectVal.Extensions)
				}
				if mtce.Type != tc.expectVal.Type {
					t.Errorf("Unmarshal() type: got %#v, want %#v", mtce.Type, tc.expectVal.Type)
				}
				if !bytes.Equal(mtce.Value, tc.expectVal.Value) {
					t.Errorf("Unmarshal() value: got %#v, want %#v", mtce.Value, tc.expectVal.Value)
				}
			}
		})
	}
}

func sequenceWrap(in []byte) []byte {
	// TBSCertificateLogEntry is DER encoded with the length and tag stripped, or equivalently
	// the concatenated fields. That means DER parsers like https://lapo.it/asn1js/ can't parse
	// it. For convenience, spit out a version that is wrapped in a SEQUENCE.
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(in)
	})
	return b.BytesOrPanic()
}
