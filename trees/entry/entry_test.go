package entry

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestFromX509(t *testing.T) {
	// Bytes from an example generated test/certs/ipki/wfe.boulder/cert.pem
	input, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(`
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
YhKuXQo=`, "\n", ""))
	if err != nil {
		t.Fatal(err)
	}

	mtce, err := FromX509(input, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	if mtce.Type != typeTBSCertEntry {
		t.Errorf("mtce.Type: got %d, want tbs_cert_entry (1)", mtce.Type)
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

	if !bytes.Equal(mtce.Value, expectedOutput) {
		t.Errorf("TBSCertificateLogEntryFromX509(): got %s, want %s",
			base64.StdEncoding.EncodeToString(mtce.Value),
			base64.StdEncoding.EncodeToString(expectedOutput))
	}
}

func TestFromX509Malformed(t *testing.T) {
	valid, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(`
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
YhKuXQo=`, "\n", ""))
	if err != nil {
		t.Fatal(err)
	}

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

func TestMerkleTreeCertEntryMarshal(t *testing.T) {
	invalidType := MTCLogEntry{
		Type: 99,
	}
	_, err := invalidType.Marshal()
	if err == nil {
		t.Errorf("invalid type: got nil err, want error")
	}

	nonEmptyNullEntry := MTCLogEntry{
		Type:  typeNullEntry,
		Value: []byte("abc"),
	}
	_, err = nonEmptyNullEntry.Marshal()
	if err == nil {
		t.Errorf("non-empty null_entry: got nil err, want error")
	}

	validNullEntry := MTCLogEntry{
		Type: typeNullEntry,
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
		Type:  typeTBSCertEntry,
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
		expectVal *MTCLogEntry
	}

	testCases := []testCase{
		{"valid TBS", "00000001616263", false, &MTCLogEntry{
			Type:  typeTBSCertEntry,
			Value: []byte("abc"),
		}},
		{"valid null_entry", "00000000", false, &MTCLogEntry{
			Type: typeNullEntry,
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
				if !bytes.Equal(mtcle.Extensions, tc.expectVal.Extensions) {
					t.Errorf("Unmarshal() extensions: got %#v, want %#v", mtcle.Extensions, tc.expectVal.Extensions)
				}
				if mtcle.Type != tc.expectVal.Type {
					t.Errorf("Unmarshal() type: got %#v, want %#v", mtcle.Type, tc.expectVal.Type)
				}
				if !bytes.Equal(mtcle.Value, tc.expectVal.Value) {
					t.Errorf("Unmarshal() value: got %#v, want %#v", mtcle.Value, tc.expectVal.Value)
				}
			}
		})
	}
}

func TestBundleBuildAndRead(t *testing.T) {
	var buf []byte
	bw := NewBundleBuilder(buf)

	for range 10 {
		bw.Add(MTCLogEntry{})
	}

	tile, err := bw.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	br := NewBundleReader(tile)

	for range 10 {
		mtce, raw, err := br.Read()
		if err != nil {
			t.Fatal(err)
		}
		if mtce.Type != typeNullEntry {
			t.Errorf("mtce.Type: got %d, want %d", mtce.Type, typeNullEntry)
		}
		if len(mtce.Extensions) != 0 {
			t.Errorf("mtce.Extensions: got %v, want nil", mtce.Extensions)
		}
		if len(mtce.Value) != 0 {
			t.Errorf("mtce.Value: got %v, want nil", mtce.Value)
		}
		expected := []byte{0, 0, 0, 0}
		if !bytes.Equal(raw, expected) {
			t.Errorf("raw mtce: got %x, want %x", raw, expected)
		}
	}
}
