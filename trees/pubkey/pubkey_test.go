package pubkey

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

var testPubkeyBytes []byte
var testPubkeySingletonSPKI crypto.PublicKey

// testPubkey returns atest MYCPublicKey and sets some global variables to values we can use and re-use
func testPubkeySingleton() *MTCPublicKey {
	if testPubkeySingletonSPKI == nil {
		generatedPubkey, err := ecdsa.GenerateKey(elliptic.P256(), nil)
		if err != nil {
			panic(err)
		}
		testPubkeySingletonSPKI = &generatedPubkey.PublicKey

	}
	if testPubkeyBytes == nil {
		marshaledPubkeyBytes, err := x509.MarshalPKIXPublicKey(testPubkeySingletonSPKI)
		if err != nil {
			panic(err)
		}
		testPubkeyBytes = marshaledPubkeyBytes
	}
	testPubkey, err := FromCryptoPubkey(testPubkeySingletonSPKI)
	if err != nil {
		panic(err)
	}
	return testPubkey
}

func TestMarshalMTCPK(t *testing.T) {
	_ = testPubkeySingleton()

	invalidType := MTCPublicKey{
		typ: 99,
	}
	_, err := invalidType.Marshal()
	if err == nil {
		t.Errorf("invalid type: got nil err, want error")
	}

	nonEmptyNullPubkey := MTCPublicKey{
		typ: typeNilPubkey,
		pub: testPubkeyBytes,
	}
	_, err = nonEmptyNullPubkey.Marshal()
	if err == nil {
		t.Errorf("non-empty null pubkey: got nil err, want error")
	}

	validNilPubkey := MTCPublicKey{
		typ: typeNilPubkey,
	}
	output, err := validNilPubkey.Marshal()
	if err != nil {
		t.Errorf("marshaling valid null pubkey: %s", err)
	}
	expected := []byte{0, 0, 0, 0}
	if !bytes.Equal(output, expected) {
		t.Errorf("marshaling valid null pubkey: got %x, want %x", output, expected)
	}

	validMTCPubkey := MTCPublicKey{
		typ: typeMTCPubkey,
		pub: testPubkeyBytes,
	}
	output, err = validMTCPubkey.Marshal()
	if err != nil {
		t.Errorf("marshaling valid pubkey: %s", err)
	}
	expected = testPubkeyBytes
	if !bytes.Equal(output, expected) {
		t.Errorf("marshaling valid pubkey: got %x, want %x", output, expected)
	}
}

func TestUnmarshalMTCPK(t *testing.T) {
	type testCase struct {
		name      string
		input     string
		expectErr bool
		expectVal *MTCPublicKey
	}

	_ = testPubkeySingleton()

	testCases := []testCase{
		{"valid pubkey", "00000000", false, &MTCPublicKey{
			typ: typeMTCPubkey,
			pub: testPubkeyBytes,
		}},
		{"valid null pubkey", "00000000", false, &MTCPublicKey{
			typ: typeNilPubkey,
		}},
		{"too short", "000000", true, nil},
		{"way too short", "00", true, nil},
		{"way way too short", "", true, nil},
		{"null pubkey with value", "000099", true, nil},
		{"invalid type", "0102616263", true, nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			val, err := hex.DecodeString(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			mtcpk, err := unmarshalMTCPK(val)
			if tc.expectErr && err == nil {
				t.Errorf("expected error")
			}
			if tc.expectVal != nil {
				if err != nil {
					t.Fatalf("Unmarshal(): %s", err)
				}
				if mtcpk.typ != tc.expectVal.typ {
					t.Errorf("Unmarshal() type: got %#v, want %#v", mtcpk.typ, tc.expectVal.typ)
				}
				pkBytes, _ := x509.MarshalPKIXPublicKey(mtcpk.pub)
				expBytes, _ := x509.MarshalPKIXPublicKey(tc.expectVal.pub)
				if !bytes.Equal(pkBytes, expBytes) {
					t.Errorf("Unmarshal() value: got %#v, want %#v", mtcpk.pub, tc.expectVal.pub)
				}
			}
		})
	}
}

func TestPubkeyBundleBuildAndRead(t *testing.T) {
	testPubkey := testPubkeySingleton()

	var buf []byte
	bb := NewBundleBuilder(buf)

	bb.Add(&MTCPublicKey{})

	for range 10 {
		bb.Add(testPubkey)
	}

	tile, err := bb.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	br := NewBundleReader(tile)

	mtcpk, raw, err := br.ReadPubkey()
	if err != nil {
		t.Fatal(err)
	}
	if mtcpk.typ != typeNilPubkey {
		t.Errorf("mtcpk.typ: got %d, want %d", mtcpk.typ, typeNilPubkey)
	}
	pkBytes, err := x509.MarshalPKIXPublicKey(mtcpk.pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkBytes) != 0 {
		t.Errorf("mtcpk.pub: got %v, want nil", mtcpk.pub)
	}
	expected := []byte{0, 0}
	if !bytes.Equal(raw, expected) {
		t.Errorf("raw mtcpk: got %x, want %x", raw, expected)
	}

	for range 10 {
		mtcpk, raw, err := br.ReadPubkey()
		if err != nil {
			t.Fatal(err)
		}
		if mtcpk.typ != typeMTCPubkey {
			t.Errorf("mtcpk.Type: got %d, want %d", mtcpk.typ, typeMTCPubkey)
		}
		pkBytes, _ := x509.MarshalPKIXPublicKey(mtcpk.pub)
		wantValue := testPubkey.Pubkey()
		if !bytes.Equal(pkBytes, wantValue) {
			t.Errorf("mtcpk.Value: got %x, want %x", mtcpk.pub, wantValue)
		}
		wantMTCPKBytes := append([]byte{0, 0, 0, 1}, wantValue...)
		if !bytes.Equal(raw, wantMTCPKBytes) {
			t.Errorf("raw MTCPubkey: got %x, want %x", raw, expected)
		}
	}
}

func TestBundleReaderSuccess(t *testing.T) {
	br := NewBundleReader(nil)
	mtcpk, pubkeyBytes, err := br.ReadPubkey()
	if err != nil && !errors.Is(err, io.EOF) {
		t.Error(err)
	}
	if mtcpk != nil {
		t.Errorf("empty reader: got %v, want nil mtcpk", mtcpk)
	}
	if len(pubkeyBytes) != 0 {
		t.Errorf("empty reader: got %x, want empty bytes", pubkeyBytes)
	}

	// - 7 bytes of data
	// - type = Pubkey (0001)
	// - fake Pubkey Data (5 bytes of 55)
	input, err := hex.DecodeString("000700015555555555") // TODO: REPLACE WITH TEST KEY
	if err != nil {
		t.Fatal(err)
	}

	br = NewBundleReader(input)
	_, _, err = br.ReadPubkey()
	if err != nil {
		t.Error(err)
	}
	_, _, err = br.ReadPubkey()
	if !errors.Is(err, io.EOF) {
		t.Errorf("second read on a 1-element bundle: want EOF, got %v", err)
	}

	br = NewBundleReader(bytes.Repeat(input, 256))
	var count int64
	for count = 0; ; count++ {
		_, _, err := br.ReadPubkey()
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

func TestPubkeyBundleReaderMalformed(t *testing.T) {
	type testCase struct {
		name, input string
	}

	testCases := []testCase{ // TODO: INTERACT WITH TEST KEY
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
				_, _, err = br.ReadPubkey()
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
