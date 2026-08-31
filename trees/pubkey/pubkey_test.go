package pubkey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"io"
	"testing"

	"golang.org/x/crypto/cryptobyte"

	"github.com/letsencrypt/boulder/test"
)

// gimmeLengthPrefixedBytes returns the bytes of a length-prefixed cryptobyte
// string of the input bytes
func gimmeLengthPrefixedBytes(in []byte) []byte {
	var buf []byte
	cbb := *cryptobyte.NewBuilder(buf)
	cbb.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(in)
	})

	return cbb.BytesOrPanic()
}

// testPubkey is a helper tests can call to get both a good MTCPublicKey, and
// the structure's inner SPKI bytes
func testPubkey() (*MTCPublicKey, []byte) {
	generatedPubkey, err := ecdsa.GenerateKey(elliptic.P256(), nil)
	if err != nil {
		panic(err)
	}

	testPubkeyBytes, err := x509.MarshalPKIXPublicKey(&generatedPubkey.PublicKey)
	if err != nil {
		panic(err)
	}

	testMTCPubkey, err := FromCryptoPubkey(&generatedPubkey.PublicKey)
	if err != nil {
		panic(err)
	}

	return testMTCPubkey, testPubkeyBytes
}

// testBundle is a helper tests can call to get a valid length-prefixed public
// key bundle
func testBundle() []byte {
	testMTCPK, _ := testPubkey()

	testBundleBody, err := testMTCPK.Marshal()
	if err != nil {
		panic(err)
	}

	return gimmeLengthPrefixedBytes(testBundleBody)
}

func TestMarshalMTCPK(t *testing.T) {
	testPubkey, testPubkeyBytes := testPubkey()

	// Test an invalid MTCPublicKey type
	invalidType := MTCPublicKey{
		typ: 99,
	}
	_, err := invalidType.Marshal()
	if err == nil {
		t.Errorf("invalid type: got nil err, want error")
	}

	// Test an invalid null MTCPublicKey
	nonEmptyNullPubkey := MTCPublicKey{
		typ: typeNullPubkey,
		pub: testPubkeyBytes,
	}
	_, err = nonEmptyNullPubkey.Marshal()
	if err == nil {
		t.Errorf("non-empty null pubkey: got nil err, want error")
	}

	// Test a valid null MTCPublicKey
	validNullPubkey := MTCPublicKey{
		typ: typeNullPubkey,
	}
	output, err := validNullPubkey.Marshal()
	if err != nil {
		t.Errorf("marshaling valid null pubkey: %s", err)
	}
	expected := []byte{0, 0}
	if !bytes.Equal(output, expected) {
		t.Errorf("marshaling valid null pubkey: got %x, want %x", output, expected)
	}

	// Test the valid MTCPublicKey
	output, err = testPubkey.Marshal()
	if err != nil {
		t.Errorf("marshaling valid pubkey: %s", err)
	}
	expected = append([]byte{0, 1}, gimmeLengthPrefixedBytes(testPubkeyBytes)...)
	if !bytes.Equal(output, expected) {
		t.Errorf("marshaling valid pubkey: got %x, want %x", output, expected)
	}
}

func TestUnmarshalMTCPK(t *testing.T) {
	type testCase struct {
		name      string
		input     []byte
		expectErr string
		expectVal *MTCPublicKey
	}

	_, testPubkeyBytes := testPubkey()
	// testPubkeyBytesLength := len(testPubkeyBytes)

	validUnmarshalable := gimmeLengthPrefixedBytes(testPubkeyBytes)
	validUnmarshalableLength := len(validUnmarshalable)

	testCases := []testCase{
		{"valid pubkey", append([]byte{0, 1}, validUnmarshalable...), "", &MTCPublicKey{
			typ: typeSPKI,
			pub: testPubkeyBytes,
		}},
		{"valid null pubkey", []byte{0, 0}, "", &MTCPublicKey{
			typ: typeNullPubkey,
		}},
		{"too short", append([]byte{0, 1}, validUnmarshalable[:validUnmarshalableLength-6]...), "malformed pubkey", nil},
		{"way too short", []byte{1}, "malformed type", nil},
		{"null pubkey type with pubkey bytes", append([]byte{0, 0}, validUnmarshalable...), "null pubkey with non-empty value", nil},
		{"pubkey type with no pubkey bytes", []byte{0, 1}, "non-null pubkey with empty value", nil},
		{"unknown type", append([]byte{0, 3}, validUnmarshalable...), "unknown MTCPubkey type", nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mtcpk, err := unmarshalMTCPK(tc.input)
			if tc.expectErr != "" && err == nil {
				t.Errorf("expected error")
			}
			if tc.expectErr != "" && err != nil {
				test.AssertContains(t, err.Error(), tc.expectErr)
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
					t.Errorf("Unmarshal() value: got %#v, want %#v", pkBytes, expBytes)
				}
			}
		})
	}
}

func TestPubkeyBundleBuildAndRead(t *testing.T) {
	testMTCPubkey, _ := testPubkey()

	var buf []byte
	cbb := *cryptobyte.NewBuilder(buf)

	// first marshal a null pubkey
	nullMTCPk := &MTCPublicKey{}
	nullPkBundle, err := nullMTCPk.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// and add the null MTCPubkey bytes to the bundle
	cbb.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(nullPkBundle)
	})

	// then add 10 copies of the test pubkey to the bundle
	for range 10 {
		testPkBundle, err := testMTCPubkey.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		cbb.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
			child.AddBytes(testPkBundle)
		})
	}

	tile, err := cbb.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	br := NewBundleReader(tile)

	// read-back the null pubkey
	mtcpk, raw, err := br.ReadPubkey()
	if err != nil {
		t.Fatal(err)
	}
	if mtcpk.typ != typeNullPubkey {
		t.Errorf("mtcpk.typ: got %d, want %d", mtcpk.typ, typeNullPubkey)
	}
	if len(mtcpk.pub) != 0 {
		t.Errorf("mtcpk.pub: got %v, want nil", mtcpk.pub)
	}
	expected := []byte{0, 0}
	if !bytes.Equal(raw, expected) {
		t.Errorf("raw mtcpk: got %x, want %x", raw, expected)
	}

	// read-back the 10 test pubkeys
	for range 10 {
		mtcpk, raw, err := br.ReadPubkey()
		if err != nil {
			t.Fatal(err)
		}
		if mtcpk.typ != typeSPKI {
			t.Errorf("mtcpk.Type: got %d, want %d", mtcpk.typ, typeSPKI)
		}
		wantValue := testMTCPubkey.Pubkey()
		if !bytes.Equal(mtcpk.pub, wantValue) {
			t.Errorf("mtcpk.Value: got %x, want %x", mtcpk.pub, wantValue)
		}
		wantMTCPKBytes := append([]byte{0, 1}, gimmeLengthPrefixedBytes(wantValue)...)
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

	input := testBundle()

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
	_, testPubkeyBytes := testPubkey()
	testBundle := testBundle()

	type testCase struct {
		name  string
		input []byte
	}

	// expecting that 0,33 is not zero, but shorter than any testPubkey
	shortLengthBundle := append([]byte{0, 33, 0, 1}, gimmeLengthPrefixedBytes(testPubkeyBytes)...)
	// expecting that 33,255 is not MAX, but larger than any testPubkey
	shortBodyBundle := append([]byte{33, 255, 0, 1}, gimmeLengthPrefixedBytes(testPubkeyBytes)...)

	testCases := []testCase{
		{"short length", shortLengthBundle},
		{"short body", shortBodyBundle},
		{"max length, short body", append([]byte{255, 255, 0, 1}, testPubkeyBytes...)},
		{"two records, short length on second", append(testBundle, shortLengthBundle...)},
		{"two records, short body on second", append(testBundle, shortBodyBundle...)},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			br := NewBundleReader(tc.input)
			for {
				_, _, err := br.ReadPubkey()
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
