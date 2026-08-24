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
)

// Broad scope var with pubkey Bytes for use in tests
var testPubkeyBytes []byte

// testPubkeySingleton always returns the same MTCPublicKey, and sets the broad
// scope var above for use in tests
func testPubkeySingleton() *MTCPublicKey {
	generatedPubkey, err := ecdsa.GenerateKey(elliptic.P256(), nil)
	if err != nil {
		panic(err)
	}

	if testPubkeyBytes == nil {
		marshaledPubkeyBytes, err := x509.MarshalPKIXPublicKey(&generatedPubkey.PublicKey)
		if err != nil {
			panic(err)
		}
		testPubkeyBytes = marshaledPubkeyBytes
	}

	testMTCPubkey, err := FromCryptoPubkey(&generatedPubkey.PublicKey)
	if err != nil {
		panic(err)
	}

	return testMTCPubkey
}

// Broad scope var for a Pubkey Bundle singleton for use in tests
var testBundleSingletonBody []byte
var testBundleSingletonBytes []byte

// testBundleSingleton always returns the same Pubkey Bundle Bytes, and sets the
// broad scope var above to the same value for use in tests
func testBundleSingleton() []byte {
	if testBundleSingletonBytes == nil {
		testMTCPK := testPubkeySingleton()

		testBody, err := testMTCPK.Marshal()
		if err != nil {
			panic(err)
		}
		testBundleSingletonBody = testBody
	}

	var buf []byte
	cbb := *cryptobyte.NewBuilder(buf)

	cbb.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(testBundleSingletonBody)
	})
	testBundleSingletonBytes := cbb.BytesOrPanic()

	return testBundleSingletonBytes
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
	expected := []byte{0, 0}
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
	expected = append([]byte{0, 1}, testPubkeyBytes...)
	if !bytes.Equal(output, expected) {
		t.Errorf("marshaling valid pubkey: got %x, want %x", output, expected)
	}
}

func TestUnmarshalMTCPK(t *testing.T) {
	type testCase struct {
		name      string
		input     []byte
		expectErr bool
		expectVal *MTCPublicKey
	}

	_ = testPubkeySingleton()
	testPubkeyBytesLength := len(testPubkeyBytes)

	testCases := []testCase{
		{"valid pubkey", append([]byte{0, 1}, testPubkeyBytes...), false, &MTCPublicKey{
			typ: typeMTCPubkey,
			pub: testPubkeyBytes,
		}},
		{"valid null pubkey", []byte{0, 0}, false, &MTCPublicKey{
			typ: typeNilPubkey,
		}},
		{"too short", append([]byte{0, 1}, testPubkeyBytes[:testPubkeyBytesLength-6]...), true, nil},
		{"way too short", []byte{1}, true, nil},
		{"null pubkey with pubkey bytes", append([]byte{0, 0}, testPubkeyBytes...), true, nil},
		{"invalid type", append([]byte{0, 3}, testPubkeyBytes...), true, nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mtcpk, err := unmarshalMTCPK(tc.input)
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
					t.Errorf("Unmarshal() value: got %#v, want %#v", pkBytes, expBytes)
				}
			}
		})
	}
}

func TestPubkeyBundleBuildAndRead(t *testing.T) {
	testPubkey := testPubkeySingleton()

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
		testPkBundle, err := testPubkey.Marshal()
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
	if mtcpk.typ != typeNilPubkey {
		t.Errorf("mtcpk.typ: got %d, want %d", mtcpk.typ, typeNilPubkey)
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
		if mtcpk.typ != typeMTCPubkey {
			t.Errorf("mtcpk.Type: got %d, want %d", mtcpk.typ, typeMTCPubkey)
		}
		wantValue := testPubkey.Pubkey()
		if !bytes.Equal(mtcpk.pub, wantValue) {
			t.Errorf("mtcpk.Value: got %x, want %x", mtcpk.pub, wantValue)
		}
		wantMTCPKBytes := append([]byte{0, 1}, wantValue...)
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

	input := testBundleSingleton()

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
	testBundle := testBundleSingleton()

	type testCase struct {
		name  string
		input []byte
	}

	// expecting that 0,33 is not zero, but shorter than any testPubkey
	shortLengthBundle := append([]byte{0, 33, 0, 1}, testPubkeyBytes...)
	// expecting that 33,255 is not MAX, but larger than any testPubkey
	shortBodyBundle := append([]byte{33, 255, 0, 1}, testPubkeyBytes...)

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
