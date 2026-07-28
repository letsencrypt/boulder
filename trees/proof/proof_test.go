package proof

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

func TestSigAlgEncoded(t *testing.T) {
	// SEQUENCE { OBJECT IDENTIFIER 1.3.6.1.4.1.44363.47.0 }, parameters omitted.
	expected, err := hex.DecodeString("300c060a2b0601040182da4b2f00")
	if err != nil {
		t.Fatal(err)
	}
	got := SigAlgEncoded()
	if !bytes.Equal(got, expected) {
		t.Errorf("SigAlgEncoded(): got %x, want %x", got, expected)
	}
}

func TestSubtreeSignatureMarshal(t *testing.T) {
	type testCase struct {
		name     string
		sig      SubtreeSignature
		expected string
	}

	testCases := []testCase{
		{
			"empty signature",
			SubtreeSignature{CosignerID: []byte{1}},
			"0101" + "0000",
		},
		{
			"basic",
			SubtreeSignature{CosignerID: []byte{1, 2}, Signature: []byte{3, 4, 5}},
			"020102" + "0003030405",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			expected, err := hex.DecodeString(tc.expected)
			if err != nil {
				t.Fatal(err)
			}
			got, err := tc.sig.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, expected) {
				t.Errorf("Marshal(): got %x, want %x", got, expected)
			}
		})
	}

	// TrustAnchorID has a minimum length of 1 byte, so an empty CosignerID
	// must be rejected.
	empty := SubtreeSignature{}
	_, err := empty.Marshal()
	if err == nil {
		t.Errorf("Marshal() with empty CosignerID: got nil err, want error")
	}
}

func TestMTCProofMarshal(t *testing.T) {
	var hash1, hash2 tlog.Hash
	_, _ = rand.Read(hash1[:])
	_, _ = rand.Read(hash1[:])

	proof := MTCProof{
		Extensions: nil,
		Start:      123,
		End:        456,
		InclusionProof: []tlog.Hash{
			hash1,
			hash2,
		},
		Signatures: []*SubtreeSignature{
			{CosignerID: []byte{0xAA}, Signature: []byte{0xBB, 0xCC}},
			{CosignerID: []byte{0x01, 0x02}, Signature: nil},
		},
	}

	expected, err := hex.DecodeString(strings.Join([]string{
		"0000",         // extensions, empty
		"00000000007b", // start = 123 as uint48
		"0000000001c8", // end = 456 as uint48
		"0040",         // inclusion_proof length: two 32-byte hashes
		hex.EncodeToString(hash1[:]),
		hex.EncodeToString(hash2[:]),
		"000b",         // signatures length
		"01aa0002bbcc", // signature 1
		"0201020000",   // signature 2
	}, ""))
	if err != nil {
		t.Fatal(err)
	}

	got, err := proof.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, expected) {
		t.Errorf("Marshal(): got %x, want %x", got, expected)
	}
}

func TestMTCProofSignatureOrdering(t *testing.T) {
	a := &SubtreeSignature{CosignerID: []byte{0xAA}, Signature: []byte{1}}
	b := &SubtreeSignature{CosignerID: []byte{0x01, 0x02}, Signature: []byte{2}}
	c := &SubtreeSignature{CosignerID: []byte{0x01, 0x03}, Signature: []byte{3}}

	expected, err := hex.DecodeString(
		"0000" + "000000000000" + "000000000000" + "0000" +
			"0011" + // combined byte length of the encoded signatures
			"01aa000101" + // a: 1-byte ID sorts before all 2-byte IDs
			"020102000102" + // b: same length as c, lexicographically first
			"020103000103") // c
	if err != nil {
		t.Fatal(err)
	}

	callerOrder := []*SubtreeSignature{c, a, b}
	proof := MTCProof{Signatures: callerOrder}
	got, err := proof.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, expected) {
		t.Errorf("Marshal(): got %x, want %x", got, expected)
	}

	// The caller's slice must not have been reordered.
	if callerOrder[0] != c || callerOrder[1] != a || callerOrder[2] != b {
		t.Errorf("Marshal() reordered the caller's Signatures slice")
	}
}

func TestMTCProofDuplicateCosignerID(t *testing.T) {
	proof := MTCProof{Signatures: []*SubtreeSignature{
		{CosignerID: []byte{1}, Signature: []byte{2}},
		{CosignerID: []byte{1}, Signature: []byte{3}},
	}}
	_, err := proof.Marshal()
	if err == nil {
		t.Errorf("Marshal() with duplicate cosigner IDs: got nil err, want error")
	}
}

func TestMTCProofMarshalRange(t *testing.T) {
	const maxUint48 = 1<<48 - 1

	atLimit := MTCProof{Start: maxUint48, End: maxUint48}
	_, err := atLimit.Marshal()
	if err != nil {
		t.Errorf("Marshal() with start and end at 2^48-1: got %s, want success", err)
	}

	startTooBig := MTCProof{Start: maxUint48 + 1}
	_, err = startTooBig.Marshal()
	if err == nil {
		t.Errorf("Marshal() with start 2^48: got nil err, want error")
	}

	endTooBig := MTCProof{End: maxUint48 + 1}
	_, err = endTooBig.Marshal()
	if err == nil {
		t.Errorf("Marshal() with end 2^48: got nil err, want error")
	}
}

// proofsEqual compares two MTCProofs field by field, treating nil and empty
// slices as equal.
func proofsEqual(t *testing.T, got, want *MTCProof) {
	t.Helper()
	if !bytes.Equal(got.Extensions, want.Extensions) {
		t.Errorf("Extensions: got %x, want %x", got.Extensions, want.Extensions)
	}
	if got.Start != want.Start {
		t.Errorf("Start: got %d, want %d", got.Start, want.Start)
	}
	if got.End != want.End {
		t.Errorf("End: got %d, want %d", got.End, want.End)
	}
	if len(got.InclusionProof) != len(want.InclusionProof) {
		t.Fatalf("InclusionProof: got %d hashes, want %d", len(got.InclusionProof), len(want.InclusionProof))
	}
	for i := range got.InclusionProof {
		if got.InclusionProof[i] != want.InclusionProof[i] {
			t.Errorf("InclusionProof[%d]: got %x, want %x", i, got.InclusionProof[i], want.InclusionProof[i])
		}
	}
	if len(got.Signatures) != len(want.Signatures) {
		t.Fatalf("Signatures: got %d, want %d", len(got.Signatures), len(want.Signatures))
	}
	for i := range got.Signatures {
		if !bytes.Equal(got.Signatures[i].CosignerID, want.Signatures[i].CosignerID) {
			t.Errorf("Signatures[%d].CosignerID: got %x, want %x",
				i, got.Signatures[i].CosignerID, want.Signatures[i].CosignerID)
		}
		if !bytes.Equal(got.Signatures[i].Signature, want.Signatures[i].Signature) {
			t.Errorf("Signatures[%d].Signature: got %x, want %x",
				i, got.Signatures[i].Signature, want.Signatures[i].Signature)
		}
	}
}

func TestMTCProofRoundTrip(t *testing.T) {
	type testCase struct {
		name  string
		proof MTCProof
	}

	testCases := []testCase{
		{"zero value", MTCProof{}},
		{"extensions only", MTCProof{Extensions: []byte{9, 9, 9}}},
		{"start and end at limit", MTCProof{Start: 1<<48 - 1, End: 1<<48 - 1}},
		{"full", MTCProof{
			Extensions: []byte{7},
			Start:      123,
			End:        456,
			InclusionProof: []tlog.Hash{
				{1, 2, 3},
				{4, 5, 6},
				{7, 8, 9},
			},
			Signatures: []*SubtreeSignature{
				{CosignerID: []byte{0xAA}, Signature: []byte{0xBB, 0xCC}},
				{CosignerID: []byte{0x01, 0x02}, Signature: []byte{0x03}},
			},
		}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			marshaled, err := tc.proof.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			got, err := UnmarshalMTCProof(marshaled)
			if err != nil {
				t.Fatal(err)
			}
			proofsEqual(t, got, &tc.proof)

			remarshaled, err := got.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(remarshaled, marshaled) {
				t.Errorf("remarshal: got %x, want %x", remarshaled, marshaled)
			}
		})
	}
}

func TestUnmarshalMTCProofMalformed(t *testing.T) {
	// Extensions: nil, Start: 0, End: 0
	const prefix = "0000" + "000000000000" + "000000000000"

	type testCase struct {
		name, input string
	}

	testCases := []testCase{
		{"empty", ""},
		{"short extensions length", "00"},
		{"extensions length exceeds input", "0001"},
		{"truncated start", "0000" + "0000"},
		{"truncated end", "0000" + "000000000000" + "0000"},
		{"missing inclusion proof", "0000" + "000000000000" + "000000000000"},
		{"inclusion proof length exceeds input", prefix + "0001"},
		{"inclusion proof not a multiple of the hash size", prefix + "0001" + "00"},
		{"missing signatures", prefix + "0000"},
		{"signatures length exceeds input", prefix + "0000" + "0001"},
		{"signature missing length", prefix + "0000" + "0002" + "01aa"},
		{"signature length exceeds vector", prefix + "0000" + "0004" + "01aa0005"},
		{"trailing bytes", prefix + "0000" + "0000" + "ff"},
		// {0x01, 0x02} (2 bytes) precedes {0xAA} (1 byte): shorter IDs must
		// come first.
		{"cosigner IDs not ordered by length", prefix + "0000" + "0009" + "0201020000" + "01aa0000"},
		// {0x02} precedes {0x01}: same-length IDs must be ordered
		// lexicographically.
		{"cosigner IDs not ordered lexicographically", prefix + "0000" + "0008" + "01020000" + "01010000"},
		{"duplicate cosigner IDs", prefix + "0000" + "0008" + "01010000" + "01010000"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input, err := hex.DecodeString(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			_, err = UnmarshalMTCProof(input)
			if err == nil {
				t.Errorf("UnmarshalMTCProof(): got nil err, want error")
			}
		})
	}

	// Two cosignerIDs in the correct order, with shortest first: 0x02 comes before
	// 0x01 0x02 because it's shorter. A naive comparison would put them the other way, so
	// test that this parses.
	input, err := hex.DecodeString(prefix + "0000" + "0009" + "01020000" + "0201020000")
	if err != nil {
		t.Fatal(err)
	}
	_, err = UnmarshalMTCProof(input)
	if err != nil {
		t.Errorf("UnmarshalMTCProof() with prefix-related ordered cosigner IDs: %s", err)
	}
}
