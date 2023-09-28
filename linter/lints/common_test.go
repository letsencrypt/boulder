package lints

import (
	"testing"

	"github.com/letsencrypt/boulder/test"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

var onlyContainsUserCertsTag = asn1.Tag(1).ContextSpecific()
var onlyContainsCACertsTag = asn1.Tag(2).ContextSpecific()
var op bool

func TestReadOptionalASN1BooleanWithTag(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		// incoming will be mutated by the function under test
		incoming []byte
		// outPresent will be mutated by the function under test if it is not
		// nil
		outPresent   *bool
		defaultValue bool
		asn1Tag      asn1.Tag
		expectedOk   bool
		// expectedTrailer counts the remaining bytes from incoming after having
		// been advanced by the function under test
		expectedTrailer      int
		expectedValuePresent bool
		expectedPresent      bool
	}{
		{
			name:                 "Good: onlyContainsUserCerts",
			incoming:             cryptobyte.String([]byte{0x81, 0x01, 0xFF}),
			outPresent:           &op,
			asn1Tag:              onlyContainsUserCertsTag,
			expectedOk:           true,
			expectedTrailer:      0,
			expectedValuePresent: true,
			expectedPresent:      true,
		},
		{
			name:                 "Good: onlyContainsCACerts",
			incoming:             cryptobyte.String([]byte{0x82, 0x01, 0xFF}),
			outPresent:           &op,
			asn1Tag:              onlyContainsCACertsTag,
			expectedOk:           true,
			expectedTrailer:      0,
			expectedValuePresent: true,
			expectedPresent:      true,
		},
		{
			name:                 "Good: Bytes are read and trailer remains",
			incoming:             cryptobyte.String([]byte{0x82, 0x01, 0xFF, 0xC0, 0xFF, 0xEE, 0xCA, 0xFE}),
			outPresent:           &op,
			asn1Tag:              onlyContainsCACertsTag,
			expectedOk:           true,
			expectedTrailer:      5,
			expectedValuePresent: true,
			expectedPresent:      true,
		},
		{
			name:                 "Bad: Read the tag, but bool value is false",
			incoming:             cryptobyte.String([]byte{0x82, 0x01, 0x00}),
			outPresent:           &op,
			asn1Tag:              onlyContainsCACertsTag,
			expectedOk:           true,
			expectedTrailer:      0,
			expectedValuePresent: true,
			expectedPresent:      false,
		},
		{
			name:                 "Bad: Read the tag, but bool value is false, trailer remains",
			incoming:             cryptobyte.String([]byte{0x82, 0x01, 0x00, 0x99}),
			outPresent:           &op,
			asn1Tag:              onlyContainsCACertsTag,
			expectedOk:           true,
			expectedTrailer:      1,
			expectedValuePresent: true,
			expectedPresent:      false,
		},
		{
			name:                 "Bad: Wrong asn1Tag compared to incoming bytes, no bytes read",
			incoming:             cryptobyte.String([]byte{0x81, 0x01, 0xFF}),
			outPresent:           &op,
			asn1Tag:              onlyContainsCACertsTag,
			expectedOk:           true,
			expectedTrailer:      3,
			expectedValuePresent: false,
			expectedPresent:      false,
		},
		{
			name:            "Good: nil outExpectedTagPresent, found expected tag",
			incoming:        cryptobyte.String([]byte{0x81, 0x01, 0xFF}),
			outPresent:      &op,
			asn1Tag:         onlyContainsUserCertsTag,
			expectedOk:      true,
			expectedTrailer: 0,
			expectedPresent: true,
		},
		{
			name:            "Bad: nil outExpectedTagPresent, did not find expected tag",
			incoming:        cryptobyte.String([]byte{0x81, 0x01, 0xFF}),
			outPresent:      &op,
			asn1Tag:         onlyContainsCACertsTag,
			expectedOk:      true,
			expectedTrailer: 3,
			expectedPresent: false,
		},
		{
			name:                 "Good: nil outPresent, found expected tag",
			incoming:             cryptobyte.String([]byte{0x81, 0x01, 0xFF}),
			outPresent:           nil,
			asn1Tag:              onlyContainsUserCertsTag,
			expectedOk:           true,
			expectedTrailer:      0,
			expectedValuePresent: true,
		},
		{
			name:                 "Bad: nil outPresent, did not find expected tag",
			incoming:             cryptobyte.String([]byte{0x81, 0x01, 0xFF}),
			outPresent:           nil,
			asn1Tag:              onlyContainsCACertsTag,
			expectedOk:           true,
			expectedTrailer:      3,
			expectedValuePresent: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ok := ReadOptionalASN1BooleanWithTag((*cryptobyte.String)(&tc.incoming), tc.outPresent, tc.asn1Tag, false)
			t.Log("Check if reading the tag was successful:")
			test.AssertEquals(t, ok, tc.expectedOk)
			if tc.outPresent != nil {
				t.Log("Check value of the optional boolean:")
				test.AssertEquals(t, *tc.outPresent, tc.expectedPresent)
			}
			t.Log("Bytes should be popped off of incoming as they're successfully read:")
			test.AssertEquals(t, len(tc.incoming), tc.expectedTrailer)
		})
	}
}
