package lints

import (
	"testing"

	"github.com/letsencrypt/boulder/test"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

var onlyContainsUserCertsTag = asn1.Tag(1).ContextSpecific()
var onlyContainsCACertsTag = asn1.Tag(2).ContextSpecific()
var emptyUint8 uint8

func TestReadOptionalASN1BooleanWithTag(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                string
		incoming            []byte
		expectedBoolPresent bool
		asn1Tag             asn1.Tag
		expectedOk          bool
		expectedTrailer     int
	}{
		{
			name:                "Good onlyContainsUserCerts",
			incoming:            cryptobyte.String([]byte{0x81, 0x01, 0xFF}),
			expectedBoolPresent: true,
			asn1Tag:             onlyContainsUserCertsTag,
			expectedOk:          true,
			expectedTrailer:     0,
		},
		{
			name:                "Good onlyContainsCACerts",
			incoming:            cryptobyte.String([]byte{0x82, 0x01, 0xFF}),
			expectedBoolPresent: true,
			asn1Tag:             onlyContainsCACertsTag,
			expectedOk:          true,
			expectedTrailer:     0,
		},
		{
			name:                "Read the tag, but bool value is false",
			incoming:            cryptobyte.String([]byte{0x82, 0x01, 0x00}),
			expectedBoolPresent: false,
			asn1Tag:             onlyContainsCACertsTag,
			expectedOk:          true,
			expectedTrailer:     0,
		},
		{
			name:                "Read the tag, but bool value is false, trailer remains",
			incoming:            cryptobyte.String([]byte{0x82, 0x01, 0x00, 0x99}),
			expectedBoolPresent: false,
			asn1Tag:             onlyContainsCACertsTag,
			expectedOk:          true,
			expectedTrailer:     1,
		},
		{
			name:                "Wrong asn1Tag compared to incoming bytes, no bytes should have been read",
			incoming:            cryptobyte.String([]byte{0x81, 0x01, 0xFF}),
			expectedBoolPresent: false,
			asn1Tag:             onlyContainsCACertsTag,
			expectedOk:          false,
			expectedTrailer:     3,
		},
		{
			name:                "Bytes are popped off and the trailer remains",
			incoming:            cryptobyte.String([]byte{0x82, 0x01, 0xFF, 0xC0, 0xFF, 0xEE, 0xCA, 0xFE}),
			expectedBoolPresent: true,
			asn1Tag:             onlyContainsCACertsTag,
			expectedOk:          true,
			expectedTrailer:     5,
		},
		{
			name:                "No incoming bytes with a valid tag",
			incoming:            cryptobyte.String([]byte{}),
			expectedBoolPresent: false,
			asn1Tag:             onlyContainsCACertsTag,
			expectedOk:          false,
			expectedTrailer:     0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ok, boolPresent := ReadOptionalASN1BooleanWithTag((*cryptobyte.String)(&tc.incoming), tc.asn1Tag)
			// Check if reading the tag was successful
			test.AssertEquals(t, ok, tc.expectedOk)
			// Check the value of the optional boolean
			test.AssertEquals(t, boolPresent, tc.expectedBoolPresent)
			// Bytes should be popped off of incoming as they're read.
			test.AssertEquals(t, len(tc.incoming), tc.expectedTrailer)
		})
	}
}
