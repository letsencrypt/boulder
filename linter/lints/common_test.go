package lints

import (
	"testing"

	"github.com/letsencrypt/boulder/test"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

var onlyContainsUserCertsTag = asn1.Tag(1).ContextSpecific()
var onlyContainsCACertsTag = asn1.Tag(2).ContextSpecific()
var oetp = false
var op = false

func TestReadOptionalASN1BooleanWithTag(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		// incoming will be mutated by the function under test
		incoming []byte
		// outExpectedTagPresent will be mutated by the function under test if
		// it is not nil
		outExpectedTagPresent *bool
		// outPresent will be mutated by the function under test if it is not
		// nil
		outPresent   *bool
		defaultValue bool
		asn1Tag      asn1.Tag
		expectedOk   bool
		// expectedTrailer counts the remaining bytes from incoming after having
		// been advanced by the function under test
		expectedTrailer    int
		expectedTagPresent bool
		expectedPresent    bool
	}{
		{
			name:                  "Good: onlyContainsUserCerts",
			incoming:              cryptobyte.String([]byte{0x81, 0x01, 0xFF}),
			outExpectedTagPresent: &oetp,
			outPresent:            &op,
			asn1Tag:               onlyContainsUserCertsTag,
			expectedOk:            true,
			expectedTrailer:       0,
			expectedTagPresent:    true,
			expectedPresent:       true,
		},
		{
			name:                  "Good: onlyContainsCACerts",
			incoming:              cryptobyte.String([]byte{0x82, 0x01, 0xFF}),
			outExpectedTagPresent: &oetp,
			outPresent:            &op,
			asn1Tag:               onlyContainsCACertsTag,
			expectedOk:            true,
			expectedTrailer:       0,
			expectedTagPresent:    true,
			expectedPresent:       true,
		},
		{
			name:                  "Good: Bytes are read and trailer remains",
			incoming:              cryptobyte.String([]byte{0x82, 0x01, 0xFF, 0xC0, 0xFF, 0xEE, 0xCA, 0xFE}),
			outExpectedTagPresent: &oetp,
			outPresent:            &op,
			asn1Tag:               onlyContainsCACertsTag,
			expectedOk:            true,
			expectedTrailer:       5,
			expectedTagPresent:    true,
			expectedPresent:       true,
		},
		{
			name:                  "Bad: No incoming bytes",
			incoming:              cryptobyte.String(nil),
			outExpectedTagPresent: &oetp,
			outPresent:            &op,
			asn1Tag:               onlyContainsCACertsTag,
			expectedOk:            false,
			expectedTrailer:       0,
			expectedTagPresent:    false,
			expectedPresent:       false,
		},
		{
			name:                  "Bad: Read the tag, but bool value is false",
			incoming:              cryptobyte.String([]byte{0x82, 0x01, 0x00}),
			outExpectedTagPresent: &oetp,
			outPresent:            &op,
			asn1Tag:               onlyContainsCACertsTag,
			expectedOk:            true,
			expectedTrailer:       0,
			expectedTagPresent:    true,
			expectedPresent:       false,
		},
		{
			name:                  "Bad: Read the tag, but bool value is false, trailer remains",
			incoming:              cryptobyte.String([]byte{0x82, 0x01, 0x00, 0x99}),
			outExpectedTagPresent: &oetp,
			outPresent:            &op,
			asn1Tag:               onlyContainsCACertsTag,
			expectedOk:            true,
			expectedTrailer:       1,
			expectedTagPresent:    true,
			expectedPresent:       false,
		},
		{
			name:                  "Bad: Wrong asn1Tag compared to incoming bytes, no bytes read",
			incoming:              cryptobyte.String([]byte{0x81, 0x01, 0xFF}),
			outExpectedTagPresent: &oetp,
			outPresent:            &op,
			asn1Tag:               onlyContainsCACertsTag,
			expectedOk:            true,
			expectedTrailer:       3,
			expectedTagPresent:    false,
			expectedPresent:       false,
		},
		{
			name:                  "Good: nil outExpectedTagPresent, found expected tag",
			incoming:              cryptobyte.String([]byte{0x81, 0x01, 0xFF}),
			outExpectedTagPresent: nil,
			outPresent:            &op,
			asn1Tag:               onlyContainsUserCertsTag,
			expectedOk:            true,
			expectedTrailer:       0,
			expectedPresent:       true,
		},
		{
			name:                  "Bad: nil outExpectedTagPresent, did not find expected tag",
			incoming:              cryptobyte.String([]byte{0x81, 0x01, 0xFF}),
			outExpectedTagPresent: nil,
			outPresent:            &op,
			asn1Tag:               onlyContainsCACertsTag,
			expectedOk:            true,
			expectedTrailer:       3,
			expectedPresent:       false,
		},
		{
			name:                  "Good: nil outPresent, found expected tag",
			incoming:              cryptobyte.String([]byte{0x81, 0x01, 0xFF}),
			outExpectedTagPresent: &oetp,
			outPresent:            nil,
			asn1Tag:               onlyContainsUserCertsTag,
			expectedOk:            true,
			expectedTrailer:       0,
			expectedTagPresent:    true,
		},
		{
			name:                  "Bad: nil outPresent, did not find expected tag",
			incoming:              cryptobyte.String([]byte{0x81, 0x01, 0xFF}),
			outExpectedTagPresent: &oetp,
			outPresent:            nil,
			asn1Tag:               onlyContainsCACertsTag,
			expectedOk:            true,
			expectedTrailer:       3,
			expectedTagPresent:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ok := ReadOptionalASN1BooleanWithTag((*cryptobyte.String)(&tc.incoming), tc.outExpectedTagPresent, tc.outPresent, tc.asn1Tag, false)
			t.Log("Check if reading the tag was successful:")
			test.AssertEquals(t, ok, tc.expectedOk)
			if tc.outExpectedTagPresent != nil {
				t.Log("Check value of finding the expected tag:")
				test.AssertEquals(t, *tc.outExpectedTagPresent, tc.expectedTagPresent)
			}
			if tc.outPresent != nil {
				t.Log("Check value of the optional boolean:")
				test.AssertEquals(t, *tc.outPresent, tc.expectedPresent)
			}
			t.Log("Bytes should be popped off of incoming as they're successfully read:")
			test.AssertEquals(t, len(tc.incoming), tc.expectedTrailer)
		})
	}
}
