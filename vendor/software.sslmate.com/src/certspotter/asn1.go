// Copyright (C) 2016 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package certspotter

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"unicode/utf8"
)

func stringFromByteSlice(chars []byte) string {
	runes := make([]rune, len(chars))
	for i, ch := range chars {
		runes[i] = rune(ch)
	}
	return string(runes)
}

func stringFromUint16Slice(chars []uint16) string {
	runes := make([]rune, len(chars))
	for i, ch := range chars {
		runes[i] = rune(ch)
	}
	return string(runes)
}

func stringFromUint32Slice(chars []uint32) string {
	runes := make([]rune, len(chars))
	for i, ch := range chars {
		runes[i] = rune(ch)
	}
	return string(runes)
}

func decodeASN1String(value *asn1.RawValue) (string, error) {
	if !value.IsCompound && value.Class == 0 {
		if value.Tag == 12 {
			// UTF8String
			if !utf8.Valid(value.Bytes) {
				return "", errors.New("Malformed UTF8String")
			}
			return string(value.Bytes), nil
		} else if value.Tag == 19 || value.Tag == 22 || value.Tag == 20 || value.Tag == 26 {
			// * PrintableString - subset of ASCII
			// * IA5String - ASCII
			// * TeletexString - 8 bit charset; not quite ISO-8859-1, but often treated as such
			// * VisibleString - subset of ASCII

			// Don't enforce character set rules. Allow any 8 bit character, since
			// CAs routinely mess this up
			return stringFromByteSlice(value.Bytes), nil
		} else if value.Tag == 30 {
			// BMPString - Unicode, encoded in big-endian format using two octets
			runes := make([]uint16, len(value.Bytes)/2)
			if err := binary.Read(bytes.NewReader(value.Bytes), binary.BigEndian, runes); err != nil {
				return "", errors.New("Malformed BMPString: " + err.Error())
			}
			return stringFromUint16Slice(runes), nil
		} else if value.Tag == 28 {
			// UniversalString - Unicode, encoded in big-endian format using four octets
			runes := make([]uint32, len(value.Bytes)/4)
			if err := binary.Read(bytes.NewReader(value.Bytes), binary.BigEndian, runes); err != nil {
				return "", errors.New("Malformed UniversalString: " + err.Error())
			}
			return stringFromUint32Slice(runes), nil
		}
	}
	return "", errors.New("Not a string")
}
