// Copyright (C) 2019 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package certspotter

import (
	"encoding/asn1"
)

func canonicalizeRDNString(fromStr string) string {
	from := []byte(fromStr)
	to := []byte{}
	inWhitespace := true
	for _, ch := range from {
		if ch == ' ' || ch == '\f' || ch == '\n' || ch == '\r' || ch == '\t' || ch == '\v' {
			if !inWhitespace {
				to = append(to, ' ')
			}
			inWhitespace = true
		} else {
			if ch >= 'A' && ch <= 'Z' {
				to = append(to, ch+32) // convert to lowercase
			} else {
				to = append(to, ch)
			}
			inWhitespace = false
		}
	}
	if inWhitespace && len(to) > 0 {
		// whack off the space character that we appended
		to = to[:len(to)-1]
	}
	return string(to)
}

func shouldCanonicalizeASN1String(value *asn1.RawValue) bool {
	if !value.IsCompound && value.Class == 0 {
		return value.Tag == 12 || value.Tag == 19 || value.Tag == 22 || value.Tag == 20 || value.Tag == 26 || value.Tag == 30 || value.Tag == 28
	}
	return false
}

func canonicalizeATV(oldATV AttributeTypeAndValue) (AttributeTypeAndValue, error) {
	if shouldCanonicalizeASN1String(&oldATV.Value) {
		str, err := decodeASN1String(&oldATV.Value)
		if err != nil {
			return AttributeTypeAndValue{}, err
		}
		str = canonicalizeRDNString(str)
		return AttributeTypeAndValue{
			Type: oldATV.Type,
			Value: asn1.RawValue{
				Class:      0,
				Tag:        asn1.TagUTF8String,
				IsCompound: false,
				Bytes:      []byte(str),
			},
		}, nil
	} else {
		return oldATV, nil
	}
}

func canonicalizeRDNSet(oldSet RelativeDistinguishedNameSET) (RelativeDistinguishedNameSET, error) {
	newSet := make([]AttributeTypeAndValue, len(oldSet))
	for i := range oldSet {
		var err error
		newSet[i], err = canonicalizeATV(oldSet[i])
		if err != nil {
			return nil, err
		}
	}
	return newSet, nil
}

func CanonicalizeRDNSequence(oldSequence RDNSequence) (RDNSequence, error) {
	newSequence := make([]RelativeDistinguishedNameSET, len(oldSequence))
	for i := range oldSequence {
		var err error
		newSequence[i], err = canonicalizeRDNSet(oldSequence[i])
		if err != nil {
			return nil, err
		}
	}
	return newSequence, nil
}
