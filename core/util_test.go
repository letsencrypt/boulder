// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
)

func TestB64(t *testing.T) {
	b64 := "Ee9hR5p2cdudb5FHm1Z_M2nGcQG-yvZit1M6qaaM5w4"
	bin := []byte{0x11, 0xef, 0x61, 0x47, 0x9a, 0x76, 0x71, 0xdb,
		0x9d, 0x6f, 0x91, 0x47, 0x9b, 0x56, 0x7f, 0x33,
		0x69, 0xc6, 0x71, 0x01, 0xbe, 0xca, 0xf6, 0x62,
		0xb7, 0x53, 0x3a, 0xa9, 0xa6, 0x8c, 0xe7, 0x0e}

	testB64 := B64enc(bin)
	if testB64 != b64 {
		t.Errorf("Base64 encoding produced incorrect result: %s", testB64)
	}

	testBin, err := B64dec(b64)
	if err != nil {
		t.Errorf("Error in base64 decode: %v", err)
	}
	if bytes.Compare(testBin, bin) != 0 {
		t.Errorf("Error in base64 decode: %v", err)
	}
}

func TestRandomString(t *testing.T) {
	byteLength := 256
	b64 := RandomString(byteLength)
	bin, err := B64dec(b64)
	if err != nil {
		t.Errorf("Error in base64 decode: %v", err)
	}
	if len(bin) != byteLength {
		t.Errorf("Improper length: %v", len(bin))
	}

}

func TestURL(t *testing.T) {
	scheme := "https"
	host := "example.com"
	path := "/acme/test"
	query := "foo"
	jsonURL := fmt.Sprintf(`{"URL":"%s://%s%s?%s"}`, scheme, host, path, query)

	var url struct{ URL AcmeURL }
	err := json.Unmarshal([]byte(jsonURL), &url)
	if err != nil {
		t.Errorf("Error in json unmarshal: %v", err)
	}
	if url.URL.Scheme != scheme || url.URL.Host != host ||
		url.URL.Path != path || url.URL.RawQuery != query {
		t.Errorf("Improper URL contents: %v", url.URL)
	}

	marshaledURL, err := json.Marshal(url)
	if err != nil {
		t.Errorf("Error in json marshal: %v", err)
	}
	if string(marshaledURL) != jsonURL {
		t.Errorf("Improper marshaled URL: %s", string(marshaledURL))
	}
}

func TestVerifyCSR(t *testing.T) {
}
