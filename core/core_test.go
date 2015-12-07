// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"
	"github.com/letsencrypt/boulder/test"
)

// challenges.go

var accountKeyJSON = `{
  "kty":"RSA",
  "n":"yNWVhtYEKJR21y9xsHV-PD_bYwbXSeNuFal46xYxVfRL5mqha7vttvjB_vc7Xg2RvgCxHPCqoxgMPTzHrZT75LjCwIW2K_klBYN8oYvTwwmeSkAz6ut7ZxPv-nZaT5TJhGk0NT2kh_zSpdriEJ_3vW-mqxYbbBmpvHqsa1_zx9fSuHYctAZJWzxzUZXykbWMWQZpEiE0J4ajj51fInEzVn7VxV-mzfMyboQjujPh7aNJxAWSq4oQEJJDgWwSh9leyoJoPpONHxh5nEE5AjE01FkGICSxjpZsF-w8hOTI3XXohUdu29Se26k2B0PolDSuj0GIQU6-W9TdLXSjBb2SpQ",
  "e":"AQAB"
}`

func TestChallenges(t *testing.T) {
	var accountKey *jose.JsonWebKey
	err := json.Unmarshal([]byte(accountKeyJSON), &accountKey)
	if err != nil {
		t.Errorf("Error unmarshaling JWK: %v", err)
	}

	http01 := HTTPChallenge01(accountKey)
	if !http01.IsSane(false) {
		t.Errorf("New http-01 challenge is not sane: %v", http01)
	}

	tlssni01 := TLSSNIChallenge01(accountKey)
	if !tlssni01.IsSane(false) {
		t.Errorf("New tls-sni-01 challenge is not sane: %v", tlssni01)
	}

	dns01 := DNSChallenge01(accountKey)
	if !dns01.IsSane(false) {
		t.Errorf("New dns-01 challenge is not sane: %v", dns01)
	}

	test.Assert(t, ValidChallenge(ChallengeTypeHTTP01), "Refused valid challenge")
	test.Assert(t, ValidChallenge(ChallengeTypeTLSSNI01), "Refused valid challenge")
	test.Assert(t, ValidChallenge(ChallengeTypeDNS01), "Refused valid challenge")
	test.Assert(t, !ValidChallenge("nonsense-71"), "Accepted invalid challenge")
}

// objects.go

var testCertificateRequestBadCSR = []byte(`{"csr":"AAAA"}`)
var testCertificateRequestGood = []byte(`{
  "csr": "MIHRMHgCAQAwFjEUMBIGA1UEAxMLZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQWUlnRrm5ErSVkTzBTk3isg1hNydfyY4NM1P_N1S-ZeD39HMrYJsQkUh2tKvy3ztfmEqWpekvO4WRktSa000BPoAAwCgYIKoZIzj0EAwMDSQAwRgIhAIZIBwu4xOUD_4dJuGgceSKaoXTFBQKA3BFBNVJvbpdsAiEAlfq3Dq_8dnYbtmyDdXgopeKkSV5_76VSpcog-wkwEwo"
}`)

func TestCertificateRequest(t *testing.T) {

	// Good
	var goodCR CertificateRequest
	err := json.Unmarshal(testCertificateRequestGood, &goodCR)
	if err != nil {
		t.Errorf("Error unmarshaling good certificate request: %v", err)
	}
	if err = VerifyCSR(goodCR.CSR); err != nil {
		t.Errorf("Valid CSR in CertificateRequest failed to verify: %v", err)
	}

	// Bad CSR
	var badCR CertificateRequest
	err = json.Unmarshal(testCertificateRequestBadCSR, &badCR)
	if err == nil {
		t.Errorf("Unexpectedly accepted certificate request with bad CSR")
	}

	// Marshal
	jsonCR, err := json.Marshal(goodCR)
	if err != nil {
		t.Errorf("Failed to marshal good certificate request: %v", err)
	}
	err = json.Unmarshal(jsonCR, &goodCR)
	if err != nil {
		t.Errorf("Marshalled certificate request failed to unmarshal: %v", err)
	}
}

// util.go

func TestErrors(t *testing.T) {
	testMessage := "test"
	errors := []error{
		NotSupportedError(testMessage),
		MalformedRequestError(testMessage),
		UnauthorizedError(testMessage),
		NotFoundError(testMessage),
		SyntaxError(testMessage),
		SignatureValidationError(testMessage),
		CertificateIssuanceError(testMessage),
	}

	for i, err := range errors {
		if msg := err.Error(); msg != testMessage {
			t.Errorf("Error %d returned unexpected message %v", i, msg)
		}
	}
}

func TestB64(t *testing.T) {
	b64Enc := "Ee9hR5p2cdudb5FHm1Z_M2nGcQG-yvZit1M6qaaM5w4"
	binEnc := []byte{0x11, 0xef, 0x61, 0x47, 0x9a, 0x76, 0x71, 0xdb,
		0x9d, 0x6f, 0x91, 0x47, 0x9b, 0x56, 0x7f, 0x33,
		0x69, 0xc6, 0x71, 0x01, 0xbe, 0xca, 0xf6, 0x62,
		0xb7, 0x53, 0x3a, 0xa9, 0xa6, 0x8c, 0xe7, 0x0e}

	testB64 := B64enc(binEnc)
	if testB64 != b64Enc {
		t.Errorf("Base64 encoding produced incorrect result: %s", testB64)
	}

	b64Dec := "wJD0zUMZ-6YMIiNbcCG0jLzxVerTxfnQ"
	binDec := []byte{192, 144, 244, 205, 67, 25, 251, 166,
		12, 34, 35, 91, 112, 33, 180, 140,
		188, 241, 85, 234, 211, 197, 249, 208}

	testBin, err := B64dec(b64Dec)
	if err != nil {
		t.Errorf("Error in base64 decode: %v", err)
	}
	if bytes.Compare(testBin, binDec) != 0 {
		t.Errorf("Base64 decoded to wrong value: %v", testBin)
	}

	b64Dec2 := "wJD0zUMZ-6YMIiNbcCG0jLzxVerTxfn"
	binDec2 := []byte{192, 144, 244, 205, 67, 25, 251, 166,
		12, 34, 35, 91, 112, 33, 180, 140,
		188, 241, 85, 234, 211, 197, 249}

	testBin2, err := B64dec(b64Dec2)
	if err != nil {
		t.Errorf("Error in base64 decode: %v", err)
	}
	if bytes.Compare(testBin2, binDec2) != 0 {
		t.Errorf("Base64 decoded to wrong value: %v", testBin)
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

	token := NewToken()
	if len(token) != 43 {
		t.Errorf("Improper length for token: %v %v", len(token), token)
	}
}

func TestFingerprint(t *testing.T) {
	in := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	out := []byte{55, 71, 8, 255, 247, 113, 157, 213,
		151, 158, 200, 117, 213, 108, 210, 40,
		111, 109, 60, 247, 236, 49, 122, 59,
		37, 99, 42, 171, 40, 236, 55, 187}

	digest := Fingerprint256(in)
	if digest != B64enc(out) {
		t.Errorf("Incorrect SHA-256 fingerprint: %v", digest)
	}
}

func TestURL(t *testing.T) {
	scheme := "https"
	host := "example.com"
	path := "/acme/test"
	query := "foo"
	jsonURL := fmt.Sprintf(`{"URL":"%s://%s%s?%s"}`, scheme, host, path, query)
	badJSON := `{"URL":666}`

	url := struct{ URL *AcmeURL }{URL: &AcmeURL{}}
	err := json.Unmarshal([]byte(jsonURL), &url)
	if err != nil {
		t.Errorf("Error in json unmarshal: %v", err)
	}
	if url.URL.Scheme != scheme || url.URL.Host != host ||
		url.URL.Path != path || url.URL.RawQuery != query {
		t.Errorf("Improper URL contents: %v", url.URL)
	}
	if s := url.URL.PathSegments(); len(s) != 2 {
		t.Errorf("Path segments failed to parse properly: %v", s)
	}

	err = json.Unmarshal([]byte(badJSON), &url)
	if err == nil {
		t.Errorf("Failed to catch bad JSON")
	}

	marshaledURL, err := json.Marshal(url)
	if err != nil {
		t.Errorf("Error in json marshal: %v", err)
	}
	if string(marshaledURL) != jsonURL {
		t.Errorf("Expected marshaled url %#v, got %#v", jsonURL, string(marshaledURL))
	}
}

var CSRs = []string{
	"3082025b308201430201003016311430120603550403130b6578616d706c652e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100b658aa6260818f1e0be2c77b220fa3c0a186d1ae8cc79914af70c7dcf7558215497b33a7ca25b142c4c6875ceb350e62a2283093f8df339d55a210d662668f63b1a4028ae04a2d95f734763b7e1196bf18eed8980bb693bf54ffd2431421a5d16f2ea04a4ef6e8cb33955ab4ef39858e9a8aa48720b85681b6fc89458087df14aaae4edc0dca74b1a2b0b87b7558d00e559392a7fff99acb134dda133dcd7704f976c197573c2c04101a6db7f7c832523510340a0c85cf7a201a61fc1a1389db7f886157138407c9acdf155e03ea439dfc787165f0fcc4592ea62e97857f0dc8138419f5eb1c21016253409c45aca9110e6dc6c63ea6d5a9443c87bfc0fbcfb10203010001a000300d06092a864886f70d01010505000382010100387f5f053b702ae80b14d5599e5adf284f82fb5d50f95aaa0c228416c81c6a99b3ccb03bdddddbd8d929bd7fe0b2e852d646a26c5c1d7ebc38bf2620c78fad910c844cc3457840e06e14473c9a5e08016ca3a1eddca29ef208d9f0b84a2ae2c7cf75a3e01c004a3862629df1b9dcd4e4732b014897a64ee66a94394baaad5e5223503b32e8f1389e9632a50f620898c0d3b1c9c05b2e1e03a4677026848d2f45151652c10e153958cbf702835a53c5fc5b43ebdb85ff6685a30dc5333f6f3284e3a66a916a6c54e6f389f0375f361351dbebc74105bdd43c4194b1384f0f6e1b21cc106c90827b57ad98f4e144d1d27981756116b22b2bc24cf2e2d0b0a0e4e2",
	"3082025b308201430201003016311430120603550403130b6578616d706c652e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100b658aa6260818f1e0be2c77b220fa3c0a186d1ae8cc79914af70c7dcf7558215497b33a7ca25b142c4c6875ceb350e62a2283093f8df339d55a210d662668f63b1a4028ae04a2d95f734763b7e1196bf18eed8980bb693bf54ffd2431421a5d16f2ea04a4ef6e8cb33955ab4ef39858e9a8aa48720b85681b6fc89458087df14aaae4edc0dca74b1a2b0b87b7558d00e559392a7fff99acb134dda133dcd7704f976c197573c2c04101a6db7f7c832523510340a0c85cf7a201a61fc1a1389db7f886157138407c9acdf155e03ea439dfc787165f0fcc4592ea62e97857f0dc8138419f5eb1c21016253409c45aca9110e6dc6c63ea6d5a9443c87bfc0fbcfb10203010001a000300d06092a864886f70d01010b050003820101006e2bdded0cfcb630f5ba70c64002f7d5f8c835a6e699f9249bc4dfe6521b8aac2e70002e1d604b365d8f11588adb652df75399748da087f92a7d98efc4d6f82298cdc0ec81d60f0714483c2187a89be37e25b7da176f43afc6375c1b86d73029f012546f2c0a1ab4e229fa0ef68239ab4ed53cd4c6aea667ceb157198d7f33fa930c39563e3e62ad08cb48f07dead417a9d2c13a788d41fb68a3ba84274bee60650a050fb0507dc7054d0f03b5202e876f793b87cc2527543c181423daa6e8c5b183df5678947160fe3d021283e08e3feb2155e5879846195423bc5f55d94082a34e230fd36755db68db6e3806bddaa5020899706b5dbb1ef66d0041f261c4a2",
	"3082025b308201430201003016311430120603550403130b6578616d706c652e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100b658aa6260818f1e0be2c77b220fa3c0a186d1ae8cc79914af70c7dcf7558215497b33a7ca25b142c4c6875ceb350e62a2283093f8df339d55a210d662668f63b1a4028ae04a2d95f734763b7e1196bf18eed8980bb693bf54ffd2431421a5d16f2ea04a4ef6e8cb33955ab4ef39858e9a8aa48720b85681b6fc89458087df14aaae4edc0dca74b1a2b0b87b7558d00e559392a7fff99acb134dda133dcd7704f976c197573c2c04101a6db7f7c832523510340a0c85cf7a201a61fc1a1389db7f886157138407c9acdf155e03ea439dfc787165f0fcc4592ea62e97857f0dc8138419f5eb1c21016253409c45aca9110e6dc6c63ea6d5a9443c87bfc0fbcfb10203010001a000300d06092a864886f70d01010c05000382010100b344093702d17782cf7ae41076910b594fb2eb3047ed862ab94be265feec4f05f328b3c041b19412e148f24b2c58e0777a98acfee5d584774268e8d2cd1b6b1235340d3c0e881acceabc15ab627790116d5f5d52bd2a9f5453cd2174c83d0d35c7b608b96c0f7baf029db8b9b047d9a4d768a3110452a472f5918264e6e5ea64ecab0423b6cfe968ec8de8baee07985712c0b7589238413de9cf65228311e678259a3f7d1e80c17cff61e1df17b1d4001ec3e38cb760e3bcb81612c80e4acb31130468e18b5bc644fadc1700865f9e75aeea95a1232e3d7ac97af99ccfe6548034fa16e571061c3766cb42deaef10d7a26ce1d9a8bffda18eff308eda1cc2ba8",
	"3082025b308201430201003016311430120603550403130b6578616d706c652e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100b658aa6260818f1e0be2c77b220fa3c0a186d1ae8cc79914af70c7dcf7558215497b33a7ca25b142c4c6875ceb350e62a2283093f8df339d55a210d662668f63b1a4028ae04a2d95f734763b7e1196bf18eed8980bb693bf54ffd2431421a5d16f2ea04a4ef6e8cb33955ab4ef39858e9a8aa48720b85681b6fc89458087df14aaae4edc0dca74b1a2b0b87b7558d00e559392a7fff99acb134dda133dcd7704f976c197573c2c04101a6db7f7c832523510340a0c85cf7a201a61fc1a1389db7f886157138407c9acdf155e03ea439dfc787165f0fcc4592ea62e97857f0dc8138419f5eb1c21016253409c45aca9110e6dc6c63ea6d5a9443c87bfc0fbcfb10203010001a000300d06092a864886f70d01010d05000382010100afd5e92fcdc19b6775efd04a9227d1088f4d75c88e7b95c3163d8aa8e602628fa7d592a3fad5e93c303a4f519fab57b4a0fbcb1c4703be88e20c5604f9b82de0352c2c495d5f72b668c2e9e449ef3a373ffa66bd582d3abf239d6707856b2d0bd9bc45d92dee5297a0e39605afdfd7b567e2668725a5723ab1236b38c10493e8b9b7ac572f87fe86ff8b3fce4da8bf832ac966f8e1a3d1a6fae8017a5ddbc4d183e5e29728f8f588ed7a431a3fbf29b5a8de1c5b65481f2e1fe5e78ef73134da6c1db9dd61cf971b845bf92e9992a3178210e072aa74ac1052eff6988dc1667f32e6269e92014f381297e694dc559d86e7f753429d7b8e3b74bb0ddd8c0b479c",
	"3081cf30780201003016311430120603550403130b6578616d706c652e636f6d3059301306072a8648ce3d020106082a8648ce3d03010703420004165259d1ae6e44ad25644f30539378ac83584dc9d7f263834cd4ffcdd52f99783dfd1ccad826c424521dad2afcb7ced7e612a5a97a4bcee16464b526b4d3404fa000300906072a8648ce3d04010348003045022027fa690d0ef92f1d81bbd252dcfbc34dac9894e7ebae1a46447c6991350c0b31022100b2744f89469791806027307754ef7486b795f2fc2c09ee05dcee151f145adbde",
	"3081d130780201003016311430120603550403130b6578616d706c652e636f6d3059301306072a8648ce3d020106082a8648ce3d03010703420004165259d1ae6e44ad25644f30539378ac83584dc9d7f263834cd4ffcdd52f99783dfd1ccad826c424521dad2afcb7ced7e612a5a97a4bcee16464b526b4d3404fa000300a06082a8648ce3d04030303490030460221008648070bb8c4e503ff8749b8681c79229aa174c5050280dc114135526f6e976c02210095fab70eaffc76761bb66c83757828a5e2a4495e7fefa552a5ca20fb0930130a",
	"3081d030780201003016311430120603550403130b6578616d706c652e636f6d3059301306072a8648ce3d020106082a8648ce3d03010703420004165259d1ae6e44ad25644f30539378ac83584dc9d7f263834cd4ffcdd52f99783dfd1ccad826c424521dad2afcb7ced7e612a5a97a4bcee16464b526b4d3404fa000300a06082a8648ce3d0403020348003045022042774cf730943f9d8181775e211d8ded5a49f0afe06ac0202dd8521541bca68c022100f748fe8f80da942888e601a396cc7dfc211ac5d643c4c864e6c7e078cc4dc08a",
	"3081d030780201003016311430120603550403130b6578616d706c652e636f6d3059301306072a8648ce3d020106082a8648ce3d03010703420004165259d1ae6e44ad25644f30539378ac83584dc9d7f263834cd4ffcdd52f99783dfd1ccad826c424521dad2afcb7ced7e612a5a97a4bcee16464b526b4d3404fa000300a06082a8648ce3d0403040348003045022100e6cdedd6cc38f88c0973024f33b4b66057c6fcc0cb3bfd328d11bb45353c905602202d3e8d812656b00a4dc3d83b892641b7f73d0dd34886184f14e348e390413a5d",
}

func TestVerifyCSR(t *testing.T) {
	for _, csrHex := range CSRs {
		csrDER, _ := hex.DecodeString(csrHex)
		csr, _ := x509.ParseCertificateRequest(csrDER)
		err := VerifyCSR(csr)
		if err != nil {
			t.Errorf("Error verifying CSR: %v", err)
		}
	}
}
