package wfe2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"golang.org/x/net/context"
	"net/http"
	"testing"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/test"

	"gopkg.in/square/go-jose.v2"
)

func TestRejectsNone(t *testing.T) {
	wfe, _ := setupWFE(t)
	_, _, _, prob := wfe.validSelfAuthenticatedPOST(makePostRequest(`
		{
			"header": {
				"alg": "none",
				"jwk": {
					"kty": "RSA",
					"n": "vrjT",
					"e": "AQAB"
				}
			},
			"payload": "aGkK",
  		"signature": "ghTIjrhiRl2pQ09vAkUUBbF5KziJdhzOTB-okM9SPRzU8Hyj0W1H5JA1Zoc-A-LuJGNAtYYHWqMw1SeZbT0l9FHcbMPeWDaJNkHS9jz5_g_Oyol8vcrWur2GDtB2Jgw6APtZKrbuGATbrF7g41Wijk6Kk9GXDoCnlfOQOhHhsrFFcWlCPLG-03TtKD6EBBoVBhmlp8DRLs7YguWRZ6jWNaEX-1WiRntBmhLqoqQFtvZxCBw_PRuaRw_RZBd1x2_BNYqEdOmVNC43UHMSJg3y_3yrPo905ur09aUTscf-C_m4Sa4M0FuDKn3bQ_pFrtz-aCCq6rcTIyxYpDqNvHMT2Q"
		}
	`), newRequestEvent())
	if prob == nil {
		t.Fatalf("validSelfAuthenticatedPOST did not reject JWS with alg: 'none'")
	}
	if prob.Detail != "signature type 'none' in JWS header is not supported, expected one of RS256, ES256, ES384 or ES512" {
		t.Fatalf("validSelfAuthenticatedPOST rejected JWS with alg: 'none', but for wrong reason: %#v", prob)
	}
}

func TestRejectsHS256(t *testing.T) {
	wfe, _ := setupWFE(t)
	_, _, _, prob := wfe.validSelfAuthenticatedPOST(makePostRequest(`
		{
			"header": {
				"alg": "HS256",
				"jwk": {
					"kty": "RSA",
					"n": "vrjT",
					"e": "AQAB"
				}
			},
			"payload": "aGkK",
  		"signature": "ghTIjrhiRl2pQ09vAkUUBbF5KziJdhzOTB-okM9SPRzU8Hyj0W1H5JA1Zoc-A-LuJGNAtYYHWqMw1SeZbT0l9FHcbMPeWDaJNkHS9jz5_g_Oyol8vcrWur2GDtB2Jgw6APtZKrbuGATbrF7g41Wijk6Kk9GXDoCnlfOQOhHhsrFFcWlCPLG-03TtKD6EBBoVBhmlp8DRLs7YguWRZ6jWNaEX-1WiRntBmhLqoqQFtvZxCBw_PRuaRw_RZBd1x2_BNYqEdOmVNC43UHMSJg3y_3yrPo905ur09aUTscf-C_m4Sa4M0FuDKn3bQ_pFrtz-aCCq6rcTIyxYpDqNvHMT2Q"
		}
	`), newRequestEvent())
	if prob == nil {
		t.Fatalf("validSelfAuthenticatedPOST did not reject JWS with alg: 'HS256'")
	}
	expected := "signature type 'HS256' in JWS header is not supported, expected one of RS256, ES256, ES384 or ES512"
	if prob.Detail != expected {
		t.Fatalf("validSelfAuthenticatedPOST rejected JWS with alg: 'none', but for wrong reason: got '%s', wanted %s", prob, expected)
	}
}

func TestCheckAlgorithm(t *testing.T) {
	testCases := []struct {
		key          jose.JSONWebKey
		jws          jose.JSONWebSignature
		expectedErr  string
		expectedStat string
	}{
		{
			jose.JSONWebKey{
				Algorithm: "HS256",
			},
			jose.JSONWebSignature{},
			"no signature algorithms suitable for given key type",
			"WFE.Errors.NoAlgorithmForKey",
		},
		{
			jose.JSONWebKey{
				Key: &rsa.PublicKey{},
			},
			jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Header: jose.Header{
							Algorithm: "HS256",
						},
					},
				},
			},
			"signature type 'HS256' in JWS header is not supported, expected one of RS256, ES256, ES384 or ES512",
			"WFE.Errors.InvalidJWSAlgorithm",
		},
		{
			jose.JSONWebKey{
				Algorithm: "HS256",
				Key:       &rsa.PublicKey{},
			},
			jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Header: jose.Header{
							Algorithm: "HS256",
						},
					},
				},
			},
			"signature type 'HS256' in JWS header is not supported, expected one of RS256, ES256, ES384 or ES512",
			"WFE.Errors.InvalidJWSAlgorithm",
		},
		{
			jose.JSONWebKey{
				Algorithm: "HS256",
				Key:       &rsa.PublicKey{},
			},
			jose.JSONWebSignature{
				Signatures: []jose.Signature{
					{
						Header: jose.Header{
							Algorithm: "RS256",
						},
					},
				},
			},
			"algorithm 'HS256' on JWK is unacceptable",
			"WFE.Errors.InvalidAlgorithmOnKey",
		},
	}
	for i, tc := range testCases {
		stat, err := checkAlgorithm(&tc.key, &tc.jws)
		if tc.expectedErr != "" && err.Error() != tc.expectedErr {
			t.Errorf("TestCheckAlgorithm %d: Expected '%s', got '%s'", i, tc.expectedErr, err)
		}
		if tc.expectedStat != "" && stat != tc.expectedStat {
			t.Errorf("TestCheckAlgorithm %d: Expected stat '%s', got '%s'", i, tc.expectedStat, stat)
		}
	}
}

func TestCheckAlgorithmSuccess(t *testing.T) {
	_, err := checkAlgorithm(&jose.JSONWebKey{
		Algorithm: "RS256",
		Key:       &rsa.PublicKey{},
	}, &jose.JSONWebSignature{
		Signatures: []jose.Signature{
			{
				Header: jose.Header{
					Algorithm: "RS256",
				},
			},
		},
	})
	if err != nil {
		t.Errorf("RS256 key: Expected nil error, got '%s'", err)
	}
	_, err = checkAlgorithm(&jose.JSONWebKey{
		Key: &rsa.PublicKey{},
	}, &jose.JSONWebSignature{
		Signatures: []jose.Signature{
			{
				Header: jose.Header{
					Algorithm: "RS256",
				},
			},
		},
	})
	if err != nil {
		t.Errorf("RS256 key: Expected nil error, got '%s'", err)
	}

	_, err = checkAlgorithm(&jose.JSONWebKey{
		Algorithm: "ES256",
		Key: &ecdsa.PublicKey{
			Curve: elliptic.P256(),
		},
	}, &jose.JSONWebSignature{
		Signatures: []jose.Signature{
			{
				Header: jose.Header{
					Algorithm: "ES256",
				},
			},
		},
	})
	if err != nil {
		t.Errorf("ES256 key: Expected nil error, got '%s'", err)
	}

	_, err = checkAlgorithm(&jose.JSONWebKey{
		Key: &ecdsa.PublicKey{
			Curve: elliptic.P256(),
		},
	}, &jose.JSONWebSignature{
		Signatures: []jose.Signature{
			{
				Header: jose.Header{
					Algorithm: "ES256",
				},
			},
		},
	})
	if err != nil {
		t.Errorf("ES256 key: Expected nil error, got '%s'", err)
	}
}

func TestValidPOSTRequest(t *testing.T) {
	wfe, _ := setupWFE(t)

	dummyContentLength := []string{"pretty long, idk, maybe a nibble or two?"}

	testCases := []struct {
		Name          string
		Headers       map[string][]string
		Body          *string
		HTTPStatus    int
		ProblemDetail string
	}{
		// POST requests without a Content-Length should produce a problem
		{
			Name:          "POST without a Content-Length header",
			Headers:       nil,
			HTTPStatus:    http.StatusLengthRequired,
			ProblemDetail: "missing Content-Length header",
		},
		// POST requests with a Replay-Nonce header should produce a problem
		{
			Name: "POST with a Replay-Nonce HTTP header",
			Headers: map[string][]string{
				"Content-Length": dummyContentLength,
				"Replay-Nonce":   []string{"ima-misplaced-nonce"},
			},
			HTTPStatus:    http.StatusBadRequest,
			ProblemDetail: "HTTP requests should NOT contain Replay-Nonce header. Use JWS nonce field",
		},
		// POST requests without a body should produce a problem
		{
			Name: "POST with an empty POST body",
			Headers: map[string][]string{
				"Content-Length": dummyContentLength,
			},
			HTTPStatus:    http.StatusBadRequest,
			ProblemDetail: "No body on POST",
		},
	}

	for _, tc := range testCases {
		input := &http.Request{
			Method: "POST",
			URL:    mustParseURL("/"),
			Header: tc.Headers,
		}
		t.Run(tc.Name, func(t *testing.T) {
			prob := wfe.validPOSTRequest(input, newRequestEvent())
			test.Assert(t, prob != nil, "No error returned for invalid POST")
			test.AssertEquals(t, prob.Type, probs.MalformedProblem)
			test.AssertEquals(t, prob.HTTPStatus, tc.HTTPStatus)
			test.AssertEquals(t, prob.Detail, tc.ProblemDetail)
		})
	}
}

func TestEnforceJWSAuthType(t *testing.T) {
	wfe, _ := setupWFE(t)

	testKeyIDJWS, _, _ := signRequestKeyID(t, 1, nil, "", "", wfe.nonceService)
	testEmbeddedJWS, _, _ := signRequestEmbed(t, nil, "", "", wfe.nonceService)

	// A hand crafted JWS that has both a Key ID and an embedded JWK
	conflictJWSBody := `
{
  "header": {
    "alg": "RS256", 
    "jwk": {
      "e": "AQAB", 
      "kty": "RSA", 
      "n": "ppbqGaMFnnq9TeMUryR6WW4Lr5WMgp46KlBXZkNaGDNQoifWt6LheeR5j9MgYkIFU7Z8Jw5-bpJzuBeEVwb-yHGh4Umwo_qKtvAJd44iLjBmhBSxq-OSe6P5hX1LGCByEZlYCyoy98zOtio8VK_XyS5VoOXqchCzBXYf32ksVUTrtH1jSlamKHGz0Q0pRKIsA2fLqkE_MD3jP6wUDD6ExMw_tKYLx21lGcK41WSrRpDH-kcZo1QdgCy2ceNzaliBX1eHmKG0-H8tY4tPQudk-oHQmWTdvUIiHO6gSKMGDZNWv6bq74VTCsRfUEAkuWhqUhgRSGzlvlZ24wjHv5Qdlw"
    }
  }, 
  "protected": "eyJub25jZSI6ICJibTl1WTJVIiwgInVybCI6ICJodHRwOi8vbG9jYWxob3N0L3Rlc3QiLCAia2lkIjogInRlc3RrZXkifQ", 
  "payload": "Zm9v", 
  "signature": "ghTIjrhiRl2pQ09vAkUUBbF5KziJdhzOTB-okM9SPRzU8Hyj0W1H5JA1Zoc-A-LuJGNAtYYHWqMw1SeZbT0l9FHcbMPeWDaJNkHS9jz5_g_Oyol8vcrWur2GDtB2Jgw6APtZKrbuGATbrF7g41Wijk6Kk9GXDoCnlfOQOhHhsrFFcWlCPLG-03TtKD6EBBoVBhmlp8DRLs7YguWRZ6jWNaEX-1WiRntBmhLqoqQFtvZxCBw_PRuaRw_RZBd1x2_BNYqEdOmVNC43UHMSJg3y_3yrPo905ur09aUTscf-C_m4Sa4M0FuDKn3bQ_pFrtz-aCCq6rcTIyxYpDqNvHMT2Q"
}
`

	conflictJWS, err := jose.ParseSigned(conflictJWSBody)
	if err != nil {
		fmt.Printf("err was: %#v\n", err)
		t.Fatal("Unable to parse conflict JWS")
	}

	testCases := []struct {
		Name             string
		JWS              *jose.JSONWebSignature
		ExpectedAuthType jwsAuthType
		ExpectedResult   *probs.ProblemDetails
	}{
		{
			Name:             "Key ID and embedded JWS",
			JWS:              conflictJWS,
			ExpectedAuthType: invalidAuthType,
			ExpectedResult: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "jwk and kid header fields are mutually exclusive",
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			Name:             "Key ID when expected is embedded JWK",
			JWS:              testKeyIDJWS,
			ExpectedAuthType: embeddedJWK,
			ExpectedResult: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "No embedded JWK in JWS header",
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			Name:             "Embedded JWK when expected is Key ID",
			JWS:              testEmbeddedJWS,
			ExpectedAuthType: embeddedKeyID,
			ExpectedResult: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "No Key ID in JWS header",
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			Name:             "Key ID when expected is KeyID",
			JWS:              testKeyIDJWS,
			ExpectedAuthType: embeddedKeyID,
			ExpectedResult:   nil,
		},
		{
			Name:             "Embedded JWK when expected is embedded JWK",
			JWS:              testEmbeddedJWS,
			ExpectedAuthType: embeddedJWK,
			ExpectedResult:   nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			prob := wfe.enforceJWSAuthType(tc.JWS, tc.ExpectedAuthType)
			if tc.ExpectedResult == nil && prob != nil {
				t.Fatal(fmt.Sprintf("Expected nil result, got %#v", prob))
			} else {
				test.AssertMarshaledEquals(t, prob, tc.ExpectedResult)
			}
		})
	}
}

type badNonceProvider struct {
}

func (badNonceProvider) Nonce() (string, error) {
	return "im-a-nonce", nil
}

func TestValidNonce(t *testing.T) {
	wfe, _ := setupWFE(t)

	// signRequestEmbed with a `nil` nonce.NonceService will result in the
	// JWS not having a protected nonce header.
	missingNonceJWS, _, _ := signRequestEmbed(t, nil, "", "", nil)

	// signRequestEmbed with a badNonceProvider will result in the JWS
	// having an invalid nonce
	invalidNonceJWS, _, _ := signRequestEmbed(t, nil, "", "", badNonceProvider{})

	goodJWS, _, _ := signRequestEmbed(t, nil, "", "", wfe.nonceService)

	testCases := []struct {
		Name           string
		JWS            *jose.JSONWebSignature
		ExpectedResult *probs.ProblemDetails
	}{
		{
			Name: "No nonce in JWS",
			JWS:  missingNonceJWS,
			ExpectedResult: &probs.ProblemDetails{
				Type:       probs.BadNonceProblem,
				Detail:     "JWS has no anti-replay nonce",
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			Name: "Invalid nonce in JWS",
			JWS:  invalidNonceJWS,
			ExpectedResult: &probs.ProblemDetails{
				Type:       probs.BadNonceProblem,
				Detail:     "JWS has an invalid anti-replay nonce: \"im-a-nonce\"",
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			Name:           "Valid nonce in JWS",
			JWS:            goodJWS,
			ExpectedResult: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			prob := wfe.validNonce(tc.JWS, newRequestEvent())
			if tc.ExpectedResult == nil && prob != nil {
				t.Fatal(fmt.Sprintf("Expected nil result, got %#v", prob))
			} else {
				test.AssertMarshaledEquals(t, prob, tc.ExpectedResult)
			}
		})
	}
}

func signExtraHeaders(
	t *testing.T,
	headers map[jose.HeaderKey]interface{},
	nonceService jose.NonceSource) (*jose.JSONWebSignature, string) {
	privateKey := loadPrivateKey(t, []byte(test1KeyPrivatePEM))

	signerKey := jose.SigningKey{
		Key:       privateKey,
		Algorithm: sigAlgForKey(t, privateKey),
	}

	opts := &jose.SignerOptions{
		NonceSource:  nonceService,
		EmbedJWK:     true,
		ExtraHeaders: headers,
	}

	signer, err := jose.NewSigner(signerKey, opts)
	test.AssertNotError(t, err, "Failed to make signer")

	jws, err := signer.Sign([]byte(""))
	test.AssertNotError(t, err, "Failed to sign req")

	body := jws.FullSerialize()
	parsedJWS, err := jose.ParseSigned(body)
	test.AssertNotError(t, err, "Failed to parse generated JWS")

	return parsedJWS, body
}

func TestValidPOSTURL(t *testing.T) {
	wfe, _ := setupWFE(t)

	// A JWS and HTTP request with no extra headers
	noHeadersJWS, noHeadersJWSBody := signExtraHeaders(t, nil, wfe.nonceService)
	noHeadersRequest := makePostRequestWithPath("test-path", noHeadersJWSBody)

	// A JWS and HTTP request with extra headers, but no "url" extra header
	noURLHeaders := map[jose.HeaderKey]interface{}{
		"nifty": "swell",
	}
	noURLHeaderJWS, noURLHeaderJWSBody := signExtraHeaders(t, noURLHeaders, wfe.nonceService)
	noURLHeaderRequest := makePostRequestWithPath("test-path", noURLHeaderJWSBody)

	// A JWS and HTTP request with a mismatched HTTP URL to JWS "url" header
	wrongURLHeaders := map[jose.HeaderKey]interface{}{
		"url": "foobar",
	}
	wrongURLHeaderJWS, wrongURLHeaderJWSBody := signExtraHeaders(t, wrongURLHeaders, wfe.nonceService)
	wrongURLHeaderRequest := makePostRequestWithPath("test-path", wrongURLHeaderJWSBody)

	correctURLHeaderJWS, _, correctURLHeaderJWSBody := signRequestEmbed(t, nil, "http://localhost/test-path", "", wfe.nonceService)
	correctURLHeaderRequest := makePostRequestWithPath("test-path", correctURLHeaderJWSBody)

	testCases := []struct {
		Name           string
		JWS            *jose.JSONWebSignature
		Request        *http.Request
		ExpectedResult *probs.ProblemDetails
	}{
		{
			Name:    "No extra headers in JWS",
			JWS:     noHeadersJWS,
			Request: noHeadersRequest,
			ExpectedResult: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "JWS header parameter 'url' required",
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			Name:    "No URL header in JWS",
			JWS:     noURLHeaderJWS,
			Request: noURLHeaderRequest,
			ExpectedResult: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "JWS header parameter 'url' required",
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			Name:    "Wrong URL header in JWS",
			JWS:     wrongURLHeaderJWS,
			Request: wrongURLHeaderRequest,
			ExpectedResult: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "JWS header parameter 'url' incorrect. Expected \"http://localhost/test-path\" got \"foobar\"",
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			Name:           "Correct URL header in JWS",
			JWS:            correctURLHeaderJWS,
			Request:        correctURLHeaderRequest,
			ExpectedResult: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			prob := wfe.validPOSTURL(tc.Request, tc.JWS, newRequestEvent())
			if tc.ExpectedResult == nil && prob != nil {
				t.Fatal(fmt.Sprintf("Expected nil result, got %#v", prob))
			} else {
				test.AssertMarshaledEquals(t, prob, tc.ExpectedResult)
			}
		})
	}
}

func multiSigJWS(t *testing.T, nonceService jose.NonceSource) (*jose.JSONWebSignature, string) {
	privateKeyA := loadPrivateKey(t, []byte(test1KeyPrivatePEM))
	privateKeyB := loadPrivateKey(t, []byte(test2KeyPrivatePEM))

	signerKeyA := jose.SigningKey{
		Key:       privateKeyA,
		Algorithm: sigAlgForKey(t, privateKeyA),
	}

	signerKeyB := jose.SigningKey{
		Key:       privateKeyB,
		Algorithm: sigAlgForKey(t, privateKeyB),
	}

	opts := &jose.SignerOptions{
		NonceSource: nonceService,
		EmbedJWK:    true,
	}

	signer, err := jose.NewMultiSigner([]jose.SigningKey{signerKeyA, signerKeyB}, opts)
	test.AssertNotError(t, err, "Failed to make multi signer")

	jws, err := signer.Sign([]byte(""))
	test.AssertNotError(t, err, "Failed to sign req")

	body := jws.FullSerialize()
	parsedJWS, err := jose.ParseSigned(body)
	test.AssertNotError(t, err, "Failed to parse generated JWS")

	return parsedJWS, body
}

func TestParseJWS(t *testing.T) {
	wfe, _ := setupWFE(t)

	_, tooManySigsJWSBody := multiSigJWS(t, wfe.nonceService)

	_, _, validJWSBody := signRequestEmbed(t, nil, "http://localhost/test-path", "", wfe.nonceService)
	validJWSRequest := makePostRequestWithPath("test-path", validJWSBody)

	/*
	   	missingSigsJWSBody := `
	   {
	     "header": {
	       "alg": "RS256",
	       "jwk": {
	         "e": "AQAB",
	         "kty": "RSA",
	         "n": "ppbqGaMFnnq9TeMUryR6WW4Lr5WMgp46KlBXZkNaGDNQoifWt6LheeR5j9MgYkIFU7Z8Jw5-bpJzuBeEVwb-yHGh4Umwo_qKtvAJd44iLjBmhBSxq-OSe6P5hX1LGCByEZlYCyoy98zOtio8VK_XyS5VoOXqchCzBXYf32ksVUTrtH1jSlamKHGz0Q0pRKIsA2fLqkE_MD3jP6wUDD6ExMw_tKYLx21lGcK41WSrRpDH-kcZo1QdgCy2ceNzaliBX1eHmKG0-H8tY4tPQudk-oHQmWTdvUIiHO6gSKMGDZNWv6bq74VTCsRfUEAkuWhqUhgRSGzlvlZ24wjHv5Qdlw"
	       }
	     },
	     "protected": "eyJub25jZSI6ICJibTl1WTJVIiwgInVybCI6ICJodHRwOi8vbG9jYWxob3N0L3Rlc3QiLCAia2lkIjogInRlc3RrZXkifQ",
	     "payload": "Zm9v",
	   }`
	*/
	missingSigsJWSBody := `{"payload":"Zm9x","protected":"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoicW5BUkxyVDdYejRnUmNLeUxkeWRtQ3ItZXk5T3VQSW1YNFg0MHRoazNvbjI2RmtNem5SM2ZSanM2NmVMSzdtbVBjQlo2dU9Kc2VVUlU2d0FhWk5tZW1vWXgxZE12cXZXV0l5aVFsZUhTRDdROHZCcmhSNnVJb080akF6SlpSLUNoelp1U0R0N2lITi0zeFVWc3B1NVhHd1hVX01WSlpzaFR3cDRUYUZ4NWVsSElUX09iblR2VE9VM1hoaXNoMDdBYmdaS21Xc1ZiWGg1cy1DcklpY1U0T2V4SlBndW5XWl9ZSkp1ZU9LbVR2bkxsVFY0TXpLUjJvWmxCS1oyN1MwLVNmZFZfUUR4X3lkbGU1b01BeUtWdGxBVjM1Y3lQTUlzWU53Z1VHQkNkWV8yVXppNWVYMGxUYzdNUFJ3ejZxUjFraXAtaTU5VmNHY1VRZ3FIVjZGeXF3IiwiZSI6IkFRQUIifSwia2lkIjoiIiwibm9uY2UiOiJyNHpuenZQQUVwMDlDN1JwZUtYVHhvNkx3SGwxZVBVdmpGeXhOSE1hQnVvIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdC9hY21lL25ldy1yZWcifQ"}`
	missingSigsJWSRequest := makePostRequestWithPath("test-path", missingSigsJWSBody)

	testCases := []struct {
		Name            string
		Request         *http.Request
		ExpectedJSON    string
		ExpectedProblem *probs.ProblemDetails
	}{
		{
			Name: "Invalid POST request",
			// No Content-Length, something that validPOSTRequest should be flagging
			Request: &http.Request{
				Method: "POST",
				URL:    mustParseURL("/"),
			},
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "missing Content-Length header",
				HTTPStatus: http.StatusLengthRequired,
			},
		},
		{
			Name:    "Invalid JWS in POST body",
			Request: makePostRequestWithPath("test-path", `{`),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "Parse error reading JWS",
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			Name:    "Too few signatures in JWS",
			Request: missingSigsJWSRequest,
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "POST JWS not signed",
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			Name:    "Too many signatures in JWS",
			Request: makePostRequestWithPath("test-path", tooManySigsJWSBody),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "Too many signatures in POST body",
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			Name:            "Valid JWS in POST request",
			Request:         validJWSRequest,
			ExpectedProblem: nil,
			ExpectedJSON:    validJWSBody,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			_, body, prob := wfe.parseJWS(tc.Request, newRequestEvent())
			if tc.ExpectedProblem == nil && prob != nil {
				t.Fatal(fmt.Sprintf("Expected nil problem, got %#v\n", prob))
			} else if tc.ExpectedProblem == nil {
				test.AssertMarshaledEquals(t, string(body), tc.ExpectedJSON)
			} else {
				test.AssertMarshaledEquals(t, prob, tc.ExpectedProblem)
			}
		})
	}
}

func TestExtractJWK(t *testing.T) {
	wfe, _ := setupWFE(t)

	keyIDJWS, _, _ := signRequestKeyID(t, 1, nil, "", "", wfe.nonceService)
	goodJWS, goodJWK, _ := signRequestEmbed(t, nil, "", "", wfe.nonceService)

	testCases := []struct {
		Name            string
		JWS             *jose.JSONWebSignature
		ExpectedKey     *jose.JSONWebKey
		ExpectedProblem *probs.ProblemDetails
	}{
		{
			Name: "JWS with wrong auth type (Key ID vs embedded JWK)",
			JWS:  keyIDJWS,
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "No embedded JWK in JWS header",
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			Name:        "Valid JWS with embedded JWK",
			JWS:         goodJWS,
			ExpectedKey: goodJWK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			jwk, prob := wfe.extractJWK(tc.JWS, newRequestEvent())
			if tc.ExpectedProblem == nil && prob != nil {
				t.Fatal(fmt.Sprintf("Expected nil problem, got %#v\n", prob))
			} else if tc.ExpectedProblem == nil {
				test.AssertMarshaledEquals(t, jwk, tc.ExpectedKey)
			} else {
				test.AssertMarshaledEquals(t, prob, tc.ExpectedProblem)
			}
		})
	}
}

func signRequestBadKeyID(t *testing.T, nonceService jose.NonceSource) (*jose.JSONWebSignature, string) {
	privateKey := loadPrivateKey(t, []byte(test1KeyPrivatePEM))

	jwk := &jose.JSONWebKey{
		Key:       privateKey,
		Algorithm: "RSA",
		KeyID:     "this is an invalid non-numeric key ID",
	}

	signerKey := jose.SigningKey{
		Key:       jwk,
		Algorithm: jose.RS256,
	}

	opts := &jose.SignerOptions{
		NonceSource: nonceService,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": "http://localhost",
		},
	}

	signer, err := jose.NewSigner(signerKey, opts)
	test.AssertNotError(t, err, "Failed to make signer")

	jws, err := signer.Sign([]byte(""))
	test.AssertNotError(t, err, "Failed to sign req")

	body := jws.FullSerialize()
	parsedJWS, err := jose.ParseSigned(body)
	test.AssertNotError(t, err, "Failed to parse generated JWS")

	return parsedJWS, body
}

func TestLookupJWK(t *testing.T) {
	wfe, _ := setupWFE(t)

	// Enable Account Deactivation to test that LookupJWK rejects a deactivated
	// account
	_ = features.Set(map[string]bool{"AllowAccountDeactivation": true})

	embeddedJWS, _, embeddedJWSBody := signRequestEmbed(t, nil, "", "", wfe.nonceService)
	invalidKeyIDJWS, invalidKeyIDJWSBody := signRequestBadKeyID(t, wfe.nonceService)
	// ID 100 is mocked to return a non-missing error from sa.GetRegistration
	errorIDJWS, _, errorIDJWSBody := signRequestKeyID(t, 100, nil, "", "", wfe.nonceService)
	// ID 102 is mocked to return an account does not exist error from sa.GetRegistration
	missingIDJWS, _, missingIDJWSBody := signRequestKeyID(t, 102, nil, "", "", wfe.nonceService)
	// ID 3 is mocked to return a deactivated account from sa.GetRegistration
	deactivatedIDJWS, _, deactivatedIDJWSBody := signRequestKeyID(t, 3, nil, "", "", wfe.nonceService)

	validJWS, validKey, validJWSBody := signRequestKeyID(t, 1, nil, "", "", wfe.nonceService)
	validAccount, _ := wfe.SA.GetRegistration(context.Background(), 1)

	// good key, log event requester is set

	testCases := []struct {
		Name            string
		JWS             *jose.JSONWebSignature
		Request         *http.Request
		ExpectedProblem *probs.ProblemDetails
		ExpectedKey     *jose.JSONWebKey
		ExpectedAccount *core.Registration
	}{
		{
			Name:    "JWS with wrong auth type (embedded JWK vs Key ID)",
			JWS:     embeddedJWS,
			Request: makePostRequestWithPath("test-path", embeddedJWSBody),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "No Key ID in JWS header",
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			Name:    "JWS with invalid key ID",
			JWS:     invalidKeyIDJWS,
			Request: makePostRequestWithPath("test-path", invalidKeyIDJWSBody),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "Malformed account ID in KeyID header",
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			Name:    "JWS with account ID that causes GetRegistration error",
			JWS:     errorIDJWS,
			Request: makePostRequestWithPath("test-path", errorIDJWSBody),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.ServerInternalProblem,
				Detail:     "Error retreiving account \"100\"",
				HTTPStatus: http.StatusInternalServerError,
			},
		},
		{
			Name:    "JWS with account ID that doesn't exist",
			JWS:     missingIDJWS,
			Request: makePostRequestWithPath("test-path", missingIDJWSBody),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.AccountDoesNotExistProblem,
				Detail:     "Account \"102\" not found",
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			Name:    "JWS with account ID that is deactivated",
			JWS:     deactivatedIDJWS,
			Request: makePostRequestWithPath("test-path", deactivatedIDJWSBody),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.UnauthorizedProblem,
				Detail:     "Account is not valid, has status \"deactivated\"",
				HTTPStatus: http.StatusForbidden,
			},
		},
		{
			Name:            "Valid JWS with valid account ID",
			JWS:             validJWS,
			Request:         makePostRequestWithPath("test-path", validJWSBody),
			ExpectedKey:     validKey,
			ExpectedAccount: &validAccount,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			inputLogEvent := newRequestEvent()
			jwk, acct, prob := wfe.lookupJWK(tc.JWS, context.Background(), tc.Request, inputLogEvent)
			if tc.ExpectedProblem == nil && prob != nil {
				t.Fatal(fmt.Sprintf("Expected nil problem, got %#v\n", prob))
			} else if tc.ExpectedProblem == nil {
				inThumb, _ := tc.ExpectedKey.Thumbprint(crypto.SHA256)
				outThumb, _ := jwk.Thumbprint(crypto.SHA256)
				test.AssertDeepEquals(t, inThumb, outThumb)
				test.AssertMarshaledEquals(t, acct, tc.ExpectedAccount)
				test.AssertEquals(t, inputLogEvent.Requester, acct.ID)
				test.AssertEquals(t, inputLogEvent.Contacts, acct.Contact)
			} else {
				test.AssertMarshaledEquals(t, prob, tc.ExpectedProblem)
			}
		})
	}
}

func TestValidJWSForKey(t *testing.T) {
	wfe, _ := setupWFE(t)

	payload := `{ "test": "payload" }`
	testURL := "http://localhost/test"
	goodJWS, goodJWK, goodJWSBody := signRequestEmbed(t, nil, testURL, payload, wfe.nonceService)

	// badSigJWSBody is a JWS that has had the payload changed by 1 byte to break the signature
	badSigJWSBody := `{"payload":"Zm9x","protected":"eyJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoicW5BUkxyVDdYejRnUmNLeUxkeWRtQ3ItZXk5T3VQSW1YNFg0MHRoazNvbjI2RmtNem5SM2ZSanM2NmVMSzdtbVBjQlo2dU9Kc2VVUlU2d0FhWk5tZW1vWXgxZE12cXZXV0l5aVFsZUhTRDdROHZCcmhSNnVJb080akF6SlpSLUNoelp1U0R0N2lITi0zeFVWc3B1NVhHd1hVX01WSlpzaFR3cDRUYUZ4NWVsSElUX09iblR2VE9VM1hoaXNoMDdBYmdaS21Xc1ZiWGg1cy1DcklpY1U0T2V4SlBndW5XWl9ZSkp1ZU9LbVR2bkxsVFY0TXpLUjJvWmxCS1oyN1MwLVNmZFZfUUR4X3lkbGU1b01BeUtWdGxBVjM1Y3lQTUlzWU53Z1VHQkNkWV8yVXppNWVYMGxUYzdNUFJ3ejZxUjFraXAtaTU5VmNHY1VRZ3FIVjZGeXF3IiwiZSI6IkFRQUIifSwia2lkIjoiIiwibm9uY2UiOiJyNHpuenZQQUVwMDlDN1JwZUtYVHhvNkx3SGwxZVBVdmpGeXhOSE1hQnVvIiwidXJsIjoiaHR0cDovL2xvY2FsaG9zdC9hY21lL25ldy1yZWcifQ","signature":"jcTdxSygm_cvD7KbXqsxgnoPApCTSkV4jolToSOd2ciRkg5W7Yl0ZKEEKwOc-dYIbQiwGiDzisyPCicwWsOUA1WSqHylKvZ3nxSMc6KtwJCW2DaOqcf0EEjy5VjiZJUrOt2c-r6b07tbn8sfOJKwlF2lsOeGi4s-rtvvkeQpAU-AWauzl9G4bv2nDUeCviAZjHx_PoUC-f9GmZhYrbDzAvXZ859ktM6RmMeD0OqPN7bhAeju2j9Gl0lnryZMtq2m0J2m1ucenQBL1g4ZkP1JiJvzd2cAz5G7Ftl2YeJJyWhqNd3qq0GVOt1P11s8PTGNaSoM0iR9QfUxT9A6jxARtg"}`
	badJWS, err := jose.ParseSigned(badSigJWSBody)
	if err != nil {
		t.Fatal("error loading badSigJWS body")
	}

	// wrongAlgJWS is a JWS that has an invalid "HS256" algorithm in its header
	wrongAlgJWS := &jose.JSONWebSignature{
		Signatures: []jose.Signature{
			{
				Header: jose.Header{
					Algorithm: "HS256",
				},
			},
		},
	}

	// invalidNonceJWS uses the badNonceProvider from TestValidNonce to check
	// that JWS with a bad nonce value are rejected
	invalidNonceJWS, _, _ := signRequestEmbed(t, nil, "", "", badNonceProvider{})

	// A JWS and HTTP request with a mismatched HTTP URL to JWS "url" header
	wrongURLHeaders := map[jose.HeaderKey]interface{}{
		"url": "foobar",
	}
	wrongURLHeaderJWS, wrongURLHeaderJWSBody := signExtraHeaders(t, wrongURLHeaders, wfe.nonceService)

	// badJSONJWS has a valid signature over a body that is not valid JSON
	badJSONJWS, _, badJSONJWSBody := signRequestEmbed(t, nil, testURL, `{`, wfe.nonceService)

	testCases := []struct {
		Name            string
		JWS             *jose.JSONWebSignature
		JWK             *jose.JSONWebKey
		Body            string
		ExpectedProblem *probs.ProblemDetails
	}{
		{
			Name: "JWS with an invalid algorithm",
			JWS:  wrongAlgJWS,
			JWK:  goodJWK,
			Body: "", // Not used
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "signature type 'HS256' in JWS header is not supported, expected one of RS256, ES256, ES384 or ES512",
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			Name: "JWS with an invalid nonce",
			JWS:  invalidNonceJWS,
			JWK:  goodJWK,
			Body: "", // Not used
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.BadNonceProblem,
				Detail:     "JWS has an invalid anti-replay nonce: \"im-a-nonce\"",
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			Name: "JWS with broken signature",
			JWS:  badJWS,
			JWK:  badJWS.Signatures[0].Header.JSONWebKey,
			Body: badSigJWSBody,
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "JWS verification error",
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			Name: "JWS with incorrect URL",
			JWS:  wrongURLHeaderJWS,
			JWK:  wrongURLHeaderJWS.Signatures[0].Header.JSONWebKey,
			Body: wrongURLHeaderJWSBody,
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "JWS header parameter 'url' incorrect. Expected \"http://localhost/test\" got \"foobar\"",
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			Name: "Valid JWS with invalid JSON in the protected body",
			JWS:  badJSONJWS,
			JWK:  goodJWK,
			Body: badJSONJWSBody,
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "Request payload did not parse as JSON",
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			Name: "Good JWS and JWK",
			JWS:  goodJWS,
			JWK:  goodJWK,
			Body: goodJWSBody,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			inputLogEvent := newRequestEvent()
			request := makePostRequestWithPath("test", tc.Body)
			outPayload, prob := wfe.validJWSForKey(tc.JWS, tc.JWK, tc.Body, request, inputLogEvent)

			if tc.ExpectedProblem == nil && prob != nil {
				t.Fatal(fmt.Sprintf("Expected nil problem, got %#v\n", prob))
			} else if tc.ExpectedProblem == nil {
				test.AssertEquals(t, inputLogEvent.Payload, payload)
				test.AssertEquals(t, string(outPayload), payload)
			} else {
				test.AssertMarshaledEquals(t, prob, tc.ExpectedProblem)
			}
		})
	}
}

func TestValidPOSTForAccount(t *testing.T) {
	wfe, _ := setupWFE(t)

	// Enable Account Deactivation to test that LookupJWK rejects a deactivated
	// account
	_ = features.Set(map[string]bool{"AllowAccountDeactivation": true})

	_, validKey, validJWSBody := signRequestKeyID(t, 1, nil, "http://localhost/test", `{"test":"passed"}`, wfe.nonceService)
	validAccount, _ := wfe.SA.GetRegistration(context.Background(), 1)

	// ID 102 is mocked to return missing
	_, _, missingJWSBody := signRequestKeyID(t, 102, nil, "http://localhost/test", "{}", wfe.nonceService)

	// ID 3 is mocked to return deactivated
	key3 := loadPrivateKey(t, []byte(test3KeyPrivatePEM))
	_, _, deactivatedJWSBody := signRequestKeyID(t, 3, key3, "http://localhost/test", "{}", wfe.nonceService)

	_, _, embeddedJWSBody := signRequestEmbed(t, nil, "http://localhost/test", `{"test":"passed"}`, wfe.nonceService)

	testCases := []struct {
		Name            string
		Request         *http.Request
		ExpectedProblem *probs.ProblemDetails
		ExpectedPayload string
		ExpectedJWK     *jose.JSONWebKey
		ExpectedAcct    *core.Registration
	}{
		{
			Name:    "Invalid JWS",
			Request: makePostRequestWithPath("test", "foo"),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "Parse error reading JWS",
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			Name:    "Embedded Key JWS",
			Request: makePostRequestWithPath("test", embeddedJWSBody),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "No Key ID in JWS header",
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			Name:    "JWS signed by account that doesn't exist",
			Request: makePostRequestWithPath("test", missingJWSBody),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.AccountDoesNotExistProblem,
				Detail:     "Account \"102\" not found",
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			Name:    "JWS signed by account that's deactivated",
			Request: makePostRequestWithPath("test", deactivatedJWSBody),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.UnauthorizedProblem,
				Detail:     "Account is not valid, has status \"deactivated\"",
				HTTPStatus: http.StatusForbidden,
			},
		},
		{
			Name:            "Valid JWS for account",
			Request:         makePostRequestWithPath("test", validJWSBody),
			ExpectedPayload: `{"test":"passed"}`,
			ExpectedJWK:     validKey,
			ExpectedAcct:    &validAccount,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			inputLogEvent := newRequestEvent()

			outPayload, jwk, _, acct, prob := wfe.validPOSTForAccount(tc.Request, context.Background(), inputLogEvent)

			if tc.ExpectedProblem == nil && prob != nil {
				t.Fatal(fmt.Sprintf("Expected nil problem, got %#v\n", prob))
			} else if tc.ExpectedProblem == nil {

				inThumb, _ := tc.ExpectedJWK.Thumbprint(crypto.SHA256)
				outThumb, _ := jwk.Thumbprint(crypto.SHA256)
				test.AssertDeepEquals(t, inThumb, outThumb)
				test.AssertEquals(t, inputLogEvent.Payload, tc.ExpectedPayload)
				test.AssertEquals(t, string(outPayload), tc.ExpectedPayload)
				test.AssertMarshaledEquals(t, acct, tc.ExpectedAcct)
			} else {
				test.AssertMarshaledEquals(t, prob, tc.ExpectedProblem)
			}
		})
	}
}

type mockSADifferentStoredKey struct {
	core.StorageGetter
}

// mockSADifferentStoredKey has a GetRegistration that will always return an
// account with the test 2 key, no matter the provided ID
func (sa mockSADifferentStoredKey) GetRegistration(_ context.Context, _ int64) (core.Registration, error) {
	keyJSON := []byte(test2KeyPublicJSON)
	var parsedKey jose.JSONWebKey
	err := parsedKey.UnmarshalJSON(keyJSON)
	if err != nil {
		panic(err)
	}
	return core.Registration{
		Key:    &parsedKey,
		Status: core.StatusValid,
	}, nil
}

func TestValidPOSTForAccountSwappedKey(t *testing.T) {
	wfe, fc := setupWFE(t)
	wfe.SA = &mockSADifferentStoredKey{mocks.NewStorageAuthority(fc)}
	event := newRequestEvent()

	payload := `{"resource":"ima-payload"}`
	// Sign a request using test1key
	_, _, body := signRequestKeyID(t, 1, nil, "http://localhost:4000/test", payload, wfe.nonceService)
	request := makePostRequestWithPath("test", body)

	// Ensure that ValidPOSTForAccount produces an error since the
	// mockSADifferentStoredKey will return a different key than the one we used to
	// sign the request
	_, _, _, _, prob := wfe.validPOSTForAccount(request, ctx, event)
	test.Assert(t, prob != nil, "No error returned for request signed by wrong key")
	test.AssertEquals(t, prob.Type, probs.MalformedProblem)
	test.AssertEquals(t, prob.Detail, "JWS verification error")
}

func TestValidSelfAuthenticatedPOST(t *testing.T) {
	wfe, _ := setupWFE(t)

	_, validKey, validJWSBody := signRequestEmbed(t, nil, "http://localhost/test", `{"test":"passed"}`, wfe.nonceService)

	_, _, keyIDJWSBody := signRequestKeyID(t, 1, nil, "http://localhost/test", `{"test":"passed"}`, wfe.nonceService)

	testCases := []struct {
		Name            string
		Request         *http.Request
		ExpectedProblem *probs.ProblemDetails
		ExpectedPayload string
		ExpectedJWK     *jose.JSONWebKey
	}{
		{
			Name:    "Invalid JWS",
			Request: makePostRequestWithPath("test", "foo"),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "Parse error reading JWS",
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			Name:    "JWS with key ID",
			Request: makePostRequestWithPath("test", keyIDJWSBody),
			ExpectedProblem: &probs.ProblemDetails{
				Type:       probs.MalformedProblem,
				Detail:     "No embedded JWK in JWS header",
				HTTPStatus: http.StatusBadRequest,
			},
		},
		{
			Name:            "Valid JWS",
			Request:         makePostRequestWithPath("test", validJWSBody),
			ExpectedPayload: `{"test":"passed"}`,
			ExpectedJWK:     validKey,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			inputLogEvent := newRequestEvent()

			outPayload, jwk, _, prob := wfe.validSelfAuthenticatedPOST(tc.Request, inputLogEvent)

			if tc.ExpectedProblem == nil && prob != nil {
				t.Fatal(fmt.Sprintf("Expected nil problem, got %#v\n", prob))
			} else if tc.ExpectedProblem == nil {

				inThumb, _ := tc.ExpectedJWK.Thumbprint(crypto.SHA256)
				outThumb, _ := jwk.Thumbprint(crypto.SHA256)
				test.AssertDeepEquals(t, inThumb, outThumb)
				test.AssertEquals(t, inputLogEvent.Payload, tc.ExpectedPayload)
				test.AssertEquals(t, string(outPayload), tc.ExpectedPayload)
			} else {
				test.AssertMarshaledEquals(t, prob, tc.ExpectedProblem)
			}
		})
	}
}
