package crl

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"reflect"
	"testing"
	"time"
)

func TestCreateCRLExt(t *testing.T) {
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %s", err)
	}
	tests := []struct {
		name          string
		issuer        x509.Certificate
		template      CRLTemplate
		expectedError string
	}{
		{
			name:          "issuer missing SubjectKeyId",
			issuer:        x509.Certificate{},
			template:      CRLTemplate{},
			expectedError: "x509: issuer certificate doesn't contain a subject key identifier",
		},
		{
			name: "nextUpdate before thisUpdate",
			issuer: x509.Certificate{
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: CRLTemplate{
				ThisUpdate: time.Time{}.Add(time.Hour),
				NextUpdate: time.Time{},
			},
			expectedError: "x509: template.ThisUpdate is after template.NextUpdate",
		},
		{
			name: "valid, extra extension",
			issuer: x509.Certificate{
				Subject: pkix.Name{
					CommonName: "testing",
				},
				SubjectKeyId: []byte{1, 2, 3},
			},
			template: CRLTemplate{
				RevokedCertificates: []pkix.RevokedCertificate{
					{
						SerialNumber:   big.NewInt(2),
						RevocationTime: time.Time{}.Add(time.Hour),
					},
				},
				Number:     5,
				ThisUpdate: time.Time{}.Add(time.Hour * 24),
				NextUpdate: time.Time{}.Add(time.Hour * 48),
				Extensions: []pkix.Extension{
					{
						Id:    []int{2, 5, 29, 99},
						Value: []byte{5, 0},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crl, err := CreateCRL(rand.Reader, &tc.issuer, ecdsaPriv, tc.template)
			if err != nil && tc.expectedError == "" {
				t.Fatalf("CreateCRL failed unexpectedly: %s", err)
			} else if err != nil && tc.expectedError != err.Error() {
				t.Fatalf("CreateCRL failed unexpectedly, wanted: %s, got: %s", tc.expectedError, err)
			} else if err == nil && tc.expectedError != "" {
				t.Fatalf("CreateCRL didn't fail, expected: %s", tc.expectedError)
			}
			if tc.expectedError != "" {
				return
			}

			parsedCRL, err := x509.ParseDERCRL(crl)
			if err != nil {
				t.Fatalf("Failed to parse generated CRL: %s", err)
			}

			if !reflect.DeepEqual(parsedCRL.TBSCertList.RevokedCertificates, tc.template.RevokedCertificates) {
				t.Fatalf("RevokedCertificates mismatch: got %v; want %v.",
					parsedCRL.TBSCertList.RevokedCertificates, tc.template.RevokedCertificates)
			}

			if len(parsedCRL.TBSCertList.Extensions) != 2+len(tc.template.Extensions) {
				t.Fatalf("Generated CRL has wrong number of extensions, wanted: %d, got: %d", 2+len(tc.template.Extensions), len(parsedCRL.TBSCertList.Extensions))
			}
			expectedAKI, err := asn1.Marshal(authKeyId{Id: tc.issuer.SubjectKeyId})
			if err != nil {
				t.Fatalf("asn1.Marshal failed: %s", err)
			}
			akiExt := pkix.Extension{
				Id:    oidExtensionAuthorityKeyId,
				Value: expectedAKI,
			}
			if !reflect.DeepEqual(parsedCRL.TBSCertList.Extensions[0], akiExt) {
				t.Fatalf("Unexpected first extension: got %v, want %v",
					parsedCRL.TBSCertList.Extensions[0], akiExt)
			}
			expectedNum, err := asn1.Marshal(tc.template.Number)
			if err != nil {
				t.Fatalf("asn1.Marshal failed: %s", err)
			}
			crlExt := pkix.Extension{
				Id:    oidExtensionCRLNumber,
				Value: expectedNum,
			}
			if !reflect.DeepEqual(parsedCRL.TBSCertList.Extensions[1], crlExt) {
				t.Fatalf("Unexpected second extension: got %v, want %v",
					parsedCRL.TBSCertList.Extensions[1], crlExt)
			}
			if !reflect.DeepEqual(parsedCRL.TBSCertList.Extensions[2:], tc.template.Extensions) {
				t.Fatalf("Extensions mismatch: got %v; want %v.",
					parsedCRL.TBSCertList.Extensions[2:], tc.template.Extensions)
			}
		})
	}
}
