package main

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/letsencrypt/boulder/crl/crl_x509"
	"github.com/letsencrypt/boulder/linter"
)

type issuerNameID int64

func generateCRL(signer crypto.Signer, issuer *x509.Certificate, thisUpdate, nextUpdate time.Time, number int64, idpBase string, revokedCertificates []crl_x509.RevokedCertificate) ([]byte, error) {
	template := &crl_x509.RevocationList{
		RevokedCertificates: revokedCertificates,
		Number:              big.NewInt(number),
		ThisUpdate:          thisUpdate,
		NextUpdate:          nextUpdate,
	}

	if nextUpdate.Before(thisUpdate) {
		return nil, errors.New("thisUpdate must be before nextUpdate")
	}
	if thisUpdate.Before(issuer.NotBefore) {
		return nil, errors.New("thisUpdate is before issuing certificate's notBefore")
	} else if nextUpdate.After(issuer.NotAfter) {
		return nil, errors.New("nextUpdate is after issuing certificate's notAfter")
	}

	// Verify that the CRL is not valid for more than 12 months as specified in
	// CABF BRs Section 4.9.7
	if nextUpdate.Sub(thisUpdate) > time.Hour*24*365 {
		return nil, errors.New("nextUpdate must be less than 12 months after thisUpdate")
	}
	// Add the Issuing Distribution Point extension.
	issuerNameID := truncatedHash(issuer.RawSubject)
	idp, err := makeIDPExt(idpBase, issuerNameID)
	if err != nil {
		return nil, fmt.Errorf("creating IDP extension: %w", err)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, *idp)

	err = linter.CheckCRL(template, issuer, signer, []string{
		// We skip this lint because our ceremony tooling issues CRLs with validity
		// periods up to 12 months, but the lint only allows up to 10 days (which
		// is the limit for CRLs containing Subscriber Certificates).
		"e_crl_validity_period",
	})
	if err != nil {
		return nil, fmt.Errorf("crl failed pre-issuance lint: %w", err)
	}

	// x509.CreateRevocationList uses an io.Reader here for signing methods that require
	// a source of randomness. Since PKCS#11 based signing generates needed randomness
	// at the HSM we don't need to pass a real reader. Instead of passing a nil reader
	// we use one that always returns errors in case the internal usage of this reader
	// changes.
	crlBytes, err := crl_x509.CreateRevocationList(&failReader{}, template, issuer, signer)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes}), nil
}

// truncatedHash computes a truncated SHA1 hash across arbitrary bytes. Uses
// SHA1 because that is the algorithm most commonly used in OCSP requests.
// PURPOSEFULLY NOT EXPORTED. Exists only to ensure that the implementations of
// Certificate.NameID() and GetIssuerNameID() never diverge. Use those instead.
func truncatedHash(name []byte) issuerNameID {
	h := crypto.SHA1.New()
	h.Write(name)
	s := h.Sum(nil)
	return issuerNameID(big.NewInt(0).SetBytes(s[:7]).Int64())
}

// distributionPointName represents the ASN.1 DistributionPointName CHOICE as
// defined in RFC 5280 Section 4.2.1.13. We only use one of the fields, so the
// others are omitted.
type distributionPointName struct {
	// Technically, FullName is of type GeneralNames, which is of type SEQUENCE OF
	// GeneralName. But GeneralName itself is of type CHOICE, and the ans1.Marhsal
	// function doesn't support marshalling structs to CHOICEs, so we have to use
	// asn1.RawValue and encode the GeneralName ourselves.
	FullName []asn1.RawValue `asn1:"optional,tag:0"`
}

// issuingDistributionPoint represents the ASN.1 IssuingDistributionPoint
// SEQUENCE as defined in RFC 5280 Section 5.2.5. We only use two of the fields,
// so the others are omitted.
type issuingDistributionPoint struct {
	DistributionPoint   distributionPointName `asn1:"optional,tag:0"`
	OnlyContainsCACerts bool                  `asn1:"optional,tag:2"`
}

// makeIDPExt returns a critical IssuingDistributionPoint extension containing a
// URI built from the base url and the issuer's NameID. It also sets the
// OnlyContainsCACerts boolean to true.
func makeIDPExt(base string, issuer issuerNameID) (*pkix.Extension, error) {
	val := issuingDistributionPoint{
		DistributionPoint: distributionPointName{
			[]asn1.RawValue{ // GeneralNames
				{ // GeneralName
					Class: 2, // context-specific
					Tag:   6, // uniformResourceIdentifier, IA5String
					Bytes: []byte(fmt.Sprintf("%s/%d.crl", base, issuer)),
				},
			},
		},
		OnlyContainsCACerts: true,
	}

	valBytes, err := asn1.Marshal(val)
	if err != nil {
		return nil, err
	}

	return &pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 28}, // id-ce-issuingDistributionPoint
		Value:    valBytes,
		Critical: true,
	}, nil
}
