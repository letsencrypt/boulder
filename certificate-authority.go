// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package anvil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"time"
)

type CertificateAuthorityImpl struct {
	privateKey     interface{}
	certificate    x509.Certificate
	derCertificate []byte
}

var (
	serialNumberBits        = uint(64)
	oneYear                 = 365 * 24 * time.Hour
	rootCertificateTemplate = x509.Certificate{
		SignatureAlgorithm: x509.SHA256WithRSA,
		Subject:            pkix.Name{Organization: []string{"ACME CA"}},
		IsCA:               true,
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	eeCertificateTemplate = x509.Certificate{
		SignatureAlgorithm: x509.SHA256WithRSA,
		IsCA:               false,
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
)

func newSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), serialNumberBits)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	return serialNumber, nil
}

func NewCertificateAuthorityImpl() (CertificateAuthorityImpl, error) {
	zero := CertificateAuthorityImpl{}

	// Generate a key pair
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return zero, err
	}

	// Sign the certificate
	template := rootCertificateTemplate
	template.SerialNumber, err = newSerialNumber()
	if err != nil {
		return zero, err
	}
	template.NotBefore = time.Now()
	template.NotAfter = template.NotBefore.Add(oneYear)
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return zero, err
	}

	// Parse the certificate
	certs, err := x509.ParseCertificates(der)
	if err != nil || len(certs) == 0 {
		return zero, err
	}

	return CertificateAuthorityImpl{
		privateKey:     priv,
		certificate:    *certs[0],
		derCertificate: der,
	}, nil
}

func (ca *CertificateAuthorityImpl) CACertificate() []byte {
	return ca.derCertificate
}

func (ca *CertificateAuthorityImpl) IssueCertificate(csr x509.CertificateRequest) ([]byte, error) {
	template := eeCertificateTemplate

	// Set serial
	serialNumber, err := newSerialNumber()
	if err != nil {
		return nil, err
	}
	template.SerialNumber = serialNumber

	// Set validity
	template.NotBefore = time.Now()
	template.NotAfter = template.NotBefore.Add(oneYear)

	// Set hostnames
	domains := csr.DNSNames
	if len(csr.Subject.CommonName) > 0 {
		domains = append(domains, csr.Subject.CommonName)
	}
	if len(domains) == 0 {
		return []byte{}, errors.New("No names provided for certificate")
	}
	template.Subject = pkix.Name{CommonName: domains[0]}
	template.DNSNames = domains

	// Sign
	return x509.CreateCertificate(rand.Reader, &template, &ca.certificate, csr.PublicKey, ca.privateKey)
}
