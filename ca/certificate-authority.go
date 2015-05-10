// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ca

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/policy"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/auth"
	cfsslConfig "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/config"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/helpers"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/ocsp"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/signer"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/signer/remote"
)

type Config struct {
	Server       string
	AuthKey      string
	Profile      string
	TestMode     bool
	DBDriver     string
	DBName       string
	SerialPrefix int
	// Path to a PEM-encoded copy of the issuer certificate.
	IssuerCert string
	// This field is only allowed if TestMode is true, indicating that we are
	// signing with a local key. In production we will use an HSM and this
	// IssuerKey must be empty (and TestMode must be false). PEM-encoded private
	// key used for signing certificates and OCSP responses.
	IssuerKey string
}

// CertificateAuthorityImpl represents a CA that signs certificates, CRLs, and
// OCSP responses.
type CertificateAuthorityImpl struct {
	profile    string
	Signer     signer.Signer
	OCSPSigner ocsp.Signer
	SA         core.StorageAuthority
	PA         core.PolicyAuthority
	DB         core.CertificateAuthorityDatabase
	log        *blog.AuditLogger
	Prefix     int // Prepended to the serial number
}

// NewCertificateAuthorityImpl creates a CA that talks to a remote CFSSL
// instance.  (To use a local signer, simply instantiate CertificateAuthorityImpl
// directly.)  Communications with the CA are authenticated with MACs,
// using CFSSL's authenticated signature scheme.  A CA created in this way
// issues for a single profile on the remote signer, which is indicated
// by name in this constructor.
func NewCertificateAuthorityImpl(cadb core.CertificateAuthorityDatabase, config Config) (*CertificateAuthorityImpl, error) {
	var ca *CertificateAuthorityImpl
	var err error
	logger := blog.GetAuditLogger()
	logger.Notice("Certificate Authority Starting")

	if config.SerialPrefix <= 0 || config.SerialPrefix >= 256 {
		err = errors.New("Must have a positive non-zero serial prefix less than 256 for CA.")
		return nil, err
	}

	// Create the remote signer
	localProfile := cfsslConfig.SigningProfile{
		Expiry:       time.Hour,     // BOGUS: Required by CFSSL, but not used
		RemoteName:   config.Server, // BOGUS: Only used as a flag by CFSSL
		RemoteServer: config.Server,
		UseSerialSeq: true,
	}

	localProfile.Provider, err = auth.New(config.AuthKey, nil)
	if err != nil {
		return nil, err
	}

	signer, err := remote.NewSigner(&cfsslConfig.Signing{Default: &localProfile})
	if err != nil {
		return nil, err
	}

	issuer, err := loadIssuer(config.IssuerCert)
	if err != nil {
		return nil, err
	}

	// In test mode, load a private key from a file. In production, use an HSM.
	if !config.TestMode {
		err = errors.New("OCSP signing with a PKCS#11 key not yet implemented.")
		return nil, err
	}
	issuerKey, err := loadIssuerKey(config.IssuerKey)
	if err != nil {
		return nil, err
	}

	// Set up our OCSP signer. Note this calls for both the issuer cert and the
	// OCSP signing cert, which are the same in our case.
	ocspSigner, err := ocsp.NewSigner(issuer, issuer, issuerKey,
		time.Hour*24*4)

	pa := policy.NewPolicyAuthorityImpl()

	ca = &CertificateAuthorityImpl{
		Signer:     signer,
		OCSPSigner: ocspSigner,
		profile:    config.Profile,
		PA:         pa,
		DB:         cadb,
		Prefix:     config.SerialPrefix,
		log:        logger,
	}
	return ca, err
}

func loadIssuer(filename string) (issuerCert *x509.Certificate, err error) {
	if filename == "" {
		err = errors.New("Issuer certificate was not provided in config.")
		return
	}
	issuerCertPEM, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}
	issuerCert, err = helpers.ParseCertificatePEM(issuerCertPEM)
	return
}

func loadIssuerKey(filename string) (issuerKey crypto.Signer, err error) {
	if filename == "" {
		err = errors.New("IssuerKey must be provided in test mode.")
		return
	}

	pem, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}
	issuerKey, err = helpers.ParsePrivateKeyPEM(pem)
	return
}

func dupeNames(names []string) bool {
	nameMap := make(map[string]int, len(names))
	for _, name := range names {
		nameMap[name] = 1
	}
	if len(names) != len(nameMap) {
		return true
	}
	return false
}

func (ca *CertificateAuthorityImpl) RevokeCertificate(serial string) (err error) {
	certDER, err := ca.SA.GetCertificate(serial)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}

	// Per https://tools.ietf.org/html/rfc5280, CRLReason 0 is "unspecified."
	// TODO: Add support for specifying reason.
	reason := 0

	signRequest := ocsp.SignRequest{
		Certificate: cert,
		Status:      string(core.OCSPStatusRevoked),
		Reason:      reason,
		RevokedAt:   time.Now(),
	}
	ocspResponse, err := ca.OCSPSigner.Sign(signRequest)
	if err != nil {
		return err
	}
	err = ca.SA.MarkCertificateRevoked(serial, ocspResponse, reason)
	return err
}

// IssueCertificate attempts to convert a CSR into a signed Certificate, while
// enforcing all policies.
func (ca *CertificateAuthorityImpl) IssueCertificate(csr x509.CertificateRequest) (core.Certificate, error) {
	emptyCert := core.Certificate{}
	var err error
	// XXX Take in authorizations and verify that union covers CSR?
	// Pull hostnames from CSR
	hostNames := csr.DNSNames // DNSNames + CN from CSR
	var commonName string
	if len(csr.Subject.CommonName) > 0 {
		commonName = csr.Subject.CommonName
	} else if len(hostNames) > 0 {
		commonName = hostNames[0]
	} else {
		err = errors.New("Cannot issue a certificate without a hostname.")
		ca.log.WarningErr(err)
		return emptyCert, err
	}

	if dupeNames(hostNames) {
		err = errors.New("Cannot issue a certificate with duplicate DNS names.")
		ca.log.WarningErr(err)
		return emptyCert, err
	}

	if len(hostNames) == 0 {
		hostNames = []string{commonName}
	}

	identifier := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: commonName}
	if err = ca.PA.WillingToIssue(identifier); err != nil {
		err = errors.New("Policy forbids issuing for name " + commonName)
		ca.log.AuditErr(err)
		return emptyCert, err
	}
	for _, name := range hostNames {
		identifier = core.AcmeIdentifier{Type: core.IdentifierDNS, Value: name}
		if err = ca.PA.WillingToIssue(identifier); err != nil {
			err = errors.New("Policy forbids issuing for name " + name)
			ca.log.AuditErr(err)
			return emptyCert, err
		}
	}

	// Convert the CSR to PEM
	csrPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	}))

	// Get the next serial number
	ca.DB.Begin()
	serialDec, err := ca.DB.IncrementAndGetSerial()
	if err != nil {
		return emptyCert, err
	}
	serialHex := fmt.Sprintf("%02X%014X", ca.Prefix, serialDec)

	// Send the cert off for signing
	req := signer.SignRequest{
		Request: csrPEM,
		Profile: ca.profile,
		Hosts:   hostNames,
		Subject: &signer.Subject{
			CN: commonName,
		},
		SerialSeq: serialHex,
	}

	certPEM, err := ca.Signer.Sign(req)
	if err != nil {
		ca.DB.Rollback()
		return emptyCert, err
	}

	if len(certPEM) == 0 {
		err = errors.New("No certificate returned by server")
		ca.log.WarningErr(err)
		ca.DB.Rollback()
		return emptyCert, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		err = errors.New("Invalid certificate value returned")
		ca.log.WarningErr(err)
		ca.DB.Rollback()
		return emptyCert, err
	}
	certDER := block.Bytes

	cert := core.Certificate{
		DER:    certDER,
		Status: core.StatusValid,
	}
	if err != nil {
		return emptyCert, err
	}

	// Store the cert with the certificate authority, if provided
	_, err = ca.SA.AddCertificate(certDER)
	if err != nil {
		ca.DB.Rollback()
		return emptyCert, err
	}

	ca.DB.Commit()
	return cert, nil
}
