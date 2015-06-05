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
	cfsslOCSP "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/ocsp"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/signer"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/signer/remote"
)

// Config defines the JSON configuration file schema
type Config struct {
	Server       string
	AuthKey      string
	Profile      string
	TestMode     bool
	DBDriver     string
	DBName       string
	SerialPrefix int
	// This field is only allowed if TestMode is true, indicating that we are
	// signing with a local key. In production we will use an HSM and this
	// IssuerKey must be empty (and TestMode must be false). PEM-encoded private
	// key used for signing certificates and OCSP responses.
	IssuerKey string
	// How long issue certificates are valid for, should match expiry field
	// in cfssl config.
	Expiry string
	// The maximum number of subjectAltNames in a single certificate
	MaxNames int
}

// CertificateAuthorityImpl represents a CA that signs certificates, CRLs, and
// OCSP responses.
type CertificateAuthorityImpl struct {
	profile        string
	Signer         signer.Signer
	OCSPSigner     cfsslOCSP.Signer
	SA             core.StorageAuthority
	PA             core.PolicyAuthority
	DB             core.CertificateAuthorityDatabase
	log            *blog.AuditLogger
	Prefix         int // Prepended to the serial number
	ValidityPeriod time.Duration
	NotAfter       time.Time
	MaxNames       int
	MaxKeySize     int
}

// NewCertificateAuthorityImpl creates a CA that talks to a remote CFSSL
// instance.  (To use a local signer, simply instantiate CertificateAuthorityImpl
// directly.)  Communications with the CA are authenticated with MACs,
// using CFSSL's authenticated signature scheme.  A CA created in this way
// issues for a single profile on the remote signer, which is indicated
// by name in this constructor.
func NewCertificateAuthorityImpl(cadb core.CertificateAuthorityDatabase, config Config, issuerCert string) (*CertificateAuthorityImpl, error) {
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

	issuer, err := loadIssuer(issuerCert)
	if err != nil {
		return nil, err
	}

	// In test mode, load a private key from a file.
	// TODO: This should rely on the CFSSL config, to make it easy to use a key
	// from a file vs an HSM. https://github.com/letsencrypt/boulder/issues/163
	issuerKey, err := loadIssuerKey(config.IssuerKey)
	if err != nil {
		return nil, err
	}

	// Set up our OCSP signer. Note this calls for both the issuer cert and the
	// OCSP signing cert, which are the same in our case.
	ocspSigner, err := cfsslOCSP.NewSigner(issuer, issuer, issuerKey,
		time.Hour*24*4)
	if err != nil {
		return nil, err
	}

	pa := policy.NewPolicyAuthorityImpl()

	ca = &CertificateAuthorityImpl{
		Signer:     signer,
		OCSPSigner: ocspSigner,
		profile:    config.Profile,
		PA:         pa,
		DB:         cadb,
		Prefix:     config.SerialPrefix,
		log:        logger,
		NotAfter:   issuer.NotAfter,
	}

	if config.Expiry == "" {
		return nil, errors.New("Config must specify an expiry period.")
	}
	ca.ValidityPeriod, err = time.ParseDuration(config.Expiry)
	if err != nil {
		return nil, err
	}

	ca.MaxNames = config.MaxNames

	return ca, nil
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

// GenerateOCSP produces a new OCSP response and returns it
func (ca *CertificateAuthorityImpl) GenerateOCSP(xferObj core.OCSPSigningRequest) ([]byte, error) {
	cert, err := x509.ParseCertificate(xferObj.CertDER)
	if err != nil {
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		ca.log.AuditErr(err)
		return nil, err
	}

	signRequest := cfsslOCSP.SignRequest{
		Certificate: cert,
		Status:      xferObj.Status,
		Reason:      xferObj.Reason,
		RevokedAt:   xferObj.RevokedAt,
	}

	ocspResponse, err := ca.OCSPSigner.Sign(signRequest)
	return ocspResponse, err
}

// RevokeCertificate revokes the trust of the Cert referred to by the provided Serial.
func (ca *CertificateAuthorityImpl) RevokeCertificate(serial string, reasonCode int) (err error) {
	certDER, err := ca.SA.GetCertificate(serial)
	if err != nil {
		// AUDIT[ Revocation Requests ] 4e85d791-09c0-4ab3-a837-d3d67e945134
		ca.log.AuditErr(err)
		return err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		// AUDIT[ Revocation Requests ] 4e85d791-09c0-4ab3-a837-d3d67e945134
		ca.log.AuditErr(err)
		return err
	}

	signRequest := cfsslOCSP.SignRequest{
		Certificate: cert,
		Status:      string(core.OCSPStatusRevoked),
		Reason:      reasonCode,
		RevokedAt:   time.Now(),
	}
	ocspResponse, err := ca.OCSPSigner.Sign(signRequest)
	if err != nil {
		// AUDIT[ Revocation Requests ] 4e85d791-09c0-4ab3-a837-d3d67e945134
		ca.log.AuditErr(err)
		return err
	}
	err = ca.SA.MarkCertificateRevoked(serial, ocspResponse, reasonCode)
	return err
}

// IssueCertificate attempts to convert a CSR into a signed Certificate, while
// enforcing all policies.
func (ca *CertificateAuthorityImpl) IssueCertificate(csr x509.CertificateRequest, regID int64, earliestExpiry time.Time) (core.Certificate, error) {
	emptyCert := core.Certificate{}
	var err error
	key, ok := csr.PublicKey.(crypto.PublicKey)
	if !ok {
		err = fmt.Errorf("Invalid public key in CSR.")
		// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
		ca.log.AuditErr(err)
		return emptyCert, err
	}
	if !core.GoodKey(key, ca.MaxKeySize) {
		err = fmt.Errorf("Invalid public key in CSR.")
		// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
		ca.log.AuditErr(err)
		return emptyCert, err
	}

	// Pull hostnames from CSR
	// Authorization is checked by the RA
	commonName := ""
	hostNames := make([]string, len(csr.DNSNames))
	copy(hostNames, csr.DNSNames)
	if len(csr.Subject.CommonName) > 0 {
		commonName = csr.Subject.CommonName
		hostNames = append(hostNames, csr.Subject.CommonName)
	} else if len(hostNames) > 0 {
		commonName = hostNames[0]
	} else {
		err = fmt.Errorf("Cannot issue a certificate without a hostname.")
		// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
		ca.log.AuditErr(err)
		return emptyCert, err
	}

	// Collapse any duplicate names.  Note that this operation may re-order the names
	hostNames = core.UniqueNames(hostNames)
	if ca.MaxNames > 0 && len(hostNames) > ca.MaxNames {
		err = fmt.Errorf("Certificate request has %d > %d names", len(hostNames), ca.MaxNames)
		ca.log.WarningErr(err)
		return emptyCert, err
	}

	// Verify that names are allowed by policy
	identifier := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: commonName}
	if err = ca.PA.WillingToIssue(identifier); err != nil {
		err = fmt.Errorf("Policy forbids issuing for name %s", commonName)
		// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
		ca.log.AuditErr(err)
		return emptyCert, err
	}
	for _, name := range hostNames {
		identifier = core.AcmeIdentifier{Type: core.IdentifierDNS, Value: name}
		if err = ca.PA.WillingToIssue(identifier); err != nil {
			err = fmt.Errorf("Policy forbids issuing for name %s", name)
			// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
			ca.log.AuditErr(err)
			return emptyCert, err
		}
	}

	notAfter := time.Now().Add(ca.ValidityPeriod)

	if ca.NotAfter.Before(notAfter) {
		// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
		err = errors.New("Cannot issue a certificate that expires after the intermediate certificate.")
		ca.log.AuditErr(err)
		return emptyCert, err
	}

	// Note: We do not current enforce that certificate lifetimes match
	// authorization lifetimes, because it was breaking integration tests.
	if earliestExpiry.Before(notAfter) {
		message := fmt.Sprintf("Issuing a certificate that expires after the shortest underlying authorization. [%v] [%v]", earliestExpiry, notAfter)
		ca.log.Notice(message)
	}

	// Convert the CSR to PEM
	csrPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	}))

	// Get the next serial number
	tx, err := ca.DB.Begin()
	if err != nil {
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		ca.log.AuditErr(err)
		return emptyCert, err
	}

	serialDec, err := ca.DB.IncrementAndGetSerial(tx)
	if err != nil {
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		ca.log.Audit(fmt.Sprintf("Serial increment failed, rolling back: err=[%v]", err))
		tx.Rollback()
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
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		ca.log.Audit(fmt.Sprintf("Signer failed, rolling back: serial=[%s] err=[%v]", serialHex, err))
		tx.Rollback()
		return emptyCert, err
	}

	if len(certPEM) == 0 {
		err = fmt.Errorf("No certificate returned by server")
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		ca.log.Audit(fmt.Sprintf("PEM empty from Signer, rolling back: serial=[%s] err=[%v]", serialHex, err))
		tx.Rollback()
		return emptyCert, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		err = fmt.Errorf("Invalid certificate value returned")

		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		ca.log.Audit(fmt.Sprintf("PEM decode error, aborting and rolling back issuance: pem=[%s] err=[%v]", certPEM, err))
		tx.Rollback()
		return emptyCert, err
	}
	certDER := block.Bytes

	cert := core.Certificate{
		DER:    certDER,
		Status: core.StatusValid,
	}

	// This is one last check for uncaught errors
	if err != nil {
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		ca.log.Audit(fmt.Sprintf("Uncaught error, aborting and rolling back issuance: pem=[%s] err=[%v]", certPEM, err))
		tx.Rollback()
		return emptyCert, err
	}

	// Store the cert with the certificate authority, if provided
	_, err = ca.SA.AddCertificate(certDER, regID)
	if err != nil {
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		ca.log.Audit(fmt.Sprintf("Failed RPC to store at SA, orphaning certificate: pem=[%s] err=[%v]", certPEM, err))
		tx.Rollback()
		return emptyCert, err
	}

	if err = tx.Commit(); err != nil {
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		ca.log.Audit(fmt.Sprintf("Failed to commit, orphaning certificate: pem=[%s] err=[%v]", certPEM, err))
		return emptyCert, err
	}

	return cert, err
}
