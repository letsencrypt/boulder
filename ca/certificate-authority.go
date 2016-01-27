// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"

	cfsslConfig "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/config"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/ocsp"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/signer"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/signer/local"
)

// This map is used to detect algorithms in crypto/x509 that
// are no longer considered sufficiently strong.
// * No MD2, MD5, or SHA-1
// * No DSA
//
// SHA1WithRSA is allowed because there's still a fair bit of it
// out there, but we should try to remove it soon.
var badSignatureAlgorithms = map[x509.SignatureAlgorithm]bool{
	x509.UnknownSignatureAlgorithm: true,
	x509.MD2WithRSA:                true,
	x509.MD5WithRSA:                true,
	x509.DSAWithSHA1:               true,
	x509.DSAWithSHA256:             true,
	x509.ECDSAWithSHA1:             true,
}

// Metrics for CA statistics
const (
	// Increments when CA observes an HSM fault
	metricHSMFaultObserved = "CA.OCSP.HSMFault.Observed"

	// Increments when CA rejects a request due to an HSM fault
	metricHSMFaultRejected = "CA.OCSP.HSMFault.Rejected"
)

// CertificateAuthorityImpl represents a CA that signs certificates, CRLs, and
// OCSP responses.
type CertificateAuthorityImpl struct {
	rsaProfile     string
	ecdsaProfile   string
	signer         signer.Signer
	ocspSigner     ocsp.Signer
	SA             core.StorageAuthority
	PA             core.PolicyAuthority
	Publisher      core.Publisher
	keyPolicy      core.KeyPolicy
	clk            clock.Clock // TODO(jmhodges): should be private, like log
	log            *blog.AuditLogger
	stats          statsd.Statter
	prefix         int // Prepended to the serial number
	validityPeriod time.Duration
	notAfter       time.Time
	maxNames       int

	hsmFaultLock         sync.Mutex
	hsmFaultLastObserved time.Time
	hsmFaultTimeout      time.Duration
}

// NewCertificateAuthorityImpl creates a CA that talks to a remote CFSSL
// instance.  (To use a local signer, simply instantiate CertificateAuthorityImpl
// directly.)  Communications with the CA are authenticated with MACs,
// using CFSSL's authenticated signature scheme.  A CA created in this way
// issues for a single profile on the remote signer, which is indicated
// by name in this constructor.
func NewCertificateAuthorityImpl(
	config cmd.CAConfig,
	clk clock.Clock,
	stats statsd.Statter,
	issuer *x509.Certificate,
	privateKey crypto.Signer,
	keyPolicy core.KeyPolicy,
) (*CertificateAuthorityImpl, error) {
	var ca *CertificateAuthorityImpl
	var err error
	logger := blog.GetAuditLogger()
	logger.Notice("Certificate Authority Starting")

	if config.SerialPrefix <= 0 || config.SerialPrefix >= 256 {
		err = errors.New("Must have a positive non-zero serial prefix less than 256 for CA.")
		return nil, err
	}

	// CFSSL requires processing JSON configs through its own LoadConfig, so we
	// serialize and then deserialize.
	cfsslJSON, err := json.Marshal(config.CFSSL)
	if err != nil {
		return nil, err
	}
	cfsslConfigObj, err := cfsslConfig.LoadConfig(cfsslJSON)
	if err != nil {
		return nil, err
	}

	signer, err := local.NewSigner(privateKey, issuer, x509.SHA256WithRSA, cfsslConfigObj.Signing)
	if err != nil {
		return nil, err
	}

	if config.LifespanOCSP == "" {
		return nil, errors.New("Config must specify an OCSP lifespan period.")
	}
	lifespanOCSP, err := time.ParseDuration(config.LifespanOCSP)
	if err != nil {
		return nil, err
	}

	// Set up our OCSP signer. Note this calls for both the issuer cert and the
	// OCSP signing cert, which are the same in our case.
	ocspSigner, err := ocsp.NewSigner(issuer, issuer, privateKey, lifespanOCSP)
	if err != nil {
		return nil, err
	}

	rsaProfile := config.RSAProfile
	ecdsaProfile := config.ECDSAProfile
	if config.Profile != "" {
		if rsaProfile != "" || ecdsaProfile != "" {
			return nil, errors.New("either specify profile or rsaProfile and ecdsaProfile, but not both")
		}

		rsaProfile = config.Profile
		ecdsaProfile = config.Profile
	}

	if rsaProfile == "" || ecdsaProfile == "" {
		return nil, errors.New("must specify rsaProfile and ecdsaProfile")
	}

	ca = &CertificateAuthorityImpl{
		signer:          signer,
		ocspSigner:      ocspSigner,
		rsaProfile:      rsaProfile,
		ecdsaProfile:    ecdsaProfile,
		prefix:          config.SerialPrefix,
		clk:             clk,
		log:             logger,
		stats:           stats,
		notAfter:        issuer.NotAfter,
		hsmFaultTimeout: config.HSMFaultTimeout.Duration,
		keyPolicy:       keyPolicy,
	}

	if config.Expiry == "" {
		return nil, errors.New("Config must specify an expiry period.")
	}
	ca.validityPeriod, err = time.ParseDuration(config.Expiry)
	if err != nil {
		return nil, err
	}

	ca.maxNames = config.MaxNames

	return ca, nil
}

// checkHSMFault checks whether there has been an HSM fault observed within the
// timeout window.  CA methods that use the HSM should call this method right
// away, to minimize the performance impact of HSM outages.
func (ca *CertificateAuthorityImpl) checkHSMFault() error {
	ca.hsmFaultLock.Lock()
	defer ca.hsmFaultLock.Unlock()

	// If no timeout is set, never gate on a fault
	if ca.hsmFaultTimeout == 0 {
		return nil
	}

	now := ca.clk.Now()
	timeout := ca.hsmFaultLastObserved.Add(ca.hsmFaultTimeout)
	if now.Before(timeout) {
		err := core.ServiceUnavailableError("HSM is unavailable")
		ca.log.WarningErr(err)
		ca.stats.Inc(metricHSMFaultRejected, 1, 1.0)
		return err
	}
	return nil
}

// noteHSMFault updates the CA's state with regard to HSM faults.  CA methods
// that use an HSM should pass errors that might be HSM errors to this method.
func (ca *CertificateAuthorityImpl) noteHSMFault(err error) {
	ca.hsmFaultLock.Lock()
	defer ca.hsmFaultLock.Unlock()

	if err != nil {
		ca.stats.Inc(metricHSMFaultObserved, 1, 1.0)
		ca.hsmFaultLastObserved = ca.clk.Now()
	}
	return
}

// GenerateOCSP produces a new OCSP response and returns it
func (ca *CertificateAuthorityImpl) GenerateOCSP(xferObj core.OCSPSigningRequest) ([]byte, error) {
	if err := ca.checkHSMFault(); err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(xferObj.CertDER)
	if err != nil {
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		ca.log.AuditErr(err)
		return nil, err
	}

	signRequest := ocsp.SignRequest{
		Certificate: cert,
		Status:      xferObj.Status,
		Reason:      int(xferObj.Reason),
		RevokedAt:   xferObj.RevokedAt,
	}

	ocspResponse, err := ca.ocspSigner.Sign(signRequest)
	ca.noteHSMFault(err)
	return ocspResponse, err
}

// IssueCertificate attempts to convert a CSR into a signed Certificate, while
// enforcing all policies. Names (domains) in the CertificateRequest will be
// lowercased before storage.
func (ca *CertificateAuthorityImpl) IssueCertificate(csr x509.CertificateRequest, regID int64) (core.Certificate, error) {
	emptyCert := core.Certificate{}
	var err error

	if err := ca.checkHSMFault(); err != nil {
		return emptyCert, err
	}

	key, ok := csr.PublicKey.(crypto.PublicKey)
	if !ok {
		err = core.MalformedRequestError("Invalid public key in CSR.")
		// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
		ca.log.AuditErr(err)
		return emptyCert, err
	}
	if err = ca.keyPolicy.GoodKey(key); err != nil {
		err = core.MalformedRequestError(fmt.Sprintf("Invalid public key in CSR: %s", err.Error()))
		// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
		ca.log.AuditErr(err)
		return emptyCert, err
	}
	if badSignatureAlgorithms[csr.SignatureAlgorithm] {
		err = core.MalformedRequestError("Invalid signature algorithm in CSR")
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
		commonName = strings.ToLower(csr.Subject.CommonName)
		hostNames = append(hostNames, commonName)
	} else if len(hostNames) > 0 {
		commonName = strings.ToLower(hostNames[0])
	} else {
		err = core.MalformedRequestError("Cannot issue a certificate without a hostname.")
		// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
		ca.log.AuditErr(err)
		return emptyCert, err
	}

	// Collapse any duplicate names.  Note that this operation may re-order the names
	hostNames = core.UniqueLowerNames(hostNames)
	if ca.maxNames > 0 && len(hostNames) > ca.maxNames {
		err = core.MalformedRequestError(fmt.Sprintf("Certificate request has %d names, maximum is %d.", len(hostNames), ca.maxNames))
		ca.log.WarningErr(err)
		return emptyCert, err
	}

	// Verify that names are allowed by policy
	identifier := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: commonName}
	if err = ca.PA.WillingToIssue(identifier, regID); err != nil {
		err = core.MalformedRequestError(fmt.Sprintf("Policy forbids issuing for name %s", commonName))
		// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
		ca.log.AuditErr(err)
		return emptyCert, err
	}
	for _, name := range hostNames {
		identifier = core.AcmeIdentifier{Type: core.IdentifierDNS, Value: name}
		if err = ca.PA.WillingToIssue(identifier, regID); err != nil {
			err = core.MalformedRequestError(fmt.Sprintf("Policy forbids issuing for name %s", name))
			// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
			ca.log.AuditErr(err)
			return emptyCert, err
		}
	}

	notAfter := ca.clk.Now().Add(ca.validityPeriod)

	if ca.notAfter.Before(notAfter) {
		err = core.InternalServerError("Cannot issue a certificate that expires after the intermediate certificate.")
		// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
		ca.log.AuditErr(err)
		return emptyCert, err
	}

	// Convert the CSR to PEM
	csrPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	}))

	// We want 136 bits of random number, plus an 8-bit instance id prefix.
	const randBits = 136
	serialBytes := make([]byte, randBits/8+1)
	serialBytes[0] = byte(ca.prefix)
	_, err = rand.Read(serialBytes[1:])
	if err != nil {
		err = core.InternalServerError(err.Error())
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		ca.log.Audit(fmt.Sprintf("Serial randomness failed, err=[%v]", err))
		return emptyCert, err
	}
	serialHex := hex.EncodeToString(serialBytes)
	serialBigInt := big.NewInt(0)
	serialBigInt = serialBigInt.SetBytes(serialBytes)

	var profile string
	switch key.(type) {
	case *rsa.PublicKey:
		profile = ca.rsaProfile
	case *ecdsa.PublicKey:
		profile = ca.ecdsaProfile
	default:
		err = core.InternalServerError(fmt.Sprintf("unsupported key type %T", key))
		// AUDIT[ Certificate Requests ] 11917fa4-10ef-4e0d-9105-bacbe7836a3c
		ca.log.AuditErr(err)
		return emptyCert, err
	}

	// Send the cert off for signing
	req := signer.SignRequest{
		Request: csrPEM,
		Profile: profile,
		Hosts:   hostNames,
		Subject: &signer.Subject{
			CN: commonName,
		},
		Serial: serialBigInt,
	}

	certPEM, err := ca.signer.Sign(req)
	ca.noteHSMFault(err)
	if err != nil {
		err = core.InternalServerError(err.Error())
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		ca.log.Audit(fmt.Sprintf("Signer failed, rolling back: serial=[%s] err=[%v]", serialHex, err))
		return emptyCert, err
	}

	if len(certPEM) == 0 {
		err = core.InternalServerError("No certificate returned by server")
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		ca.log.Audit(fmt.Sprintf("PEM empty from Signer, rolling back: serial=[%s] err=[%v]", serialHex, err))
		return emptyCert, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		err = core.InternalServerError("Invalid certificate value returned")
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		ca.log.Audit(fmt.Sprintf("PEM decode error, aborting and rolling back issuance: pem=[%s] err=[%v]", certPEM, err))
		return emptyCert, err
	}
	certDER := block.Bytes

	cert := core.Certificate{
		DER: certDER,
	}

	// This is one last check for uncaught errors
	if err != nil {
		err = core.InternalServerError(err.Error())
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		ca.log.Audit(fmt.Sprintf("Uncaught error, aborting and rolling back issuance: pem=[%s] err=[%v]", certPEM, err))
		return emptyCert, err
	}

	// Store the cert with the certificate authority, if provided
	_, err = ca.SA.AddCertificate(certDER, regID)
	if err != nil {
		err = core.InternalServerError(err.Error())
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		ca.log.Audit(fmt.Sprintf(
			"Failed RPC to store at SA, orphaning certificate: b64der=[%s] err=[%v], regID=[%d]",
			base64.StdEncoding.EncodeToString(certDER),
			err,
			regID,
		))
		return emptyCert, err
	}

	// Submit the certificate to any configured CT logs
	go ca.Publisher.SubmitToCT(certDER)

	// Do not return an err at this point; caller must know that the Certificate
	// was issued. (Also, it should be impossible for err to be non-nil here)
	return cert, nil
}
