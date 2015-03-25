// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"time"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/policy"

	"github.com/cloudflare/cfssl/auth"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/remote"
)

type CertificateAuthorityImpl struct {
	profile string
	Signer  signer.Signer
	SA      core.StorageAuthority
	PA      core.PolicyAuthority
}

// NewCertificateAuthorityImpl creates a CA that talks to a remote CFSSL
// instance.  (To use a local signer, simply instantiate CertificateAuthorityImpl
// directly.)  Communications with the CA are authenticated with MACs,
// using CFSSL's authenticated signature scheme.  A CA created in this way
// issues for a single profile on the remote signer, which is indicated
// by name in this constructor.
func NewCertificateAuthorityImpl(hostport string, authKey string, profile string) (ca *CertificateAuthorityImpl, err error) {
	// Create the remote signer
	localProfile := config.SigningProfile{
		Expiry:       time.Hour, // BOGUS: Required by CFSSL, but not used
		RemoteName:   hostport,  // BOGUS: Only used as a flag by CFSSL
		RemoteServer: hostport,
	}

	localProfile.Provider, err = auth.New(authKey, nil)
	if err != nil {
		return
	}

	signer, err := remote.NewSigner(&config.Signing{Default: &localProfile})
	if err != nil {
		return
	}

	pa := policy.NewPolicyAuthorityImpl()

	ca = &CertificateAuthorityImpl{Signer: signer, profile: profile, PA: pa}
	return
}

// When we receive CSRs from a client, we extract only the fields we care about
// (names and public key), then create a new CSR from those to pass on to CFSSL.
// The new CSR requires a signature, but that signature is not used for any
// security purposes. The validity of the signing request is checked by the
// registration authority, and the certificate authority authenticates itself to
// CFSSL with CFSSL's own signature scheme. For the vestigial signature on the
// re-wrapped CSR we use this single-purpose, insecure 512 bit "private" key.
var csrResigningKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAMLsxrThLEHt5Yzr4jxnn8rcX5HqhpkBKJ6V5gRAg+WXaJUR7mhe
pAuZvNUbW2J127GvWH2QNkSNa/WMvOm/pH0CAwEAAQJAX2cb6jO7QZl6HHrnA8GE
B/nMHNK4hfJ3OwcKyVH6PEgAB+7RaMqGsqdZ0vqabna6nM5rHYvPanuFgiFLKzqA
AQIhAONw64nBvuPbqaA3GnDrOgzLsbZaz5Bz1FOxA5GxiWx9AiEA22agE9JsrRZR
gjaZBfnTgNj1HDbPOrkr5Oui9AS8mAECIQCMHWadiSRGT27ias/5PJCYjWw/wRYa
EaF+pZBjUxIsKQIhAMyHvD0eUi99edjA2yCGCBS6rK1zrvYYf4H15UBEVigBAiAH
xilAU/SLRXqt06pbv/hshGAJhl3F8Rs1/8gf2CorAw==
-----END RSA PRIVATE KEY-----
`

// Given a CSR provided by the user and validated by the registration authority,
// extract the names and public key, and pass them on to a CFSSL instance for
// signing. IMPORTANT: This method must only be called by the registration
// authority, and only after verifying that all names are authorized for the
// requesting account key.
// TODO: Add technical controls to only accept messages from the registration
// authority.
func (ca *CertificateAuthorityImpl) IssueCertificate(unsafeCsr x509.CertificateRequest) (cert core.Certificate, err error) {
	// Only sign RSA certificates until we explicitly support ECDSA.
	if unsafeCsr.PublicKeyAlgorithm != x509.RSA {
		err = errors.New("Non-RSA key provided in CSR.")
	}
	// Don't accept the provided CSR as-is: Take only the public key and the names
	// from it.
	safeCsr := x509.CertificateRequest{
		PublicKeyAlgorithm: unsafeCsr.PublicKeyAlgorithm,
		PublicKey: unsafeCsr.PublicKey,
	}
	// Pull hostnames from CSR
	hostNames := unsafeCsr.DNSNames // DNSNames + CN from CSR

	// The CommonName from the Subject must always be present in the
	// SubjectAltNames. If it was present, accept the provided CN.
	cn := unsafeCsr.Subject.CommonName
	if len(cn) > 0 {
		hostNames = append(hostNames, cn)
		safeCsr.Subject = pkix.Name{
			CommonName: cn,
		}
	} else if len(hostNames) > 0 {
		// If CN was not provided, pick one of the SubjectAltNames.
		safeCsr.Subject = pkix.Name{
			CommonName: hostNames[0],
		}
	} else {
		// If there was no CN and no SubjectAltNames, fail.
		err = errors.New("Cannot issue a certificate without a hostname.")
		return
	}

	// There may be duplicate entries in the input subjectAltNames + CN, so
	// de-duplicate them with a map at the same time we check them for validity.
	hostNamesMap := make(map[string]int)
	for _, name := range hostNames {
		identifier := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: name}
		if willingErr := ca.PA.WillingToIssue(identifier); willingErr != nil {
			err = errors.New("Policy forbids issuing for name " + name)
			return
		}
		hostNamesMap[name] = 1
	}

	// Iterate through the map extracting the names again.
	for k, _ := range hostNamesMap {
		safeCsr.DNSNames = append(safeCsr.DNSNames, k)
	}

	// To produce DER bytes from this new CSR, we need to provide a signing key.
	// This signing key is not security-critical, as described above.
	privateKeyBlock, _ := pem.Decode([]byte(csrResigningKey))
	rsaPriv, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	safeCsrDerBytes, csrErr := x509.CreateCertificateRequest(
		rand.Reader, &safeCsr, rsaPriv)
	if csrErr != nil {
		err = errors.New("Problem creating CSR")
		return
	}

	// Convert the CSR to PEM
	safeCsrPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: safeCsrDerBytes,
	}))

	// Send the cert off for signing
	req := signer.SignRequest{
		Request: safeCsrPEM,
		Profile: ca.profile,
		Hosts:   hostNames,
	}
	certPEM, err := ca.Signer.Sign(req)
	if err != nil {
		return
	}

	if len(certPEM) == 0 {
		err = errors.New("No certificate returned by server")
		return
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		err = errors.New("Invalid certificate value returned")
		return
	}
	certDER := block.Bytes

	// Store the cert with the certificate authority, if provided
	certID, err := ca.SA.AddCertificate(certDER)
	if err != nil {
		return
	}

	cert = core.Certificate{
		ID:     certID,
		DER:    certDER,
		Status: core.StatusValid,
	}
	return
}
