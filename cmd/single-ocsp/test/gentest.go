package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/pkcs11key"
)

const pkcs11FileName = "pkcs11.json"
const caCertFileName = "ca-cert.der"
const eeCertFileName = "ee-cert.der"
const ocspCertFileName = "ocsp-cert.der"
const caCertFileNamePEM = "ca-cert.pem"
const eeCertFileNamePEM = "ee-cert.pem"
const ocspCertFileNamePEM = "ocsp-cert.pem"

func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}

func makeCert(template, issuer *x509.Certificate, pub interface{}, priv crypto.Signer) *x509.Certificate {
	// Set a random serial number
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1000))
	panicOnError(err)
	template.SerialNumber = serialNumber

	certDER, err := x509.CreateCertificate(rand.Reader, template, issuer, pub, priv)
	panicOnError(err)
	cert, err := x509.ParseCertificate(certDER)
	panicOnError(err)
	return cert
}

func toPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

func main() {
	// Instantiate the PKCS11 key
	var pkcs11 struct {
		Module          string
		TokenLabel      string
		PIN             string
		PrivateKeyLabel string
	}
	pkcs11Bytes, err := ioutil.ReadFile(pkcs11FileName)
	panicOnError(err)
	err = json.Unmarshal(pkcs11Bytes, &pkcs11)
	panicOnError(err)
	p11key, err := pkcs11key.New(pkcs11.Module, pkcs11.TokenLabel, pkcs11.PIN, pkcs11.PrivateKeyLabel)
	panicOnError(err)

	// All of the certificates start and end at the same time
	notBefore := time.Now().Truncate(time.Hour).Add(-1 * time.Hour)
	notAfter := notBefore.AddDate(1, 0, 0)

	// Make some keys for the CA and EE
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	panicOnError(err)
	eeKey, err := rsa.GenerateKey(rand.Reader, 2048)
	panicOnError(err)

	// Make CA cert with ephemeral key
	template := &x509.Certificate{
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		Subject:               pkix.Name{CommonName: "Happy Hacker Fake CA"},
		BasicConstraintsValid: true,
		IsCA: true,
	}
	caCert := makeCert(template, template, caKey.Public(), caKey)

	// Make EE cert with ephemeral key and print
	template = &x509.Certificate{
		NotBefore: notBefore,
		NotAfter:  notAfter,
		Subject:   pkix.Name{CommonName: "example.com"},
	}
	eeCert := makeCert(template, caCert, eeKey.Public(), caKey)

	// Make OCSP responder cert with PKCS#11 key
	template = &x509.Certificate{
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		Subject:     pkix.Name{CommonName: "Happy Hacker OCSP Signer"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}
	ocspCert := makeCert(template, caCert, p11key.Public(), caKey)

	// Write out all the certs in DER and PEM
	ioutil.WriteFile(caCertFileName, caCert.Raw, 0666)
	ioutil.WriteFile(eeCertFileName, eeCert.Raw, 0666)
	ioutil.WriteFile(ocspCertFileName, ocspCert.Raw, 0666)
	ioutil.WriteFile(caCertFileNamePEM, toPEM(caCert), 0666)
	ioutil.WriteFile(eeCertFileNamePEM, toPEM(eeCert), 0666)
	ioutil.WriteFile(ocspCertFileNamePEM, toPEM(ocspCert), 0666)
}
