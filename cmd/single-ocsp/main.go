package main

import (
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/letsencrypt/boulder/cmd"

	"github.com/letsencrypt/pkcs11key"
	"golang.org/x/crypto/ocsp"
)

// PKCS11Config defines how to load a module for an HSM.
// XXX(rlb@ipv.sx) Copied from certificate-authority.go
type PKCS11Config struct {
	Module          string
	TokenLabel      string
	PrivateKeyLabel string
	PIN             string
}

const usage = `
name:
  single-ocsp - Creates a single OCSP response

usage:
  single-ocsp [args]

description:
  According to the BRs, the OCSP responses for intermediate certificate must
  be issued once per year.  So there's a need to issue OCSP responses for
  these certificates, but it doesn't make sense to use all the infrastructure
  that the "ocsp-updater" tool requires.  This tool allows an administrator
  to manually generate an OCSP response for an intermediate certificate.
`

const templateUsage = `
OCSP template file (JSON), e.g.:

{
  "Status": 0, // Good
  "ThisUpdate": "2015-08-26T00:00:00Z",
  "NextUpdate": "2016-08-26T00:00:00Z"
}

{
  "Status": 1, // Revoked
  "ThisUpdate": "2015-08-26T00:00:00Z",
  "NextUpdate": "2016-08-26T00:00:00Z",
  "RevokedAt": "2015-08-20T00:00:00Z",
  "RevocationReason": 1 // Key compromise
}
`

const pkcs11Usage = `
PKCS#11 configuration (JSON), e.g.:

{
  "Module": "/Library/OpenSC/lib/opensc-pkcs11.so",
  "Token": "Yubico Yubikey NEO CCID",
  "Label": "PIV AUTH key",
  "PIN": "123456"
}
`

func readFiles(issuerFileName, responderFileName, targetFileName, templateFileName, pkcs11FileName string) (issuer, responder, target *x509.Certificate, template ocsp.Response, pkcs11 PKCS11Config, err error) {
	// Issuer certificate
	issuerBytes, err := ioutil.ReadFile(issuerFileName)
	if err != nil {
		return
	}

	issuer, err = x509.ParseCertificate(issuerBytes)
	if err != nil {
		return
	}

	// Responder certificate
	responderBytes, err := ioutil.ReadFile(responderFileName)
	if err != nil {
		return
	}

	responder, err = x509.ParseCertificate(responderBytes)
	if err != nil {
		return
	}

	// Target certificate
	targetBytes, err := ioutil.ReadFile(targetFileName)
	if err != nil {
		return
	}

	target, err = x509.ParseCertificate(targetBytes)
	if err != nil {
		return
	}

	// OCSP template
	templateBytes, err := ioutil.ReadFile(templateFileName)
	if err != nil {
		return
	}

	err = json.Unmarshal(templateBytes, &template)
	if err != nil {
		return
	}

	// PKCS#11 config
	pkcs11Bytes, err := ioutil.ReadFile(pkcs11FileName)
	if err != nil {
		return
	}

	err = json.Unmarshal(pkcs11Bytes, &pkcs11)
	return
}

func main() {
	issuerFile := flag.String("issuer", "", "Issuer certificate (DER)")
	responderFile := flag.String("responder", "", "OCSP responder certificate (DER)")
	targetFile := flag.String("target", "", "Certificate whose status is being reported (DER)")
	templateFile := flag.String("template", "", templateUsage)
	pkcs11File := flag.String("pkcs11", "", pkcs11Usage)
	outFile := flag.String("out", "", "File to which the OCSP response will be written")
	flag.Parse()

	issuer, responder, target, template, pkcs11, err := readFiles(*issuerFile, *responderFile, *targetFile, *templateFile, *pkcs11File)
	cmd.FailOnError(err, "Failed to read files")

	// Instantiate the private key from PKCS11
	priv, err := pkcs11key.New(pkcs11.Module, pkcs11.TokenLabel, pkcs11.PIN, pkcs11.PrivateKeyLabel)
	cmd.FailOnError(err, "Failed to load PKCS#11 key")

	// Populate the remaining fields in the template
	template.SerialNumber = target.SerialNumber
	template.Certificate = responder

	// Sign the OCSP response
	responseBytes, err := ocsp.CreateResponse(issuer, responder, template, priv)
	cmd.FailOnError(err, "Failed to sign OCSP response")

	// Write the OCSP response to stdout
	if len(*outFile) == 0 {
		cmd.FailOnError(fmt.Errorf(""), "No output file provided")
	}
	err = ioutil.WriteFile(*outFile, responseBytes, 0666)
	cmd.FailOnError(err, "Failed to write output file")
}
