package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/letsencrypt/boulder/cmd"

	"github.com/letsencrypt/pkcs11key"
	"golang.org/x/crypto/ocsp"
)

const usage = `
name:
  single-ocsp - Creates a single OCSP response

usage:
  single-ocsp [args]

description:
  According to the BRs, the OCSP responses for intermediate certificate must
  be issued once per year.  So we need to issue OCSP responses for these
	certificates, but it doesn't make sense to use all the infrastructure
  that the "ocsp-updater" tool requires.  This tool allows an administrator
  to manually generate an OCSP response for an intermediate certificate.

	This will write a base64-encoded DER format OCSP response to the file
	specified with -out, ending in a newline. This output can be directly
	appended to the flat file used by ocsp-responder for intermediate and
	root OCSP responses.
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
	"module": "/usr/local/lib/libpkcs11-proxy.so",
	"tokenLabel": "token_label",
	"pin": "5678",
	"privateKeyLabel": "key_label"
}
`

func readFiles(issuerFileName, responderFileName, targetFileName, templateFileName, pkcs11FileName string) (issuer, responder, target *x509.Certificate, template ocsp.Response, pkcs11Config pkcs11key.Config, err error) {
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

	err = json.Unmarshal(pkcs11Bytes, &pkcs11Config)
	if pkcs11Config.Module == "" ||
		pkcs11Config.TokenLabel == "" ||
		pkcs11Config.PIN == "" ||
		pkcs11Config.PrivateKeyLabel == "" {
		err = fmt.Errorf("Missing a field in pkcs11Config %#v", pkcs11Config)
		return
	}
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

	if len(*outFile) == 0 {
		cmd.FailOnError(fmt.Errorf(""), "No output file provided")
	}

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

	responseBytesBase64 := base64.StdEncoding.EncodeToString(responseBytes) + "\n"

	// Write the OCSP response to stdout
	err = ioutil.WriteFile(*outFile, []byte(responseBytesBase64), 0666)
	cmd.FailOnError(err, "Failed to write output file")
}
