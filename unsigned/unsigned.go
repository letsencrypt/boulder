// Package unsigned implements RFC 9925 Unsigned X.509 Certificates.
//
// https://datatracker.ietf.org/doc/html/rfc9925
package unsigned

import (
	encoding_asn1 "encoding/asn1"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// Design parses the input as an X.509 certificate and returns an unsigned certificate
// with the same contents.
//
// RFC 9925 says "Senders SHOULD omit the authority key identifier and issuer alternative
// name extensions", but since we use this for returning lint certificate bytes we leave
// all fields unchanged, including those fields.
//
// If replaceSigAlg is true, Design emits a proper RFC 9925 certificate with the signature
// algorithm id-alg-unsigned in both slots. If false, it retains the original signature
// algorithm and simply truncates the signature. This is convenient for efficiently storing
// lint certificates where we don't care about the signature bytes.
func Design(cert []byte, replaceSigAlg bool) ([]byte, error) {
	certificate := cryptobyte.String(cert)

	// https://datatracker.ietf.org/doc/html/rfc5280#page-116
	//
	//		Certificate  ::=  SEQUENCE  {
	//		    tbsCertificate       TBSCertificate,
	//          signatureAlgorithm   AlgorithmIdentifier,
	//          signature            BIT STRING  }
	//
	//		TBSCertificate  ::=  SEQUENCE  {
	//		    version         [0]  Version DEFAULT v1,
	//		    serialNumber         CertificateSerialNumber,
	//          signature            AlgorithmIdentifier,
	//	     ...
	var certificateInner cryptobyte.String
	if !certificate.ReadASN1(&certificateInner, asn1.SEQUENCE) {
		return nil, fmt.Errorf("failed to read outer sequence")
	}

	var tbsCertificate cryptobyte.String
	if !certificateInner.ReadASN1(&tbsCertificate, asn1.SEQUENCE) {
		return nil, fmt.Errorf("failed to read tbsCertificate")
	}

	var versionElement cryptobyte.String
	if !tbsCertificate.ReadASN1Element(&versionElement, asn1.Tag(0).Constructed().ContextSpecific()) {
		return nil, fmt.Errorf("failed to read version")
	}

	var serialNumberElement cryptobyte.String
	if !tbsCertificate.ReadASN1Element(&serialNumberElement, asn1.INTEGER) {
		return nil, fmt.Errorf("failed to read serial number")
	}

	var innerSignatureAlgorithm cryptobyte.String
	if !tbsCertificate.ReadASN1(&innerSignatureAlgorithm, asn1.SEQUENCE) {
		return nil, fmt.Errorf("failed to read inner signature field")
	}

	// back out to the certificate
	var signatureAlgorithm cryptobyte.String
	if !certificateInner.ReadASN1Element(&signatureAlgorithm, asn1.SEQUENCE) {
		return nil, fmt.Errorf("failed to read signatureAlgorithm")
	}

	var signature cryptobyte.String
	if !certificateInner.ReadASN1(&signature, asn1.BIT_STRING) {
		return nil, fmt.Errorf("failed to read signature")
	}

	if !certificate.Empty() {
		return nil, fmt.Errorf("extra bytes at end")
	}

	var b cryptobyte.Builder

	idAlgUnsigned := encoding_asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 36}

	b.AddASN1(asn1.SEQUENCE, func(outTBS *cryptobyte.Builder) {
		outTBS.AddASN1(asn1.SEQUENCE, func(outBytes *cryptobyte.Builder) {
			outBytes.AddBytes(versionElement)
			outBytes.AddBytes(serialNumberElement)
			outBytes.AddASN1(asn1.SEQUENCE, func(algorithmIdentifier *cryptobyte.Builder) {
				if replaceSigAlg {
					algorithmIdentifier.AddASN1ObjectIdentifier(idAlgUnsigned)
				} else {
					algorithmIdentifier.AddBytes(innerSignatureAlgorithm)
				}
			})
			outBytes.AddBytes([]byte(tbsCertificate))
		})
		outTBS.AddASN1(asn1.SEQUENCE, func(algorithmIdentifier *cryptobyte.Builder) {
			if replaceSigAlg {
				algorithmIdentifier.AddASN1ObjectIdentifier(idAlgUnsigned)
			} else {
				algorithmIdentifier.AddBytes(innerSignatureAlgorithm)
			}
		})
		// The Certificate's signatureValue field MUST be a BIT STRING of length zero.
		outTBS.AddASN1BitString(nil)
	})

	return b.Bytes()
}
