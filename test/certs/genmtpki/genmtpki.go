//go:build go1.27

package main

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"flag"
	"log"
	"math/big"
	"os"
	"path"
	"time"
)

func main() {
	err := main2()
	if err != nil {
		log.Fatal(err)
	}
}

const basename = "mtca1"

func main2() error {
	outputDir := flag.String("output-dir", "", "Directory to write outputs to")
	flag.Parse()

	if *outputDir == "" {
		return errors.New("-output-dir flag required")
	}

	basepath := path.Join(*outputDir, basename)

	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		return err
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	keyFile, err := os.OpenFile(basepath+".key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	err = pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	if err != nil {
		return err
	}

	extn, err := mtcaExtension()
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		// TODO: decide how to generate serial number for MTCA certificates; presumably random?
		SerialNumber: big.NewInt(123),
		Subject:      mtcaSubject(),
		// CA ID, encoded
		// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-representing-certification-
		// The subject key identifier extension, if present, SHOULD be set to the CA ID (Section 5.1).
		// The CA ID is encoded in its binary representation, as defined in Section 3 of [I-D.ietf-tls-trust-anchor-ids].
		SubjectKeyId: []byte{0x82, 0xdf, 0x13, 1, 2, 1},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		// The key usage extension (Section 4.2.1.3 of [RFC5280]) MUST be present and assert at least the keyCertSign bit.
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{extn},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return err
	}

	_, err = x509.ParseCertificate(certBytes)
	if err != nil {
		return err
	}

	certFile, err := os.OpenFile(basepath+".cert.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer certFile.Close()

	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return err
	}

	return nil
}

func mtcaSubject() pkix.Name {
	// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-certification-authority-ide
	// For initial experimentation, early implementations of this design will:
	//  - Use UTF8String to represent the attribute's value rather than RELATIVE-OID. The UTF8String contains trust anchor ID's ASCII representation, e.g. 32473.1.
	//  - Use the OID 1.3.6.1.4.1.44363.47.1 instead of id-rdna-trustAnchorID.
	// idRDNATrustAnchorID := asn1.ObjectIdentifier{ 1, 3, 6, 1, 5, 5, 7, 25 }
	idRDNATrustAnchorIDExperimental := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 1}

	// https://letsencrypt.org/docs/oids/
	// 44947 is ISRG; 44947.4.1 will be temporarily for our prototype MTC implementation, with ".1"
	// representing one CA instance.
	mtcaID := "44947.4.1"
	attributes := []pkix.AttributeTypeAndValue{
		{
			Type:  idRDNATrustAnchorIDExperimental,
			Value: asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte(mtcaID)},
		},
	}

	return pkix.Name{
		ExtraNames: attributes,
	}
}

func mtcaExtension() (pkix.Extension, error) {
	// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-representing-certification-
	// For initial experimentation, early implementations of this design will use the OID 1.3.6.1.4.1.44363.47.2 instead of id-pe-mtcCertificationAuthority.
	extnOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 2}

	// Copied from https://cs.opensource.google/go/go/+/refs/tags/go1.26.3:src/crypto/x509/x509.go;l=345-350
	oidSHA256 := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	// https://www.rfc-editor.org/info/rfc9881/
	oidSignatureMLDSA44 := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}

	extnMarshaled, err := asn1.Marshal(struct {
		LogHash   pkix.AlgorithmIdentifier
		SigAlg    pkix.AlgorithmIdentifier
		MinSerial int64
	}{
		LogHash: pkix.AlgorithmIdentifier{Algorithm: oidSHA256},
		SigAlg:  pkix.AlgorithmIdentifier{Algorithm: oidSignatureMLDSA44},
		// Just for fun, exercise MinSerial functionality.
		MinSerial: 999,
	})

	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:       extnOID,
		Critical: true,
		Value:    extnMarshaled,
	}, nil
}
