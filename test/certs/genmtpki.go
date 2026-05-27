package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"
)

func main() {
	err := main2()
	if err != nil {
		log.Fatal(err)
	}
}

func main2() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), nil)
	if err != nil {
		return err
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	keyFile, err := os.OpenFile("mtpki/mtca1.key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})

	extn, err := mtcaExtension()
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(123),
		Subject:      mtcaSubject(),
		// CA ID, encoded
		SubjectKeyId:          []byte{0x82, 0xdf, 0x13, 1, 2, 1},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
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

	certFile, err := os.OpenFile("mtpki/mtca1.cert.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer certFile.Close()

	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	return nil
}

func mtcaSubject() pkix.Name {
	// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-certification-authority-ide
	// For initial experimentation, early implementations of this design will:
	//  - Use UTF8String to represent the attribute's value rather than RELATIVE-OID. The UTF8String contains trust anchor ID's ASCII representation, e.g. 32473.1.
	//  - Use the OID 1.3.6.1.4.1.44363.47.1 instead of id-rdna-trustAnchorID.
	// idRDNATrustAnchorID := asn1.ObjectIdentifier{ 1, 3, 6, 1, 5, 5, 7, 25 }
	idRDNATrustAnchorIDExperimental := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 1}

	// https://www.alvestrand.no/objectid/1.3.6.1.4.1.44947.1.html
	// 44947.1 is Let's Encrypt; 44947.1.2 will be temporarily for our prototype MTC implementation, with ".1"
	// representing one CA instance.
	mtcaID := "44947.1.2.1"
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
	oidSignatureECDSAWithSHA256 := asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}

	extnMarshaled, err := asn1.Marshal(struct {
		LogHash   pkix.AlgorithmIdentifier
		SigAlg    pkix.AlgorithmIdentifier
		MinSerial int64
	}{
		LogHash: pkix.AlgorithmIdentifier{Algorithm: oidSHA256},
		SigAlg:  pkix.AlgorithmIdentifier{Algorithm: oidSignatureECDSAWithSHA256},
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
