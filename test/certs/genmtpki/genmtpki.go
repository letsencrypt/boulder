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

	"golang.org/x/crypto/cryptobyte"
	casn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/unsigned"
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
	tlogPrefixURL := flag.String("tlog-prefix-url", "", "URL for tlog tile serving")
	flag.Parse()

	if *outputDir == "" {
		return errors.New("-output-dir flag required")
	}
	if *tlogPrefixURL == "" {
		return errors.New("-tlog-prefix-url flag required")
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

	mtcaExtn, err := mtcaExtension()
	if err != nil {
		return err
	}

	tlogPrefixExtn, err := tlogPrefixExtn(*tlogPrefixURL)
	if err != nil {
		return err
	}

	// https://letsencrypt.org/docs/oids/
	// 44947 is ISRG; 44947.4.1 will be temporarily for our prototype MTC implementation, with ".1"
	// representing one CA instance.
	mtcaID := "44947.4.1"
	skid, _ := core.EncodeRelativeOID(mtcaID)

	template := &x509.Certificate{
		// TODO: decide how to generate serial number for MTCA certificates; presumably random?
		SerialNumber: big.NewInt(123),
		Subject:      mtcaSubject(mtcaID),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		// The key usage extension (Section 4.2.1.3 of [RFC5280]) MUST be present and assert at least the keyCertSign bit.
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		// The subject key identifier extension (Section 4.2.1.2 of [RFC5280]), if present, SHOULD be set to the CA ID Section 5.1.
		// The CA ID is encoded in its binary representation, as defined in Section 4 of [I-D.ietf-tls-trust-anchor-ids].
		SubjectKeyId:          skid,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		ExtraExtensions:       []pkix.Extension{mtcaExtn, tlogPrefixExtn},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return err
	}

	unsignedBytes, err := unsigned.Design(certBytes, true)
	if err != nil {
		return err
	}

	_, err = x509.ParseCertificate(unsignedBytes)
	if err != nil {
		return err
	}

	certFile, err := os.OpenFile(basepath+".cert.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer certFile.Close()

	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: unsignedBytes})
	if err != nil {
		return err
	}

	caSPKI, err := x509.MarshalPKIXPublicKey(key.PublicKey())
	if err != nil {
		return err
	}

	caPubFile, err := os.OpenFile(basepath+".pub.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer caPubFile.Close()

	return pem.Encode(caPubFile, &pem.Block{Type: "PUBLIC KEY", Bytes: caSPKI})
}

func mtcaSubject(relativeOID string) pkix.Name {
	// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-certification-authority-ide
	// A CA ID determines a PKIX distinguished name (Section 4.1.2.4 of [RFC5280]) that can be used in the issuer or subject field of an X.509 TBSCertificate.
	// This distinguished name has a single relative distinguished name, which has a single attribute. The attribute has type id-rdna-trustAnchorID, defined below:
	// 	id-rdna-trustAnchorID OBJECT IDENTIFIER ::= {
	// 			iso(1) identified-organization(3) dod(6) internet(1) security(5)
	// 			mechanisms(5) pkix(7) rdna(25) 3 }
	idRDNATrustAnchorID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 25, 3}

	// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-certification-authority-ide
	// The attribute's value is a RELATIVE-OID containing the trust anchor ID's ASN.1 representation.
	//
	// https://www.ietf.org/archive/id/draft-housley-asn1-layman-guide-03.html#section-2
	// 	Type					Decimal Tag Number	Hexadecimal Tag Number
	// 	RELATIVE-OID	13									0d
	tagRelativeOID := 13

	// Throw away the err because this is just test setup code and we know that
	// we're providing well-formed relative OIDs.
	val, _ := core.EncodeRelativeOID(relativeOID)

	attributes := []pkix.AttributeTypeAndValue{
		{
			Type:  idRDNATrustAnchorID,
			Value: asn1.RawValue{Tag: tagRelativeOID, Bytes: val},
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

// tlogPrefixExtn returns the extension containing the CA prefix URL.
//
// https://c2sp.org/mtc-tlog#parameters
//
//	id-mtcTlogPrefixURL OBJECT IDENTIFIER ::= {
//	    iso(1) org(3) dod(6) internet(1) private(4) enterprise(1) C2SP(64829)
//	    mtc-tlog(2) 1 }
//
//	ext-mtcTlogPrefixURL EXTENSION ::= {
//	    SYNTAX IA5String
//	    IDENTIFIED BY id-mtcTlogPrefixURL
//	    CRITICALITY FALSE
//	}
func tlogPrefixExtn(url string) (pkix.Extension, error) {
	extnMarshaled, err := asn1.MarshalWithParams(url, "ia5")
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 64829, 2, 1},
		Critical: false,
		Value:    extnMarshaled,
	}, nil
}
