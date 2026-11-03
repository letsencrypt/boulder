package mtx509

import (
	"bytes"
	"crypto"
	"crypto/mldsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/core/reloid"
	"github.com/letsencrypt/boulder/trees/cosigned"
	"github.com/letsencrypt/boulder/trees/entry"
	"github.com/letsencrypt/boulder/trees/issuancelog"
	"github.com/letsencrypt/boulder/trees/proof"
	"github.com/letsencrypt/boulder/trees/subtree"
)

// MTCAID returns the trust anchor ID from an issuer certificate's Subject or an
// MTC certificate's Issuer. It returns an error if no trust anchor ID is found.
func MTCAID(rdn pkix.Name) (*reloid.RelativeOID, error) {
	idRDNATrustAnchorID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 25, 3}
	for _, attribute := range rdn.Names {
		if attribute.Type.Equal(idRDNATrustAnchorID) {
			caID, ok := attribute.Value.(asn1.RawValue)
			if !ok {
				return nil, fmt.Errorf("invalid trust anchor attribute type %T", attribute.Value)
			}
			if len(caID.FullBytes) == 0 {
				return nil, fmt.Errorf("empty mtcaID")
			}
			if caID.FullBytes[0] != 0x0d { // Universal Primitive Relative-OID (13)
				return nil, fmt.Errorf("invalid mtcaID asn1 tag byte %x", caID.FullBytes[0])
			}
			ret, err := reloid.FromBytes(caID.Bytes)
			if err != nil {
				return nil, fmt.Errorf("invalid mtcaID relative OID: %w", err)
			}
			return ret, nil
		}
	}
	return nil, fmt.Errorf("DistinguishedName %q did not contain trust anchor ID OID %q",
		rdn, idRDNATrustAnchorID)
}

// VerifyStandalone verifies the given certificate as a standalone MTC against solely
// the given issuer.
//
// TODO(#9085): this should accept a list of acceptable CA cosigners and a list
// of acceptable mirror cosigners, and enforce the minimum policy we want across
// root programs.
func VerifyStandalone(certDER []byte, issuer *x509.Certificate) error {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("x509.ParseCertificate: %s", err)
	}

	if !bytes.Equal(cert.RawIssuer, issuer.RawSubject) {
		return fmt.Errorf("end-entity issuer %q does not match issuer's subject %q",
			cert.Issuer, issuer.Subject)
	}

	mtcaID, err := MTCAID(cert.Issuer)
	if err != nil {
		return err
	}

	caPubkey, ok := issuer.PublicKey.(*mldsa.PublicKey)
	if !ok {
		return fmt.Errorf("unsupported pubkey type %T", issuer.PublicKey)
	}

	if !cert.SerialNumber.IsUint64() {
		return fmt.Errorf("serial number %x is not representable as a uint64", cert.SerialNumber)
	}
	logNumber, entryIndex, err := core.DecodeMTCSerial(cert.SerialNumber.Uint64())
	if err != nil {
		return err
	}

	if !bytes.Equal(cert.RawSignatureAlgorithm, proof.SigAlgEncoded()) {
		return fmt.Errorf("cert.RawSignatureAlgorithm: %x, want %x", cert.RawSignatureAlgorithm, proof.SigAlgEncoded())
	}
	mtcProof, err := proof.UnmarshalMTCProof(cert.Signature)
	if err != nil {
		return fmt.Errorf("unmarshaling MTCProof: %s", err)
	}

	if len(mtcProof.Signatures) == 0 {
		return fmt.Errorf("no signatures in MTCProof when verifying standalone MTC")
	}

	if len(mtcProof.Extensions) > 0 {
		return fmt.Errorf("MTCProof extensions are not supported")
	}

	// Transform into an MTCLogEntry containing a TBSCertificateLogEntry.
	mtcle, err := entry.FromX509(certDER, crypto.SHA256)
	if err != nil {
		return err
	}

	mtcleMarshaled, err := mtcle.Marshal()
	if err != nil {
		return err
	}

	expectedSubtreeHash, err := subtree.HashFromProof(
		tlog.RecordHash(mtcleMarshaled),
		mtcProof.InclusionProof,
		entryIndex,
		mtcProof.Start,
		mtcProof.End,
	)
	if err != nil {
		return fmt.Errorf("evaluating subtree inclusion proof: %s", err)
	}

	logID, err := issuancelog.Config{
		CAID:      mtcaID.String(),
		LogNumber: logNumber,
	}.Load()
	if err != nil {
		return err
	}

	cosignedMessage, err := (&cosigned.Message{
		CosignerName: logID.CACosignerName(),
		Timestamp:    0,
		LogOrigin:    logID.Origin(),
		Start:        mtcProof.Start,
		End:          mtcProof.End,
		SubtreeHash:  expectedSubtreeHash,
	}).Marshal()
	if err != nil {
		return fmt.Errorf("marshaling CosignedMessage: %s", err)
	}

	for _, sig := range mtcProof.Signatures {
		// Ignore all signatures except the one for the CA we are verifying against.
		// TODO(#9085) also check mirror signatures for mirrors we recognize.
		if !bytes.Equal(sig.CosignerID, mtcaID.Bytes()) {
			continue
		}
		err := mldsa.Verify(caPubkey, cosignedMessage, sig.Signature, nil)
		if err != nil {
			return err
		}
		return nil
	}

	return fmt.Errorf("of %d signatures, none were by CA %q", len(mtcProof.Signatures), logID.CAID())
}
