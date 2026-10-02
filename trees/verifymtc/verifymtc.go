package verifymtc

import (
	"bytes"
	"crypto"
	"crypto/mldsa"
	"crypto/x509"
	"fmt"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/trees/cosigned"
	"github.com/letsencrypt/boulder/trees/entry"
	"github.com/letsencrypt/boulder/trees/issuancelog"
	"github.com/letsencrypt/boulder/trees/proof"
	"github.com/letsencrypt/boulder/trees/subtree"
)

// Standalone verifies the given certificate as a standalone MTC against solely the given issuer.
//
// TODO: this should accept a list of acceptable CA cosigners and a list of acceptable mirror cosigners,
// and enforce the minimum policy we want across root programs.
func Standalone(certDER []byte, issuer *x509.Certificate) error {
	mtcaID, err := issuancelog.MTCAID(issuer)
	if err != nil {
		return err
	}

	caPubkey, ok := issuer.PublicKey.(*mldsa.PublicKey)
	if !ok {
		return fmt.Errorf("unsupported pubkey type %T", issuer.PublicKey)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("x509.ParseCertificate: %s", err)
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
		return fmt.Errorf("verifymtc.Standalone: received landmark-relative certificate (no signatures in MTCProof)")
	}

	if len(mtcProof.Extensions) > 0 {
		return fmt.Errorf("verifymtc.Standalone: unrecognized extensions in MTCProof")
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

	logID := issuancelog.ID{
		CAID:      mtcaID,
		LogNumber: logNumber,
	}

	cosignedMessage, err := (&cosigned.Message{
		CosignerName: logID.CACosignerName(),
		Timestamp:    0,
		LogOrigin:    logID.Origin(),
		Start:        uint64(mtcProof.Start), //nolint: gosec // G115: these are guaranteed < 1<<48
		End:          uint64(mtcProof.End),   //nolint: gosec // G115: these are guaranteed < 1<<48
		SubtreeHash:  expectedSubtreeHash,
	}).Marshal()
	if err != nil {
		return fmt.Errorf("marshaling CosignedMessage: %s", err)
	}

	for _, sig := range mtcProof.Signatures {
		// TODO: this assumes CosignerID is the ASCII representation, which is wrong.
		// Fix it once RELATIVE-OID encoding is implemented.
		if string(sig.CosignerID) != mtcaID {
			continue
		}
		err := mldsa.Verify(caPubkey, cosignedMessage, sig.Signature, nil)
		if err != nil {
			return err
		}
		return nil
	}

	return fmt.Errorf("of %d signatures, none were by CA %q", len(mtcProof.Signatures), logID.CAID)
}
