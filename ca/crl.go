package ca

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
)

type crlImpl struct {
	capb.UnimplementedCRLGeneratorServer
	issuers   map[issuance.IssuerNameID]*issuance.Issuer
	lifetime  time.Duration
	maxLogLen int
	log       blog.Logger
}

func NewCRLImpl(issuers []*issuance.Issuer, lifetime time.Duration, maxLogLen int, logger blog.Logger) (*crlImpl, error) {
	issuersByNameID := make(map[issuance.IssuerNameID]*issuance.Issuer, len(issuers))
	for _, issuer := range issuers {
		issuersByNameID[issuer.Cert.NameID()] = issuer
	}

	if lifetime == 0 {
		logger.Warningf("got zero for crl lifetime; setting to default 9 days")
		lifetime = 9 * 24 * time.Hour
	} else if lifetime >= 10*24*time.Hour {
		return nil, fmt.Errorf("crl lifetime cannot be more than 10 days, got %q", lifetime)
	} else if lifetime <= 0*time.Hour {
		return nil, fmt.Errorf("crl lifetime must be positive, got %q", lifetime)
	}

	return &crlImpl{
		issuers:   issuersByNameID,
		lifetime:  lifetime,
		maxLogLen: maxLogLen,
		log:       logger,
	}, nil
}

func (ci *crlImpl) GenerateCRL(stream capb.CRLGenerator_GenerateCRLServer) error {
	var issuer *issuance.Issuer
	var template *x509.RevocationList
	var shard int64
	rcs := make([]pkix.RevokedCertificate, 0)

	for {
		in, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		switch payload := in.Payload.(type) {
		case *capb.GenerateCRLRequest_Metadata:
			if template != nil {
				return errors.New("got more than one metadata message")
			}

			template, err = ci.metadataToTemplate(payload.Metadata)
			if err != nil {
				return err
			}

			var ok bool
			issuer, ok = ci.issuers[issuance.IssuerNameID(payload.Metadata.IssuerNameID)]
			if !ok {
				return fmt.Errorf("got unrecognized IssuerNameID: %d", payload.Metadata.IssuerNameID)
			}

			shard = payload.Metadata.Shard

		case *capb.GenerateCRLRequest_Entry:
			rc, err := ci.entryToRevokedCertificate(payload.Entry)
			if err != nil {
				return err
			}

			rcs = append(rcs, *rc)

		default:
			return errors.New("got empty or malformed message in input stream")
		}
	}

	if template == nil {
		return errors.New("no crl metadata received")
	}

	// Compute a unique ID for this issuer-number-shard combo, to tie together all
	// the audit log lines related to its issuance.
	logID := blog.LogLineChecksum(fmt.Sprintf("%d", issuer.Cert.NameID()) + template.Number.String() + fmt.Sprintf("%d", shard))
	ci.log.AuditInfof(
		"Signing CRL: logID=[%s] issuer=[%s] number=[%s] shard=[%d] thisUpdate=[%s] nextUpdate=[%s] numEntries=[%d]",
		logID, issuer.Cert.Subject.CommonName, template.Number.String(), template.ThisUpdate, template.NextUpdate, len(rcs),
	)

	builder := strings.Builder{}
	for i := 0; i < len(rcs); i += 1 {
		if builder.Len() == 0 {
			fmt.Fprintf(&builder, "Signing CRL: logID=[%s] entries=[", logID)
		}

		// TODO: Figure out how best to include the reason code here, since it's
		// slow/difficult to extract it from the already-encoded entry extension.
		fmt.Fprintf(&builder, "%x,", rcs[i].SerialNumber.Bytes())

		if builder.Len() != ci.maxLogLen {
			ci.log.AuditInfof("%s", builder)
			builder = strings.Builder{}
		}
	}

	template.RevokedCertificates = rcs
	crlBytes, err := x509.CreateRevocationList(
		rand.Reader,
		template,
		issuer.Cert.Certificate,
		issuer.Signer,
	)
	if err != nil {
		return fmt.Errorf("signing crl: %w", err)
	}

	hash := sha256.Sum256(crlBytes)
	ci.log.AuditInfof(
		"Signing CRL success: logID=[%s] size=[%d] hash=[%d]",
		logID, len(crlBytes), hash[:],
	)

	for i := 0; i < len(crlBytes); i += 1000 {
		j := i + 1000
		if j > len(crlBytes) {
			j = len(crlBytes)
		}
		err = stream.Send(&capb.GenerateCRLResponse{
			Chunk: crlBytes[i:j],
		})
		if err != nil {
			return err
		}
		if i%1000 == 0 {
			ci.log.Debugf("Wrote %d bytes to output stream", i*1000)
		}
	}

	return nil
}

func (ci *crlImpl) metadataToTemplate(meta *capb.CRLMetadata) (*x509.RevocationList, error) {
	if meta.IssuerNameID == 0 || meta.ThisUpdate == 0 {
		return nil, errors.New("got incomplete metadata message")
	}

	// The CRL Number MUST be at most 20 octets, per RFC 5280 Section 5.2.3.
	// A 64-bit (8-byte) integer will never exceed that requirement, but lets
	// us guarantee that the CRL Number is always increasing without having to
	// store or look up additional state.
	number := big.NewInt(meta.ThisUpdate)
	thisUpdate := time.Unix(0, meta.ThisUpdate)

	return &x509.RevocationList{
		Number:     number,
		ThisUpdate: thisUpdate,
		NextUpdate: thisUpdate.Add(-time.Second).Add(ci.lifetime),
	}, nil

}

func (ci *crlImpl) entryToRevokedCertificate(entry *corepb.CRLEntry) (*pkix.RevokedCertificate, error) {
	serial, err := core.StringToSerial(entry.Serial)
	if err != nil {
		return nil, err
	}

	if entry.RevokedAt == 0 {
		return nil, errors.New("got empty or zero revocation timestamp")
	}
	revokedAt := time.Unix(0, entry.RevokedAt)

	// RFC 5280 Section 5.3.1 says "the reason code CRL entry extension SHOULD be
	// absent instead of using the unspecified (0) reasonCode value.", so we make
	// sure we only add this extension if we have a non-zero revocation reason.
	var extensions []pkix.Extension
	if entry.Reason != 0 {
		reasonBytes, err := asn1.Marshal(asn1.Enumerated(entry.Reason))
		if err != nil {
			return nil, err
		}

		extensions = []pkix.Extension{
			// The Reason Code extension, as defined in RFC 5280 Section 5.3.1:
			// https://datatracker.ietf.org/doc/html/rfc5280#section-5.3.1
			{
				Id:    asn1.ObjectIdentifier{2, 5, 29, 21}, // id-ce-reasonCode
				Value: reasonBytes,
			},
		}
	}

	return &pkix.RevokedCertificate{
		SerialNumber:   serial,
		RevocationTime: revokedAt,
		Extensions:     extensions,
	}, nil
}
