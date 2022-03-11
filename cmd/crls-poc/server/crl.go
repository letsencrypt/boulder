package server

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	crlpb "github.com/letsencrypt/boulder/cmd/crls-poc/proto"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
)

type crlImpl struct {
	crlpb.UnimplementedCRLGeneratorServer
	issuers  map[issuance.IssuerNameID]*issuance.Issuer
	lifetime time.Duration
	log      blog.Logger
}

var _ crlpb.CRLGeneratorServer = (*crlImpl)(nil)

func NewCRLImpl(issuers []*issuance.Issuer, lifetime time.Duration, logger blog.Logger) (*crlImpl, error) {
	issuersByNameID := make(map[issuance.IssuerNameID]*issuance.Issuer, len(issuers))
	for _, issuer := range issuers {
		issuersByNameID[issuer.Cert.NameID()] = issuer
	}

	if lifetime >= 10*24*time.Hour {
		return nil, fmt.Errorf("crl lifetime cannot be more than 10 days, got: %s", lifetime)
	}

	return &crlImpl{
		issuers:  issuersByNameID,
		lifetime: lifetime,
		log:      logger,
	}, nil
}

func (ci *crlImpl) GenerateCRL(stream crlpb.CRLGenerator_GenerateCRLServer) error {
	rcs := make([]pkix.RevokedCertificate, 0)
	var number *big.Int
	var thisUpdate time.Time
	var issuer *issuance.Issuer

	for {
		in, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		switch payload := in.Payload.(type) {
		case *crlpb.GenerateCRLRequest_Metadata:
			if number != nil || !thisUpdate.IsZero() || issuer != nil {
				return errors.New("got more than one metadata message")
			}
			if payload.Metadata.IssuerNameID == 0 || payload.Metadata.ThisUpdate == 0 {
				return errors.New("got incomplete metadata message")
			}

			number = big.NewInt(payload.Metadata.ThisUpdate)
			thisUpdate = time.Unix(0, payload.Metadata.ThisUpdate)

			var ok bool
			issuer, ok = ci.issuers[issuance.IssuerNameID(payload.Metadata.IssuerNameID)]
			if !ok {
				return fmt.Errorf("got unrecognized IssuerNameID: %d", payload.Metadata.IssuerNameID)
			}

		case *crlpb.GenerateCRLRequest_Entry:
			serial, err := core.StringToSerial(payload.Entry.Serial)
			if err != nil {
				return err
			}

			if payload.Entry.RevokedAt == 0 {
				return errors.New("got empty or zero revocation timestamp")
			}
			revokedAt := time.Unix(0, payload.Entry.RevokedAt)

			var extensions []pkix.Extension
			if payload.Entry.Reason != 0 {
				reasonBytes, err := asn1.Marshal(asn1.Enumerated(payload.Entry.Reason))
				if err != nil {
					return err
				}

				extensions = []pkix.Extension{
					{
						Id:    asn1.ObjectIdentifier{2, 5, 29, 21},
						Value: reasonBytes,
					},
				}
			}

			rcs = append(rcs, pkix.RevokedCertificate{
				SerialNumber:   serial,
				RevocationTime: revokedAt,
				Extensions:     extensions,
			})

			if len(rcs)%1000 == 0 {
				ci.log.Debugf("Read %d crlEntries from input stream", len(rcs))
			}

		default:
			return errors.New("got empty or malformed message in input stream")
		}
	}

	template := x509.RevocationList{
		RevokedCertificates: rcs,
		Number:              number,
		ThisUpdate:          thisUpdate,
		NextUpdate:          thisUpdate.Add(-time.Second).Add(ci.lifetime),
	}

	crlBytes, err := x509.CreateRevocationList(
		rand.Reader,
		&template,
		issuer.Cert.Certificate,
		issuer.Signer,
	)
	if err != nil {
		return err
	}

	for i := 0; i < len(crlBytes); i += 1000 {
		j := i + 1000
		if j > len(crlBytes) {
			j = len(crlBytes)
		}
		err = stream.Send(&crlpb.GenerateCRLResponse{
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
