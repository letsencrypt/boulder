package sa

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/db"
	berrors "github.com/letsencrypt/boulder/errors"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

var errIncompleteRequest = errors.New("Incomplete gRPC request message")

// AddSerial writes a record of a serial number generation to the DB.
func (ssa *SQLStorageAuthority) AddSerial(ctx context.Context, req *sapb.AddSerialRequest) (*corepb.Empty, error) {
	if core.IsAnyNilOrZero(req.Created, req.Expires, req.Serial, req.RegID) {
		return nil, errIncompleteRequest
	}
	err := ssa.dbMap.WithContext(ctx).Insert(&recordedSerialModel{
		Serial:         req.Serial,
		RegistrationID: req.RegID,
		Created:        time.Unix(0, req.Created),
		Expires:        time.Unix(0, req.Expires),
	})
	if err != nil {
		return nil, err
	}
	return &corepb.Empty{}, nil
}

// AddPrecertificate writes a record of a precertificate generation to the DB.
// Note: this is not idempotent: it does not protect against inserting the same
// certificate multiple times. Calling code needs to first insert the cert's
// serial into the Serials table to ensure uniqueness.
func (ssa *SQLStorageAuthority) AddPrecertificate(ctx context.Context, req *sapb.AddCertificateRequest) (*corepb.Empty, error) {
	if core.IsAnyNilOrZero(req.Der, req.Issued, req.RegID, req.IssuerID) {
		return nil, errIncompleteRequest
	}
	parsed, err := x509.ParseCertificate(req.Der)
	if err != nil {
		return nil, err
	}
	issued := time.Unix(0, req.Issued)
	serialHex := core.SerialToString(parsed.SerialNumber)

	preCertModel := &precertificateModel{
		Serial:         serialHex,
		RegistrationID: req.RegID,
		DER:            req.Der,
		Issued:         issued,
		Expires:        parsed.NotAfter,
	}

	_, overallError := db.WithTransaction(ctx, ssa.dbMap, func(txWithCtx db.Executor) (interface{}, error) {
		if err := txWithCtx.Insert(preCertModel); err != nil {
			return nil, err
		}

		certStatusFields := certStatusFields()
		fieldNames := []string{}
		for _, fieldName := range certStatusFields {
			fieldNames = append(fieldNames, ":"+fieldName)
		}
		args := map[string]interface{}{
			"serial":                serialHex,
			"status":                string(core.OCSPStatusGood),
			"ocspLastUpdated":       ssa.clk.Now(),
			"revokedDate":           time.Time{},
			"revokedReason":         0,
			"lastExpirationNagSent": time.Time{},
			"ocspResponse":          req.Ocsp,
			"notAfter":              parsed.NotAfter,
			"isExpired":             false,
			"issuerID":              req.IssuerID,
		}
		if len(args) > len(certStatusFields) {
			return nil, fmt.Errorf("too many arguments inserting row into certificateStatus")
		}

		_, err = txWithCtx.Exec(fmt.Sprintf(
			"INSERT INTO certificateStatus (%s) VALUES (%s)",
			strings.Join(certStatusFields, ","),
			strings.Join(fieldNames, ","),
		), args)
		if err != nil {
			return nil, err
		}

		// NOTE(@cpu): When we collect up names to check if an FQDN set exists (e.g.
		// that it is a renewal) we use just the DNSNames from the certificate and
		// ignore the Subject Common Name (if any). This is a safe assumption because
		// if a certificate we issued were to have a Subj. CN not present as a SAN it
		// would be a misissuance and miscalculating whether the cert is a renewal or
		// not for the purpose of rate limiting is the least of our troubles.
		isRenewal, err := ssa.checkFQDNSetExists(
			txWithCtx.SelectOne,
			parsed.DNSNames)
		if err != nil {
			return nil, err
		}
		if err := addIssuedNames(txWithCtx, parsed, isRenewal); err != nil {
			return nil, err
		}
		if err := addKeyHash(txWithCtx, parsed); err != nil {
			return nil, err
		}

		return nil, nil
	})
	if overallError != nil {
		return nil, overallError
	}
	return &corepb.Empty{}, nil
}

// GetPrecertificate takes a serial number and returns the corresponding
// precertificate, or error if it does not exist.
func (ssa *SQLStorageAuthority) GetPrecertificate(ctx context.Context, reqSerial *sapb.Serial) (*corepb.Certificate, error) {
	if !core.ValidSerial(reqSerial.Serial) {
		return nil,
			fmt.Errorf("Invalid precertificate serial %q", reqSerial.Serial)
	}
	cert, err := SelectPrecertificate(ssa.dbMap.WithContext(ctx), reqSerial.Serial)
	if err != nil {
		if db.IsNoRows(err) {
			return nil, berrors.NotFoundError(
				"precertificate with serial %q not found",
				reqSerial.Serial)
		}
		return nil, err
	}

	return bgrpc.CertToPB(cert), nil
}
