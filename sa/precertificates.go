package sa

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/db"
	berrors "github.com/letsencrypt/boulder/errors"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

// AddSerial writes a record of a serial number generation to the DB.
func (ssa *SQLStorageAuthority) AddSerial(ctx context.Context, req *sapb.AddSerialRequest) (*emptypb.Empty, error) {
	if req.Serial == "" || req.RegID == 0 || req.Created == 0 || req.Expires == 0 {
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
	return &emptypb.Empty{}, nil
}

// AddPrecertificate writes a record of a precertificate generation to the DB.
// Note: this is not idempotent: it does not protect against inserting the same
// certificate multiple times. Calling code needs to first insert the cert's
// serial into the Serials table to ensure uniqueness.
func (ssa *SQLStorageAuthority) AddPrecertificate(ctx context.Context, req *sapb.AddCertificateRequest) (*emptypb.Empty, error) {
	if len(req.Der) == 0 || req.RegID == 0 || req.Issued == 0 || req.IssuerID == 0 {
		return nil, errIncompleteRequest
	}
	parsed, err := x509.ParseCertificate(req.Der)
	if err != nil {
		return nil, err
	}
	serialHex := core.SerialToString(parsed.SerialNumber)

	preCertModel := &precertificateModel{
		Serial:         serialHex,
		RegistrationID: req.RegID,
		DER:            req.Der,
		Issued:         time.Unix(0, req.Issued),
		Expires:        parsed.NotAfter,
	}

	_, overallError := db.WithTransaction(ctx, ssa.dbMap, func(txWithCtx db.Executor) (interface{}, error) {
		// Select to see if precert exists
		var row struct {
			Count int64
		}
		if err := txWithCtx.SelectOne(&row, "SELECT count(1) as count FROM precertificates WHERE serial=?", serialHex); err != nil {
			return nil, err
		}
		if row.Count > 0 {
			return nil, berrors.DuplicateError("cannot add a duplicate cert")
		}
		if err := txWithCtx.Insert(preCertModel); err != nil {
			return nil, err
		}

		err = ssa.dbMap.WithContext(ctx).Insert(
			&core.CertificateStatus{
				Serial:                serialHex,
				Status:                core.OCSPStatusGood,
				OCSPLastUpdated:       ssa.clk.Now(),
				RevokedDate:           time.Time{},
				RevokedReason:         0,
				LastExpirationNagSent: time.Time{},
				OCSPResponse:          req.Ocsp,
				NotAfter:              parsed.NotAfter,
				IsExpired:             false,
				IssuerID:              req.IssuerID,
			})

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
	return &emptypb.Empty{}, nil
}

// GetPrecertificate takes a serial number and returns the corresponding
// precertificate, or error if it does not exist.
func (ssa *SQLStorageAuthority) GetPrecertificate(ctx context.Context, req *sapb.Serial) (*corepb.Certificate, error) {
	if req == nil || req.Serial == "" {
		return nil, errIncompleteRequest
	}
	if !core.ValidSerial(req.Serial) {
		return nil, fmt.Errorf("Invalid precertificate serial %q", req.Serial)
	}
	cert, err := SelectPrecertificate(ssa.dbMap.WithContext(ctx), req.Serial)
	if err != nil {
		if db.IsNoRows(err) {
			return nil, berrors.NotFoundError(
				"precertificate with serial %q not found",
				req.Serial)
		}
		return nil, err
	}

	return bgrpc.CertToPB(cert), nil
}
