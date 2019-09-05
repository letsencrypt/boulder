package sa

import (
	"crypto/x509"
	"time"

	"golang.org/x/net/context"

	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

// AddSerail writes a
func (ssa *SQLStorageAuthority) AddSerial(ctx context.Context, req *sapb.AddSerialRequest) (*corepb.Empty, error) {
	ssa.log.Infof("addserial %s", *req.Serial)
	created := time.Unix(0, *req.Created)
	expires := time.Unix(0, *req.Expires)
	err := ssa.dbMap.WithContext(ctx).Insert(&recordedSerialModel{
		Serial:         *req.Serial,
		RegistrationID: *req.RegID,
		Created:        created,
		Expires:        expires,
	})
	if err != nil {
		return nil, err
	}
	return &corepb.Empty{}, nil
}

func (ssa *SQLStorageAuthority) AddPrecertificate(ctx context.Context, req *sapb.AddCertificateRequest) (*corepb.Empty, error) {
	parsed, err := x509.ParseCertificate(req.Der)
	if err != nil {
		return nil, err
	}
	issued := time.Unix(0, *req.Issued)
	serialHex := core.SerialToString(parsed.SerialNumber)
	ssa.log.Infof("addprecert %s", serialHex)
	err = ssa.dbMap.WithContext(ctx).Insert(&precertificateModel{
		Serial:         serialHex,
		RegistrationID: *req.RegID,
		DER:            req.Der,
		Issued:         issued,
		Expires:        parsed.NotAfter,
	})
	if err != nil {
		return nil, err
	}

	err = ssa.dbMap.WithContext(ctx).Insert(&certStatusModel{
		Status:          core.OCSPStatus("good"),
		OCSPLastUpdated: ssa.clk.Now(),
		OCSPResponse:    req.Ocsp,
		Serial:          serialHex,
		RevokedDate:     time.Time{},
		RevokedReason:   0,
		NotAfter:        parsed.NotAfter,
	})
	if err != nil {
		return nil, err
	}
	return &corepb.Empty{}, nil
}
