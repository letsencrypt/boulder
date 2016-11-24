package rpc

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/context"
	jose "gopkg.in/square/go-jose.v1"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/revocation"
	vaPB "github.com/letsencrypt/boulder/va/proto"
)

// This file defines RPC wrappers around the ${ROLE}Impl classes,
// where ROLE covers:
//  * RegistrationAuthority
//  * ValidationAuthority
//  * CertificateAuthority
//  * StorageAuthority
//
// For each one of these, the are ${ROLE}Client and ${ROLE}Server
// types.  ${ROLE}Server is to be run on the server side, as a more
// or less stand-alone component.  ${ROLE}Client is loaded by the
// code making use of the functionality.
//
// The WebFrontEnd role does not expose any functionality over RPC,
// so it doesn't need wrappers.

// These strings are used by the RPC layer to identify function points.
const (
	MethodNewRegistration                   = "NewRegistration"                   // RA, SA
	MethodNewAuthorization                  = "NewAuthorization"                  // RA
	MethodNewCertificate                    = "NewCertificate"                    // RA
	MethodUpdateRegistration                = "UpdateRegistration"                // RA, SA
	MethodUpdateAuthorization               = "UpdateAuthorization"               // RA
	MethodRevokeCertificateWithReg          = "RevokeCertificateWithReg"          // RA
	MethodAdministrativelyRevokeCertificate = "AdministrativelyRevokeCertificate" // RA
	MethodPerformValidation                 = "PerformValidation"                 // VA
	MethodIsSafeDomain                      = "IsSafeDomain"                      // VA
	MethodIssueCertificate                  = "IssueCertificate"                  // CA
	MethodGenerateOCSP                      = "GenerateOCSP"                      // CA
	MethodGetRegistration                   = "GetRegistration"                   // SA
	MethodGetRegistrationByKey              = "GetRegistrationByKey"              // RA, SA
	MethodGetAuthorization                  = "GetAuthorization"                  // SA
	MethodGetValidAuthorizations            = "GetValidAuthorizations"            // SA
	MethodGetCertificate                    = "GetCertificate"                    // SA
	MethodGetCertificateStatus              = "GetCertificateStatus"              // SA
	MethodMarkCertificateRevoked            = "MarkCertificateRevoked"            // SA
	MethodNewPendingAuthorization           = "NewPendingAuthorization"           // SA
	MethodUpdatePendingAuthorization        = "UpdatePendingAuthorization"        // SA
	MethodFinalizeAuthorization             = "FinalizeAuthorization"             // SA
	MethodAddCertificate                    = "AddCertificate"                    // SA
	MethodCountCertificatesRange            = "CountCertificatesRange"            // SA
	MethodCountCertificatesByNames          = "CountCertificatesByNames"          // SA
	MethodCountRegistrationsByIP            = "CountRegistrationsByIP"            // SA
	MethodCountPendingAuthorizations        = "CountPendingAuthorizations"        // SA
	MethodGetSCTReceipt                     = "GetSCTReceipt"                     // SA
	MethodAddSCTReceipt                     = "AddSCTReceipt"                     // SA
	MethodSubmitToCT                        = "SubmitToCT"                        // Pub
	MethodSubmitToSingleCT                  = "SubmitToSingleCT"                  // Pub
	MethodRevokeAuthorizationsByDomain      = "RevokeAuthorizationsByDomain"      // SA
	MethodCountFQDNSets                     = "CountFQDNSets"                     // SA
	MethodFQDNSetExists                     = "FQDNSetExists"                     // SA
	MethodDeactivateAuthorizationSA         = "DeactivateAuthorizationSA"         // SA
	MethodDeactivateAuthorization           = "DeactivateAuthorization"           // RA
	MethodDeactivateRegistrationSA          = "DeactivateRegistrationSA"          // SA
	MethodDeactivateRegistration            = "DeactivateRegistration"            // RA
)

// Request structs
type registrationRequest struct {
	Reg core.Registration
}

type getRegistrationRequest struct {
	ID int64
}

type updateRegistrationRequest struct {
	Base, Update core.Registration
}

type authorizationRequest struct {
	Authz core.Authorization
	RegID int64
}

type updateAuthorizationRequest struct {
	Authz    core.Authorization
	Index    int
	Response core.Challenge
}

type latestValidAuthorizationRequest struct {
	RegID      int64
	Identifier core.AcmeIdentifier
}

type getValidAuthorizationsRequest struct {
	RegID int64
	Names []string
	Now   time.Time
}

type certificateRequest struct {
	Req   core.CertificateRequest
	RegID int64
}

type issueCertificateRequest struct {
	Bytes []byte
	RegID int64
}

type addCertificateRequest struct {
	Bytes []byte
	RegID int64
}

type revokeCertificateRequest struct {
	Serial     string
	ReasonCode revocation.Reason
}

type markCertificateRevokedRequest struct {
	Serial     string
	ReasonCode revocation.Reason
}

type caaRequest struct {
	Ident core.AcmeIdentifier
}

type validationRequest struct {
	Authz core.Authorization
	Index int
}

type performValidationRequest struct {
	Domain    string
	Challenge core.Challenge
	// TODO(#1626): remove
	Authz core.Authorization
}

type deactivateRegistrationRequest struct {
	ID int64
}

type performValidationResponse struct {
	Records []core.ValidationRecord
	Problem *probs.ProblemDetails
}

type countRequest struct {
	Start time.Time
	End   time.Time
}

type countCertificatesByNamesRequest struct {
	Names    []string
	Earliest time.Time
	Latest   time.Time
}

type countRegistrationsByIPRequest struct {
	IP       net.IP
	Earliest time.Time
	Latest   time.Time
}

type countPendingAuthorizationsRequest struct {
	RegID int64
}

type revokeAuthsRequest struct {
	Ident core.AcmeIdentifier
}

type countFQDNsRequest struct {
	Window time.Duration
	Names  []string
}

type fqdnSetExistsRequest struct {
	Names []string
}

// Response structs
type caaResponse struct {
	Present bool
	Valid   bool
	Err     error
}

type revokeAuthsResponse struct {
	FinalRevoked   int64
	PendingRevoked int64
}

type countFQDNSetsResponse struct {
	Count int64
}

type fqdnSetExistsResponse struct {
	Exists bool
}

func improperMessage(method string, err error, obj interface{}) {
	log := blog.Get()
	log.AuditErr(fmt.Sprintf("Improper message. method: %s err: %s data: %+v", method, err, obj))
}
func errorCondition(method string, err error, obj interface{}) {
	log := blog.Get()
	log.AuditErr(fmt.Sprintf("RPC internal error condition. method: %s err: %s data: %+v", method, err, obj))
}

// NewRegistrationAuthorityServer constructs an RPC server
func NewRegistrationAuthorityServer(rpc Server, impl core.RegistrationAuthority, log blog.Logger) error {
	rpc.Handle(MethodNewRegistration, func(ctx context.Context, req []byte) (response []byte, err error) {
		var rr registrationRequest
		if err = json.Unmarshal(req, &rr); err != nil {
			improperMessage(MethodNewRegistration, err, req)
			return
		}

		reg, err := impl.NewRegistration(ctx, rr.Reg)
		if err != nil {
			return
		}

		response, err = json.Marshal(reg)
		if err != nil {
			errorCondition(MethodNewRegistration, err, req)
			return
		}
		return
	})

	rpc.Handle(MethodNewAuthorization, func(ctx context.Context, req []byte) (response []byte, err error) {
		var ar authorizationRequest
		if err = json.Unmarshal(req, &ar); err != nil {
			improperMessage(MethodNewAuthorization, err, req)
			return
		}

		authz, err := impl.NewAuthorization(ctx, ar.Authz, ar.RegID)
		if err != nil {
			return
		}

		response, err = json.Marshal(authz)
		if err != nil {
			errorCondition(MethodNewAuthorization, err, req)
			return
		}
		return
	})

	rpc.Handle(MethodNewCertificate, func(ctx context.Context, req []byte) (response []byte, err error) {
		var cr certificateRequest
		if err = json.Unmarshal(req, &cr); err != nil {
			improperMessage(MethodNewCertificate, err, req)
			return
		}

		cert, err := impl.NewCertificate(ctx, cr.Req, cr.RegID)
		if err != nil {
			return
		}

		response, err = json.Marshal(cert)
		if err != nil {
			errorCondition(MethodNewCertificate, err, req)
			return
		}
		return
	})

	rpc.Handle(MethodUpdateRegistration, func(ctx context.Context, req []byte) (response []byte, err error) {
		var urReq updateRegistrationRequest
		err = json.Unmarshal(req, &urReq)
		if err != nil {
			improperMessage(MethodUpdateRegistration, err, req)
			return
		}

		reg, err := impl.UpdateRegistration(ctx, urReq.Base, urReq.Update)
		if err != nil {
			return
		}

		response, err = json.Marshal(reg)
		if err != nil {
			errorCondition(MethodUpdateRegistration, err, req)
			return
		}
		return
	})

	rpc.Handle(MethodUpdateAuthorization, func(ctx context.Context, req []byte) (response []byte, err error) {
		var uaReq updateAuthorizationRequest
		err = json.Unmarshal(req, &uaReq)
		if err != nil {
			improperMessage(MethodUpdateAuthorization, err, req)
			return
		}

		newAuthz, err := impl.UpdateAuthorization(ctx, uaReq.Authz, uaReq.Index, uaReq.Response)
		if err != nil {
			return
		}

		response, err = json.Marshal(newAuthz)
		if err != nil {
			errorCondition(MethodUpdateAuthorization, err, req)
			return
		}
		return
	})

	rpc.Handle(MethodRevokeCertificateWithReg, func(ctx context.Context, req []byte) (response []byte, err error) {
		var revReq struct {
			Cert   []byte
			Reason revocation.Reason
			RegID  int64
		}
		if err = json.Unmarshal(req, &revReq); err != nil {
			improperMessage(MethodRevokeCertificateWithReg, err, req)
			return
		}
		cert, err := x509.ParseCertificate(revReq.Cert)
		if err != nil {
			return
		}

		err = impl.RevokeCertificateWithReg(ctx, *cert, revReq.Reason, revReq.RegID)
		return
	})

	rpc.Handle(MethodAdministrativelyRevokeCertificate, func(ctx context.Context, req []byte) (response []byte, err error) {
		var revReq struct {
			Cert   []byte
			Reason revocation.Reason
			User   string
		}
		if err = json.Unmarshal(req, &revReq); err != nil {
			improperMessage(MethodAdministrativelyRevokeCertificate, err, req)
			return
		}
		cert, err := x509.ParseCertificate(revReq.Cert)
		if err != nil {
			return
		}

		err = impl.AdministrativelyRevokeCertificate(ctx, *cert, revReq.Reason, revReq.User)
		return
	})

	rpc.Handle(MethodDeactivateAuthorization, func(ctx context.Context, req []byte) (response []byte, err error) {
		var authz core.Authorization
		err = json.Unmarshal(req, &authz)
		if err != nil {
			errorCondition(MethodDeactivateAuthorization, err, req)
			return
		}
		err = impl.DeactivateAuthorization(ctx, authz)
		return
	})

	rpc.Handle(MethodDeactivateRegistration, func(ctx context.Context, req []byte) (response []byte, err error) {
		var reg core.Registration
		err = json.Unmarshal(req, &reg)
		if err != nil {
			errorCondition(MethodDeactivateRegistration, err, req)
			return
		}
		err = impl.DeactivateRegistration(ctx, reg)
		return
	})

	return nil
}

// RegistrationAuthorityClient represents an RA RPC client
type RegistrationAuthorityClient struct {
	rpc Client
}

// NewRegistrationAuthorityClient constructs an RPC client
func NewRegistrationAuthorityClient(clientName string, amqpConf *cmd.AMQPConfig, stats metrics.Scope) (*RegistrationAuthorityClient, error) {
	client, err := NewAmqpRPCClient(clientName+"->RA", amqpConf, amqpConf.RA, stats)
	return &RegistrationAuthorityClient{rpc: client}, err
}

// NewRegistration sends a New Registration request
func (rac RegistrationAuthorityClient) NewRegistration(ctx context.Context, reg core.Registration) (newReg core.Registration, err error) {
	data, err := json.Marshal(registrationRequest{reg})
	if err != nil {
		return
	}

	newRegData, err := rac.rpc.DispatchSync(MethodNewRegistration, data)
	if err != nil {
		return
	}

	err = json.Unmarshal(newRegData, &newReg)
	return
}

// NewAuthorization sends a New Authorization request
func (rac RegistrationAuthorityClient) NewAuthorization(ctx context.Context, authz core.Authorization, regID int64) (newAuthz core.Authorization, err error) {
	data, err := json.Marshal(authorizationRequest{authz, regID})
	if err != nil {
		return
	}

	newAuthzData, err := rac.rpc.DispatchSync(MethodNewAuthorization, data)
	if err != nil {
		return
	}

	err = json.Unmarshal(newAuthzData, &newAuthz)
	return
}

// NewCertificate sends a New Certificate request
func (rac RegistrationAuthorityClient) NewCertificate(ctx context.Context, cr core.CertificateRequest, regID int64) (cert core.Certificate, err error) {
	data, err := json.Marshal(certificateRequest{cr, regID})
	if err != nil {
		return
	}

	certData, err := rac.rpc.DispatchSync(MethodNewCertificate, data)
	if err != nil {
		return
	}

	err = json.Unmarshal(certData, &cert)
	return
}

// UpdateRegistration sends an Update Registration request
func (rac RegistrationAuthorityClient) UpdateRegistration(ctx context.Context, base core.Registration, update core.Registration) (newReg core.Registration, err error) {
	var urReq updateRegistrationRequest
	urReq.Base = base
	urReq.Update = update

	data, err := json.Marshal(urReq)
	if err != nil {
		return
	}

	newRegData, err := rac.rpc.DispatchSync(MethodUpdateRegistration, data)
	if err != nil {
		return
	}

	err = json.Unmarshal(newRegData, &newReg)
	return
}

// UpdateAuthorization sends an Update Authorization request
func (rac RegistrationAuthorityClient) UpdateAuthorization(ctx context.Context, authz core.Authorization, index int, response core.Challenge) (newAuthz core.Authorization, err error) {
	var uaReq updateAuthorizationRequest
	uaReq.Authz = authz
	uaReq.Index = index
	uaReq.Response = response

	data, err := json.Marshal(uaReq)
	if err != nil {
		return
	}

	newAuthzData, err := rac.rpc.DispatchSync(MethodUpdateAuthorization, data)
	if err != nil {
		return
	}

	err = json.Unmarshal(newAuthzData, &newAuthz)
	return
}

// RevokeCertificateWithReg sends a Revoke Certificate request initiated by the
// WFE
func (rac RegistrationAuthorityClient) RevokeCertificateWithReg(ctx context.Context, cert x509.Certificate, reason revocation.Reason, regID int64) (err error) {
	var revReq struct {
		Cert   []byte
		Reason revocation.Reason
		RegID  int64
	}
	revReq.Cert = cert.Raw
	revReq.Reason = reason
	revReq.RegID = regID
	data, err := json.Marshal(revReq)
	if err != nil {
		return
	}
	_, err = rac.rpc.DispatchSync(MethodRevokeCertificateWithReg, data)
	return
}

// AdministrativelyRevokeCertificate sends a Revoke Certificate request initiated by the
// admin-revoker
func (rac RegistrationAuthorityClient) AdministrativelyRevokeCertificate(ctx context.Context, cert x509.Certificate, reason revocation.Reason, user string) (err error) {
	var revReq struct {
		Cert   []byte
		Reason revocation.Reason
		User   string
	}
	revReq.Cert = cert.Raw
	revReq.Reason = reason
	revReq.User = user
	data, err := json.Marshal(revReq)
	if err != nil {
		return
	}
	_, err = rac.rpc.DispatchSync(MethodAdministrativelyRevokeCertificate, data)
	return
}

// DeactivateAuthorization deactivates a currently valid or pending authorization
func (rac RegistrationAuthorityClient) DeactivateAuthorization(ctx context.Context, authz core.Authorization) error {
	data, err := json.Marshal(authz)
	if err != nil {
		return err
	}
	_, err = rac.rpc.DispatchSync(MethodDeactivateAuthorization, data)
	return err
}

// DeactivateRegistration deactivates a currently valid registration
func (rac RegistrationAuthorityClient) DeactivateRegistration(ctx context.Context, reg core.Registration) error {
	data, err := json.Marshal(reg)
	if err != nil {
		return err
	}
	_, err = rac.rpc.DispatchSync(MethodDeactivateRegistration, data)
	return err
}

// NewValidationAuthorityServer constructs an RPC server
//
// ValidationAuthorityClient / Server
func NewValidationAuthorityServer(rpc Server, impl core.ValidationAuthority) (err error) {
	rpc.Handle(MethodPerformValidation, func(ctx context.Context, req []byte) (response []byte, err error) {
		var vaReq performValidationRequest
		if err = json.Unmarshal(req, &vaReq); err != nil {
			improperMessage(MethodPerformValidation, err, req)
			return nil, err
		}

		records, err := impl.PerformValidation(ctx, vaReq.Domain, vaReq.Challenge, vaReq.Authz)
		// If the type of error was a ProblemDetails, we need to return
		// both that and the records to the caller (so it can update
		// the challenge / authz in the SA with the failing records).
		// The least error-prone way of doing this is to send a struct
		// as the RPC response and return a nil error on the RPC layer,
		// then unpack that into (records, error) to the caller.
		probs, ok := err.(*probs.ProblemDetails)
		if !ok && err != nil {
			return nil, err
		}
		return json.Marshal(performValidationResponse{records, probs})
	})

	rpc.Handle(MethodIsSafeDomain, func(ctx context.Context, req []byte) ([]byte, error) {
		r := &vaPB.IsSafeDomainRequest{}
		if err := json.Unmarshal(req, r); err != nil {
			improperMessage(MethodIsSafeDomain, err, req)
			return nil, err
		}
		resp, err := impl.IsSafeDomain(ctx, r)
		if err != nil {
			return nil, err
		}
		return json.Marshal(resp)
	})

	return nil
}

// ValidationAuthorityClient represents an RPC client for the VA
type ValidationAuthorityClient struct {
	rpc Client
}

// NewValidationAuthorityClient constructs an RPC client
func NewValidationAuthorityClient(clientName string, amqpConf *cmd.AMQPConfig, stats metrics.Scope) (*ValidationAuthorityClient, error) {
	client, err := NewAmqpRPCClient(clientName+"->VA", amqpConf, amqpConf.VA, stats)
	return &ValidationAuthorityClient{rpc: client}, err
}

// PerformValidation has the VA revalidate the specified challenge and returns
// the updated Challenge object.
func (vac ValidationAuthorityClient) PerformValidation(ctx context.Context, domain string, challenge core.Challenge, authz core.Authorization) ([]core.ValidationRecord, error) {
	vaReq := performValidationRequest{
		Domain:    domain,
		Challenge: challenge,
		Authz:     authz,
	}
	data, err := json.Marshal(vaReq)
	if err != nil {
		return nil, err
	}
	jsonResp, err := vac.rpc.DispatchSync(MethodPerformValidation, data)
	if err != nil {
		return nil, err
	}
	var resp performValidationResponse
	err = json.Unmarshal(jsonResp, &resp)
	if err != nil {
		return nil, err
	}
	return resp.Records, resp.Problem
}

// IsSafeDomain returns true if the domain given is determined to be safe by an
// third-party safe browsing API.
func (vac ValidationAuthorityClient) IsSafeDomain(ctx context.Context, req *vaPB.IsSafeDomainRequest) (resp *vaPB.IsDomainSafe, err error) {
	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	jsonResp, err := vac.rpc.DispatchSync(MethodIsSafeDomain, data)
	if err != nil {
		return nil, err
	}
	resp = new(vaPB.IsDomainSafe)
	err = json.Unmarshal(jsonResp, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// NewPublisherServer creates a new server that wraps a CT publisher
func NewPublisherServer(rpc Server, impl core.Publisher) (err error) {
	rpc.Handle(MethodSubmitToCT, func(ctx context.Context, req []byte) (response []byte, err error) {
		err = impl.SubmitToCT(ctx, req)
		return
	})

	return nil
}

// PublisherClient is a client to communicate with the Publisher Authority
type PublisherClient struct {
	rpc Client
}

// NewPublisherClient constructs an RPC client
func NewPublisherClient(clientName string, amqpConf *cmd.AMQPConfig, stats metrics.Scope) (*PublisherClient, error) {
	client, err := NewAmqpRPCClient(clientName+"->Publisher", amqpConf, amqpConf.Publisher, stats)
	return &PublisherClient{rpc: client}, err
}

// SubmitToCT sends a request to submit a certifcate to CT logs
func (pub PublisherClient) SubmitToCT(ctx context.Context, der []byte) (err error) {
	_, err = pub.rpc.DispatchSync(MethodSubmitToCT, der)
	return
}

// SubmitToSingleCT sends a request to submit a certificate to one CT log
// specified by URL and public key
func (pub PublisherClient) SubmitToSingleCT(ctx context.Context, logURL, logPublicKey string, der []byte) (err error) {

	var ctReq struct {
		LogURL       string
		LogPublicKey string
		Der          []byte
	}

	ctReq.LogURL = logURL
	ctReq.LogPublicKey = logPublicKey
	ctReq.Der = der
	data, err := json.Marshal(ctReq)
	if err != nil {
		return
	}
	_, err = pub.rpc.DispatchSync(MethodSubmitToSingleCT, data)
	return
}

// NewCertificateAuthorityServer constructs an RPC server
//
// CertificateAuthorityClient / Server
//  -> IssueCertificate
func NewCertificateAuthorityServer(rpc Server, impl core.CertificateAuthority) (err error) {
	rpc.Handle(MethodIssueCertificate, func(ctx context.Context, req []byte) (response []byte, err error) {
		var icReq issueCertificateRequest
		err = json.Unmarshal(req, &icReq)
		if err != nil {
			improperMessage(MethodIssueCertificate, err, req)
			return
		}

		csr, err := x509.ParseCertificateRequest(icReq.Bytes)
		if err != nil {
			improperMessage(MethodIssueCertificate, err, req)
			return
		}

		cert, err := impl.IssueCertificate(ctx, *csr, icReq.RegID)
		if err != nil {
			return
		}

		response, err = json.Marshal(cert)
		if err != nil {
			errorCondition(MethodIssueCertificate, err, req)
			return
		}

		return
	})

	rpc.Handle(MethodGenerateOCSP, func(ctx context.Context, req []byte) (response []byte, err error) {
		var xferObj core.OCSPSigningRequest
		err = json.Unmarshal(req, &xferObj)
		if err != nil {
			errorCondition(MethodGenerateOCSP, err, req)
			return
		}

		response, err = impl.GenerateOCSP(ctx, xferObj)
		if err != nil {
			return
		}

		return
	})

	return nil
}

// CertificateAuthorityClient is a client to communicate with the CA.
type CertificateAuthorityClient struct {
	rpc Client
}

// NewCertificateAuthorityClient constructs an RPC client
func NewCertificateAuthorityClient(clientName string, amqpConf *cmd.AMQPConfig, stats metrics.Scope) (*CertificateAuthorityClient, error) {
	client, err := NewAmqpRPCClient(clientName+"->CA", amqpConf, amqpConf.CA, stats)
	return &CertificateAuthorityClient{rpc: client}, err
}

// IssueCertificate sends a request to issue a certificate
func (cac CertificateAuthorityClient) IssueCertificate(ctx context.Context, csr x509.CertificateRequest, regID int64) (cert core.Certificate, err error) {
	var icReq issueCertificateRequest
	icReq.Bytes = csr.Raw
	icReq.RegID = regID
	data, err := json.Marshal(icReq)
	if err != nil {
		return
	}

	jsonResponse, err := cac.rpc.DispatchSync(MethodIssueCertificate, data)
	if err != nil {
		return
	}

	err = json.Unmarshal(jsonResponse, &cert)
	return
}

// GenerateOCSP sends a request to generate an OCSP response
func (cac CertificateAuthorityClient) GenerateOCSP(ctx context.Context, signRequest core.OCSPSigningRequest) (resp []byte, err error) {
	data, err := json.Marshal(signRequest)
	if err != nil {
		errorCondition(MethodGenerateOCSP, err, signRequest)
		return
	}

	resp, err = cac.rpc.DispatchSync(MethodGenerateOCSP, data)
	if err != nil {
		return
	}
	if len(resp) < 1 {
		err = fmt.Errorf("Failure at Signer")
		return
	}
	return
}

// NewStorageAuthorityServer constructs an RPC server
func NewStorageAuthorityServer(rpc Server, impl core.StorageAuthority) error {
	rpc.Handle(MethodUpdateRegistration, func(ctx context.Context, req []byte) (response []byte, err error) {
		var reg core.Registration
		if err = json.Unmarshal(req, &reg); err != nil {
			improperMessage(MethodUpdateRegistration, err, req)
			return
		}

		err = impl.UpdateRegistration(ctx, reg)
		return
	})

	rpc.Handle(MethodGetRegistration, func(ctx context.Context, req []byte) (response []byte, err error) {
		var grReq getRegistrationRequest
		err = json.Unmarshal(req, &grReq)
		if err != nil {
			improperMessage(MethodGetRegistration, err, req)
			return
		}

		reg, err := impl.GetRegistration(ctx, grReq.ID)
		if err != nil {
			return
		}

		response, err = json.Marshal(reg)
		if err != nil {
			errorCondition(MethodGetRegistration, err, req)
			return
		}
		return
	})

	rpc.Handle(MethodGetRegistrationByKey, func(ctx context.Context, req []byte) (response []byte, err error) {
		var jwk *jose.JsonWebKey
		if err = json.Unmarshal(req, &jwk); err != nil {
			improperMessage(MethodGetRegistrationByKey, err, req)
			return
		}

		reg, err := impl.GetRegistrationByKey(ctx, jwk)
		if err != nil {
			return
		}

		response, err = json.Marshal(reg)
		if err != nil {
			errorCondition(MethodGetRegistrationByKey, err, req)
			return
		}
		return
	})

	rpc.Handle(MethodGetAuthorization, func(ctx context.Context, req []byte) (response []byte, err error) {
		authz, err := impl.GetAuthorization(ctx, string(req))
		if err != nil {
			return
		}

		response, err = json.Marshal(authz)
		if err != nil {
			errorCondition(MethodGetAuthorization, err, req)
			return
		}
		return
	})

	rpc.Handle(MethodGetValidAuthorizations, func(ctx context.Context, req []byte) (response []byte, err error) {
		var mreq getValidAuthorizationsRequest
		if err = json.Unmarshal(req, &mreq); err != nil {
			improperMessage(MethodGetValidAuthorizations, err, req)
			return
		}

		auths, err := impl.GetValidAuthorizations(ctx, mreq.RegID, mreq.Names, mreq.Now)
		if err != nil {
			return
		}

		response, err = json.Marshal(auths)
		if err != nil {
			errorCondition(MethodGetValidAuthorizations, err, req)
			return
		}
		return
	})

	rpc.Handle(MethodAddCertificate, func(ctx context.Context, req []byte) (response []byte, err error) {
		var acReq addCertificateRequest
		err = json.Unmarshal(req, &acReq)
		if err != nil {
			improperMessage(MethodAddCertificate, err, req)
			return
		}

		id, err := impl.AddCertificate(ctx, acReq.Bytes, acReq.RegID)
		if err != nil {
			return
		}
		response = []byte(id)
		return
	})

	rpc.Handle(MethodNewRegistration, func(ctx context.Context, req []byte) (response []byte, err error) {
		var registration core.Registration
		err = json.Unmarshal(req, &registration)
		if err != nil {
			improperMessage(MethodNewRegistration, err, req)
			return
		}

		output, err := impl.NewRegistration(ctx, registration)
		if err != nil {
			return
		}

		response, err = json.Marshal(output)
		if err != nil {
			errorCondition(MethodNewRegistration, err, req)
			return
		}
		return
	})

	rpc.Handle(MethodNewPendingAuthorization, func(ctx context.Context, req []byte) (response []byte, err error) {
		var authz core.Authorization
		if err = json.Unmarshal(req, &authz); err != nil {
			improperMessage(MethodNewPendingAuthorization, err, req)
			return
		}

		output, err := impl.NewPendingAuthorization(ctx, authz)
		if err != nil {
			return
		}

		response, err = json.Marshal(output)
		if err != nil {
			errorCondition(MethodNewPendingAuthorization, err, req)
			return
		}
		return
	})

	rpc.Handle(MethodUpdatePendingAuthorization, func(ctx context.Context, req []byte) (response []byte, err error) {
		var authz core.Authorization
		if err = json.Unmarshal(req, &authz); err != nil {
			improperMessage(MethodUpdatePendingAuthorization, err, req)
			return
		}

		err = impl.UpdatePendingAuthorization(ctx, authz)
		return
	})

	rpc.Handle(MethodFinalizeAuthorization, func(ctx context.Context, req []byte) (response []byte, err error) {
		var authz core.Authorization
		if err = json.Unmarshal(req, &authz); err != nil {
			improperMessage(MethodFinalizeAuthorization, err, req)
			return
		}

		err = impl.FinalizeAuthorization(ctx, authz)
		return
	})

	rpc.Handle(MethodRevokeAuthorizationsByDomain, func(ctx context.Context, req []byte) (response []byte, err error) {
		var reqObj revokeAuthsRequest
		err = json.Unmarshal(req, &reqObj)
		if err != nil {
			return
		}
		aRevoked, paRevoked, err := impl.RevokeAuthorizationsByDomain(ctx, reqObj.Ident)
		if err != nil {
			return
		}
		var raResp = revokeAuthsResponse{FinalRevoked: aRevoked, PendingRevoked: paRevoked}
		response, err = json.Marshal(raResp)
		return
	})

	rpc.Handle(MethodGetCertificate, func(ctx context.Context, req []byte) (response []byte, err error) {
		cert, err := impl.GetCertificate(ctx, string(req))
		if err != nil {
			return
		}

		jsonResponse, err := json.Marshal(cert)
		if err != nil {
			errorCondition(MethodGetCertificate, err, req)
			return
		}

		return jsonResponse, nil
	})

	rpc.Handle(MethodGetCertificateStatus, func(ctx context.Context, req []byte) (response []byte, err error) {
		status, err := impl.GetCertificateStatus(ctx, string(req))
		if err != nil {
			return
		}

		response, err = json.Marshal(status)
		if err != nil {
			errorCondition(MethodGetCertificateStatus, err, req)
			return
		}
		return
	})

	rpc.Handle(MethodMarkCertificateRevoked, func(ctx context.Context, req []byte) (response []byte, err error) {
		var mcrReq markCertificateRevokedRequest

		if err = json.Unmarshal(req, &mcrReq); err != nil {
			improperMessage(MethodMarkCertificateRevoked, err, req)
			return
		}

		err = impl.MarkCertificateRevoked(ctx, mcrReq.Serial, mcrReq.ReasonCode)
		return
	})

	rpc.Handle(MethodCountCertificatesRange, func(ctx context.Context, req []byte) (response []byte, err error) {
		var cReq countRequest
		err = json.Unmarshal(req, &cReq)
		if err != nil {
			return
		}

		count, err := impl.CountCertificatesRange(ctx, cReq.Start, cReq.End)
		if err != nil {
			return
		}
		return json.Marshal(count)
	})

	rpc.Handle(MethodCountCertificatesByNames, func(ctx context.Context, req []byte) (response []byte, err error) {
		var cReq countCertificatesByNamesRequest
		err = json.Unmarshal(req, &cReq)
		if err != nil {
			return
		}

		counts, err := impl.CountCertificatesByNames(ctx, cReq.Names, cReq.Earliest, cReq.Latest)
		if err != nil {
			return
		}
		return json.Marshal(counts)
	})

	rpc.Handle(MethodCountRegistrationsByIP, func(ctx context.Context, req []byte) (response []byte, err error) {
		var cReq countRegistrationsByIPRequest
		err = json.Unmarshal(req, &cReq)
		if err != nil {
			return
		}

		count, err := impl.CountRegistrationsByIP(ctx, cReq.IP, cReq.Earliest, cReq.Latest)
		if err != nil {
			return
		}
		return json.Marshal(count)
	})

	rpc.Handle(MethodCountPendingAuthorizations, func(ctx context.Context, req []byte) (response []byte, err error) {
		var cReq countPendingAuthorizationsRequest
		err = json.Unmarshal(req, &cReq)
		if err != nil {
			return
		}

		count, err := impl.CountPendingAuthorizations(ctx, cReq.RegID)
		if err != nil {
			return
		}
		return json.Marshal(count)
	})

	rpc.Handle(MethodGetSCTReceipt, func(ctx context.Context, req []byte) (response []byte, err error) {
		var gsctReq struct {
			Serial string
			LogID  string
		}

		err = json.Unmarshal(req, &gsctReq)
		if err != nil {
			improperMessage(MethodGetSCTReceipt, err, req)
			return
		}

		sct, err := impl.GetSCTReceipt(ctx, gsctReq.Serial, gsctReq.LogID)
		jsonResponse, err := json.Marshal(sct)
		if err != nil {
			errorCondition(MethodGetSCTReceipt, err, req)
			return
		}

		return jsonResponse, nil
	})

	rpc.Handle(MethodAddSCTReceipt, func(ctx context.Context, req []byte) (response []byte, err error) {
		var sct core.SignedCertificateTimestamp
		err = json.Unmarshal(req, &sct)
		if err != nil {
			improperMessage(MethodAddSCTReceipt, err, req)
			return
		}

		return nil, impl.AddSCTReceipt(ctx, core.SignedCertificateTimestamp(sct))
	})

	rpc.Handle(MethodCountFQDNSets, func(ctx context.Context, req []byte) (response []byte, err error) {
		var r countFQDNsRequest
		err = json.Unmarshal(req, &r)
		if err != nil {
			errorCondition(MethodCountFQDNSets, err, req)
			return
		}
		count, err := impl.CountFQDNSets(ctx, r.Window, r.Names)
		if err != nil {
			return
		}

		response, err = json.Marshal(countFQDNSetsResponse{count})
		if err != nil {
			errorCondition(MethodCountFQDNSets, err, req)
			return
		}

		return
	})

	rpc.Handle(MethodFQDNSetExists, func(ctx context.Context, req []byte) (response []byte, err error) {
		var r fqdnSetExistsRequest
		err = json.Unmarshal(req, &r)
		if err != nil {
			errorCondition(MethodFQDNSetExists, err, req)
			return
		}
		exists, err := impl.FQDNSetExists(ctx, r.Names)
		if err != nil {
			return
		}
		response, err = json.Marshal(fqdnSetExistsResponse{exists})
		if err != nil {
			errorCondition(MethodFQDNSetExists, err, req)
			return
		}

		return
	})

	rpc.Handle(MethodDeactivateAuthorizationSA, func(ctx context.Context, req []byte) (response []byte, err error) {
		err = impl.DeactivateAuthorization(ctx, string(req))
		return
	})

	rpc.Handle(MethodDeactivateRegistrationSA, func(ctx context.Context, req []byte) (response []byte, err error) {
		var drReq deactivateRegistrationRequest
		err = json.Unmarshal(req, &drReq)
		if err != nil {
			return
		}
		err = impl.DeactivateRegistration(ctx, drReq.ID)
		return
	})

	return nil
}

// StorageAuthorityClient is a client to communicate with the Storage Authority
type StorageAuthorityClient struct {
	rpc Client
}

// NewStorageAuthorityClient constructs an RPC client
func NewStorageAuthorityClient(clientName string, amqpConf *cmd.AMQPConfig, stats metrics.Scope) (*StorageAuthorityClient, error) {
	client, err := NewAmqpRPCClient(clientName+"->SA", amqpConf, amqpConf.SA, stats)
	return &StorageAuthorityClient{rpc: client}, err
}

// GetRegistration sends a request to get a registration by ID
func (cac StorageAuthorityClient) GetRegistration(ctx context.Context, id int64) (reg core.Registration, err error) {
	var grReq getRegistrationRequest
	grReq.ID = id

	data, err := json.Marshal(grReq)
	if err != nil {
		return
	}

	jsonReg, err := cac.rpc.DispatchSync(MethodGetRegistration, data)
	if err != nil {
		return
	}

	err = json.Unmarshal(jsonReg, &reg)
	return
}

// GetRegistrationByKey sends a request to get a registration by JWK
func (cac StorageAuthorityClient) GetRegistrationByKey(ctx context.Context, key *jose.JsonWebKey) (reg core.Registration, err error) {
	jsonKey, err := key.MarshalJSON()
	if err != nil {
		return
	}

	jsonReg, err := cac.rpc.DispatchSync(MethodGetRegistrationByKey, jsonKey)
	if err != nil {
		return
	}

	err = json.Unmarshal(jsonReg, &reg)
	return
}

// GetAuthorization sends a request to get an Authorization by ID
func (cac StorageAuthorityClient) GetAuthorization(ctx context.Context, id string) (authz core.Authorization, err error) {
	jsonAuthz, err := cac.rpc.DispatchSync(MethodGetAuthorization, []byte(id))
	if err != nil {
		return
	}

	err = json.Unmarshal(jsonAuthz, &authz)
	return
}

// GetValidAuthorizations sends a request to get a batch of Authorizations by
// RegID and dnsName. The current time is also included in the request to
// assist filtering.
func (cac StorageAuthorityClient) GetValidAuthorizations(ctx context.Context, registrationID int64, names []string, now time.Time) (auths map[string]*core.Authorization, err error) {
	data, err := json.Marshal(getValidAuthorizationsRequest{
		RegID: registrationID,
		Names: names,
		Now:   now,
	})
	if err != nil {
		return
	}

	jsonAuths, err := cac.rpc.DispatchSync(MethodGetValidAuthorizations, data)
	if err != nil {
		return
	}

	err = json.Unmarshal(jsonAuths, &auths)
	return
}

// GetCertificate sends a request to get a Certificate by ID
func (cac StorageAuthorityClient) GetCertificate(ctx context.Context, id string) (cert core.Certificate, err error) {
	jsonCert, err := cac.rpc.DispatchSync(MethodGetCertificate, []byte(id))
	if err != nil {
		return
	}

	err = json.Unmarshal(jsonCert, &cert)
	return
}

// GetCertificateStatus sends a request to obtain the current status of a
// certificate by ID
func (cac StorageAuthorityClient) GetCertificateStatus(ctx context.Context, id string) (status core.CertificateStatus, err error) {
	jsonStatus, err := cac.rpc.DispatchSync(MethodGetCertificateStatus, []byte(id))
	if err != nil {
		return
	}

	err = json.Unmarshal(jsonStatus, &status)
	return
}

// MarkCertificateRevoked sends a request to mark a certificate as revoked
func (cac StorageAuthorityClient) MarkCertificateRevoked(ctx context.Context, serial string, reasonCode revocation.Reason) (err error) {
	var mcrReq markCertificateRevokedRequest

	mcrReq.Serial = serial
	mcrReq.ReasonCode = reasonCode

	data, err := json.Marshal(mcrReq)
	if err != nil {
		return
	}

	_, err = cac.rpc.DispatchSync(MethodMarkCertificateRevoked, data)
	return
}

// UpdateRegistration sends a request to store an updated registration
func (cac StorageAuthorityClient) UpdateRegistration(ctx context.Context, reg core.Registration) (err error) {
	jsonReg, err := json.Marshal(reg)
	if err != nil {
		return
	}

	_, err = cac.rpc.DispatchSync(MethodUpdateRegistration, jsonReg)
	return
}

// NewRegistration sends a request to store a new registration
func (cac StorageAuthorityClient) NewRegistration(ctx context.Context, reg core.Registration) (output core.Registration, err error) {
	jsonReg, err := json.Marshal(reg)
	if err != nil {
		err = errors.New("NewRegistration RPC failed")
		return
	}
	response, err := cac.rpc.DispatchSync(MethodNewRegistration, jsonReg)
	if err != nil {
		return
	}
	err = json.Unmarshal(response, &output)
	if err != nil {
		err = errors.New("NewRegistration RPC failed")
		return
	}
	return output, nil
}

// NewPendingAuthorization sends a request to store a pending authorization
func (cac StorageAuthorityClient) NewPendingAuthorization(ctx context.Context, authz core.Authorization) (output core.Authorization, err error) {
	jsonAuthz, err := json.Marshal(authz)
	if err != nil {
		return
	}
	response, err := cac.rpc.DispatchSync(MethodNewPendingAuthorization, jsonAuthz)
	if err != nil {
		return
	}
	err = json.Unmarshal(response, &output)
	if err != nil {
		err = errors.New("NewRegistration RPC failed")
		return
	}
	return
}

// UpdatePendingAuthorization sends a request to update the data in a pending
// authorization
func (cac StorageAuthorityClient) UpdatePendingAuthorization(ctx context.Context, authz core.Authorization) (err error) {
	jsonAuthz, err := json.Marshal(authz)
	if err != nil {
		return
	}

	_, err = cac.rpc.DispatchSync(MethodUpdatePendingAuthorization, jsonAuthz)
	return
}

// FinalizeAuthorization sends a request to finalize an authorization (convert
// from pending)
func (cac StorageAuthorityClient) FinalizeAuthorization(ctx context.Context, authz core.Authorization) (err error) {
	jsonAuthz, err := json.Marshal(authz)
	if err != nil {
		return
	}

	_, err = cac.rpc.DispatchSync(MethodFinalizeAuthorization, jsonAuthz)
	return
}

// RevokeAuthorizationsByDomain sends a request to revoke all pending or finalized authorizations
// for a single domain
func (cac StorageAuthorityClient) RevokeAuthorizationsByDomain(ctx context.Context, ident core.AcmeIdentifier) (aRevoked int64, paRevoked int64, err error) {
	data, err := json.Marshal(revokeAuthsRequest{Ident: ident})
	if err != nil {
		return
	}
	resp, err := cac.rpc.DispatchSync(MethodRevokeAuthorizationsByDomain, data)
	if err != nil {
		return
	}
	var raResp revokeAuthsResponse
	err = json.Unmarshal(resp, &raResp)
	if err != nil {
		return
	}
	aRevoked = raResp.FinalRevoked
	paRevoked = raResp.PendingRevoked
	return
}

// AddCertificate sends a request to record the issuance of a certificate
func (cac StorageAuthorityClient) AddCertificate(ctx context.Context, cert []byte, regID int64) (id string, err error) {
	var acReq addCertificateRequest
	acReq.Bytes = cert
	acReq.RegID = regID
	data, err := json.Marshal(acReq)
	if err != nil {
		return
	}

	response, err := cac.rpc.DispatchSync(MethodAddCertificate, data)
	if err != nil {
		return
	}
	id = string(response)
	return
}

// CountCertificatesRange sends a request to count the number of certificates
// issued in  a certain time range
func (cac StorageAuthorityClient) CountCertificatesRange(ctx context.Context, start, end time.Time) (count int64, err error) {
	var cReq countRequest
	cReq.Start, cReq.End = start, end
	data, err := json.Marshal(cReq)
	if err != nil {
		return
	}
	response, err := cac.rpc.DispatchSync(MethodCountCertificatesRange, data)
	if err != nil {
		return
	}
	err = json.Unmarshal(response, &count)
	return
}

// CountCertificatesByNames calls CountCertificatesRange on the remote
// StorageAuthority.
func (cac StorageAuthorityClient) CountCertificatesByNames(ctx context.Context, names []string, earliest, latest time.Time) (counts map[string]int, err error) {
	var cReq countCertificatesByNamesRequest
	cReq.Names, cReq.Earliest, cReq.Latest = names, earliest, latest
	data, err := json.Marshal(cReq)
	if err != nil {
		return
	}
	response, err := cac.rpc.DispatchSync(MethodCountCertificatesByNames, data)
	if err != nil {
		return
	}
	err = json.Unmarshal(response, &counts)
	return
}

// CountRegistrationsByIP calls CountRegistrationsByIP on the remote
// StorageAuthority.
func (cac StorageAuthorityClient) CountRegistrationsByIP(ctx context.Context, ip net.IP, earliest, latest time.Time) (count int, err error) {
	var cReq countRegistrationsByIPRequest
	cReq.IP, cReq.Earliest, cReq.Latest = ip, earliest, latest
	data, err := json.Marshal(cReq)
	if err != nil {
		return
	}
	response, err := cac.rpc.DispatchSync(MethodCountRegistrationsByIP, data)
	if err != nil {
		return
	}
	err = json.Unmarshal(response, &count)
	return
}

// CountPendingAuthorizations calls CountPendingAuthorizations on the remote
// StorageAuthority.
func (cac StorageAuthorityClient) CountPendingAuthorizations(ctx context.Context, regID int64) (count int, err error) {
	var cReq countPendingAuthorizationsRequest
	cReq.RegID = regID
	data, err := json.Marshal(cReq)
	if err != nil {
		return
	}
	response, err := cac.rpc.DispatchSync(MethodCountPendingAuthorizations, data)
	if err != nil {
		return
	}
	err = json.Unmarshal(response, &count)
	return
}

// GetSCTReceipt retrieves an SCT according to the serial number of a certificate
// and the logID of the log to which it was submitted.
func (cac StorageAuthorityClient) GetSCTReceipt(ctx context.Context, serial string, logID string) (receipt core.SignedCertificateTimestamp, err error) {
	var gsctReq struct {
		Serial string
		LogID  string
	}
	gsctReq.Serial = serial
	gsctReq.LogID = logID

	data, err := json.Marshal(gsctReq)
	if err != nil {
		return
	}

	response, err := cac.rpc.DispatchSync(MethodGetSCTReceipt, data)
	if err != nil {
		return
	}

	err = json.Unmarshal(response, receipt)
	return
}

// AddSCTReceipt adds a new SCT to the database.
func (cac StorageAuthorityClient) AddSCTReceipt(ctx context.Context, sct core.SignedCertificateTimestamp) (err error) {
	data, err := json.Marshal(sct)
	if err != nil {
		return
	}

	_, err = cac.rpc.DispatchSync(MethodAddSCTReceipt, data)
	return
}

// CountFQDNSets reutrns the number of currently valid sets with hash |setHash|
func (cac StorageAuthorityClient) CountFQDNSets(ctx context.Context, window time.Duration, names []string) (int64, error) {
	data, err := json.Marshal(countFQDNsRequest{window, names})
	if err != nil {
		return 0, err
	}
	response, err := cac.rpc.DispatchSync(MethodCountFQDNSets, data)
	if err != nil {
		return 0, err
	}
	var count countFQDNSetsResponse
	err = json.Unmarshal(response, &count)
	return count.Count, err
}

// FQDNSetExists returns a bool indicating whether the FQDN set |name|
// exists in the database
func (cac StorageAuthorityClient) FQDNSetExists(ctx context.Context, names []string) (bool, error) {
	data, err := json.Marshal(fqdnSetExistsRequest{names})
	if err != nil {
		return false, err
	}
	response, err := cac.rpc.DispatchSync(MethodFQDNSetExists, data)
	if err != nil {
		return false, err
	}
	var exists fqdnSetExistsResponse
	err = json.Unmarshal(response, &exists)
	return exists.Exists, err
}

// DeactivateAuthorization deactivates a currently valid or pending authorization
func (cac StorageAuthorityClient) DeactivateAuthorization(ctx context.Context, id string) error {
	_, err := cac.rpc.DispatchSync(MethodDeactivateAuthorizationSA, []byte(id))
	return err
}

// DeactivateRegistration deactivates a currently valid registration
func (cac StorageAuthorityClient) DeactivateRegistration(ctx context.Context, id int64) error {
	data, err := json.Marshal(deactivateRegistrationRequest{id})
	if err != nil {
		return err
	}
	_, err = cac.rpc.DispatchSync(MethodDeactivateRegistrationSA, data)
	return err
}
