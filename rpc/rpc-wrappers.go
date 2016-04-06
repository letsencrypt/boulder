// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package rpc

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/square/go-jose"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/probs"
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
	MethodOnValidationUpdate                = "OnValidationUpdate"                // RA
	MethodUpdateValidations                 = "UpdateValidations"                 // VA
	MethodPerformValidation                 = "PerformValidation"                 // VA
	MethodIsSafeDomain                      = "IsSafeDomain"                      // VA
	MethodIssueCertificate                  = "IssueCertificate"                  // CA
	MethodGenerateOCSP                      = "GenerateOCSP"                      // CA
	MethodGetRegistration                   = "GetRegistration"                   // SA
	MethodGetRegistrationByKey              = "GetRegistrationByKey"              // RA, SA
	MethodGetAuthorization                  = "GetAuthorization"                  // SA
	MethodGetLatestValidAuthorization       = "GetLatestValidAuthorization"       // SA
	MethodGetValidAuthorizations            = "GetValidAuthorizations"            // SA
	MethodGetCertificate                    = "GetCertificate"                    // SA
	MethodGetCertificateStatus              = "GetCertificateStatus"              // SA
	MethodMarkCertificateRevoked            = "MarkCertificateRevoked"            // SA
	MethodUpdateOCSP                        = "UpdateOCSP"                        // SA
	MethodNewPendingAuthorization           = "NewPendingAuthorization"           // SA
	MethodUpdatePendingAuthorization        = "UpdatePendingAuthorization"        // SA
	MethodFinalizeAuthorization             = "FinalizeAuthorization"             // SA
	MethodAddCertificate                    = "AddCertificate"                    // SA
	MethodAlreadyDeniedCSR                  = "AlreadyDeniedCSR"                  // SA
	MethodCountCertificatesRange            = "CountCertificatesRange"            // SA
	MethodCountCertificatesByNames          = "CountCertificatesByNames"          // SA
	MethodCountRegistrationsByIP            = "CountRegistrationsByIP"            // SA
	MethodCountPendingAuthorizations        = "CountPendingAuthorizations"        // SA
	MethodGetSCTReceipt                     = "GetSCTReceipt"                     // SA
	MethodAddSCTReceipt                     = "AddSCTReceipt"                     // SA
	MethodSubmitToCT                        = "SubmitToCT"                        // Pub
	MethodRevokeAuthorizationsByDomain      = "RevokeAuthorizationsByDomain"      // SA
	MethodCountFQDNSets                     = "CountFQDNSets"                     // SA
	MethodFQDNSetExists                     = "FQDNSetExists"                     // SA
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
	ReasonCode core.RevocationCode
}

type markCertificateRevokedRequest struct {
	Serial     string
	ReasonCode core.RevocationCode
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

type performValidationResponse struct {
	Records []core.ValidationRecord
	Problem *probs.ProblemDetails
}

type alreadyDeniedCSRReq struct {
	Names []string
}

type updateOCSPRequest struct {
	Serial       string
	OCSPResponse []byte
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
	log := blog.GetAuditLogger()
	log.AuditErr(fmt.Errorf("Improper message. method: %s err: %s data: %+v", method, err, obj))
}
func errorCondition(method string, err error, obj interface{}) {
	log := blog.GetAuditLogger()
	log.AuditErr(fmt.Errorf("Error condition. method: %s err: %s data: %+v", method, err, obj))
}

// NewRegistrationAuthorityServer constructs an RPC server
func NewRegistrationAuthorityServer(rpc Server, impl core.RegistrationAuthority) error {
	log := blog.GetAuditLogger()

	rpc.Handle(MethodNewRegistration, func(req []byte) (response []byte, err error) {
		var rr registrationRequest
		if err = json.Unmarshal(req, &rr); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodNewRegistration, err, req)
			return
		}

		reg, err := impl.NewRegistration(rr.Reg)
		if err != nil {
			return
		}

		response, err = json.Marshal(reg)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodNewRegistration, err, req)
			return
		}
		return
	})

	rpc.Handle(MethodNewAuthorization, func(req []byte) (response []byte, err error) {
		var ar authorizationRequest
		if err = json.Unmarshal(req, &ar); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodNewAuthorization, err, req)
			return
		}

		authz, err := impl.NewAuthorization(ar.Authz, ar.RegID)
		if err != nil {
			return
		}

		response, err = json.Marshal(authz)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodNewAuthorization, err, req)
			return
		}
		return
	})

	rpc.Handle(MethodNewCertificate, func(req []byte) (response []byte, err error) {
		log.Info(fmt.Sprintf(" [.] Entering MethodNewCertificate"))
		var cr certificateRequest
		if err = json.Unmarshal(req, &cr); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodNewCertificate, err, req)
			return
		}
		log.Info(fmt.Sprintf(" [.] No problem unmarshaling request"))

		cert, err := impl.NewCertificate(cr.Req, cr.RegID)
		if err != nil {
			return
		}
		log.Info(fmt.Sprintf(" [.] No problem issuing new cert"))

		response, err = json.Marshal(cert)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodNewCertificate, err, req)
			return
		}
		return
	})

	rpc.Handle(MethodUpdateRegistration, func(req []byte) (response []byte, err error) {
		var urReq updateRegistrationRequest
		err = json.Unmarshal(req, &urReq)
		if err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodUpdateRegistration, err, req)
			return
		}

		reg, err := impl.UpdateRegistration(urReq.Base, urReq.Update)
		if err != nil {
			return
		}

		response, err = json.Marshal(reg)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodUpdateRegistration, err, req)
			return
		}
		return
	})

	rpc.Handle(MethodUpdateAuthorization, func(req []byte) (response []byte, err error) {
		var uaReq updateAuthorizationRequest
		err = json.Unmarshal(req, &uaReq)
		if err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodUpdateAuthorization, err, req)
			return
		}

		newAuthz, err := impl.UpdateAuthorization(uaReq.Authz, uaReq.Index, uaReq.Response)
		if err != nil {
			return
		}

		response, err = json.Marshal(newAuthz)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodUpdateAuthorization, err, req)
			return
		}
		return
	})

	rpc.Handle(MethodRevokeCertificateWithReg, func(req []byte) (response []byte, err error) {
		var revReq struct {
			Cert   []byte
			Reason core.RevocationCode
			RegID  int64
		}
		if err = json.Unmarshal(req, &revReq); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodRevokeCertificateWithReg, err, req)
			return
		}
		cert, err := x509.ParseCertificate(revReq.Cert)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			return
		}

		err = impl.RevokeCertificateWithReg(*cert, revReq.Reason, revReq.RegID)
		return
	})

	rpc.Handle(MethodAdministrativelyRevokeCertificate, func(req []byte) (response []byte, err error) {
		var revReq struct {
			Cert   []byte
			Reason core.RevocationCode
			User   string
		}
		if err = json.Unmarshal(req, &revReq); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodAdministrativelyRevokeCertificate, err, req)
			return
		}
		cert, err := x509.ParseCertificate(revReq.Cert)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			return
		}

		err = impl.AdministrativelyRevokeCertificate(*cert, revReq.Reason, revReq.User)
		return
	})

	rpc.Handle(MethodOnValidationUpdate, func(req []byte) (response []byte, err error) {
		var authz core.Authorization
		if err = json.Unmarshal(req, &authz); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodOnValidationUpdate, err, req)
			return
		}

		err = impl.OnValidationUpdate(authz)
		return
	})

	return nil
}

// RegistrationAuthorityClient represents an RA RPC client
type RegistrationAuthorityClient struct {
	rpc Client
}

// NewRegistrationAuthorityClient constructs an RPC client
func NewRegistrationAuthorityClient(clientName string, amqpConf *cmd.AMQPConfig, stats statsd.Statter) (*RegistrationAuthorityClient, error) {
	client, err := NewAmqpRPCClient(clientName+"->RA", amqpConf, amqpConf.RA, stats)
	return &RegistrationAuthorityClient{rpc: client}, err
}

// NewRegistration sends a New Registration request
func (rac RegistrationAuthorityClient) NewRegistration(reg core.Registration) (newReg core.Registration, err error) {
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
func (rac RegistrationAuthorityClient) NewAuthorization(authz core.Authorization, regID int64) (newAuthz core.Authorization, err error) {
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
func (rac RegistrationAuthorityClient) NewCertificate(cr core.CertificateRequest, regID int64) (cert core.Certificate, err error) {
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
func (rac RegistrationAuthorityClient) UpdateRegistration(base core.Registration, update core.Registration) (newReg core.Registration, err error) {
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
func (rac RegistrationAuthorityClient) UpdateAuthorization(authz core.Authorization, index int, response core.Challenge) (newAuthz core.Authorization, err error) {
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
func (rac RegistrationAuthorityClient) RevokeCertificateWithReg(cert x509.Certificate, reason core.RevocationCode, regID int64) (err error) {
	var revReq struct {
		Cert   []byte
		Reason core.RevocationCode
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
func (rac RegistrationAuthorityClient) AdministrativelyRevokeCertificate(cert x509.Certificate, reason core.RevocationCode, user string) (err error) {
	var revReq struct {
		Cert   []byte
		Reason core.RevocationCode
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

// OnValidationUpdate senda a notice that a validation has updated
func (rac RegistrationAuthorityClient) OnValidationUpdate(authz core.Authorization) (err error) {
	data, err := json.Marshal(authz)
	if err != nil {
		return
	}

	_, err = rac.rpc.DispatchSync(MethodOnValidationUpdate, data)
	return
}

// NewValidationAuthorityServer constructs an RPC server
//
// ValidationAuthorityClient / Server
//  -> UpdateValidations
func NewValidationAuthorityServer(rpc Server, impl core.ValidationAuthority) (err error) {
	rpc.Handle(MethodUpdateValidations, func(req []byte) (response []byte, err error) {
		var vaReq validationRequest
		if err = json.Unmarshal(req, &vaReq); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodUpdateValidations, err, req)
			return
		}

		return nil, impl.UpdateValidations(vaReq.Authz, vaReq.Index)
	})

	rpc.Handle(MethodPerformValidation, func(req []byte) (response []byte, err error) {
		var vaReq performValidationRequest
		if err = json.Unmarshal(req, &vaReq); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodPerformValidation, err, req)
			return nil, err
		}

		records, err := impl.PerformValidation(vaReq.Domain, vaReq.Challenge, vaReq.Authz)
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

	rpc.Handle(MethodIsSafeDomain, func(req []byte) ([]byte, error) {
		r := &core.IsSafeDomainRequest{}
		if err := json.Unmarshal(req, r); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodIsSafeDomain, err, req)
			return nil, err
		}
		resp, err := impl.IsSafeDomain(r)
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
func NewValidationAuthorityClient(clientName string, amqpConf *cmd.AMQPConfig, stats statsd.Statter) (*ValidationAuthorityClient, error) {
	client, err := NewAmqpRPCClient(clientName+"->VA", amqpConf, amqpConf.VA, stats)
	return &ValidationAuthorityClient{rpc: client}, err
}

// UpdateValidations sends an Update Validations request
func (vac ValidationAuthorityClient) UpdateValidations(authz core.Authorization, index int) error {
	vaReq := validationRequest{
		Authz: authz,
		Index: index,
	}
	data, err := json.Marshal(vaReq)
	if err != nil {
		return err
	}

	_, err = vac.rpc.DispatchSync(MethodUpdateValidations, data)
	return err
}

// PerformValidation has the VA revalidate the specified challenge and returns
// the updated Challenge object.
func (vac ValidationAuthorityClient) PerformValidation(domain string, challenge core.Challenge, authz core.Authorization) ([]core.ValidationRecord, error) {
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
func (vac ValidationAuthorityClient) IsSafeDomain(req *core.IsSafeDomainRequest) (*core.IsSafeDomainResponse, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	jsonResp, err := vac.rpc.DispatchSync(MethodIsSafeDomain, data)
	if err != nil {
		return nil, err
	}
	resp := &core.IsSafeDomainResponse{}
	err = json.Unmarshal(jsonResp, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// NewPublisherServer creates a new server that wraps a CT publisher
func NewPublisherServer(rpc Server, impl core.Publisher) (err error) {
	rpc.Handle(MethodSubmitToCT, func(req []byte) (response []byte, err error) {
		err = impl.SubmitToCT(req)
		return
	})

	return nil
}

// PublisherClient is a client to communicate with the Publisher Authority
type PublisherClient struct {
	rpc Client
}

// NewPublisherClient constructs an RPC client
func NewPublisherClient(clientName string, amqpConf *cmd.AMQPConfig, stats statsd.Statter) (*PublisherClient, error) {
	client, err := NewAmqpRPCClient(clientName+"->Publisher", amqpConf, amqpConf.Publisher, stats)
	return &PublisherClient{rpc: client}, err
}

// SubmitToCT sends a request to submit a certifcate to CT logs
func (pub PublisherClient) SubmitToCT(der []byte) (err error) {
	_, err = pub.rpc.DispatchSync(MethodSubmitToCT, der)
	return
}

// NewCertificateAuthorityServer constructs an RPC server
//
// CertificateAuthorityClient / Server
//  -> IssueCertificate
func NewCertificateAuthorityServer(rpc Server, impl core.CertificateAuthority) (err error) {
	rpc.Handle(MethodIssueCertificate, func(req []byte) (response []byte, err error) {
		var icReq issueCertificateRequest
		err = json.Unmarshal(req, &icReq)
		if err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodIssueCertificate, err, req)
			return
		}

		csr, err := x509.ParseCertificateRequest(icReq.Bytes)
		if err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodIssueCertificate, err, req)
			return
		}

		cert, err := impl.IssueCertificate(*csr, icReq.RegID)
		if err != nil {
			return
		}

		response, err = json.Marshal(cert)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodGetRegistration, err, req)
			return
		}

		return
	})

	rpc.Handle(MethodGenerateOCSP, func(req []byte) (response []byte, err error) {
		var xferObj core.OCSPSigningRequest
		err = json.Unmarshal(req, &xferObj)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodGenerateOCSP, err, req)
			return
		}

		response, err = impl.GenerateOCSP(xferObj)
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
func NewCertificateAuthorityClient(clientName string, amqpConf *cmd.AMQPConfig, stats statsd.Statter) (*CertificateAuthorityClient, error) {
	client, err := NewAmqpRPCClient(clientName+"->CA", amqpConf, amqpConf.CA, stats)
	return &CertificateAuthorityClient{rpc: client}, err
}

// IssueCertificate sends a request to issue a certificate
func (cac CertificateAuthorityClient) IssueCertificate(csr x509.CertificateRequest, regID int64) (cert core.Certificate, err error) {
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
func (cac CertificateAuthorityClient) GenerateOCSP(signRequest core.OCSPSigningRequest) (resp []byte, err error) {
	data, err := json.Marshal(signRequest)
	if err != nil {
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
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
	rpc.Handle(MethodUpdateRegistration, func(req []byte) (response []byte, err error) {
		var reg core.Registration
		if err = json.Unmarshal(req, &reg); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodUpdateRegistration, err, req)
			return
		}

		err = impl.UpdateRegistration(reg)
		return
	})

	rpc.Handle(MethodGetRegistration, func(req []byte) (response []byte, err error) {
		var grReq getRegistrationRequest
		err = json.Unmarshal(req, &grReq)
		if err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodGetRegistration, err, req)
			return
		}

		reg, err := impl.GetRegistration(grReq.ID)
		if err != nil {
			return
		}

		response, err = json.Marshal(reg)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodGetRegistration, err, req)
			return
		}
		return
	})

	rpc.Handle(MethodGetRegistrationByKey, func(req []byte) (response []byte, err error) {
		var jwk jose.JsonWebKey
		if err = json.Unmarshal(req, &jwk); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodGetRegistrationByKey, err, req)
			return
		}

		reg, err := impl.GetRegistrationByKey(jwk)
		if err != nil {
			return
		}

		response, err = json.Marshal(reg)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodGetRegistrationByKey, err, req)
			return
		}
		return
	})

	rpc.Handle(MethodGetAuthorization, func(req []byte) (response []byte, err error) {
		authz, err := impl.GetAuthorization(string(req))
		if err != nil {
			return
		}

		response, err = json.Marshal(authz)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodGetAuthorization, err, req)
			return
		}
		return
	})

	rpc.Handle(MethodGetLatestValidAuthorization, func(req []byte) (response []byte, err error) {
		var lvar latestValidAuthorizationRequest
		if err = json.Unmarshal(req, &lvar); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodNewAuthorization, err, req)
			return
		}

		authz, err := impl.GetLatestValidAuthorization(lvar.RegID, lvar.Identifier)
		if err != nil {
			return
		}

		response, err = json.Marshal(authz)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodGetLatestValidAuthorization, err, req)
			return
		}
		return
	})

	rpc.Handle(MethodGetValidAuthorizations, func(req []byte) (response []byte, err error) {
		var mreq getValidAuthorizationsRequest
		if err = json.Unmarshal(req, &mreq); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodGetValidAuthorizations, err, req)
			return
		}

		auths, err := impl.GetValidAuthorizations(mreq.RegID, mreq.Names, mreq.Now)
		if err != nil {
			return
		}

		response, err = json.Marshal(auths)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodGetValidAuthorizations, err, req)
			return
		}
		return
	})

	rpc.Handle(MethodAddCertificate, func(req []byte) (response []byte, err error) {
		var acReq addCertificateRequest
		err = json.Unmarshal(req, &acReq)
		if err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodAddCertificate, err, req)
			return
		}

		id, err := impl.AddCertificate(acReq.Bytes, acReq.RegID)
		if err != nil {
			return
		}
		response = []byte(id)
		return
	})

	rpc.Handle(MethodNewRegistration, func(req []byte) (response []byte, err error) {
		var registration core.Registration
		err = json.Unmarshal(req, &registration)
		if err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodNewRegistration, err, req)
			return
		}

		output, err := impl.NewRegistration(registration)
		if err != nil {
			return
		}

		response, err = json.Marshal(output)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodNewRegistration, err, req)
			return
		}
		return
	})

	rpc.Handle(MethodNewPendingAuthorization, func(req []byte) (response []byte, err error) {
		var authz core.Authorization
		if err = json.Unmarshal(req, &authz); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodNewPendingAuthorization, err, req)
			return
		}

		output, err := impl.NewPendingAuthorization(authz)
		if err != nil {
			return
		}

		response, err = json.Marshal(output)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodNewPendingAuthorization, err, req)
			return
		}
		return
	})

	rpc.Handle(MethodUpdatePendingAuthorization, func(req []byte) (response []byte, err error) {
		var authz core.Authorization
		if err = json.Unmarshal(req, &authz); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodUpdatePendingAuthorization, err, req)
			return
		}

		err = impl.UpdatePendingAuthorization(authz)
		return
	})

	rpc.Handle(MethodFinalizeAuthorization, func(req []byte) (response []byte, err error) {
		var authz core.Authorization
		if err = json.Unmarshal(req, &authz); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodFinalizeAuthorization, err, req)
			return
		}

		err = impl.FinalizeAuthorization(authz)
		return
	})

	rpc.Handle(MethodRevokeAuthorizationsByDomain, func(req []byte) (response []byte, err error) {
		var reqObj revokeAuthsRequest
		err = json.Unmarshal(req, &reqObj)
		if err != nil {
			return
		}
		aRevoked, paRevoked, err := impl.RevokeAuthorizationsByDomain(reqObj.Ident)
		if err != nil {
			return
		}
		var raResp = revokeAuthsResponse{FinalRevoked: aRevoked, PendingRevoked: paRevoked}
		response, err = json.Marshal(raResp)
		return
	})

	rpc.Handle(MethodGetCertificate, func(req []byte) (response []byte, err error) {
		cert, err := impl.GetCertificate(string(req))
		if err != nil {
			return
		}

		jsonResponse, err := json.Marshal(cert)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodGetCertificate, err, req)
			return
		}

		return jsonResponse, nil
	})

	rpc.Handle(MethodGetCertificateStatus, func(req []byte) (response []byte, err error) {
		status, err := impl.GetCertificateStatus(string(req))
		if err != nil {
			return
		}

		response, err = json.Marshal(status)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodGetCertificateStatus, err, req)
			return
		}
		return
	})

	rpc.Handle(MethodMarkCertificateRevoked, func(req []byte) (response []byte, err error) {
		var mcrReq markCertificateRevokedRequest

		if err = json.Unmarshal(req, &mcrReq); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodMarkCertificateRevoked, err, req)
			return
		}

		err = impl.MarkCertificateRevoked(mcrReq.Serial, mcrReq.ReasonCode)
		return
	})

	rpc.Handle(MethodUpdateOCSP, func(req []byte) (response []byte, err error) {
		var updateOCSPReq updateOCSPRequest

		if err = json.Unmarshal(req, &updateOCSPReq); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodUpdateOCSP, err, req)
			return
		}

		err = impl.UpdateOCSP(updateOCSPReq.Serial, updateOCSPReq.OCSPResponse)
		return
	})

	rpc.Handle(MethodAlreadyDeniedCSR, func(req []byte) (response []byte, err error) {
		var adcReq alreadyDeniedCSRReq

		err = json.Unmarshal(req, &adcReq)
		if err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodAlreadyDeniedCSR, err, req)
			return
		}

		exists, err := impl.AlreadyDeniedCSR(adcReq.Names)
		if err != nil {
			return
		}

		if exists {
			response = []byte{1}
		} else {
			response = []byte{0}
		}
		return
	})

	rpc.Handle(MethodCountCertificatesRange, func(req []byte) (response []byte, err error) {
		var cReq countRequest
		err = json.Unmarshal(req, &cReq)
		if err != nil {
			return
		}

		count, err := impl.CountCertificatesRange(cReq.Start, cReq.End)
		if err != nil {
			return
		}
		return json.Marshal(count)
	})

	rpc.Handle(MethodCountCertificatesByNames, func(req []byte) (response []byte, err error) {
		var cReq countCertificatesByNamesRequest
		err = json.Unmarshal(req, &cReq)
		if err != nil {
			return
		}

		counts, err := impl.CountCertificatesByNames(cReq.Names, cReq.Earliest, cReq.Latest)
		if err != nil {
			return
		}
		return json.Marshal(counts)
	})

	rpc.Handle(MethodCountRegistrationsByIP, func(req []byte) (response []byte, err error) {
		var cReq countRegistrationsByIPRequest
		err = json.Unmarshal(req, &cReq)
		if err != nil {
			return
		}

		count, err := impl.CountRegistrationsByIP(cReq.IP, cReq.Earliest, cReq.Latest)
		if err != nil {
			return
		}
		return json.Marshal(count)
	})

	rpc.Handle(MethodCountPendingAuthorizations, func(req []byte) (response []byte, err error) {
		var cReq countPendingAuthorizationsRequest
		err = json.Unmarshal(req, &cReq)
		if err != nil {
			return
		}

		count, err := impl.CountPendingAuthorizations(cReq.RegID)
		if err != nil {
			return
		}
		return json.Marshal(count)
	})

	rpc.Handle(MethodGetSCTReceipt, func(req []byte) (response []byte, err error) {
		var gsctReq struct {
			Serial string
			LogID  string
		}

		err = json.Unmarshal(req, &gsctReq)
		if err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodGetSCTReceipt, err, req)
			return
		}

		sct, err := impl.GetSCTReceipt(gsctReq.Serial, gsctReq.LogID)
		jsonResponse, err := json.Marshal(sct)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodGetSCTReceipt, err, req)
			return
		}

		return jsonResponse, nil
	})

	rpc.Handle(MethodAddSCTReceipt, func(req []byte) (response []byte, err error) {
		var sct core.SignedCertificateTimestamp
		err = json.Unmarshal(req, &sct)
		if err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodAddSCTReceipt, err, req)
			return
		}

		return nil, impl.AddSCTReceipt(core.SignedCertificateTimestamp(sct))
	})

	rpc.Handle(MethodCountFQDNSets, func(req []byte) (response []byte, err error) {
		var r countFQDNsRequest
		err = json.Unmarshal(req, &r)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodCountFQDNSets, err, req)
			return
		}
		count, err := impl.CountFQDNSets(r.Window, r.Names)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodCountFQDNSets, err, req)
			return
		}

		response, err = json.Marshal(countFQDNSetsResponse{count})
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodCountFQDNSets, err, req)
			return
		}

		return
	})

	rpc.Handle(MethodFQDNSetExists, func(req []byte) (response []byte, err error) {
		var r fqdnSetExistsRequest
		err = json.Unmarshal(req, &r)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodFQDNSetExists, err, req)
			return
		}
		exists, err := impl.FQDNSetExists(r.Names)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodFQDNSetExists, err, req)
			return
		}
		response, err = json.Marshal(fqdnSetExistsResponse{exists})
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodFQDNSetExists, err, req)
			return
		}

		return
	})

	return nil
}

// StorageAuthorityClient is a client to communicate with the Storage Authority
type StorageAuthorityClient struct {
	rpc Client
}

// NewStorageAuthorityClient constructs an RPC client
func NewStorageAuthorityClient(clientName string, amqpConf *cmd.AMQPConfig, stats statsd.Statter) (*StorageAuthorityClient, error) {
	client, err := NewAmqpRPCClient(clientName+"->SA", amqpConf, amqpConf.SA, stats)
	return &StorageAuthorityClient{rpc: client}, err
}

// GetRegistration sends a request to get a registration by ID
func (cac StorageAuthorityClient) GetRegistration(id int64) (reg core.Registration, err error) {
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
func (cac StorageAuthorityClient) GetRegistrationByKey(key jose.JsonWebKey) (reg core.Registration, err error) {
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
func (cac StorageAuthorityClient) GetAuthorization(id string) (authz core.Authorization, err error) {
	jsonAuthz, err := cac.rpc.DispatchSync(MethodGetAuthorization, []byte(id))
	if err != nil {
		return
	}

	err = json.Unmarshal(jsonAuthz, &authz)
	return
}

// GetLatestValidAuthorization sends a request to get an Authorization by RegID, Identifier
func (cac StorageAuthorityClient) GetLatestValidAuthorization(registrationID int64, identifier core.AcmeIdentifier) (authz core.Authorization, err error) {

	var lvar latestValidAuthorizationRequest
	lvar.RegID = registrationID
	lvar.Identifier = identifier

	data, err := json.Marshal(lvar)
	if err != nil {
		return
	}

	jsonAuthz, err := cac.rpc.DispatchSync(MethodGetLatestValidAuthorization, data)
	if err != nil {
		return
	}

	err = json.Unmarshal(jsonAuthz, &authz)
	return
}

// GetValidAuthorizations sends a request to get a batch of Authorizations by
// RegID and dnsName. The current time is also included in the request to
// assist filtering.
func (cac StorageAuthorityClient) GetValidAuthorizations(registrationID int64, names []string, now time.Time) (auths map[string]*core.Authorization, err error) {
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
func (cac StorageAuthorityClient) GetCertificate(id string) (cert core.Certificate, err error) {
	jsonCert, err := cac.rpc.DispatchSync(MethodGetCertificate, []byte(id))
	if err != nil {
		return
	}

	err = json.Unmarshal(jsonCert, &cert)
	return
}

// GetCertificateStatus sends a request to obtain the current status of a
// certificate by ID
func (cac StorageAuthorityClient) GetCertificateStatus(id string) (status core.CertificateStatus, err error) {
	jsonStatus, err := cac.rpc.DispatchSync(MethodGetCertificateStatus, []byte(id))
	if err != nil {
		return
	}

	err = json.Unmarshal(jsonStatus, &status)
	return
}

// MarkCertificateRevoked sends a request to mark a certificate as revoked
func (cac StorageAuthorityClient) MarkCertificateRevoked(serial string, reasonCode core.RevocationCode) (err error) {
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

// UpdateOCSP sends a request to store an updated OCSP response
func (cac StorageAuthorityClient) UpdateOCSP(serial string, ocspResponse []byte) (err error) {
	var updateOCSPReq updateOCSPRequest

	updateOCSPReq.Serial = serial
	updateOCSPReq.OCSPResponse = ocspResponse

	data, err := json.Marshal(updateOCSPReq)
	if err != nil {
		return
	}

	_, err = cac.rpc.DispatchSync(MethodUpdateOCSP, data)
	return
}

// UpdateRegistration sends a request to store an updated registration
func (cac StorageAuthorityClient) UpdateRegistration(reg core.Registration) (err error) {
	jsonReg, err := json.Marshal(reg)
	if err != nil {
		return
	}

	_, err = cac.rpc.DispatchSync(MethodUpdateRegistration, jsonReg)
	return
}

// NewRegistration sends a request to store a new registration
func (cac StorageAuthorityClient) NewRegistration(reg core.Registration) (output core.Registration, err error) {
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
func (cac StorageAuthorityClient) NewPendingAuthorization(authz core.Authorization) (output core.Authorization, err error) {
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
func (cac StorageAuthorityClient) UpdatePendingAuthorization(authz core.Authorization) (err error) {
	jsonAuthz, err := json.Marshal(authz)
	if err != nil {
		return
	}

	_, err = cac.rpc.DispatchSync(MethodUpdatePendingAuthorization, jsonAuthz)
	return
}

// FinalizeAuthorization sends a request to finalize an authorization (convert
// from pending)
func (cac StorageAuthorityClient) FinalizeAuthorization(authz core.Authorization) (err error) {
	jsonAuthz, err := json.Marshal(authz)
	if err != nil {
		return
	}

	_, err = cac.rpc.DispatchSync(MethodFinalizeAuthorization, jsonAuthz)
	return
}

// RevokeAuthorizationsByDomain sends a request to revoke all pending or finalized authorizations
// for a single domain
func (cac StorageAuthorityClient) RevokeAuthorizationsByDomain(ident core.AcmeIdentifier) (aRevoked int64, paRevoked int64, err error) {
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
func (cac StorageAuthorityClient) AddCertificate(cert []byte, regID int64) (id string, err error) {
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

// AlreadyDeniedCSR sends a request to search for denied names
func (cac StorageAuthorityClient) AlreadyDeniedCSR(names []string) (exists bool, err error) {
	var adcReq alreadyDeniedCSRReq
	adcReq.Names = names

	data, err := json.Marshal(adcReq)
	if err != nil {
		return
	}

	response, err := cac.rpc.DispatchSync(MethodAlreadyDeniedCSR, data)
	if err != nil {
		return
	}

	switch response[0] {
	case 0:
		exists = false
	case 1:
		exists = true
	}
	return
}

// CountCertificatesRange sends a request to count the number of certificates
// issued in  a certain time range
func (cac StorageAuthorityClient) CountCertificatesRange(start, end time.Time) (count int64, err error) {
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
func (cac StorageAuthorityClient) CountCertificatesByNames(names []string, earliest, latest time.Time) (counts map[string]int, err error) {
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
func (cac StorageAuthorityClient) CountRegistrationsByIP(ip net.IP, earliest, latest time.Time) (count int, err error) {
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
func (cac StorageAuthorityClient) CountPendingAuthorizations(regID int64) (count int, err error) {
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
func (cac StorageAuthorityClient) GetSCTReceipt(serial string, logID string) (receipt core.SignedCertificateTimestamp, err error) {
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
func (cac StorageAuthorityClient) AddSCTReceipt(sct core.SignedCertificateTimestamp) (err error) {
	data, err := json.Marshal(sct)
	if err != nil {
		return
	}

	_, err = cac.rpc.DispatchSync(MethodAddSCTReceipt, data)
	return
}

// CountFQDNSets reutrns the number of currently valid sets with hash |setHash|
func (cac StorageAuthorityClient) CountFQDNSets(window time.Duration, names []string) (int64, error) {
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
func (cac StorageAuthorityClient) FQDNSetExists(names []string) (bool, error) {
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
