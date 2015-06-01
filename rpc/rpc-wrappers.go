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
	"time"

	jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/square/go-jose"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/streadway/amqp"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
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

const (
	MethodNewRegistration             = "NewRegistration"             // RA, SA
	MethodNewAuthorization            = "NewAuthorization"            // RA
	MethodNewCertificate              = "NewCertificate"              // RA
	MethodUpdateRegistration          = "UpdateRegistration"          // RA, SA
	MethodUpdateAuthorization         = "UpdateAuthorization"         // RA
	MethodRevokeCertificate           = "RevokeCertificate"           // RA, CA
	MethodOnValidationUpdate          = "OnValidationUpdate"          // RA
	MethodUpdateValidations           = "UpdateValidations"           // VA
	MethodIssueCertificate            = "IssueCertificate"            // CA
	MethodGenerateOCSP                = "GenerateOCSP"                // CA
	MethodGetRegistration             = "GetRegistration"             // SA
	MethodGetRegistrationByKey        = "GetRegistrationByKey"        // RA, SA
	MethodGetAuthorization            = "GetAuthorization"            // SA
	MethodGetCertificate              = "GetCertificate"              // SA
	MethodGetCertificateByShortSerial = "GetCertificateByShortSerial" // SA
	MethodGetCertificateStatus        = "GetCertificateStatus"        // SA
	MethodMarkCertificateRevoked      = "MarkCertificateRevoked"      // SA
	MethodNewPendingAuthorization     = "NewPendingAuthorization"     // SA
	MethodUpdatePendingAuthorization  = "UpdatePendingAuthorization"  // SA
	MethodFinalizeAuthorization       = "FinalizeAuthorization"       // SA
	MethodAddCertificate              = "AddCertificate"              // SA
	MethodAlreadyDeniedCSR            = "AlreadyDeniedCSR"            // SA
)

// RegistrationAuthorityClient / Server
//  -> NewAuthorization
//  -> NewCertificate
//  -> UpdateAuthorization
//  -> RevokeCertificate
//  -> OnValidationUpdate
type registrationRequest struct {
	Reg core.Registration
}

type authorizationRequest struct {
	Authz core.Authorization
	RegID int64
}

type certificateRequest struct {
	Req   core.CertificateRequest
	RegID int64
}

func improperMessage(method string, err error, obj interface{}) {
	log := blog.GetAuditLogger()
	log.Audit(fmt.Sprintf("Improper message. method: %s err: %s data: %+v", method, err, obj))
}
func errorCondition(method string, err error, obj interface{}) {
	log := blog.GetAuditLogger()
	log.Audit(fmt.Sprintf("Error condition. method: %s err: %s data: %+v", method, err, obj))
}

func NewRegistrationAuthorityServer(serverQueue string, channel *amqp.Channel, impl core.RegistrationAuthority) (*AmqpRPCServer, error) {
	log := blog.GetAuditLogger()
	rpc := NewAmqpRPCServer(serverQueue, channel)

	rpc.Handle(MethodNewRegistration, func(req []byte) (response []byte) {
		var rr registrationRequest
		if err := json.Unmarshal(req, &rr); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodNewRegistration, err, req)
			return nil
		}

		reg, err := impl.NewRegistration(rr.Reg)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodNewRegistration, err, reg)
			return nil
		}

		response, err = json.Marshal(reg)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodNewRegistration, err, req)
			return nil
		}
		return response
	})

	rpc.Handle(MethodNewAuthorization, func(req []byte) (response []byte) {
		var ar authorizationRequest
		if err := json.Unmarshal(req, &ar); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodNewAuthorization, err, req)
			return nil
		}

		authz, err := impl.NewAuthorization(ar.Authz, ar.RegID)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodNewAuthorization, err, ar)
			return nil
		}

		response, err = json.Marshal(authz)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodNewAuthorization, err, req)
			return nil
		}
		return response
	})

	rpc.Handle(MethodNewCertificate, func(req []byte) []byte {
		log.Info(fmt.Sprintf(" [.] Entering MethodNewCertificate"))
		var cr certificateRequest
		if err := json.Unmarshal(req, &cr); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodNewCertificate, err, req)
			return nil
		}
		log.Info(fmt.Sprintf(" [.] No problem unmarshaling request"))

		cert, err := impl.NewCertificate(cr.Req, cr.RegID)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodNewCertificate, err, cr)
			return nil
		}
		log.Info(fmt.Sprintf(" [.] No problem issuing new cert"))

		response, err := json.Marshal(cert)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodNewCertificate, err, req)
			return nil
		}
		return response
	})

	rpc.Handle(MethodUpdateRegistration, func(req []byte) (response []byte) {
		var request struct {
			Base, Update core.Registration
		}
		err := json.Unmarshal(req, &request)
		if err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodUpdateRegistration, err, req)
			return nil
		}

		reg, err := impl.UpdateRegistration(request.Base, request.Update)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodUpdateRegistration, err, request)
			return nil
		}

		response, err = json.Marshal(reg)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodUpdateRegistration, err, req)
			return nil
		}
		return response
	})

	rpc.Handle(MethodUpdateAuthorization, func(req []byte) (response []byte) {
		var authz struct {
			Authz    core.Authorization
			Index    int
			Response core.Challenge
		}
		err := json.Unmarshal(req, &authz)
		if err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodUpdateAuthorization, err, req)
			return nil
		}

		newAuthz, err := impl.UpdateAuthorization(authz.Authz, authz.Index, authz.Response)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodUpdateAuthorization, err, authz)
			return nil
		}

		response, err = json.Marshal(newAuthz)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodUpdateAuthorization, err, req)
			return nil
		}
		return response
	})

	rpc.Handle(MethodRevokeCertificate, func(req []byte) []byte {
		certs, err := x509.ParseCertificates(req)
		if err != nil || len(certs) == 0 {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodRevokeCertificate, err, req)
			return nil
		}

		// Error explicitly ignored since response is nil anyway
		err = impl.RevokeCertificate(*certs[0])
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodRevokeCertificate, err, certs)
		}
		return nil
	})

	rpc.Handle(MethodOnValidationUpdate, func(req []byte) []byte {
		var authz core.Authorization
		if err := json.Unmarshal(req, &authz); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodOnValidationUpdate, err, req)
			return nil
		}

		if err := impl.OnValidationUpdate(authz); err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodOnValidationUpdate, err, authz)
		}
		return nil
	})

	return rpc, nil
}

type RegistrationAuthorityClient struct {
	rpc *AmqpRPCCLient
}

func NewRegistrationAuthorityClient(clientQueue, serverQueue string, channel *amqp.Channel) (rac RegistrationAuthorityClient, err error) {
	rpc, err := NewAmqpRPCCLient(clientQueue, serverQueue, channel)
	if err != nil {
		return
	}

	rac = RegistrationAuthorityClient{rpc: rpc}
	return
}

func (rac RegistrationAuthorityClient) NewRegistration(reg core.Registration) (newReg core.Registration, err error) {
	data, err := json.Marshal(registrationRequest{reg})
	if err != nil {
		return
	}

	newRegData, err := rac.rpc.DispatchSync(MethodNewRegistration, data)
	if err != nil || len(newRegData) == 0 {
		return
	}

	err = json.Unmarshal(newRegData, &newReg)
	return
}

func (rac RegistrationAuthorityClient) NewAuthorization(authz core.Authorization, regID int64) (newAuthz core.Authorization, err error) {
	data, err := json.Marshal(authorizationRequest{authz, regID})
	if err != nil {
		return
	}

	newAuthzData, err := rac.rpc.DispatchSync(MethodNewAuthorization, data)
	if err != nil || len(newAuthzData) == 0 {
		return
	}

	err = json.Unmarshal(newAuthzData, &newAuthz)
	return
}

func (rac RegistrationAuthorityClient) NewCertificate(cr core.CertificateRequest, regID int64) (cert core.Certificate, err error) {
	data, err := json.Marshal(certificateRequest{cr, regID})
	if err != nil {
		return
	}

	certData, err := rac.rpc.DispatchSync(MethodNewCertificate, data)
	if err != nil || len(certData) == 0 {
		return
	}

	err = json.Unmarshal(certData, &cert)
	return
}

func (rac RegistrationAuthorityClient) UpdateRegistration(base core.Registration, update core.Registration) (newReg core.Registration, err error) {
	var toSend struct{ Base, Update core.Registration }
	toSend.Base = base
	toSend.Update = update

	data, err := json.Marshal(toSend)
	if err != nil {
		return
	}

	newRegData, err := rac.rpc.DispatchSync(MethodUpdateRegistration, data)
	if err != nil || len(newRegData) == 0 {
		return
	}

	err = json.Unmarshal(newRegData, &newReg)
	return
}

func (rac RegistrationAuthorityClient) UpdateAuthorization(authz core.Authorization, index int, response core.Challenge) (newAuthz core.Authorization, err error) {
	var toSend struct {
		Authz    core.Authorization
		Index    int
		Response core.Challenge
	}
	toSend.Authz = authz
	toSend.Index = index
	toSend.Response = response

	data, err := json.Marshal(toSend)
	if err != nil {
		return
	}

	newAuthzData, err := rac.rpc.DispatchSync(MethodUpdateAuthorization, data)
	if err != nil || len(newAuthzData) == 0 {
		return
	}

	err = json.Unmarshal(newAuthzData, &newAuthz)
	return
}

func (rac RegistrationAuthorityClient) RevokeCertificate(cert x509.Certificate) (err error) {
	rac.rpc.Dispatch(MethodRevokeCertificate, cert.Raw)
	return
}

func (rac RegistrationAuthorityClient) OnValidationUpdate(authz core.Authorization) (err error) {
	data, err := json.Marshal(authz)
	if err != nil {
		return
	}

	rac.rpc.Dispatch(MethodOnValidationUpdate, data)
	return
}

// ValidationAuthorityClient / Server
//  -> UpdateValidations
func NewValidationAuthorityServer(serverQueue string, channel *amqp.Channel, impl core.ValidationAuthority) (rpc *AmqpRPCServer, err error) {
	rpc = NewAmqpRPCServer(serverQueue, channel)

	rpc.Handle(MethodUpdateValidations, func(req []byte) []byte {
		var vaReq struct {
			Authz core.Authorization
			Index int
		}
		if err := json.Unmarshal(req, &vaReq); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodUpdateValidations, err, req)
			return nil
		}

		if err := impl.UpdateValidations(vaReq.Authz, vaReq.Index); err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodUpdateValidations, err, vaReq)
		}
		return nil
	})

	return rpc, nil
}

type ValidationAuthorityClient struct {
	rpc *AmqpRPCCLient
}

func NewValidationAuthorityClient(clientQueue, serverQueue string, channel *amqp.Channel) (vac ValidationAuthorityClient, err error) {
	rpc, err := NewAmqpRPCCLient(clientQueue, serverQueue, channel)
	if err != nil {
		return
	}

	vac = ValidationAuthorityClient{rpc: rpc}
	return
}

func (vac ValidationAuthorityClient) UpdateValidations(authz core.Authorization, index int) error {
	var vaReq struct {
		Authz core.Authorization
		Index int
	}
	vaReq.Authz = authz
	vaReq.Index = index
	data, err := json.Marshal(vaReq)
	if err != nil {
		return err
	}

	vac.rpc.Dispatch(MethodUpdateValidations, data)
	return nil
}

// CertificateAuthorityClient / Server
//  -> IssueCertificate
func NewCertificateAuthorityServer(serverQueue string, channel *amqp.Channel, impl core.CertificateAuthority) (rpc *AmqpRPCServer, err error) {
	rpc = NewAmqpRPCServer(serverQueue, channel)

	rpc.Handle(MethodIssueCertificate, func(req []byte) []byte {
		var icReq struct {
			Bytes          []byte
			RegID          int64
			EarliestExpiry time.Time
		}
		err := json.Unmarshal(req, &icReq)
		if err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodIssueCertificate, err, req)
			return nil
		}

		csr, err := x509.ParseCertificateRequest(icReq.Bytes)
		if err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodIssueCertificate, err, req)
			return nil // XXX
		}

		cert, err := impl.IssueCertificate(*csr, icReq.RegID, icReq.EarliestExpiry)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodIssueCertificate, err, csr)
			return nil // XXX
		}

		serialized, err := json.Marshal(cert)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodGetRegistration, err, req)
			return nil // XXX
		}

		return serialized
	})

	rpc.Handle(MethodRevokeCertificate, func(req []byte) []byte {
		var revokeReq struct {
			Serial     string
			ReasonCode int
		}
		err := json.Unmarshal(req, &revokeReq)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodRevokeCertificate, err, req)
			return nil
		}

		if err := impl.RevokeCertificate(revokeReq.Serial, revokeReq.ReasonCode); err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodRevokeCertificate, err, req)
		}

		return nil
	})

	rpc.Handle(MethodGenerateOCSP, func(req []byte) []byte {
		var xferObj core.OCSPSigningRequest
		err := json.Unmarshal(req, &xferObj)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodGenerateOCSP, err, req)
			return nil
		}

		data, err := impl.GenerateOCSP(xferObj)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodGenerateOCSP, err, req)
			return nil
		}

		return data
	})

	return
}

type CertificateAuthorityClient struct {
	rpc *AmqpRPCCLient
}

func NewCertificateAuthorityClient(clientQueue, serverQueue string, channel *amqp.Channel) (cac CertificateAuthorityClient, err error) {
	rpc, err := NewAmqpRPCCLient(clientQueue, serverQueue, channel)
	if err != nil {
		return
	}

	cac = CertificateAuthorityClient{rpc: rpc}
	return
}

func (cac CertificateAuthorityClient) IssueCertificate(csr x509.CertificateRequest, regID int64, earliestExpiry time.Time) (cert core.Certificate, err error) {
	var icReq struct {
		Bytes          []byte
		RegID          int64
		EarliestExpiry time.Time
	}
	icReq.Bytes = csr.Raw
	icReq.RegID = regID
	data, err := json.Marshal(icReq)
	if err != nil {
		return
	}

	jsonResponse, err := cac.rpc.DispatchSync(MethodIssueCertificate, data)
	if len(jsonResponse) == 0 {
		// TODO: Better error handling
		return
	}

	err = json.Unmarshal(jsonResponse, &cert)
	return
}

func (cac CertificateAuthorityClient) RevokeCertificate(serial string, reasonCode int) (err error) {
	var revokeReq struct {
		Serial     string
		ReasonCode int
	}
	revokeReq.Serial = serial
	revokeReq.ReasonCode = reasonCode

	data, err := json.Marshal(revokeReq)
	if err != nil {
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		errorCondition(MethodRevokeCertificate, err, revokeReq)
		return
	}

	_, err = cac.rpc.DispatchSync(MethodRevokeCertificate, data)
	return
}

func (cac CertificateAuthorityClient) GenerateOCSP(signRequest core.OCSPSigningRequest) (resp []byte, err error) {
	data, err := json.Marshal(signRequest)
	if err != nil {
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		errorCondition(MethodGetRegistration, err, signRequest)
		return
	}

	resp, err = cac.rpc.DispatchSync(MethodGenerateOCSP, data)
	return
}

func NewStorageAuthorityServer(serverQueue string, channel *amqp.Channel, impl core.StorageAuthority) *AmqpRPCServer {
	rpc := NewAmqpRPCServer(serverQueue, channel)

	rpc.Handle(MethodUpdateRegistration, func(req []byte) (response []byte) {
		var reg core.Registration
		if err := json.Unmarshal(req, &reg); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodUpdateRegistration, err, req)
			return nil
		}

		if err := impl.UpdateRegistration(reg); err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodUpdateRegistration, err, req)
		}

		return nil
	})

	rpc.Handle(MethodGetRegistration, func(req []byte) (response []byte) {
		var intReq struct {
			ID int64
		}
		err := json.Unmarshal(req, &intReq)
		if err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodGetRegistration, err, req)
			return nil
		}

		reg, err := impl.GetRegistration(intReq.ID)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodGetRegistration, err, req)
			return nil
		}

		response, err = json.Marshal(reg)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodGetRegistration, err, req)
			return nil
		}
		return response
	})

	rpc.Handle(MethodGetRegistrationByKey, func(req []byte) (response []byte) {
		var jwk jose.JsonWebKey
		if err := json.Unmarshal(req, &jwk); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodGetRegistrationByKey, err, req)
			return nil
		}

		reg, err := impl.GetRegistrationByKey(jwk)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodGetRegistrationByKey, err, jwk)
			return nil
		}

		response, err = json.Marshal(reg)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodGetRegistrationByKey, err, req)
			return nil
		}
		return response
	})

	rpc.Handle(MethodGetAuthorization, func(req []byte) []byte {
		authz, err := impl.GetAuthorization(string(req))
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodGetAuthorization, err, req)
			return nil
		}

		jsonAuthz, err := json.Marshal(authz)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodGetAuthorization, err, req)
			return nil
		}
		return jsonAuthz
	})

	rpc.Handle(MethodAddCertificate, func(req []byte) []byte {
		var icReq struct {
			Bytes []byte
			RegID int64
		}
		err := json.Unmarshal(req, &icReq)
		if err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodAddCertificate, err, req)
			return nil
		}

		id, err := impl.AddCertificate(icReq.Bytes, icReq.RegID)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodAddCertificate, err, req)
			return nil
		}
		return []byte(id)
	})

	rpc.Handle(MethodNewRegistration, func(req []byte) []byte {
		var registration core.Registration
		err := json.Unmarshal(req, &registration)
		if err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodNewRegistration, err, req)
			return nil
		}

		output, err := impl.NewRegistration(registration)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodNewRegistration, err, registration)
			return nil
		}

		jsonOutput, err := json.Marshal(output)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodNewRegistration, err, req)
			return nil
		}
		return []byte(jsonOutput)
	})

	rpc.Handle(MethodNewPendingAuthorization, func(req []byte) []byte {
		var authz core.Authorization
		if err := json.Unmarshal(req, &authz); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodNewPendingAuthorization, err, req)
			return nil
		}

		output, err := impl.NewPendingAuthorization(authz)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodNewPendingAuthorization, err, req)
			return nil
		}

		jsonOutput, err := json.Marshal(output)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodNewPendingAuthorization, err, req)
			return nil
		}
		return []byte(jsonOutput)
	})

	rpc.Handle(MethodUpdatePendingAuthorization, func(req []byte) []byte {
		var authz core.Authorization
		if err := json.Unmarshal(req, &authz); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodUpdatePendingAuthorization, err, req)
			return nil
		}

		if err := impl.UpdatePendingAuthorization(authz); err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodUpdatePendingAuthorization, err, authz)
		}
		return nil
	})

	rpc.Handle(MethodFinalizeAuthorization, func(req []byte) []byte {
		var authz core.Authorization
		if err := json.Unmarshal(req, &authz); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodFinalizeAuthorization, err, req)
			return nil
		}

		if err := impl.FinalizeAuthorization(authz); err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodFinalizeAuthorization, err, authz)
		}
		return nil
	})

	rpc.Handle(MethodGetCertificate, func(req []byte) (response []byte) {
		cert, err := impl.GetCertificate(string(req))
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodGetCertificate, err, req)
		} else {
			response = []byte(cert)
		}
		return response
	})

	rpc.Handle(MethodGetCertificateByShortSerial, func(req []byte) (response []byte) {
		cert, err := impl.GetCertificateByShortSerial(string(req))
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodGetCertificateByShortSerial, err, req)
		}

		jsonResponse, err := json.Marshal(cert)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodGetCertificateByShortSerial, err, req)
			return nil
		}

		return jsonResponse
	})

	rpc.Handle(MethodGetCertificateStatus, func(req []byte) (response []byte) {
		status, err := impl.GetCertificateStatus(string(req))
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodGetCertificateStatus, err, req)
			return nil
		}

		jsonStatus, err := json.Marshal(status)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodGetCertificateStatus, err, req)
			return nil
		}
		return jsonStatus
	})

	rpc.Handle(MethodMarkCertificateRevoked, func(req []byte) (response []byte) {
		var revokeReq struct {
			Serial       string
			OCSPResponse []byte
			ReasonCode   int
		}

		if err := json.Unmarshal(req, &revokeReq); err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodMarkCertificateRevoked, err, req)
			return nil
		}

		// Error explicitly ignored since response is nil anyway
		err := impl.MarkCertificateRevoked(revokeReq.Serial, revokeReq.OCSPResponse, revokeReq.ReasonCode)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodMarkCertificateRevoked, err, revokeReq)
		}
		return nil
	})

	rpc.Handle(MethodAlreadyDeniedCSR, func(req []byte) []byte {
		var csrReq struct {
			Names []string
		}

		err := json.Unmarshal(req, &csrReq)
		if err != nil {
			// AUDIT[ Improper Messages ] 0786b6f2-91ca-4f48-9883-842a19084c64
			improperMessage(MethodAlreadyDeniedCSR, err, req)
			return nil
		}

		exists, err := impl.AlreadyDeniedCSR(csrReq.Names)
		if err != nil {
			// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
			errorCondition(MethodAlreadyDeniedCSR, err, csrReq)
			return nil
		}

		if exists {
			return []byte{1}
		} else {
			return []byte{0}
		}
	})

	return rpc
}

type StorageAuthorityClient struct {
	rpc *AmqpRPCCLient
}

func NewStorageAuthorityClient(clientQueue, serverQueue string, channel *amqp.Channel) (sac StorageAuthorityClient, err error) {
	rpc, err := NewAmqpRPCCLient(clientQueue, serverQueue, channel)
	if err != nil {
		return
	}

	sac = StorageAuthorityClient{rpc: rpc}
	return
}

func (cac StorageAuthorityClient) GetRegistration(id int64) (reg core.Registration, err error) {
	var intReq struct {
		ID int64
	}
	intReq.ID = id

	data, err := json.Marshal(intReq)
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

func (cac StorageAuthorityClient) GetAuthorization(id string) (authz core.Authorization, err error) {
	jsonAuthz, err := cac.rpc.DispatchSync(MethodGetAuthorization, []byte(id))
	if err != nil {
		return
	}

	err = json.Unmarshal(jsonAuthz, &authz)
	return
}

func (cac StorageAuthorityClient) GetCertificate(id string) (cert []byte, err error) {
	cert, err = cac.rpc.DispatchSync(MethodGetCertificate, []byte(id))
	return
}

func (cac StorageAuthorityClient) GetCertificateByShortSerial(id string) (cert core.Certificate, err error) {
	jsonCert, err := cac.rpc.DispatchSync(MethodGetCertificateByShortSerial, []byte(id))
	if err != nil {
		return
	}

	err = json.Unmarshal(jsonCert, &cert)
	return
}

func (cac StorageAuthorityClient) GetCertificateStatus(id string) (status core.CertificateStatus, err error) {
	jsonStatus, err := cac.rpc.DispatchSync(MethodGetCertificateStatus, []byte(id))
	if err != nil {
		return
	}

	err = json.Unmarshal(jsonStatus, &status)
	return
}

func (cac StorageAuthorityClient) MarkCertificateRevoked(serial string, ocspResponse []byte, reasonCode int) (err error) {
	var revokeReq struct {
		Serial       string
		OCSPResponse []byte
		ReasonCode   int
	}

	revokeReq.Serial = serial
	revokeReq.OCSPResponse = ocspResponse
	revokeReq.ReasonCode = reasonCode

	data, err := json.Marshal(revokeReq)
	if err != nil {
		return
	}

	_, err = cac.rpc.DispatchSync(MethodMarkCertificateRevoked, data)
	return
}

func (cac StorageAuthorityClient) UpdateRegistration(reg core.Registration) (err error) {
	jsonReg, err := json.Marshal(reg)
	if err != nil {
		return
	}

	// XXX: Is this catching all the errors?
	_, err = cac.rpc.DispatchSync(MethodUpdateRegistration, jsonReg)
	return
}

func (cac StorageAuthorityClient) NewRegistration(reg core.Registration) (output core.Registration, err error) {
	jsonReg, err := json.Marshal(reg)
	if err != nil {
		err = errors.New("NewRegistration RPC failed")
		return
	}
	response, err := cac.rpc.DispatchSync(MethodNewRegistration, jsonReg)
	if err != nil || len(response) == 0 {
		err = errors.New("NewRegistration RPC failed") // XXX
		return
	}
	err = json.Unmarshal(response, &output)
	if err != nil {
		err = errors.New("NewRegistration RPC failed")
		return
	}
	return output, nil
}

func (cac StorageAuthorityClient) NewPendingAuthorization(authz core.Authorization) (output core.Authorization, err error) {
	jsonAuthz, err := json.Marshal(authz)
	if err != nil {
		return
	}
	response, err := cac.rpc.DispatchSync(MethodNewPendingAuthorization, jsonAuthz)
	if err != nil || len(response) == 0 {
		err = errors.New("NewPendingAuthorization RPC failed") // XXX
		return
	}
	err = json.Unmarshal(response, &output)
	if err != nil {
		err = errors.New("NewRegistration RPC failed")
		return
	}
	return
}

func (cac StorageAuthorityClient) UpdatePendingAuthorization(authz core.Authorization) (err error) {
	jsonAuthz, err := json.Marshal(authz)
	if err != nil {
		return
	}

	// XXX: Is this catching all the errors?
	_, err = cac.rpc.DispatchSync(MethodUpdatePendingAuthorization, jsonAuthz)
	return
}

func (cac StorageAuthorityClient) FinalizeAuthorization(authz core.Authorization) (err error) {
	jsonAuthz, err := json.Marshal(authz)
	if err != nil {
		return
	}

	// XXX: Is this catching all the errors?
	_, err = cac.rpc.DispatchSync(MethodFinalizeAuthorization, jsonAuthz)
	return
}

func (cac StorageAuthorityClient) AddCertificate(cert []byte, regID int64) (id string, err error) {
	var icReq struct {
		Bytes []byte
		RegID int64
	}
	icReq.Bytes = cert
	icReq.RegID = regID
	data, err := json.Marshal(icReq)
	if err != nil {
		return
	}

	response, err := cac.rpc.DispatchSync(MethodAddCertificate, data)
	if err != nil || len(response) == 0 {
		err = errors.New("AddCertificate RPC failed") // XXX
		return
	}
	id = string(response)
	return
}

func (cac StorageAuthorityClient) AlreadyDeniedCSR(names []string) (exists bool, err error) {
	var sliceReq struct {
		Names []string
	}
	sliceReq.Names = names

	data, err := json.Marshal(sliceReq)
	if err != nil {
		return
	}

	response, err := cac.rpc.DispatchSync(MethodAlreadyDeniedCSR, data)
	if err != nil || len(response) == 0 {
		err = errors.New("AlreadyDeniedCSR RPC failed") // XXX
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
