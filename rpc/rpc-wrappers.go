// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package rpc

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"log"

	"github.com/streadway/amqp"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/jose"
)

// This file defines RPC wrappers around the ${ROLE}Impl classes,
// where ROLE covers:
//  * RegistrationAuthority
//  * ValidationAuthority
//  * CertficateAuthority
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
	MethodNewRegistration            = "NewRegistration"            // RA, SA
	MethodNewAuthorization           = "NewAuthorization"           // RA
	MethodNewCertificate             = "NewCertificate"             // RA
	MethodUpdateRegistration         = "UpdateRegistration"         // RA, SA
	MethodUpdateAuthorization        = "UpdateAuthorization"        // RA
	MethodRevokeCertificate          = "RevokeCertificate"          // RA
	MethodOnValidationUpdate         = "OnValidationUpdate"         // RA
	MethodUpdateValidations          = "UpdateValidations"          // VA
	MethodIssueCertificate           = "IssueCertificate"           // CA
	MethodGetRegistration            = "GetRegistration"            // SA
	MethodGetAuthorization           = "GetAuthorization"           // SA
	MethodGetCertificate             = "GetCertificate"             // SA
	MethodNewPendingAuthorization    = "NewPendingAuthorization"    // SA
	MethodUpdatePendingAuthorization = "UpdatePendingAuthorization" // SA
	MethodFinalizeAuthorization      = "FinalizeAuthorization"      // SA
	MethodAddCertificate             = "AddCertificate"             // SA
)

// RegistrationAuthorityClient / Server
//  -> NewAuthorization
//  -> NewCertificate
//  -> UpdateAuthorization
//  -> RevokeCertificate
//  -> OnValidationUpdate
type registrationRequest struct {
	Reg core.Registration
	Key jose.JsonWebKey
}

type authorizationRequest struct {
	Authz core.Authorization
	Key   jose.JsonWebKey
}

type certificateRequest struct {
	Req core.CertificateRequest
	Key jose.JsonWebKey
}

func NewRegistrationAuthorityServer(serverQueue string, channel *amqp.Channel, impl core.RegistrationAuthority) (rpc *AmqpRpcServer, err error) {
	rpc = NewAmqpRpcServer(serverQueue, channel)

	rpc.Handle(MethodNewRegistration, func(req []byte) (response []byte) {
		var rr registrationRequest
		err := json.Unmarshal(req, &rr)
		if err != nil {
			return
		}

		reg, err := impl.NewRegistration(rr.Reg, rr.Key)
		if err != nil {
			return
		}

		response, err = json.Marshal(reg)
		if err != nil {
			response = []byte{}
		}
		return
	})

	rpc.Handle(MethodNewAuthorization, func(req []byte) (response []byte) {
		var ar authorizationRequest
		err := json.Unmarshal(req, &ar)
		if err != nil {
			return
		}

		authz, err := impl.NewAuthorization(ar.Authz, ar.Key)
		if err != nil {
			return
		}

		response, err = json.Marshal(authz)
		if err != nil {
			response = []byte{}
		}
		return
	})

	rpc.Handle(MethodNewCertificate, func(req []byte) (response []byte) {
		log.Printf(" [.] Entering MethodNewCertificate")
		var cr certificateRequest
		err := json.Unmarshal(req, &cr)
		if err != nil {
			log.Printf(" [!] Error unmarshaling certificate request: %s", err.Error())
			log.Printf("     JSON data: %s", string(req))
			return
		}
		log.Printf(" [.] No problem unmarshaling request")

		cert, err := impl.NewCertificate(cr.Req, cr.Key)
		if err != nil {
			log.Printf(" [!] Error issuing new certificate: %s", err.Error())
			return
		}
		log.Printf(" [.] No problem issuing new cert")

		response, err = json.Marshal(cert)
		if err != nil {
			response = []byte{}
		}
		return
	})

	rpc.Handle(MethodUpdateRegistration, func(req []byte) (response []byte) {
		var request struct {
			Base, Update core.Registration
		}
		err := json.Unmarshal(req, &request)
		if err != nil {
			return
		}

		reg, err := impl.UpdateRegistration(request.Base, request.Update)
		if err != nil {
			return
		}

		response, err = json.Marshal(reg)
		if err != nil {
			response = []byte{}
		}
		return
	})

	rpc.Handle(MethodUpdateAuthorization, func(req []byte) (response []byte) {
		var authz struct {
			Authz    core.Authorization
			Index    int
			Response core.Challenge
		}
		err := json.Unmarshal(req, &authz)
		if err != nil {
			return
		}

		newAuthz, err := impl.UpdateAuthorization(authz.Authz, authz.Index, authz.Response)
		if err != nil {
			return
		}

		response, err = json.Marshal(newAuthz)
		if err != nil {
			response = []byte{}
		}
		return
	})

	rpc.Handle(MethodRevokeCertificate, func(req []byte) (response []byte) {
		// Nobody's listening, so it doesn't matter what we return
		response = []byte{}

		certs, err := x509.ParseCertificates(req)
		if err != nil || len(certs) == 0 {
			return
		}

		impl.RevokeCertificate(*certs[0])
		return
	})

	rpc.Handle(MethodOnValidationUpdate, func(req []byte) (response []byte) {
		// Nobody's listening, so it doesn't matter what we return
		response = []byte{}

		var authz core.Authorization
		err := json.Unmarshal(req, &authz)
		if err != nil {
			return
		}

		impl.OnValidationUpdate(authz)
		return
	})

	return rpc, nil
}

type RegistrationAuthorityClient struct {
	rpc *AmqpRpcClient
}

func NewRegistrationAuthorityClient(clientQueue, serverQueue string, channel *amqp.Channel) (rac RegistrationAuthorityClient, err error) {
	rpc, err := NewAmqpRpcClient(clientQueue, serverQueue, channel)
	if err != nil {
		return
	}

	rac = RegistrationAuthorityClient{rpc: rpc}
	return
}

func (rac RegistrationAuthorityClient) NewRegistration(reg core.Registration, key jose.JsonWebKey) (newReg core.Registration, err error) {
	data, err := json.Marshal(registrationRequest{reg, key})
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

func (rac RegistrationAuthorityClient) NewAuthorization(authz core.Authorization, key jose.JsonWebKey) (newAuthz core.Authorization, err error) {
	data, err := json.Marshal(authorizationRequest{authz, key})
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

func (rac RegistrationAuthorityClient) NewCertificate(cr core.CertificateRequest, key jose.JsonWebKey) (cert core.Certificate, err error) {
	data, err := json.Marshal(certificateRequest{cr, key})
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

func (rac RegistrationAuthorityClient) OnValidationUpdate(authz core.Authorization) {
	data, err := json.Marshal(authz)
	if err != nil {
		return
	}

	rac.rpc.Dispatch(MethodOnValidationUpdate, data)
	return
}

// ValidationAuthorityClient / Server
//  -> UpdateValidations
func NewValidationAuthorityServer(serverQueue string, channel *amqp.Channel, impl core.ValidationAuthority) (rpc *AmqpRpcServer, err error) {
	rpc = NewAmqpRpcServer(serverQueue, channel)

	rpc.Handle(MethodUpdateValidations, func(req []byte) []byte {
		// Nobody's listening, so it doesn't matter what we return
		zero := []byte{}

		var authz core.Authorization
		err := json.Unmarshal(req, &authz)
		if err != nil {
			return zero
		}

		impl.UpdateValidations(authz)
		return zero
	})

	return rpc, nil
}

type ValidationAuthorityClient struct {
	rpc *AmqpRpcClient
}

func NewValidationAuthorityClient(clientQueue, serverQueue string, channel *amqp.Channel) (vac ValidationAuthorityClient, err error) {
	rpc, err := NewAmqpRpcClient(clientQueue, serverQueue, channel)
	if err != nil {
		return
	}

	vac = ValidationAuthorityClient{rpc: rpc}
	return
}

func (vac ValidationAuthorityClient) UpdateValidations(authz core.Authorization) error {
	data, err := json.Marshal(authz)
	if err != nil {
		return err
	}

	vac.rpc.Dispatch(MethodUpdateValidations, data)
	return nil
}

// CertificateAuthorityClient / Server
//  -> IssueCertificate
func NewCertificateAuthorityServer(serverQueue string, channel *amqp.Channel, impl core.CertificateAuthority) (rpc *AmqpRpcServer, err error) {
	rpc = NewAmqpRpcServer(serverQueue, channel)

	rpc.Handle(MethodIssueCertificate, func(req []byte) []byte {
		zero := []byte{}

		csr, err := x509.ParseCertificateRequest(req)
		if err != nil {
			return zero // XXX
		}

		cert, err := impl.IssueCertificate(*csr)
		if err != nil {
			return zero // XXX
		}

		serialized, err := json.Marshal(cert)
		if err != nil {
			return zero // XXX
		}

		return serialized
	})

	return
}

type CertificateAuthorityClient struct {
	rpc *AmqpRpcClient
}

func NewCertificateAuthorityClient(clientQueue, serverQueue string, channel *amqp.Channel) (cac CertificateAuthorityClient, err error) {
	rpc, err := NewAmqpRpcClient(clientQueue, serverQueue, channel)
	if err != nil {
		return
	}

	cac = CertificateAuthorityClient{rpc: rpc}
	return
}

func (cac CertificateAuthorityClient) IssueCertificate(csr x509.CertificateRequest) (cert core.Certificate, err error) {
	jsonResponse, err := cac.rpc.DispatchSync(MethodIssueCertificate, csr.Raw)
	if len(jsonResponse) == 0 {
		// TODO: Better error handling
		return
	}

	err = json.Unmarshal(jsonResponse, &cert)
	return
}

func NewStorageAuthorityServer(serverQueue string, channel *amqp.Channel, impl core.StorageAuthority) (rpc *AmqpRpcServer) {
	rpc = NewAmqpRpcServer(serverQueue, channel)

	rpc.Handle(MethodGetRegistration, func(req []byte) (response []byte) {
		reg, err := impl.GetCertificate(string(req))
		if err != nil {
			return
		}

		jsonReg, err := json.Marshal(reg)
		if err != nil {
			return
		}
		response = jsonReg
		return
	})

	rpc.Handle(MethodGetAuthorization, func(req []byte) (response []byte) {
		authz, err := impl.AddCertificate(req)
		if err != nil {
			return
		}

		jsonAuthz, err := json.Marshal(authz)
		if err == nil {
			response = jsonAuthz
		}
		return
	})

	rpc.Handle(MethodAddCertificate, func(req []byte) (response []byte) {
		id, err := impl.AddCertificate(req)
		if err == nil {
			response = []byte(id)
		}
		return
	})

	rpc.Handle(MethodNewRegistration, func(req []byte) (response []byte) {
		id, err := impl.NewRegistration()
		if err == nil {
			response = []byte(id)
		}
		return
	})

	rpc.Handle(MethodNewPendingAuthorization, func(req []byte) (response []byte) {
		id, err := impl.NewPendingAuthorization()
		if err == nil {
			response = []byte(id)
		}
		return
	})

	rpc.Handle(MethodUpdatePendingAuthorization, func(req []byte) (response []byte) {
		var authz core.Authorization
		err := json.Unmarshal(req, authz)
		if err != nil {
			return
		}

		impl.UpdatePendingAuthorization(authz)
		return
	})

	rpc.Handle(MethodFinalizeAuthorization, func(req []byte) (response []byte) {
		var authz core.Authorization
		err := json.Unmarshal(req, authz)
		if err != nil {
			return
		}

		impl.FinalizeAuthorization(authz)
		return
	})

	rpc.Handle(MethodGetCertificate, func(req []byte) (response []byte) {
		cert, err := impl.GetCertificate(string(req))
		if err == nil {
			response = []byte(cert)
		}
		return
	})

	return
}

type StorageAuthorityClient struct {
	rpc *AmqpRpcClient
}

func NewStorageAuthorityClient(clientQueue, serverQueue string, channel *amqp.Channel) (sac StorageAuthorityClient, err error) {
	rpc, err := NewAmqpRpcClient(clientQueue, serverQueue, channel)
	if err != nil {
		return
	}

	sac = StorageAuthorityClient{rpc: rpc}
	return
}

func (cac StorageAuthorityClient) GetRegistration(id string) (reg core.Registration, err error) {
	jsonReg, err := cac.rpc.DispatchSync(MethodGetRegistration, []byte(id))
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

func (cac StorageAuthorityClient) UpdateRegistration(reg core.Registration) (err error) {
	jsonReg, err := json.Marshal(reg)
	if err != nil {
		return
	}

	// XXX: Is this catching all the errors?
	_, err = cac.rpc.DispatchSync(MethodUpdatePendingAuthorization, jsonReg)
	return
}

func (cac StorageAuthorityClient) NewRegistration() (id string, err error) {
	response, err := cac.rpc.DispatchSync(MethodNewPendingAuthorization, []byte{})
	if err != nil || len(response) == 0 {
		err = errors.New("NewRegistration RPC failed") // XXX
		return
	}
	id = string(response)
	return
}

func (cac StorageAuthorityClient) NewPendingAuthorization() (id string, err error) {
	response, err := cac.rpc.DispatchSync(MethodNewPendingAuthorization, []byte{})
	if err != nil || len(response) == 0 {
		err = errors.New("NewPendingAuthorization RPC failed") // XXX
		return
	}
	id = string(response)
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

func (cac StorageAuthorityClient) AddCertificate(cert []byte) (id string, err error) {
	response, err := cac.rpc.DispatchSync(MethodAddCertificate, cert)
	if err != nil || len(response) == 0 {
		err = errors.New("AddCertificate RPC failed") // XXX
		return
	}
	id = string(response)
	return
}
