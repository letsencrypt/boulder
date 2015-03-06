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

	"github.com/bifurcation/gose"
	"github.com/streadway/amqp"

	"github.com/letsencrypt/boulder/core"
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
	MethodNewAuthorization           = "NewAuthorization"           // RA
	MethodNewCertificate             = "NewCertificate"             // RA
	MethodUpdateAuthorization        = "UpdateAuthorization"        // RA
	MethodRevokeCertificate          = "RevokeCertificate"          // RA
	MethodOnValidationUpdate         = "OnValidationUpdate"         // RA
	MethodUpdateValidations          = "UpdateValidations"          // VA
	MethodIssueCertificate           = "IssueCertificate"           // CA
	MethodGetCertificate             = "GetCertificate"             // SA
	MethodGetAuthorization           = "GetAuthorization"           // SA
	MethodAddCertificate             = "AddCertificate"             // SA
	MethodNewPendingAuthorization    = "NewPendingAuthorization"    // SA
	MethodUpdatePendingAuthorization = "UpdatePendingAuthorization" // SA
	MethodFinalizeAuthorization      = "FinalizeAuthorization"      // SA
)

// RegistrationAuthorityClient / Server
//  -> NewAuthorization
//  -> NewCertificate
//  -> UpdateAuthorization
//  -> RevokeCertificate
//  -> OnValidationUpdate
type authorizationRequest struct {
	Authz core.Authorization
	Key   jose.JsonWebKey
}

type certificateRequest struct {
	Req core.CertificateRequest
	Key jose.JsonWebKey
}

func NewRegistrationAuthorityServer(serverQueue string, channel *amqp.Channel, impl core.RegistrationAuthority) (rpc *AmqpRPCServer, err error) {
	rpc = NewAmqpRPCServer(serverQueue, channel)

	rpc.Handle(MethodNewAuthorization, func(req []byte) []byte {
		var ar authorizationRequest
		if err := json.Unmarshal(req, &ar); err != nil {
			return nil
		}

		authz, err := impl.NewAuthorization(ar.Authz, ar.Key)
		if err != nil {
			return nil
		}

		response, err := json.Marshal(authz)
		if err != nil {
			return nil
		}
		return response
	})

	rpc.Handle(MethodNewCertificate, func(req []byte) []byte {
		log.Printf(" [.] Entering MethodNewCertificate")
		var cr certificateRequest
		if err := json.Unmarshal(req, &cr); err != nil {
			log.Printf(" [!] Error unmarshaling certificate request: %s", err.Error())
			log.Printf("     JSON data: %s", string(req))
			return nil
		}
		log.Printf(" [.] No problem unmarshaling request")

		cert, err := impl.NewCertificate(cr.Req, cr.Key)
		if err != nil {
			log.Printf(" [!] Error issuing new certificate: %s", err.Error())
			return nil
		}
		log.Printf(" [.] No problem issuing new cert")

		response, err := json.Marshal(cert)
		if err != nil {
			return nil
		}
		return response
	})

	rpc.Handle(MethodUpdateAuthorization, func(req []byte) []byte {
		var authz core.Authorization
		if err := json.Unmarshal(req, &authz); err != nil {
			return nil
		}

		newAuthz, err := impl.UpdateAuthorization(authz)
		if err != nil {
			return nil
		}

		response, err := json.Marshal(newAuthz)
		if err != nil {
			return nil
		}
		return response
	})

	rpc.Handle(MethodRevokeCertificate, func(req []byte) []byte {
		certs, err := x509.ParseCertificates(req)
		if err != nil || len(certs) == 0 {
			return nil
		}

		// Error explicitly ignored since response is nil anyway
		_ = impl.RevokeCertificate(*certs[0])
		return nil
	})

	rpc.Handle(MethodOnValidationUpdate, func(req []byte) []byte {
		var authz core.Authorization
		if err := json.Unmarshal(req, &authz); err != nil {
			return nil
		}

		impl.OnValidationUpdate(authz)
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

func (rac RegistrationAuthorityClient) UpdateAuthorization(authz core.Authorization) (newAuthz core.Authorization, err error) {
	data, err := json.Marshal(authz)
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
func NewValidationAuthorityServer(serverQueue string, channel *amqp.Channel, impl core.ValidationAuthority) (rpc *AmqpRPCServer, err error) {
	rpc = NewAmqpRPCServer(serverQueue, channel)

	rpc.Handle(MethodUpdateValidations, func(req []byte) []byte {
		var authz core.Authorization
		if err := json.Unmarshal(req, &authz); err != nil {
			return nil
		}

		// Error explicitly ignored since response is nil anyway
		_ = impl.UpdateValidations(authz)
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
func NewCertificateAuthorityServer(serverQueue string, channel *amqp.Channel, impl core.CertificateAuthority) (rpc *AmqpRPCServer, err error) {
	rpc = NewAmqpRPCServer(serverQueue, channel)

	rpc.Handle(MethodIssueCertificate, func(req []byte) []byte {
		csr, err := x509.ParseCertificateRequest(req)
		if err != nil {
			return nil // XXX
		}

		cert, err := impl.IssueCertificate(*csr)
		if err != nil {
			return nil // XXX
		}

		serialized, err := json.Marshal(cert)
		if err != nil {
			return nil // XXX
		}

		return serialized
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

func (cac CertificateAuthorityClient) IssueCertificate(csr x509.CertificateRequest) (cert core.Certificate, err error) {
	jsonResponse, err := cac.rpc.DispatchSync(MethodIssueCertificate, csr.Raw)
	if len(jsonResponse) == 0 {
		// TODO: Better error handling
		return
	}

	err = json.Unmarshal(jsonResponse, &cert)
	return
}

func NewStorageAuthorityServer(serverQueue string, channel *amqp.Channel, impl core.StorageAuthority) (rpc *AmqpRPCServer) {
	rpc = NewAmqpRPCServer(serverQueue, channel)

	rpc.Handle(MethodGetCertificate, func(req []byte) []byte {
		cert, err := impl.GetCertificate(string(req))
		if err != nil {
			return nil
		}
		return []byte(cert)
	})

	rpc.Handle(MethodGetAuthorization, func(req []byte) []byte {
		authz, err := impl.AddCertificate(req)
		if err != nil {
			return nil
		}

		jsonAuthz, err := json.Marshal(authz)
		if err != nil {
			return nil
		}
		return jsonAuthz
	})

	rpc.Handle(MethodAddCertificate, func(req []byte) []byte {
		id, err := impl.AddCertificate(req)
		if err != nil {
			return nil
		}
		return []byte(id)
	})

	rpc.Handle(MethodNewPendingAuthorization, func(req []byte) []byte {
		id, err := impl.NewPendingAuthorization()
		if err != nil {
			return nil
		}
		return []byte(id)
	})

	rpc.Handle(MethodUpdatePendingAuthorization, func(req []byte) []byte {
		var authz core.Authorization
		err := json.Unmarshal(req, authz)
		if err != nil {
			return nil
		}

		// Error explicitly ignored since response is nil anyway
		_ = impl.UpdatePendingAuthorization(authz)
		return nil
	})

	rpc.Handle(MethodUpdatePendingAuthorization, func(req []byte) []byte {
		var authz core.Authorization
		err := json.Unmarshal(req, authz)
		if err != nil {
			return nil
		}

		// Error explicitly ignored since response is nil anyway
		_ = impl.UpdatePendingAuthorization(authz)
		return nil
	})

	rpc.Handle(MethodFinalizeAuthorization, func(req []byte) []byte {
		var authz core.Authorization
		err := json.Unmarshal(req, authz)
		if err != nil {
			return nil
		}

		// Error explicitly ignored since response is nil anyway
		_ = impl.FinalizeAuthorization(authz)
		return nil
	})

	return
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

func (cac StorageAuthorityClient) GetCertificate(id string) (cert []byte, err error) {
	cert, err = cac.rpc.DispatchSync(MethodGetCertificate, []byte(id))
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

func (cac StorageAuthorityClient) AddCertificate(cert []byte) (id string, err error) {
	response, err := cac.rpc.DispatchSync(MethodAddCertificate, cert)
	if err != nil || len(response) == 0 {
		err = errors.New("AddCertificate RPC failed") // XXX
		return
	}
	id = string(response)
	return
}

func (cac StorageAuthorityClient) NewPendingAuthorization() (id string, err error) {
	response, err := cac.rpc.DispatchSync(MethodNewPendingAuthorization, nil)
	if err != nil || len(response) == 0 {
		err = errors.New("AddCertificate RPC failed") // XXX
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
