// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package rpc

import (
	"net"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/square/go-jose"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/rpc/pb"
)

// This file defines functions to translate between the protobuf types and the
// code types.

func marshalAuthzMeta(authz core.Authorization) (*pb.AuthzMeta, error) {
	return &pb.AuthzMeta{
		Id:    authz.ID,
		RegID: authz.RegistrationID,
	}, nil
}

func unmarshalAuthzMeta(in *pb.AuthzMeta) (core.Authorization, error) {
	if in == nil {
		return core.Authorization{}, ErrMissingParameters
	}
	return core.Authorization{
		ID:             in.Id,
		RegistrationID: in.RegID,
	}, nil
}

func marshalJWK(jwk *jose.JsonWebKey) (string, error) {
	bytes, err := jwk.MarshalJSON()
	return string(bytes), err
}

func unmarshalJWK(in string) (*jose.JsonWebKey, error) {
	var jwk = new(jose.JsonWebKey)
	err := jwk.UnmarshalJSON([]byte(in))
	if err != nil {
		return nil, err
	}
	return jwk, nil
}

func marshalKeyAuthorization(keyAuth *core.KeyAuthorization) (*pb.KeyAuthorization, error) {
	return &pb.KeyAuthorization{
		Token:      keyAuth.Token,
		Thumbprint: keyAuth.Thumbprint,
	}, nil
}

func unmarshalKeyAuthorization(in *pb.KeyAuthorization) (*core.KeyAuthorization, error) {
	if in == nil {
		return nil, ErrMissingParameters
	}
	return &core.KeyAuthorization{
		Token:      in.Token,
		Thumbprint: in.Thumbprint,
	}, nil
}

func marshalProblemDetails(prob *probs.ProblemDetails) (*pb.ProblemDetails, error) {
	return &pb.ProblemDetails{
		ProblemType: string(prob.Type),
		Detail:      prob.Detail,
		HttpStatus:  int32(prob.HTTPStatus),
	}, nil
}

func unmarshalProblemDetails(in *pb.ProblemDetails) (*probs.ProblemDetails, error) {
	if in == nil {
		return nil, nil // !!! nil problemDetails is valid
	}
	return &probs.ProblemDetails{
		Type:       probs.ProblemType(in.ProblemType),
		Detail:     in.Detail,
		HTTPStatus: int(in.HttpStatus),
	}, nil
}

func marshalVAChallenge(challenge core.Challenge) (*pb.VAChallenge, error) {
	accountKey, err := marshalJWK(challenge.AccountKey)
	if err != nil {
		return nil, err
	}
	keyAuth, err := marshalKeyAuthorization(challenge.KeyAuthorization)
	if err != nil {
		return nil, err
	}
	return &pb.VAChallenge{
		Id:               challenge.ID,
		Type:             challenge.Type,
		Token:            challenge.Token,
		AccountKey:       accountKey,
		KeyAuthorization: keyAuth,
	}, nil
}

func unmarshalVAChallenge(in *pb.VAChallenge) (challenge core.Challenge, err error) {
	if in == nil {
		return core.Challenge{}, ErrMissingParameters
	}
	jwk, err := unmarshalJWK(in.AccountKey)
	if err != nil {
		return
	}
	keyAuth, err := unmarshalKeyAuthorization(in.KeyAuthorization)
	if err != nil {
		return
	}
	return core.Challenge{
		ID:               in.Id,
		Type:             in.Type,
		Token:            in.Token,
		KeyAuthorization: keyAuth,
		AccountKey:       jwk,
	}, nil
}

func marshalIPAddr(ip net.IP) (string, error) {
	bytes, err := ip.MarshalText()
	return string(bytes), err
}

func unmarshalIPAddr(in string) (net.IP, error) {
	var ip net.IP
	err := ip.UnmarshalText([]byte(in))
	return ip, err
}

func marshalValidationRecord(record core.ValidationRecord) (*pb.ValidationRecord, error) {
	addrs := make([]string, len(record.AddressesResolved))
	var err error
	for i, v := range record.AddressesResolved {
		addrs[i], err = marshalIPAddr(v)
		if err != nil {
			return nil, err
		}
	}
	addrUsed, err := marshalIPAddr(record.AddressUsed)
	if err != nil {
		return nil, err
	}
	return &pb.ValidationRecord{
		Hostname:          record.Hostname,
		Port:              record.Port,
		AddressesResolved: addrs,
		AddressUsed:       addrUsed,
		Authorities:       record.Authorities,
		Url:               record.URL,
	}, nil
}

func unmarshalValidationRecord(in *pb.ValidationRecord) (record core.ValidationRecord, err error) {
	if in == nil {
		return core.ValidationRecord{}, ErrMissingParameters
	}
	addrs := make([]net.IP, len(in.AddressesResolved))
	for i, v := range in.AddressesResolved {
		addrs[i], err = unmarshalIPAddr(v)
		if err != nil {
			return
		}
	}
	addrUsed, err := unmarshalIPAddr(in.AddressUsed)
	if err != nil {
		return
	}
	return core.ValidationRecord{
		Hostname:          in.Hostname,
		Port:              in.Port,
		AddressesResolved: addrs,
		AddressUsed:       addrUsed,
		Authorities:       in.Authorities,
		URL:               in.Url,
	}, nil
}

func marshalValidationRecords(records []core.ValidationRecord, prob *probs.ProblemDetails) (*pb.ValidationRecords, error) {
	recordAry := make([]*pb.ValidationRecord, len(records))
	var err error
	for i, v := range records {
		recordAry[i], err = marshalValidationRecord(v)
		if err != nil {
			return nil, err
		}
	}
	marshalledProbs, err := marshalProblemDetails(prob)
	if err != nil {
		return nil, err
	}
	return &pb.ValidationRecords{recordAry, marshalledProbs}, nil
}

func unmarshalValidationRecords(in *pb.ValidationRecords) ([]core.ValidationRecord, *probs.ProblemDetails, error) {
	if in == nil {
		return nil, nil, ErrMissingParameters
	}
	recordAry := make([]core.ValidationRecord, len(in.Records))
	var err error
	for i, v := range in.Records {
		recordAry[i], err = unmarshalValidationRecord(v)
		if err != nil {
			return nil, nil, err
		}
	}
	prob, err := unmarshalProblemDetails(in.Problems)
	if err != nil {
		return nil, nil, err
	}
	return recordAry, prob, nil
}
