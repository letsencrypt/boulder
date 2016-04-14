// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package rpc

import (
	"net"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/square/go-jose"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/google.golang.org/grpc/codes"

	"github.com/letsencrypt/boulder/core"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/probs"
	corepb "github.com/letsencrypt/boulder/rpc/pb/core"
	vapb "github.com/letsencrypt/boulder/rpc/pb/va"
)

var ErrMissingParameters = bgrpc.CodedError(codes.FailedPrecondition, "required RPC parameter was missing")

// This file defines functions to translate between the protobuf types and the
// code types.

func marshalAuthzMeta(authz core.Authorization) (*vapb.AuthzMeta, error) {
	return &vapb.AuthzMeta{
		Id:    &authz.ID,
		RegID: &authz.RegistrationID,
	}, nil
}

func unmarshalAuthzMeta(in *vapb.AuthzMeta) (core.Authorization, error) {
	if in == nil || in.Id == nil || in.RegID == nil {
		return core.Authorization{}, ErrMissingParameters
	}
	return core.Authorization{
		ID:             *in.Id,
		RegistrationID: *in.RegID,
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

func marshalProblemDetails(prob *probs.ProblemDetails) (*corepb.ProblemDetails, error) {
	pt := string(prob.Type)
	st := int32(prob.HTTPStatus)
	return &corepb.ProblemDetails{
		ProblemType: &pt,
		Detail:      &prob.Detail,
		HttpStatus:  &st,
	}, nil
}

func unmarshalProblemDetails(in *corepb.ProblemDetails) (*probs.ProblemDetails, error) {
	if in == nil {
		return nil, nil // !!! nil problemDetails is valid
	}
	if in.ProblemType == nil || in.Detail == nil {
		return nil, ErrMissingParameters
	}
	prob := &probs.ProblemDetails{
		Type:   probs.ProblemType(*in.ProblemType),
		Detail: *in.Detail,
	}
	if in.HttpStatus != nil {
		prob.HTTPStatus = int(*in.HttpStatus)
	}
	return prob, nil
}

func marshalVAChallenge(challenge core.Challenge) (*vapb.VAChallenge, error) {
	accountKey, err := marshalJWK(challenge.AccountKey)
	if err != nil {
		return nil, err
	}
	return &vapb.VAChallenge{
		Id:               &challenge.ID,
		Type:             &challenge.Type,
		Token:            &challenge.Token,
		AccountKey:       &accountKey,
		KeyAuthorization: &challenge.ProvidedKeyAuthorization,
	}, nil
}

func unmarshalVAChallenge(in *vapb.VAChallenge) (challenge core.Challenge, err error) {
	if in == nil {
		return core.Challenge{}, ErrMissingParameters
	}
	if in.AccountKey == nil || in.Id == nil || in.Type == nil || in.Token == nil || in.KeyAuthorization == nil {
		return core.Challenge{}, ErrMissingParameters
	}
	jwk, err := unmarshalJWK(*in.AccountKey)
	if err != nil {
		return
	}
	return core.Challenge{
		ID:                       *in.Id,
		Type:                     *in.Type,
		Token:                    *in.Token,
		AccountKey:               jwk,
		ProvidedKeyAuthorization: *in.KeyAuthorization,
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

func marshalValidationRecord(record core.ValidationRecord) (*vapb.ValidationRecord, error) {
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
	return &vapb.ValidationRecord{
		Hostname:          &record.Hostname,
		Port:              &record.Port,
		AddressesResolved: addrs,
		AddressUsed:       &addrUsed,
		Authorities:       record.Authorities,
		Url:               &record.URL,
	}, nil
}

func unmarshalValidationRecord(in *vapb.ValidationRecord) (record core.ValidationRecord, err error) {
	if in == nil {
		return core.ValidationRecord{}, ErrMissingParameters
	}
	if in.AddressUsed == nil || in.Hostname == nil || in.Port == nil || in.Url == nil {
		return core.ValidationRecord{}, ErrMissingParameters
	}
	addrs := make([]net.IP, len(in.AddressesResolved))
	for i, v := range in.AddressesResolved {
		addrs[i], err = unmarshalIPAddr(v)
		if err != nil {
			return
		}
	}
	addrUsed, err := unmarshalIPAddr(*in.AddressUsed)
	if err != nil {
		return
	}
	return core.ValidationRecord{
		Hostname:          *in.Hostname,
		Port:              *in.Port,
		AddressesResolved: addrs,
		AddressUsed:       addrUsed,
		Authorities:       in.Authorities,
		URL:               *in.Url,
	}, nil
}

func marshalValidationRecords(records []core.ValidationRecord, prob *probs.ProblemDetails) (*vapb.ValidationRecords, error) {
	recordAry := make([]*vapb.ValidationRecord, len(records))
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
	return &vapb.ValidationRecords{
		Records:  recordAry,
		Problems: marshalledProbs,
	}, nil
}

func unmarshalValidationRecords(in *vapb.ValidationRecords) ([]core.ValidationRecord, *probs.ProblemDetails, error) {
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
