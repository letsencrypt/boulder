// Copyright 2016 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package grpc

import (
	"net"

	"github.com/square/go-jose"
	"google.golang.org/grpc/codes"

	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/probs"
	vapb "github.com/letsencrypt/boulder/va/proto"
)

var ErrMissingParameters = CodedError(codes.FailedPrecondition, "required RPC parameter was missing")

// This file defines functions to translate between the protobuf types and the
// code types.

func authzMetaToPB(authz core.Authorization) (*vapb.AuthzMeta, error) {
	return &vapb.AuthzMeta{
		Id:    &authz.ID,
		RegID: &authz.RegistrationID,
	}, nil
}

func pbToAuthzMeta(in *vapb.AuthzMeta) (core.Authorization, error) {
	if in == nil || in.Id == nil || in.RegID == nil {
		return core.Authorization{}, ErrMissingParameters
	}
	return core.Authorization{
		ID:             *in.Id,
		RegistrationID: *in.RegID,
	}, nil
}

func jwkToString(jwk *jose.JsonWebKey) (string, error) {
	bytes, err := jwk.MarshalJSON()
	return string(bytes), err
}

func stringToJWK(in string) (*jose.JsonWebKey, error) {
	var jwk = new(jose.JsonWebKey)
	err := jwk.UnmarshalJSON([]byte(in))
	if err != nil {
		return nil, err
	}
	return jwk, nil
}

func problemDetailsToPB(prob *probs.ProblemDetails) (*corepb.ProblemDetails, error) {
	if prob == nil {
		// nil problemDetails is valid
		return nil, nil
	}
	pt := string(prob.Type)
	st := int32(prob.HTTPStatus)
	return &corepb.ProblemDetails{
		ProblemType: &pt,
		Detail:      &prob.Detail,
		HttpStatus:  &st,
	}, nil
}

func pbToProblemDetails(in *corepb.ProblemDetails) (*probs.ProblemDetails, error) {
	if in == nil {
		// nil problemDetails is valid
		return nil, nil
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

func vaChallengeToPB(challenge core.Challenge) (*corepb.Challenge, error) {
	st := string(challenge.Status)
	return &corepb.Challenge{
		Id:               &challenge.ID,
		Type:             &challenge.Type,
		Status:           &st,
		Token:            &challenge.Token,
		KeyAuthorization: &challenge.ProvidedKeyAuthorization,
	}, nil
}

func pbToVAChallenge(in *corepb.Challenge) (challenge core.Challenge, err error) {
	if in == nil {
		return core.Challenge{}, ErrMissingParameters
	}
	if in.Id == nil || in.Type == nil || in.Status == nil || in.Token == nil || in.KeyAuthorization == nil {
		return core.Challenge{}, ErrMissingParameters
	}
	return core.Challenge{
		ID:     *in.Id,
		Type:   *in.Type,
		Status: core.AcmeStatus(*in.Status),
		Token:  *in.Token,
		ProvidedKeyAuthorization: *in.KeyAuthorization,
	}, nil
}

func validationRecordToPB(record core.ValidationRecord) (*corepb.ValidationRecord, error) {
	addrs := make([][]byte, len(record.AddressesResolved))
	var err error
	for i, v := range record.AddressesResolved {
		addrs[i] = []byte(v)
	}
	addrUsed, err := record.AddressUsed.MarshalText()
	if err != nil {
		return nil, err
	}
	return &corepb.ValidationRecord{
		Hostname:          &record.Hostname,
		Port:              &record.Port,
		AddressesResolved: addrs,
		AddressUsed:       addrUsed,
		Authorities:       record.Authorities,
		Url:               &record.URL,
	}, nil
}

func pbToValidationRecord(in *corepb.ValidationRecord) (record core.ValidationRecord, err error) {
	if in == nil {
		return core.ValidationRecord{}, ErrMissingParameters
	}
	if in.AddressUsed == nil || in.Hostname == nil || in.Port == nil || in.Url == nil {
		return core.ValidationRecord{}, ErrMissingParameters
	}
	addrs := make([]net.IP, len(in.AddressesResolved))
	for i, v := range in.AddressesResolved {
		addrs[i] = net.IP(v)
	}
	var addrUsed net.IP
	err = addrUsed.UnmarshalText(in.AddressUsed)
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

func validationResultToPB(records []core.ValidationRecord, prob *probs.ProblemDetails) (*vapb.ValidationResult, error) {
	recordAry := make([]*corepb.ValidationRecord, len(records))
	var err error
	for i, v := range records {
		recordAry[i], err = validationRecordToPB(v)
		if err != nil {
			return nil, err
		}
	}
	marshalledProbs, err := problemDetailsToPB(prob)
	if err != nil {
		return nil, err
	}
	return &vapb.ValidationResult{
		Records:  recordAry,
		Problems: marshalledProbs,
	}, nil
}

func pbToValidationResult(in *vapb.ValidationResult) ([]core.ValidationRecord, *probs.ProblemDetails, error) {
	if in == nil {
		return nil, nil, ErrMissingParameters
	}
	recordAry := make([]core.ValidationRecord, len(in.Records))
	var err error
	for i, v := range in.Records {
		recordAry[i], err = pbToValidationRecord(v)
		if err != nil {
			return nil, nil, err
		}
	}
	prob, err := pbToProblemDetails(in.Problems)
	if err != nil {
		return nil, nil, err
	}
	return recordAry, prob, nil
}

func performValidationReqToArgs(in *vapb.PerformValidationRequest) (domain string, challenge core.Challenge, authz core.Authorization, err error) {
	if in == nil {
		err = ErrMissingParameters
		return
	}
	if in.Domain == nil {
		err = ErrMissingParameters
		return
	}
	domain = *in.Domain
	challenge, err = pbToVAChallenge(in.Challenge)
	if err != nil {
		return
	}
	authz, err = pbToAuthzMeta(in.Authz)
	if err != nil {
		return
	}

	return domain, challenge, authz, nil
}

func argsToPerformValidationRequest(domain string, challenge core.Challenge, authz core.Authorization) (*vapb.PerformValidationRequest, error) {
	pbChall, err := vaChallengeToPB(challenge)
	if err != nil {
		return nil, err
	}
	authzMeta, err := authzMetaToPB(authz)
	if err != nil {
		return nil, err
	}
	return &vapb.PerformValidationRequest{
		Domain:    &domain,
		Challenge: pbChall,
		Authz:     authzMeta,
	}, nil

}
