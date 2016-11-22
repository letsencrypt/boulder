// Copyright 2016 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package grpc

import (
	"encoding/json"
	"net"
	"time"

	"google.golang.org/grpc/codes"
	"gopkg.in/square/go-jose.v1"

	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/probs"
	rapb "github.com/letsencrypt/boulder/ra/proto"
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

func challengeToPB(challenge core.Challenge) (*corepb.Challenge, error) {
	st := string(challenge.Status)
	return &corepb.Challenge{
		Id:               &challenge.ID,
		Type:             &challenge.Type,
		Status:           &st,
		Token:            &challenge.Token,
		KeyAuthorization: &challenge.ProvidedKeyAuthorization,
	}, nil
}

func pbToChallenge(in *corepb.Challenge) (challenge core.Challenge, err error) {
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
	challenge, err = pbToChallenge(in.Challenge)
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
	pbChall, err := challengeToPB(challenge)
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

func registrationToPB(reg core.Registration) (*rapb.Registration, error) {
	keyBytes, err := reg.Key.MarshalJSON()
	if err != nil {
		return nil, err
	}
	ipBytes, err := reg.InitialIP.MarshalText()
	if err != nil {
		return nil, err
	}
	createdAt := reg.CreatedAt.UnixNano()
	status := string(reg.Status)
	return &rapb.Registration{
		Id:        &reg.ID,
		Key:       keyBytes,
		Contact:   *reg.Contact,
		Agreement: &reg.Agreement,
		InitialIP: ipBytes,
		CreatedAt: &createdAt,
		Status:    &status,
	}, nil
}

func pbToRegistration(pb *rapb.Registration) (core.Registration, error) {
	var key jose.JsonWebKey
	err := key.UnmarshalJSON(pb.Key)
	if err != nil {
		return core.Registration{}, err
	}
	var initialIP net.IP
	err = initialIP.UnmarshalText(pb.InitialIP)
	if err != nil {
		return core.Registration{}, err
	}
	return core.Registration{
		ID:        *pb.Id,
		Key:       &key,
		Contact:   &pb.Contact,
		Agreement: *pb.Agreement,
		InitialIP: initialIP,
		CreatedAt: time.Unix(0, *pb.CreatedAt),
		Status:    core.AcmeStatus(*pb.Status),
	}, nil
}

func authzToPB(authz core.Authorization) (*rapb.Authorization, error) {
	challs := make([]*corepb.Challenge, len(authz.Challenges))
	for _, c := range authz.Challenges {
		pbChall, err := challengeToPB(c)
		if err != nil {
			return nil, err
		}
		challs = append(challs, pbChall)
	}
	comboBytes, err := json.Marshal(authz.Combinations)
	if err != nil {
		return nil, err
	}
	status := string(authz.Status)
	expires := authz.Expires.UnixNano()
	return &rapb.Authorization{
		Id:             &authz.ID,
		Identifier:     &authz.Identifier.Value,
		RegistrationID: &authz.RegistrationID,
		Status:         &status,
		Expires:        &expires,
		Challenges:     challs,
		Combinations:   comboBytes,
	}, nil
}

func pbToAuthz(pb *rapb.Authorization) (core.Authorization, error) {
	challs := make([]core.Challenge, len(pb.Challenges))
	for _, c := range pb.Challenges {
		chall, err := pbToChallenge(c)
		if err != nil {
			return core.Authorization{}, err
		}
		challs = append(challs, chall)
	}
	var combos [][]int
	err := json.Unmarshal(pb.Combinations, &combos)
	if err != nil {
		return core.Authorization{}, err
	}
	expires := time.Unix(0, *pb.Expires)
	return core.Authorization{
		ID:             *pb.Id,
		Identifier:     core.AcmeIdentifier{Type: core.IdentifierDNS, Value: *pb.Identifier},
		RegistrationID: *pb.RegistrationID,
		Status:         core.AcmeStatus(*pb.Status),
		Expires:        &expires,
		Challenges:     challs,
		Combinations:   combos,
	}, nil
}
