// Copyright 2016 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package wrappers wraps the GRPC calls in the core interfaces.
package grpc

import (
	"net"
	"time"

	"golang.org/x/net/context"
	"gopkg.in/square/go-jose.v1"

	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/revocation"
	sa "github.com/letsencrypt/boulder/sa"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

// StorageAuthorityClientWrapper is the gRPC version of a core.StorageAuthority client
type StorageAuthorityClientWrapper struct {
	inner sapb.StorageAuthorityClient
}

func NewStorageAuthorityClient(inner sapb.StorageAuthorityClient) *StorageAuthorityClientWrapper {
	return &StorageAuthorityClientWrapper{inner}
}

func (sac StorageAuthorityClientWrapper) GetRegistration(ctx context.Context, regID int64) (core.Registration, error) {
	response, err := sac.inner.GetRegistration(ctx, &sapb.RegistrationID{Id: &regID})
	if err != nil {
		return core.Registration{}, err
	}

	if response == nil || !registrationValid(response) {
		return core.Registration{}, errIncompleteResponse
	}

	return pbToRegistration(response)
}

func (sac StorageAuthorityClientWrapper) GetRegistrationByKey(ctx context.Context, key *jose.JsonWebKey) (core.Registration, error) {
	keyBytes, err := key.MarshalJSON()
	if err != nil {
		return core.Registration{}, err
	}

	response, err := sac.inner.GetRegistrationByKey(ctx, &sapb.JsonWebKey{Jwk: keyBytes})
	if err != nil {
		return core.Registration{}, err
	}

	if response == nil || !registrationValid(response) {
		return core.Registration{}, errIncompleteResponse
	}

	return pbToRegistration(response)
}

func (sac StorageAuthorityClientWrapper) GetAuthorization(ctx context.Context, authID string) (core.Authorization, error) {
	response, err := sac.inner.GetAuthorization(ctx, &sapb.AuthorizationID{Id: &authID})
	if err != nil {
		return core.Authorization{}, err
	}

	if response == nil || !authorizationValid(response) {
		return core.Authorization{}, errIncompleteResponse
	}

	return pbToAuthz(response)
}

func (sac StorageAuthorityClientWrapper) GetValidAuthorizations(ctx context.Context, regID int64, domains []string, now time.Time) (map[string]*core.Authorization, error) {
	nowUnix := now.UnixNano()

	response, err := sac.inner.GetValidAuthorizations(ctx, &sapb.GetValidAuthorizationsRequest{
		RegistrationID: &regID,
		Domains:        domains,
		Now:            &nowUnix,
	})
	if err != nil {
		return nil, err
	}

	if response == nil {
		return nil, errIncompleteResponse
	}

	auths := make(map[string]*core.Authorization, len(response.Valid))
	for _, element := range response.Valid {
		if element == nil || element.Domain == nil || !authorizationValid(element.Authz) {
			return nil, errIncompleteResponse
		}
		authz, err := pbToAuthz(element.Authz)
		if err != nil {
			return nil, err
		}
		auths[*element.Domain] = &authz
	}
	return auths, nil
}

func (sac StorageAuthorityClientWrapper) GetCertificate(ctx context.Context, serial string) (core.Certificate, error) {
	response, err := sac.inner.GetCertificate(ctx, &sapb.Serial{Serial: &serial})
	if err != nil {
		return core.Certificate{}, err
	}

	if response == nil || !certificateValid(response) {
		return core.Certificate{}, errIncompleteResponse
	}

	return pbToCert(response), nil
}

func (sac StorageAuthorityClientWrapper) GetCertificateStatus(ctx context.Context, serial string) (core.CertificateStatus, error) {
	response, err := sac.inner.GetCertificateStatus(ctx, &sapb.Serial{Serial: &serial})
	if err != nil {
		return core.CertificateStatus{}, err
	}

	if response == nil || response.Serial == nil || response.SubscriberApproved == nil || response.Status == nil || response.OcspLastUpdated == nil || response.RevokedDate == nil || response.RevokedReason == nil || response.LastExpirationNagSent == nil || response.OcspResponse == nil || response.NotAfter == nil || response.IsExpired == nil {
		return core.CertificateStatus{}, errIncompleteResponse
	}

	return core.CertificateStatus{
		Serial:                *response.Serial,
		SubscriberApproved:    *response.SubscriberApproved,
		Status:                core.OCSPStatus(*response.Status),
		OCSPLastUpdated:       time.Unix(0, *response.OcspLastUpdated),
		RevokedDate:           time.Unix(0, *response.RevokedDate),
		RevokedReason:         revocation.Reason(*response.RevokedReason),
		LastExpirationNagSent: time.Unix(0, *response.LastExpirationNagSent),
		OCSPResponse:          response.OcspResponse,
		NotAfter:              time.Unix(0, *response.NotAfter),
		IsExpired:             *response.IsExpired,
	}, nil
}

func (sac StorageAuthorityClientWrapper) CountCertificatesRange(ctx context.Context, earliest, latest time.Time) (int64, error) {
	earliestNano := earliest.UnixNano()
	latestNano := latest.UnixNano()

	response, err := sac.inner.CountCertificatesRange(ctx, &sapb.Range{
		Earliest: &earliestNano,
		Latest:   &latestNano,
	})
	if err != nil {
		return 0, err
	}

	if response == nil || response.Count == nil {
		return 0, errIncompleteResponse
	}

	return *response.Count, nil
}

func (sac StorageAuthorityClientWrapper) CountCertificatesByNames(ctx context.Context, domains []string, earliest, latest time.Time) ([]*sapb.CountByNames_MapElement, error) {
	earliestNano := earliest.UnixNano()
	latestNano := latest.UnixNano()

	response, err := sac.inner.CountCertificatesByNames(ctx, &sapb.CountCertificatesByNamesRequest{
		Names: domains,
		Range: &sapb.Range{
			Earliest: &earliestNano,
			Latest:   &latestNano,
		},
	})
	if err != nil {
		return nil, err
	}

	if response == nil || response.CountByNames == nil {
		return nil, errIncompleteResponse
	}

	return response.CountByNames, nil
}

func (sac StorageAuthorityClientWrapper) CountCertificatesByExactNames(ctx context.Context, domains []string, earliest, latest time.Time) ([]*sapb.CountByNames_MapElement, error) {
	earliestNano := earliest.UnixNano()
	latestNano := latest.UnixNano()

	response, err := sac.inner.CountCertificatesByExactNames(ctx, &sapb.CountCertificatesByNamesRequest{
		Names: domains,
		Range: &sapb.Range{
			Earliest: &earliestNano,
			Latest:   &latestNano,
		},
	})
	if err != nil {
		return nil, err
	}

	if response == nil || response.CountByNames == nil {
		return nil, errIncompleteResponse
	}

	return response.CountByNames, nil
}

func (sac StorageAuthorityClientWrapper) CountRegistrationsByIP(ctx context.Context, ip net.IP, earliest, latest time.Time) (int, error) {
	earliestNano := earliest.UnixNano()
	latestNano := latest.UnixNano()

	response, err := sac.inner.CountRegistrationsByIP(ctx, &sapb.CountRegistrationsByIPRequest{
		Range: &sapb.Range{
			Earliest: &earliestNano,
			Latest:   &latestNano,
		},
		Ip: ip,
	})
	if err != nil {
		return 0, err
	}

	if response == nil || response.Count == nil {
		return 0, errIncompleteResponse
	}

	return int(*response.Count), nil
}

func (sac StorageAuthorityClientWrapper) CountRegistrationsByIPRange(ctx context.Context, ip net.IP, earliest, latest time.Time) (int, error) {
	earliestNano := earliest.UnixNano()
	latestNano := latest.UnixNano()

	response, err := sac.inner.CountRegistrationsByIPRange(ctx, &sapb.CountRegistrationsByIPRequest{
		Range: &sapb.Range{
			Earliest: &earliestNano,
			Latest:   &latestNano,
		},
		Ip: ip,
	})
	if err != nil {
		return 0, err
	}

	if response == nil || response.Count == nil {
		return 0, errIncompleteResponse
	}

	return int(*response.Count), nil
}

func (sac StorageAuthorityClientWrapper) CountPendingAuthorizations(ctx context.Context, regID int64) (int, error) {
	response, err := sac.inner.CountPendingAuthorizations(ctx, &sapb.RegistrationID{Id: &regID})
	if err != nil {
		return 0, err
	}

	if response == nil || response.Count == nil {
		return 0, errIncompleteResponse
	}

	return int(*response.Count), nil
}

func (sac StorageAuthorityClientWrapper) CountInvalidAuthorizations(ctx context.Context, request *sapb.CountInvalidAuthorizationsRequest) (*sapb.Count, error) {
	return sac.inner.CountInvalidAuthorizations(ctx, request)
}

func (sac StorageAuthorityClientWrapper) GetSCTReceipt(ctx context.Context, serial, logID string) (core.SignedCertificateTimestamp, error) {
	response, err := sac.inner.GetSCTReceipt(ctx, &sapb.GetSCTReceiptRequest{Serial: &serial, LogID: &logID})
	if err != nil {
		return core.SignedCertificateTimestamp{}, err
	}

	if response == nil || !sctValid(response) {
		return core.SignedCertificateTimestamp{}, errIncompleteResponse
	}

	return pbToSCT(response), nil
}

func (sac StorageAuthorityClientWrapper) CountFQDNSets(ctx context.Context, window time.Duration, domains []string) (int64, error) {
	windowNanos := window.Nanoseconds()

	response, err := sac.inner.CountFQDNSets(ctx, &sapb.CountFQDNSetsRequest{
		Window:  &windowNanos,
		Domains: domains,
	})
	if err != nil {
		return 0, err
	}

	if response == nil || response.Count == nil {
		return 0, errIncompleteResponse
	}

	return *response.Count, nil
}

func (sac StorageAuthorityClientWrapper) FQDNSetExists(ctx context.Context, domains []string) (bool, error) {
	response, err := sac.inner.FQDNSetExists(ctx, &sapb.FQDNSetExistsRequest{Domains: domains})
	if err != nil {
		return false, err
	}

	if response == nil || response.Exists == nil {
		return false, errIncompleteResponse
	}

	return *response.Exists, nil
}

func (sac StorageAuthorityClientWrapper) NewRegistration(ctx context.Context, reg core.Registration) (core.Registration, error) {
	regPB, err := registrationToPB(reg)
	if err != nil {
		return core.Registration{}, err
	}

	response, err := sac.inner.NewRegistration(ctx, regPB)
	if err != nil {
		return core.Registration{}, err
	}

	if response == nil || !registrationValid(response) {
		return core.Registration{}, errIncompleteResponse
	}

	return pbToRegistration(response)
}

func (sac StorageAuthorityClientWrapper) UpdateRegistration(ctx context.Context, reg core.Registration) error {
	regPB, err := registrationToPB(reg)
	if err != nil {
		return err
	}

	_, err = sac.inner.UpdateRegistration(ctx, regPB)
	if err != nil {
		return err
	}

	return nil
}

func (sac StorageAuthorityClientWrapper) NewPendingAuthorization(ctx context.Context, authz core.Authorization) (core.Authorization, error) {
	authPB, err := authzToPB(authz)
	if err != nil {
		return core.Authorization{}, err
	}

	response, err := sac.inner.NewPendingAuthorization(ctx, authPB)
	if err != nil {
		return core.Authorization{}, err
	}

	if response == nil || !authorizationValid(response) {
		return core.Authorization{}, errIncompleteResponse
	}

	return pbToAuthz(response)
}

func (sac StorageAuthorityClientWrapper) UpdatePendingAuthorization(ctx context.Context, authz core.Authorization) error {
	authPB, err := authzToPB(authz)
	if err != nil {
		return err
	}

	_, err = sac.inner.UpdatePendingAuthorization(ctx, authPB)
	if err != nil {
		return err
	}

	return nil
}

func (sac StorageAuthorityClientWrapper) FinalizeAuthorization(ctx context.Context, authz core.Authorization) error {
	authPB, err := authzToPB(authz)
	if err != nil {
		return err
	}

	_, err = sac.inner.FinalizeAuthorization(ctx, authPB)
	if err != nil {
		return err
	}

	return nil
}

func (sac StorageAuthorityClientWrapper) MarkCertificateRevoked(ctx context.Context, serial string, reasonCode revocation.Reason) error {
	reason := int64(reasonCode)

	_, err := sac.inner.MarkCertificateRevoked(ctx, &sapb.MarkCertificateRevokedRequest{
		Serial: &serial,
		Code:   &reason,
	})
	if err != nil {
		return err
	}

	return nil
}

func (sac StorageAuthorityClientWrapper) AddCertificate(ctx context.Context, der []byte, regID int64, ocspResponse []byte) (string, error) {
	response, err := sac.inner.AddCertificate(ctx, &sapb.AddCertificateRequest{
		Der:   der,
		RegID: &regID,
		Ocsp:  ocspResponse,
	})
	if err != nil {
		return "", err
	}

	if response == nil || response.Digest == nil {
		return "", errIncompleteResponse
	}

	return *response.Digest, nil
}

func (sac StorageAuthorityClientWrapper) AddSCTReceipt(ctx context.Context, sct core.SignedCertificateTimestamp) error {
	_, err := sac.inner.AddSCTReceipt(ctx, sctToPB(sct))
	if err != nil {
		return err
	}

	return nil
}

func (sac StorageAuthorityClientWrapper) RevokeAuthorizationsByDomain(ctx context.Context, domain core.AcmeIdentifier) (int64, int64, error) {
	response, err := sac.inner.RevokeAuthorizationsByDomain(ctx, &sapb.RevokeAuthorizationsByDomainRequest{Domain: &domain.Value})
	if err != nil {
		return 0, 0, err
	}

	if response == nil || response.Finalized == nil || response.Pending == nil {
		return 0, 0, errIncompleteResponse
	}

	return *response.Finalized, *response.Pending, nil
}

func (sac StorageAuthorityClientWrapper) DeactivateRegistration(ctx context.Context, id int64) error {
	_, err := sac.inner.DeactivateRegistration(ctx, &sapb.RegistrationID{Id: &id})
	if err != nil {
		return err
	}

	return nil
}

func (sac StorageAuthorityClientWrapper) DeactivateAuthorization(ctx context.Context, id string) error {
	_, err := sac.inner.DeactivateAuthorization(ctx, &sapb.AuthorizationID{Id: &id})
	if err != nil {
		return err
	}

	return nil
}

// StorageAuthorityServerWrapper is the gRPC version of a core.ServerAuthority server
type StorageAuthorityServerWrapper struct {
	inner *sa.SQLStorageAuthority
}

func NewStorageAuthorityServer(inner *sa.SQLStorageAuthority) *StorageAuthorityServerWrapper {
	return &StorageAuthorityServerWrapper{inner}
}

func (sas StorageAuthorityServerWrapper) GetRegistration(ctx context.Context, request *sapb.RegistrationID) (*corepb.Registration, error) {
	if request == nil || request.Id == nil {
		return nil, errIncompleteRequest
	}

	reg, err := sas.inner.GetRegistration(ctx, *request.Id)
	if err != nil {
		return nil, err
	}

	return registrationToPB(reg)
}

func (sas StorageAuthorityServerWrapper) GetRegistrationByKey(ctx context.Context, request *sapb.JsonWebKey) (*corepb.Registration, error) {
	if request == nil || request.Jwk == nil {
		return nil, errIncompleteRequest
	}

	var jwk jose.JsonWebKey
	err := jwk.UnmarshalJSON(request.Jwk)
	if err != nil {
		return nil, err
	}

	reg, err := sas.inner.GetRegistrationByKey(ctx, &jwk)
	if err != nil {
		return nil, err
	}

	return registrationToPB(reg)
}

func (sas StorageAuthorityServerWrapper) GetAuthorization(ctx context.Context, request *sapb.AuthorizationID) (*corepb.Authorization, error) {
	if request == nil || request.Id == nil {
		return nil, errIncompleteRequest
	}

	authz, err := sas.inner.GetAuthorization(ctx, *request.Id)
	if err != nil {
		return nil, err
	}

	return authzToPB(authz)
}

func (sas StorageAuthorityServerWrapper) GetValidAuthorizations(ctx context.Context, request *sapb.GetValidAuthorizationsRequest) (*sapb.ValidAuthorizations, error) {
	if request == nil || request.RegistrationID == nil || request.Domains == nil || request.Now == nil {
		return nil, errIncompleteRequest
	}

	valid, err := sas.inner.GetValidAuthorizations(ctx, *request.RegistrationID, request.Domains, time.Unix(0, *request.Now))
	if err != nil {
		return nil, err
	}

	resp := &sapb.ValidAuthorizations{}
	for k, v := range valid {
		authzPB, err := authzToPB(*v)
		if err != nil {
			return nil, err
		}
		// Make a copy of k because it will be reassigned with each loop.
		kCopy := k
		resp.Valid = append(resp.Valid, &sapb.ValidAuthorizations_MapElement{Domain: &kCopy, Authz: authzPB})
	}

	return resp, nil
}

func (sas StorageAuthorityServerWrapper) GetCertificate(ctx context.Context, request *sapb.Serial) (*corepb.Certificate, error) {
	if request == nil || request.Serial == nil {
		return nil, errIncompleteRequest
	}

	cert, err := sas.inner.GetCertificate(ctx, *request.Serial)
	if err != nil {
		return nil, err
	}

	return certToPB(cert), nil
}

func (sas StorageAuthorityServerWrapper) GetCertificateStatus(ctx context.Context, request *sapb.Serial) (*sapb.CertificateStatus, error) {
	if request == nil || request.Serial == nil {
		return nil, errIncompleteRequest
	}

	certStatus, err := sas.inner.GetCertificateStatus(ctx, *request.Serial)
	if err != nil {
		return nil, err
	}

	ocspLastUpdatedNano := certStatus.OCSPLastUpdated.UnixNano()
	revokedDateNano := certStatus.RevokedDate.UnixNano()
	lastExpirationNagSentNano := certStatus.LastExpirationNagSent.UnixNano()
	notAfterNano := certStatus.NotAfter.UnixNano()
	reason := int64(certStatus.RevokedReason)
	status := string(certStatus.Status)

	return &sapb.CertificateStatus{
		Serial:                &certStatus.Serial,
		SubscriberApproved:    &certStatus.SubscriberApproved,
		Status:                &status,
		OcspLastUpdated:       &ocspLastUpdatedNano,
		RevokedDate:           &revokedDateNano,
		RevokedReason:         &reason,
		LastExpirationNagSent: &lastExpirationNagSentNano,
		OcspResponse:          certStatus.OCSPResponse,
		NotAfter:              &notAfterNano,
		IsExpired:             &certStatus.IsExpired,
	}, nil
}

func (sas StorageAuthorityServerWrapper) CountCertificatesRange(ctx context.Context, request *sapb.Range) (*sapb.Count, error) {
	if request == nil || request.Earliest == nil || request.Latest == nil {
		return nil, errIncompleteRequest
	}

	count, err := sas.inner.CountCertificatesRange(ctx, time.Unix(0, *request.Earliest), time.Unix(0, *request.Latest))
	if err != nil {
		return nil, err
	}

	return &sapb.Count{Count: &count}, nil
}

func (sas StorageAuthorityServerWrapper) CountCertificatesByNames(ctx context.Context, request *sapb.CountCertificatesByNamesRequest) (*sapb.CountByNames, error) {
	if request == nil || request.Range == nil || request.Range.Earliest == nil || request.Range.Latest == nil || request.Names == nil {
		return nil, errIncompleteRequest
	}

	byNames, err := sas.inner.CountCertificatesByNames(ctx, request.Names, time.Unix(0, *request.Range.Earliest), time.Unix(0, *request.Range.Latest))
	if err != nil {
		return nil, err
	}

	return &sapb.CountByNames{CountByNames: byNames}, nil
}

func (sas StorageAuthorityServerWrapper) CountCertificatesByExactNames(ctx context.Context, request *sapb.CountCertificatesByNamesRequest) (*sapb.CountByNames, error) {
	if request == nil || request.Range == nil || request.Range.Earliest == nil || request.Range.Latest == nil || request.Names == nil {
		return nil, errIncompleteRequest
	}

	byNames, err := sas.inner.CountCertificatesByExactNames(ctx, request.Names, time.Unix(0, *request.Range.Earliest), time.Unix(0, *request.Range.Latest))
	if err != nil {
		return nil, err
	}

	return &sapb.CountByNames{CountByNames: byNames}, nil
}

func (sas StorageAuthorityServerWrapper) CountRegistrationsByIP(ctx context.Context, request *sapb.CountRegistrationsByIPRequest) (*sapb.Count, error) {
	if request == nil || request.Ip == nil || request.Range == nil || request.Range.Earliest == nil || request.Range.Latest == nil {
		return nil, errIncompleteRequest
	}

	count, err := sas.inner.CountRegistrationsByIP(
		ctx,
		net.IP(request.Ip),
		time.Unix(0, *request.Range.Earliest),
		time.Unix(0, *request.Range.Latest))
	if err != nil {
		return nil, err
	}

	castedCount := int64(count)
	return &sapb.Count{Count: &castedCount}, nil
}

func (sas StorageAuthorityServerWrapper) CountRegistrationsByIPRange(ctx context.Context, request *sapb.CountRegistrationsByIPRequest) (*sapb.Count, error) {
	if request == nil || request.Ip == nil || request.Range == nil || request.Range.Earliest == nil || request.Range.Latest == nil {
		return nil, errIncompleteRequest
	}

	count, err := sas.inner.CountRegistrationsByIPRange(
		ctx,
		net.IP(request.Ip),
		time.Unix(0, *request.Range.Earliest),
		time.Unix(0, *request.Range.Latest))
	if err != nil {
		return nil, err
	}

	castedCount := int64(count)
	return &sapb.Count{Count: &castedCount}, nil
}

func (sas StorageAuthorityServerWrapper) CountPendingAuthorizations(ctx context.Context, request *sapb.RegistrationID) (*sapb.Count, error) {
	if request == nil || request.Id == nil {
		return nil, errIncompleteRequest
	}

	count, err := sas.inner.CountPendingAuthorizations(ctx, *request.Id)
	if err != nil {
		return nil, err
	}

	castedCount := int64(count)
	return &sapb.Count{Count: &castedCount}, nil
}

func (sas StorageAuthorityServerWrapper) CountInvalidAuthorizations(ctx context.Context, request *sapb.CountInvalidAuthorizationsRequest) (*sapb.Count, error) {
	return sas.inner.CountInvalidAuthorizations(ctx, request)
}

func (sas StorageAuthorityServerWrapper) GetSCTReceipt(ctx context.Context, request *sapb.GetSCTReceiptRequest) (*sapb.SignedCertificateTimestamp, error) {
	if request == nil || request.Serial == nil || request.LogID == nil {
		return nil, errIncompleteRequest
	}

	sct, err := sas.inner.GetSCTReceipt(ctx, *request.Serial, *request.LogID)
	if err != nil {
		return nil, err
	}

	return sctToPB(sct), nil
}

func (sas StorageAuthorityServerWrapper) CountFQDNSets(ctx context.Context, request *sapb.CountFQDNSetsRequest) (*sapb.Count, error) {
	if request == nil || request.Window == nil || request.Domains == nil {
		return nil, errIncompleteRequest
	}

	window := time.Duration(*request.Window)

	count, err := sas.inner.CountFQDNSets(ctx, window, request.Domains)
	if err != nil {
		return nil, err
	}

	castedCount := int64(count)
	return &sapb.Count{Count: &castedCount}, nil
}

func (sas StorageAuthorityServerWrapper) FQDNSetExists(ctx context.Context, request *sapb.FQDNSetExistsRequest) (*sapb.Exists, error) {
	if request == nil || request.Domains == nil {
		return nil, errIncompleteRequest
	}

	exists, err := sas.inner.FQDNSetExists(ctx, request.Domains)
	if err != nil {
		return nil, err
	}

	return &sapb.Exists{Exists: &exists}, nil
}

func (sas StorageAuthorityServerWrapper) NewRegistration(ctx context.Context, request *corepb.Registration) (*corepb.Registration, error) {
	if request == nil || !registrationValid(request) {
		return nil, errIncompleteRequest
	}

	reg, err := pbToRegistration(request)
	if err != nil {
		return nil, err
	}

	newReg, err := sas.inner.NewRegistration(ctx, reg)
	if err != nil {
		return nil, err
	}

	return registrationToPB(newReg)
}

func (sas StorageAuthorityServerWrapper) UpdateRegistration(ctx context.Context, request *corepb.Registration) (*corepb.Empty, error) {
	if request == nil || !registrationValid(request) {
		return nil, errIncompleteRequest
	}

	reg, err := pbToRegistration(request)
	if err != nil {
		return nil, err
	}

	err = sas.inner.UpdateRegistration(ctx, reg)
	if err != nil {
		return nil, err
	}

	return &corepb.Empty{}, nil
}

func (sas StorageAuthorityServerWrapper) NewPendingAuthorization(ctx context.Context, request *corepb.Authorization) (*corepb.Authorization, error) {
	if request == nil || !authorizationValid(request) {
		return nil, errIncompleteRequest
	}

	authz, err := pbToAuthz(request)
	if err != nil {
		return nil, err
	}

	newAuthz, err := sas.inner.NewPendingAuthorization(ctx, authz)
	if err != nil {
		return nil, err
	}

	return authzToPB(newAuthz)
}

func (sas StorageAuthorityServerWrapper) UpdatePendingAuthorization(ctx context.Context, request *corepb.Authorization) (*corepb.Empty, error) {
	if request == nil || !authorizationValid(request) {
		return nil, errIncompleteRequest
	}

	authz, err := pbToAuthz(request)
	if err != nil {
		return nil, err
	}

	err = sas.inner.UpdatePendingAuthorization(ctx, authz)
	if err != nil {
		return nil, err
	}

	return &corepb.Empty{}, nil
}

func (sas StorageAuthorityServerWrapper) FinalizeAuthorization(ctx context.Context, request *corepb.Authorization) (*corepb.Empty, error) {
	if request == nil || !authorizationValid(request) {
		return nil, errIncompleteRequest
	}

	authz, err := pbToAuthz(request)
	if err != nil {
		return nil, err
	}

	err = sas.inner.FinalizeAuthorization(ctx, authz)
	if err != nil {
		return nil, err
	}

	return &corepb.Empty{}, nil
}

func (sas StorageAuthorityServerWrapper) MarkCertificateRevoked(ctx context.Context, request *sapb.MarkCertificateRevokedRequest) (*corepb.Empty, error) {
	if request == nil || request.Serial == nil || request.Code == nil {
		return nil, errIncompleteRequest
	}

	err := sas.inner.MarkCertificateRevoked(ctx, *request.Serial, revocation.Reason(*request.Code))
	if err != nil {
		return nil, err
	}

	return &corepb.Empty{}, nil
}

func (sas StorageAuthorityServerWrapper) AddCertificate(ctx context.Context, request *sapb.AddCertificateRequest) (*sapb.AddCertificateResponse, error) {
	if request == nil || request.Der == nil || request.RegID == nil {
		return nil, errIncompleteRequest
	}

	digest, err := sas.inner.AddCertificate(ctx, request.Der, *request.RegID, request.Ocsp)
	if err != nil {
		return nil, err
	}

	return &sapb.AddCertificateResponse{Digest: &digest}, nil
}

func (sas StorageAuthorityServerWrapper) AddSCTReceipt(ctx context.Context, request *sapb.SignedCertificateTimestamp) (*corepb.Empty, error) {
	if request == nil || !sctValid(request) {
		return nil, errIncompleteRequest
	}

	err := sas.inner.AddSCTReceipt(ctx, pbToSCT(request))
	if err != nil {
		return nil, err
	}

	return &corepb.Empty{}, nil
}

func (sas StorageAuthorityServerWrapper) RevokeAuthorizationsByDomain(ctx context.Context, request *sapb.RevokeAuthorizationsByDomainRequest) (*sapb.RevokeAuthorizationsByDomainResponse, error) {
	if request == nil || request.Domain == nil {
		return nil, errIncompleteRequest
	}

	finalized, pending, err := sas.inner.RevokeAuthorizationsByDomain(ctx, core.AcmeIdentifier{Value: *request.Domain, Type: core.IdentifierDNS})
	if err != nil {
		return nil, err
	}

	return &sapb.RevokeAuthorizationsByDomainResponse{Finalized: &finalized, Pending: &pending}, nil
}

func (sas StorageAuthorityServerWrapper) DeactivateRegistration(ctx context.Context, request *sapb.RegistrationID) (*corepb.Empty, error) {
	if request == nil || request.Id == nil {
		return nil, errIncompleteRequest
	}

	err := sas.inner.DeactivateRegistration(ctx, *request.Id)
	if err != nil {
		return nil, err
	}

	return &corepb.Empty{}, nil
}

func (sas StorageAuthorityServerWrapper) DeactivateAuthorization(ctx context.Context, request *sapb.AuthorizationID) (*corepb.Empty, error) {
	if request == nil || request.Id == nil {
		return nil, errIncompleteRequest
	}

	err := sas.inner.DeactivateAuthorization(ctx, *request.Id)
	if err != nil {
		return nil, err
	}

	return &corepb.Empty{}, nil
}
