package sfe

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	blog "github.com/letsencrypt/boulder/log"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	rl "github.com/letsencrypt/boulder/ratelimits"
	"github.com/letsencrypt/boulder/sfe/zendesk"

	"github.com/jmhodges/clock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type raBehavior int

const (
	ok raBehavior = iota
	alwaysError
	alwaysAdministrativelyDisabled
)

type raFakeServer struct {
	rapb.UnimplementedRegistrationAuthorityServer
	behavior raBehavior

	mu          sync.Mutex
	lastRequest *rapb.AddRateLimitOverrideRequest
	allRequests []*rapb.AddRateLimitOverrideRequest
}

func (s *raFakeServer) AddRateLimitOverride(ctx context.Context, r *rapb.AddRateLimitOverrideRequest) (*rapb.AddRateLimitOverrideResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.lastRequest = r
	s.allRequests = append(s.allRequests, r)

	switch s.behavior {
	case ok:
		return &rapb.AddRateLimitOverrideResponse{Enabled: true}, nil
	case alwaysAdministrativelyDisabled:
		return &rapb.AddRateLimitOverrideResponse{Enabled: false}, nil
	case alwaysError:
		return nil, status.Error(codes.Internal, "oh no, something has gone terriby awry!")
	default:
		return &rapb.AddRateLimitOverrideResponse{Enabled: true}, nil
	}
}

func (s *raFakeServer) calls() []*rapb.AddRateLimitOverrideRequest {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]*rapb.AddRateLimitOverrideRequest, len(s.allRequests))
	copy(out, s.allRequests)
	return out
}

func startRAFakeSrv(t *testing.T, behavior raBehavior) (*raFakeServer, rapb.RegistrationAuthorityClient, func()) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Errorf("while creating listener: %s", err)
	}

	srv := grpc.NewServer()
	fake := &raFakeServer{behavior: behavior}
	rapb.RegisterRegistrationAuthorityServer(srv, fake)

	done := make(chan struct{})
	go func() {
		_ = srv.Serve(lis)
		close(done)
	}()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Errorf("while creating grpc client: %s", err)
	}
	return fake, rapb.NewRegistrationAuthorityClient(conn), func() {
		srv.GracefulStop()
		<-done
		_ = conn.Close()
		_ = lis.Close()
	}
}

func newImporter(t *testing.T, ra rapb.RegistrationAuthorityClient, zd *zendesk.Client, p ProcessMode) *OverridesImporter {
	t.Helper()

	var lg blog.Logger = blog.NewMock()
	im, err := NewOverridesImporter(p, time.Minute, zd, ra, clock.New(), lg)
	if err != nil {
		t.Errorf("while creating OverridesImporter: %s", err)
	}
	return im
}

func createApprovedTicket(t *testing.T, c *zendesk.Client) int64 {
	t.Helper()

	fields := map[string]string{
		RateLimitFieldName:    rl.NewOrdersPerAccount.String(),
		TierFieldName:         "1000",
		OrganizationFieldName: "Acme Corp",
		AccountURIFieldName:   "https://acme-v02.api.letsencrypt.org/acme/acct/999",
		ReviewStatusFieldName: reviewStatusApproved,
	}

	id, err := c.CreateTicket("foo@bar.biz", "Test Ticket", "Test Body", fields)
	if err != nil {
		t.Errorf("while creating test ticket: %s", err)
	}
	err = c.UpdateTicketStatus(id, "open", "", false)
	if err != nil {
		t.Errorf("while updating ticket %d to open: %s", id, err)
	}
	return id
}

func TestOverridesImporterProcessTicketHappyPath(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                       string
		fields                     map[string]string
		expectLimit                rl.Name
		expectBucketKey            string
		expectTier                 int64
		expectBurst                int64
		expectCount                int64
		expectPeriod               time.Duration
		expectOrgComment           string
		expectLastCommentSubstring string
	}{
		{
			name: "NewOrdersPerAccount with valid Account URI",
			fields: map[string]string{
				RateLimitFieldName:    rl.NewOrdersPerAccount.String(),
				TierFieldName:         "1000",
				OrganizationFieldName: "Acme Corp",
				AccountURIFieldName:   "https://acme-v02.api.letsencrypt.org/acme/acct/12345",
			},
			expectLimit:                rl.NewOrdersPerAccount,
			expectBucketKey:            "3:12345",
			expectTier:                 1000,
			expectBurst:                1000,
			expectCount:                1000,
			expectPeriod:               7 * 24 * time.Hour,
			expectOrgComment:           "Acme Corp",
			expectLastCommentSubstring: "has been approved. Your new limit is 1000 per week",
		},
		{
			name: "CertificatesPerDomain with valid Registered Domain",
			fields: map[string]string{
				RateLimitFieldName:        rl.CertificatesPerDomain.String() + perDNSNameSuffix,
				TierFieldName:             "300",
				OrganizationFieldName:     "Acme Corp",
				RegisteredDomainFieldName: "example.com",
			},
			expectLimit:                rl.CertificatesPerDomain,
			expectBucketKey:            "5:example.com",
			expectTier:                 300,
			expectBurst:                300,
			expectCount:                300,
			expectPeriod:               7 * 24 * time.Hour,
			expectOrgComment:           "Acme Corp",
			expectLastCommentSubstring: "has been approved. Your new limit is 300 per week",
		},
		{
			name: "CertificatesPerDomain with valid IPv4 Address",
			fields: map[string]string{
				RateLimitFieldName:    rl.CertificatesPerDomain.String() + perIPSuffix,
				TierFieldName:         "300",
				OrganizationFieldName: "Acme Corp",
				IPAddressFieldName:    "64.112.11.11",
			},
			expectLimit:                rl.CertificatesPerDomain,
			expectBucketKey:            "5:64.112.11.11/32",
			expectTier:                 300,
			expectBurst:                300,
			expectCount:                300,
			expectPeriod:               7 * 24 * time.Hour,
			expectOrgComment:           "Acme Corp",
			expectLastCommentSubstring: "has been approved. Your new limit is 300 per week",
		},
		{
			name: "CertificatesPerDomain with valid IPv6",
			fields: map[string]string{
				RateLimitFieldName:    rl.CertificatesPerDomain.String() + perIPSuffix,
				TierFieldName:         "300",
				OrganizationFieldName: "Acme Corp",
				IPAddressFieldName:    "2606:4700:4700::1111",
			},
			expectLimit:     rl.CertificatesPerDomain,
			expectBucketKey: "5:2606:4700:4700::/64",
			expectTier:      300, expectBurst: 300, expectCount: 300,
			expectPeriod:               7 * 24 * time.Hour,
			expectOrgComment:           "Acme Corp",
			expectLastCommentSubstring: "has been approved. Your new limit is 300 per week",
		},
		{
			name: "CertificatesPerDomainPerAccount with valid Account URI",
			fields: map[string]string{
				RateLimitFieldName:    rl.CertificatesPerDomainPerAccount.String(),
				TierFieldName:         "300",
				OrganizationFieldName: "Acme Corp",
				AccountURIFieldName:   "https://acme-v02.api.letsencrypt.org/acme/acct/12345",
			},
			expectLimit:                rl.CertificatesPerDomainPerAccount,
			expectBucketKey:            "6:12345",
			expectTier:                 300,
			expectBurst:                300,
			expectCount:                300,
			expectPeriod:               7 * 24 * time.Hour,
			expectOrgComment:           "Acme Corp",
			expectLastCommentSubstring: "has been approved. Your new limit is 300 per week",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			zdServer, zdClient := createFakeZendeskClientServer(t)
			raSrv, raClient, stopRA := startRAFakeSrv(t, ok)
			defer stopRA()

			ticketID := createApprovedTicket(t, zdClient)

			im := newImporter(t, raClient, zdClient, ProcessAll)
			err := im.processTicket(context.Background(), ticketID, tc.fields)
			if err != nil {
				t.Errorf("processTicket got an unexpected error: %s", err)
			}

			req := raSrv.lastRequest
			if req == nil {
				t.Errorf("RA AddRateLimitOverride was not called")
				return
			}
			if req.LimitEnum != int64(tc.expectLimit) {
				t.Errorf("got rapb.AddRateLimitOverrideRequest.LimitEnum=%d, expected %d", req.LimitEnum, tc.expectLimit)
			}
			if req.Comment != tc.expectOrgComment {
				t.Errorf("got rapb.AddRateLimitOverrideRequest.Comment=%q, expected %q", req.Comment, tc.expectOrgComment)
			}
			if req.Count != tc.expectCount {
				t.Errorf("got rapb.AddRateLimitOverrideRequest.Count=%d, expected %d", req.Count, tc.expectCount)
			}
			if req.Burst != tc.expectBurst {
				t.Errorf("got rapb.AddRateLimitOverrideRequest.Burst=%d, expected %d", req.Burst, tc.expectBurst)
			}
			gotPeriod := req.Period.AsDuration()
			if gotPeriod != tc.expectPeriod {
				t.Errorf("got rapb.AddRateLimitOverrideRequest.Period=%s, expected %s", gotPeriod, tc.expectPeriod)
			}
			if req.BucketKey != tc.expectBucketKey {
				t.Errorf("got rapb.AddRateLimitOverrideRequest.BucketKey=%q, expected %q", req.BucketKey, tc.expectBucketKey)
			}

			got, ok := zdServer.GetTicket(ticketID)
			if !ok {
				t.Errorf("ticket %d not found in zendesk store", ticketID)
			}
			if got.Status != "solved" {
				// Ticket should remain "solved" after successful processing.
				t.Errorf("unexpected ticket status=%q, expected solved", got.Status)
			}

			if tc.expectLastCommentSubstring == "" {
				if len(got.Comments) != 1 {
					t.Errorf("unexpected comments count: got %d, expected 1", len(got.Comments))
				}
			} else {
				if len(got.Comments) < 2 {
					t.Errorf("expected an additional comment, got %d comments (%#v)", len(got.Comments), got.Comments)
				}
				last := got.Comments[len(got.Comments)-1]
				if !last.Public {
					t.Errorf("expected last comment to be public but it was private")
				}
				if !strings.Contains(last.Body, tc.expectLastCommentSubstring) {
					t.Errorf("last comment body %q does not contain %q", last.Body, tc.expectLastCommentSubstring)
				}
			}
		})
	}
}

func TestOverridesImporterProcessTicketSadPath(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                       string
		tickerFields               map[string]string
		raFakeBehavior             raBehavior
		expectErrSubstring         string
		expectStatus               string
		expectLastCommentSubstring string
	}{
		{
			name:                       "missing rate limit field",
			tickerFields:               map[string]string{OrganizationFieldName: "Acme Corp"},
			raFakeBehavior:             ok,
			expectErrSubstring:         "missing rate limit field",
			expectStatus:               "pending",
			expectLastCommentSubstring: "missing rate limit field",
		},
		{
			name: "invalid tier option (validation error)",
			tickerFields: map[string]string{
				RateLimitFieldName:    rl.NewOrdersPerAccount.String(),
				TierFieldName:         "999",
				OrganizationFieldName: "Acme Corp",
				AccountURIFieldName:   "https://acme-v02.api.letsencrypt.org/acme/acct/12345",
			},
			raFakeBehavior:             ok,
			expectErrSubstring:         "invalid request override quantity",
			expectStatus:               "pending",
			expectLastCommentSubstring: "getting/validating tier field",
		},
		{
			name: "invalid account URI (validation error)",
			tickerFields: map[string]string{
				RateLimitFieldName:    rl.NewOrdersPerAccount.String(),
				TierFieldName:         "1000",
				OrganizationFieldName: "Acme Corp",
				AccountURIFieldName:   "https://acme-v02.ap1.letsencrypt.org/acme/acct/1",
			},
			raFakeBehavior:             ok,
			expectErrSubstring:         "account URI is invalid",
			expectStatus:               "pending",
			expectLastCommentSubstring: "getting/validating accountURI",
		},
		{
			name: "invalid IP (validation error)",
			tickerFields: map[string]string{
				RateLimitFieldName:    rl.CertificatesPerDomain.String() + perIPSuffix,
				TierFieldName:         "300",
				OrganizationFieldName: "Acme Corp",
				IPAddressFieldName:    "2606:4700:4700::1111:12345",
			},
			raFakeBehavior: ok,

			expectErrSubstring:         "IP address is invalid",
			expectStatus:               "pending",
			expectLastCommentSubstring: "getting/validating ipAddress",
		},
		{
			name: "RA administratively disabled",
			tickerFields: map[string]string{
				RateLimitFieldName:    rl.NewOrdersPerAccount.String(),
				TierFieldName:         "1000",
				OrganizationFieldName: "Acme Corp",
				AccountURIFieldName:   "https://acme-v02.api.letsencrypt.org/acme/acct/12345",
			},
			raFakeBehavior:             alwaysAdministrativelyDisabled,
			expectErrSubstring:         "administratively disabled",
			expectStatus:               "pending",
			expectLastCommentSubstring: "administratively disabled",
		},
		{
			name: "RA internal error (no ticket update)",
			tickerFields: map[string]string{
				RateLimitFieldName:    rl.NewOrdersPerAccount.String(),
				TierFieldName:         "1000",
				OrganizationFieldName: "Acme Corp",
				AccountURIFieldName:   "https://acme-v02.api.letsencrypt.org/acme/acct/12345",
			},
			raFakeBehavior:     alwaysError,
			expectErrSubstring: "calling ra.AddRateLimitOverride",
			expectStatus:       "open",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			zdServer, zdClient := createFakeZendeskClientServer(t)

			_, raClient, stopRA := startRAFakeSrv(t, tc.raFakeBehavior)
			defer stopRA()

			ticketID := createApprovedTicket(t, zdClient)

			im := newImporter(t, raClient, zdClient, ProcessAll)

			err := im.processTicket(context.Background(), ticketID, tc.tickerFields)
			if err == nil {
				t.Errorf("processTicket error = nil, expected error containing %q", tc.expectErrSubstring)
			}
			if tc.expectErrSubstring != "" && !strings.Contains(err.Error(), tc.expectErrSubstring) {
				t.Errorf("error=%q does not contain %q", err.Error(), tc.expectErrSubstring)
			}

			got, ok := zdServer.GetTicket(ticketID)
			if !ok {
				t.Errorf("ticket %d not found in zendesk store", ticketID)
			}
			if got.Status != tc.expectStatus {
				t.Errorf("unexpected ticket status=%q, expected %q", got.Status, tc.expectStatus)
			}

			if tc.expectLastCommentSubstring == "" {
				if len(got.Comments) != 1 {
					t.Errorf("unexpected comments count: got %d; expected 1", len(got.Comments))
				}
			} else {
				if len(got.Comments) < 2 {
					t.Errorf("expected an additional comment, got %d comments (%#v)", len(got.Comments), got.Comments)
				}
				last := got.Comments[len(got.Comments)-1]
				if last.Public != false {
					t.Errorf("last comment Public=%t, expected false; errors should not be shown to end users", last.Public)
				}
				if !strings.Contains(last.Body, tc.expectLastCommentSubstring) {
					t.Errorf("last comment body %q does not contain %q", last.Body, tc.expectLastCommentSubstring)
				}

			}
		})
	}
}

func TestTickProcessModes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                 string
		mode                 ProcessMode
		expectTicketIDs      []int64
		expectRARequestCount int
	}{
		{
			name:                 "importer.tick() with Mode=ProcessAll",
			mode:                 ProcessAll,
			expectTicketIDs:      []int64{1, 2, 3},
			expectRARequestCount: 3,
		},
		{
			name:                 "importer.tick() with Mode=ProcessEven",
			mode:                 processEven,
			expectTicketIDs:      []int64{2},
			expectRARequestCount: 1,
		},
		{
			name:                 "importer.tick() with Mode=ProcessOdd",
			mode:                 processOdd,
			expectTicketIDs:      []int64{1, 3},
			expectRARequestCount: 2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			zdServer, zdClient := createFakeZendeskClientServer(t)
			raSrv, raClient, stopRA := startRAFakeSrv(t, ok)
			defer stopRA()

			var initialTicketIDs []int64
			initialTicketIDToCommentsCount := make(map[int64]int)
			for range 3 {
				ticketID := createApprovedTicket(t, zdClient)
				initialTicketIDs = append(initialTicketIDs, ticketID)

				initialTicket, ok := zdServer.GetTicket(ticketID)
				if !ok {
					t.Errorf("ticket %d not found in zendesk store", ticketID)
				}
				initialTicketIDToCommentsCount[ticketID] = len(initialTicket.Comments)
			}

			im := newImporter(t, raClient, zdClient, tc.mode)
			im.tick(context.Background())

			AddRateLimitOverrideCalls := raSrv.calls()
			if len(AddRateLimitOverrideCalls) != tc.expectRARequestCount {
				t.Errorf("got %d RA AddRateLimitOverride calls, expected %d", len(AddRateLimitOverrideCalls), tc.expectRARequestCount)
			}

			processedTickets := make(map[int64]bool)
			for _, id := range initialTicketIDs {
				resultingTicket, ok := zdServer.GetTicket(id)
				if !ok {
					t.Errorf("ticket %d not found after tick", id)
				}
				if len(resultingTicket.Comments) > initialTicketIDToCommentsCount[id] {
					// We know that a ticket was processed if it has more comments than it started with.
					processedTickets[id] = true
				}
			}

			if len(processedTickets) != len(tc.expectTicketIDs) {
				t.Errorf("got %d processed tickets, expected %d", len(processedTickets), len(tc.expectTicketIDs))
			}
			for _, id := range tc.expectTicketIDs {
				if !processedTickets[id] {
					t.Errorf("expected ticket %d to be processed, but it was not", id)
				}
			}
		})
	}
}
