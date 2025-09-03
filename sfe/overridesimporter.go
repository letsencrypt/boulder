package sfe

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jmhodges/clock"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/letsencrypt/boulder/identifier"
	blog "github.com/letsencrypt/boulder/log"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	rl "github.com/letsencrypt/boulder/ratelimits"
	"github.com/letsencrypt/boulder/sfe/zendesk"
)

// ProcessMode determines which ticket IDs the importer will process.
type ProcessMode string

const (
	// ProcessAll indicates that all tickets should be processed, as opposed to
	// just even or odd numbered tickets.
	ProcessAll  ProcessMode = "all"
	processEven ProcessMode = "even"
	processOdd  ProcessMode = "odd"
)

type OverridesImporter struct {
	mode     ProcessMode
	interval time.Duration

	zendesk *zendesk.Client
	ra      rapb.RegistrationAuthorityClient

	clk clock.Clock
	log blog.Logger
}

// NewOverridesImporter creates a new OverridesImporter that will process
// tickets in the given mode at the given interval. An error is returned if the
// interval is left unspecified.
func NewOverridesImporter(mode ProcessMode, interval time.Duration, client *zendesk.Client, sa rapb.RegistrationAuthorityClient, clk clock.Clock, log blog.Logger) (*OverridesImporter, error) {
	if interval <= 0 {
		return nil, fmt.Errorf("interval cannot be 0")
	}
	return &OverridesImporter{
		mode:     mode,
		interval: interval,
		zendesk:  client,
		ra:       sa,
		clk:      clk,
		log:      log,
	}, nil
}

// Start begins the periodic import of approved override requests from Zendesk.
// This method blocks until the provided context is cancelled.
func (im *OverridesImporter) Start(ctx context.Context) {
	ticker := time.NewTicker(im.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			im.tick(ctx)
		}
	}
}

// tick performs a single import pass, serially processing all tickets in the
// configured mode that have been marked "open" and "approved".
func (im *OverridesImporter) tick(ctx context.Context) {
	tickets, err := im.zendesk.FindTickets(map[string]string{ReviewStatusFieldName: reviewStatusApproved}, "open")
	if err != nil {
		im.log.Errf("while searching zendesk for solved and approved tickets: %s", err)
		return
	}

	processed := 0
	failures := 0
	for id, fields := range tickets {
		switch im.mode {
		case processEven:
			if id%2 != 0 {
				continue
			}
		case processOdd:
			if id%2 == 0 {
				continue
			}
		}

		err = im.processTicket(ctx, id, fields)
		if err != nil {
			im.log.Errf("while processing ticket %d: %s", id, err)
			failures++
			continue
		}
		processed++
	}
	im.log.Infof("overrides importer processed %d tickets with %d failures", processed, failures)
}

func accountURIToID(s string) (int64, error) {
	u, err := url.Parse(s)
	if err != nil {
		return 0, err
	}
	rawID := strings.TrimPrefix(u.Path, "/acme/acct/")
	return strconv.ParseInt(rawID, 10, 64)
}

// transitionToPendingWithComment sets the status of the given ticket to
// "pending" and adds a private comment with the given cause. If updating the
// ticket fails, the error is logged.
func (im *OverridesImporter) transitionToPendingWithComment(ticketID int64, cause string) {
	privateBody := fmt.Sprintf(
		"A failure occurred while importing this override:\n\n%s\n\n"+
			"This ticket's status has been set to pending.\n\n"+
			"Once the error has been corrected, change the status back to \"open\" to retry.\n",
		cause,
	)
	err := im.zendesk.UpdateTicketStatus(ticketID, "pending", privateBody, false)
	if err != nil {
		im.log.Errf("failed to update ticket %d: %s", ticketID, err)
	}
}

func (im *OverridesImporter) getValidatedFieldValue(fields map[string]string, fieldName, rateLimit string) (string, error) {
	val := fields[fieldName]
	err := validateOverrideRequestField(fieldName, val, rateLimit)
	if err != nil {
		return "", err
	}
	return val, nil
}

func (im *OverridesImporter) makeAddOverrideRequest(fields map[string]string) (*rapb.AddRateLimitOverrideRequest, string, error) {
	makeReq := func(limit rl.Name, bucket, organization string, tier int64) *rapb.AddRateLimitOverrideRequest {
		return &rapb.AddRateLimitOverrideRequest{
			LimitEnum: int64(limit),
			BucketKey: bucket,
			Count:     tier,
			Burst:     tier,
			Period:    durationpb.New(7 * 24 * time.Hour),
			Comment:   organization,
		}
	}

	rateLimit, ok := fields[RateLimitFieldName]
	if !ok {
		return nil, "", fmt.Errorf("missing rate limit field")
	}
	tierStr, err := im.getValidatedFieldValue(fields, TierFieldName, rateLimit)
	if err != nil {
		return nil, "", fmt.Errorf("getting/validating tier field: %s", err)
	}
	tier, err := strconv.ParseInt(tierStr, 10, 64)
	if err != nil {
		return nil, "", fmt.Errorf("parsing tier: %s", err)
	}
	organization, err := im.getValidatedFieldValue(fields, OrganizationFieldName, "")
	if err != nil {
		return nil, "", fmt.Errorf("getting/validating organization: %s", err)
	}

	var req *rapb.AddRateLimitOverrideRequest
	var accountDomainOrIP string

	switch rateLimit {
	case rl.NewOrdersPerAccount.String():
		accountURI, err := im.getValidatedFieldValue(fields, AccountURIFieldName, "")
		if err != nil {
			return nil, "", fmt.Errorf("getting/validating accountURI: %s", err)
		}
		accountID, err := accountURIToID(accountURI)
		if err != nil {
			return nil, "", fmt.Errorf("parsing accountURI to accountID: %s", err)
		}
		bucketKey, err := rl.BuildBucketKey(rl.NewOrdersPerAccount, accountID, identifier.ACMEIdentifier{}, identifier.ACMEIdentifiers{}, netip.Addr{})
		if err != nil {
			return nil, "", fmt.Errorf("building bucket key: %s", err)
		}
		req = makeReq(rl.NewOrdersPerAccount, bucketKey, organization, tier)
		accountDomainOrIP = accountURI

	case rl.CertificatesPerDomainPerAccount.String():
		accountURI, err := im.getValidatedFieldValue(fields, AccountURIFieldName, "")
		if err != nil {
			return nil, "", fmt.Errorf("getting/validating accountURI: %s", err)
		}
		accountID, err := accountURIToID(accountURI)
		if err != nil {
			return nil, "", fmt.Errorf("parsing accountURI to accountID: %s", err)
		}
		bucketKey, err := rl.BuildBucketKey(rl.CertificatesPerDomainPerAccount, accountID, identifier.ACMEIdentifier{}, identifier.ACMEIdentifiers{}, netip.Addr{})
		if err != nil {
			return nil, "", fmt.Errorf("building bucket key: %s", err)
		}
		req = makeReq(rl.CertificatesPerDomainPerAccount, bucketKey, organization, tier)
		accountDomainOrIP = accountURI

	case rl.CertificatesPerDomain.String() + perDNSNameSuffix:
		dnsName, err := im.getValidatedFieldValue(fields, RegisteredDomainFieldName, rateLimit)
		if err != nil {
			return nil, "", fmt.Errorf("getting/validating registeredDomain: %s", err)
		}
		bucketKey, err := rl.BuildBucketKey(rl.CertificatesPerDomain, 0, identifier.NewDNS(dnsName), identifier.ACMEIdentifiers{}, netip.Addr{})
		if err != nil {
			return nil, "", fmt.Errorf("building bucket key: %s", err)
		}
		accountDomainOrIP = dnsName
		req = makeReq(rl.CertificatesPerDomain, bucketKey, organization, tier)

	case rl.CertificatesPerDomain.String() + perIPSuffix:
		ipAddrStr, err := im.getValidatedFieldValue(fields, IPAddressFieldName, rateLimit)
		if err != nil {
			return nil, "", fmt.Errorf("getting/validating ipAddress: %s", err)
		}
		ipAddr, err := netip.ParseAddr(ipAddrStr)
		if err != nil {
			return nil, "", fmt.Errorf("parsing ipAddress: %s", err)
		}
		bucketKey, err := rl.BuildBucketKey(rl.CertificatesPerDomain, 0, identifier.NewIP(ipAddr), identifier.ACMEIdentifiers{}, netip.Addr{})
		if err != nil {
			return nil, "", fmt.Errorf("building bucket key: %s", err)
		}
		req = makeReq(rl.CertificatesPerDomain, bucketKey, organization, tier)
		accountDomainOrIP = ipAddrStr

	default:
		return nil, "", fmt.Errorf("unknown rate limit")
	}
	return req, accountDomainOrIP, nil
}

func (im *OverridesImporter) processTicket(ctx context.Context, ticketID int64, fields map[string]string) error {
	req, accountDomainOrIP, err := im.makeAddOverrideRequest(fields)
	if err != nil {
		// This will recur until the operator corrects the ticket.
		im.transitionToPendingWithComment(ticketID, err.Error())
		return fmt.Errorf("preparing override request: %w", err)
	}

	resp, err := im.ra.AddRateLimitOverride(ctx, req)
	if err != nil {
		// This is likely a transient error, we'll re-attempt on the next pass.
		return fmt.Errorf("calling ra.AddRateLimitOverride: %w", err)
	}

	rateLimit := rl.Name(req.LimitEnum).String()
	if !resp.Enabled {
		// This will recur until the existing override is re-enabled.
		im.transitionToPendingWithComment(ticketID, "An existing override for this limit and requester is currently administratively disabled.")
		return fmt.Errorf("override for rate limit %s and account/domain/IP: %s is administratively disabled", rateLimit, accountDomainOrIP)
	}

	successCommentBody := fmt.Sprintf(
		"Your override request for rate limit %s and account/domain/IP: %s "+
			"has been approved. Your new limit is %d per week. Please allow up to 30 minutes for this change to take effect.",
		rateLimit, accountDomainOrIP, req.Count,
	)

	err = im.zendesk.UpdateTicketStatus(ticketID, "solved", successCommentBody, true)
	if err != nil {
		return fmt.Errorf("transitioning ticket %d to solved with a comment: %w", ticketID, err)
	}
	return nil
}
