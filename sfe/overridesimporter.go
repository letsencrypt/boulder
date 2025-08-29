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
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 3 {
		return 0, fmt.Errorf("unexpected path %q", u.Path)
	}
	id, convErr := strconv.ParseInt(parts[len(parts)-1], 10, 64)
	if convErr != nil {
		return 0, convErr
	}
	return id, nil
}

// transitionToPendingWithComment sets the status of the given ticket to
// "pending" and adds a private comment with the given cause. If updating the
// ticket fails, the error is logged.
func (im *OverridesImporter) transitionToPendingWithComment(ticketID int64, cause string) {
	privateBody := fmt.Sprintf(
		"A failure occurred while importing this override:\n\n%s\n\n"+
			"This ticket's status has been set to pending.\n\n"+
			"Once the error has been corrected, change the status back to \"solved\" to retry.\n",
		cause,
	)
	err := im.zendesk.UpdateTicketStatus(ticketID, "pending", privateBody, false)
	if err != nil {
		im.log.Errf("failed to update ticket %d: %s", ticketID, err)
	}
}

func makeAddOverrideRequest(limit rl.Name, bucket, organization string, tier int64) *rapb.AddRateLimitOverrideRequest {
	return &rapb.AddRateLimitOverrideRequest{
		LimitEnum: int64(limit),
		BucketKey: bucket,
		Count:     tier,
		Burst:     tier,
		Period:    durationpb.New(7 * 24 * time.Hour),
		Comment:   organization,
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

func (im *OverridesImporter) processTicket(ctx context.Context, ticketID int64, fields map[string]string) error {
	var pendingComment string
	defer func() {
		if pendingComment != "" {
			im.transitionToPendingWithComment(ticketID, pendingComment)
		}
	}()

	rateLimit, ok := fields[RateLimitFieldName]
	if !ok {
		pendingComment = "missing rate limit field"
		return fmt.Errorf("missing rate limit field")
	}
	tierStr, err := im.getValidatedFieldValue(fields, TierFieldName, rateLimit)
	if err != nil {
		pendingComment = fmt.Sprintf("getting/validating tier field: %s", err)
		return err
	}
	tier, err := strconv.ParseInt(tierStr, 10, 64)
	if err != nil {
		pendingComment = fmt.Sprintf("parsing tier: %s", err)
		return err
	}
	organization, err := im.getValidatedFieldValue(fields, OrganizationFieldName, "")
	if err != nil {
		pendingComment = fmt.Sprintf("getting/validating organization: %s", err)
		return err
	}

	var req *rapb.AddRateLimitOverrideRequest
	var accountDomainOrIP string

	switch rateLimit {
	case rl.NewOrdersPerAccount.String():
		accountURI, err := im.getValidatedFieldValue(fields, AccountURIFieldName, "")
		if err != nil {
			pendingComment = fmt.Sprintf("getting/validating accountURI: %s", err)
			return err
		}
		accountID, err := accountURIToID(accountURI)
		if err != nil {
			pendingComment = fmt.Sprintf("parsing accountURI to accountID: %s", err)
			return err
		}
		bucketKey, err := rl.BuildBucketKey(rl.NewOrdersPerAccount, accountID, identifier.ACMEIdentifier{}, identifier.ACMEIdentifiers{}, netip.Addr{})
		if err != nil {
			pendingComment = fmt.Sprintf("building bucket key: %s", err)
			return err
		}
		req = makeAddOverrideRequest(rl.NewOrdersPerAccount, bucketKey, organization, tier)
		accountDomainOrIP = accountURI

	case rl.CertificatesPerDomainPerAccount.String():
		accountURI, err := im.getValidatedFieldValue(fields, AccountURIFieldName, "")
		if err != nil {
			pendingComment = fmt.Sprintf("getting/validating accountURI: %s", err)
			return err
		}
		accountID, err := accountURIToID(accountURI)
		if err != nil {
			pendingComment = fmt.Sprintf("parsing accountURI to accountID: %s", err)
			return err
		}
		bucketKey, err := rl.BuildBucketKey(rl.CertificatesPerDomainPerAccount, accountID, identifier.ACMEIdentifier{}, identifier.ACMEIdentifiers{}, netip.Addr{})
		if err != nil {
			pendingComment = fmt.Sprintf("building bucket key: %s", err)
			return err
		}
		req = makeAddOverrideRequest(rl.CertificatesPerDomainPerAccount, bucketKey, organization, tier)
		accountDomainOrIP = accountURI

	case rl.CertificatesPerDomain.String() + perDNSNameSuffix:
		dnsName, err := im.getValidatedFieldValue(fields, RegisteredDomainFieldName, rateLimit)
		if err != nil {
			pendingComment = fmt.Sprintf("getting/validating registeredDomain: %s", err)
			return err
		}
		bucketKey, err := rl.BuildBucketKey(rl.CertificatesPerDomain, 0, identifier.NewDNS(dnsName), identifier.ACMEIdentifiers{}, netip.Addr{})
		if err != nil {
			pendingComment = fmt.Sprintf("building bucket key: %s", err)
			return err
		}
		req = makeAddOverrideRequest(rl.CertificatesPerDomain, bucketKey, organization, tier)
		accountDomainOrIP = dnsName

	case rl.CertificatesPerDomain.String() + perIPSuffix:
		ipAddrStr, err := im.getValidatedFieldValue(fields, IPAddressFieldName, rateLimit)
		if err != nil {
			pendingComment = fmt.Sprintf("getting/validating ipAddress: %s", err)
			return err
		}
		ipAddr, err := netip.ParseAddr(ipAddrStr)
		if err != nil {
			pendingComment = fmt.Sprintf("parsing ipAddress: %s", err)
			return err
		}
		bucketKey, err := rl.BuildBucketKey(rl.CertificatesPerDomain, 0, identifier.NewIP(ipAddr), identifier.ACMEIdentifiers{}, netip.Addr{})
		if err != nil {
			pendingComment = fmt.Sprintf("building bucket key: %s", err)
			return err
		}
		req = makeAddOverrideRequest(rl.CertificatesPerDomain, bucketKey, organization, tier)
		accountDomainOrIP = ipAddrStr

	default:
		err = fmt.Errorf("unknown rate limit %q", rateLimit)
		pendingComment = "unknown rate limit"
		return err
	}

	if accountDomainOrIP == "" {
		// If this has occurred we have failed to set the accountDNSNameOrIP in
		// one of the above cases, which is a bug.
		return fmt.Errorf("no account/domain/IP specified for rate limit %s", rateLimit)
	}

	resp, err := im.ra.AddRateLimitOverride(ctx, req)
	if err != nil {
		// This is likely a transient error, so we leave the ticket as "solved"
		// so that it will be retried on the next pass.
		return fmt.Errorf("calling ra.AddRateLimitOverride: %w", err)
	}

	if !resp.Enabled {
		pendingComment = "An existing override for this limit and requester is currently administratively disabled."
		return fmt.Errorf("override for rate limit %s and account/domain/IP: %s is administratively disabled", rateLimit, accountDomainOrIP)
	}

	successCommentBody := fmt.Sprintf(
		"Your override request for rate limit %s and account/domain/IP: %s "+
			"has been approved. Your new limit is %d per week. Please allow up to 30 minutes for this change to take effect.",
		rateLimit, accountDomainOrIP, tier,
	)

	err = im.zendesk.UpdateTicketStatus(ticketID, "solved", successCommentBody, true)
	if err != nil {
		return fmt.Errorf("transitioning ticket %d to solved with a comment: %w", ticketID, err)
	}
	return nil
}
