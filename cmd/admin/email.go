package main

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/letsencrypt/boulder/sa"
)

// subcommandClearEmail encapsulates the "admin clear-email" command.
//
// Note that this command may be very slow, as the initial query to find the
// set of accounts which have a matching contact email address does not use a
// database index. Therefore, when removing contact email addresses from found
// accounts, it does not exit on failure, preferring to continue and make as
// much progress as possible.
func (a *admin) subcommandClearEmail(ctx context.Context, args []string) error {
	subflags := flag.NewFlagSet("clear-email", flag.ExitOnError)
	email := subflags.String("address", "", "Email address to remove (required)")
	_ = subflags.Parse(args)

	if *email == "" {
		return errors.New("the -address flag is required")
	}

	a.log.AuditInfof("Scanning database for accounts with email addresses matching %q in order to clear the email addresses.", *email)

	// We use SQL `CONCAT` rather than interpolating with `+` or `%s` because we want to
	// use a `?` placeholder for the email, which prevents SQL injection.
	// Since this uses a substring match, it is important
	// to subsequently parse the JSON list of addresses and look for exact matches.
	// Because this does not use an index, it is very slow.
	var regIDs []int64
	_, err := a.dbMap.Select(ctx, &regIDs, "SELECT id FROM registrations WHERE contact LIKE CONCAT('%\"mailto:', ?, '\"%')", *email)
	if err != nil {
		return fmt.Errorf("identifying matching accounts: %w", err)
	}

	a.log.Infof("Found %d registration IDs matching email %q.", len(regIDs), *email)

	failures := 0
	for _, regID := range regIDs {
		if a.dryRun {
			a.log.Infof("dry-run: remove %q from account %d", *email, regID)
			continue
		}

		err := sa.ClearEmail(ctx, a.dbMap, regID, *email)
		if err != nil {
			// Log, but don't fail, because it took a long time to find the relevant registration IDs
			// and we don't want to have to redo that work.
			a.log.AuditErrf("failed to clear email %q for registration ID %d: %s", *email, regID, err)
			failures++
		} else {
			a.log.AuditInfof("cleared email %q for registration ID %d", *email, regID)
		}
	}
	if failures > 0 {
		return fmt.Errorf("failed to clear email for %d out of %d registration IDs", failures, len(regIDs))
	}

	return nil
}
