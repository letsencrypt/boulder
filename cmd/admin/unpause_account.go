package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"

	sapb "github.com/letsencrypt/boulder/sa/proto"
	"golang.org/x/exp/maps"
)

// subcommandUnpauseAccount encapsulates the "admin unpause-account" command.
type subcommandUnpauseAccount struct {
	batchFile string
	regID     int64
}

var _ subcommand = (*subcommandUnpauseAccount)(nil)

func (u *subcommandUnpauseAccount) Desc() string {
	return "Administratively unpause an account to allow certificate issuance attempts"
}

func (u *subcommandUnpauseAccount) Flags(flag *flag.FlagSet) {
	flag.StringVar(&u.batchFile, "batch-file", "", "Path to a file containing multiple account IDs where each is separated by a newline")
	flag.Int64Var(&u.regID, "account", 0, "A single account ID to unpause")
}

func (u *subcommandUnpauseAccount) Run(ctx context.Context, a *admin) error {
	// This is a map of all input-selection flags to whether or not they were set
	// to a non-default value. We use this to ensure that exactly one input
	// selection flag was given on the command line.
	setInputs := map[string]bool{
		"-account":    u.regID != 0,
		"-batch-file": u.batchFile != "",
	}
	maps.DeleteFunc(setInputs, func(_ string, v bool) bool { return !v })
	if len(setInputs) == 0 {
		return errors.New("at least one input method flag must be specified")
	} else if len(setInputs) > 1 {
		return fmt.Errorf("more than one input method flag specified: %v", maps.Keys(setInputs))
	}

	var regIDs []int64
	var err error
	switch maps.Keys(setInputs)[0] {
	case "-account":
		regIDs = []int64{u.regID}
	case "-batch-file":
		regIDs, err = a.readUnpauseAccountFile(u.batchFile)
	default:
		return errors.New("no recognized input method flag set (this shouldn't happen)")
	}
	if err != nil {
		return fmt.Errorf("collecting serials to revoke: %w", err)
	}

	_, err = a.unpauseAccounts(ctx, regIDs)
	if err != nil {
		return err
	}

	return nil
}

// unpauseAccount allows administratively unpausing all identifiers for an
// account. Returns a slice of int64 which is counter of unpaused accounts or an
// error.
func (a *admin) unpauseAccounts(ctx context.Context, regIDs []int64) ([]int64, error) {
	var count []int64
	if len(regIDs) <= 0 {
		return count, errors.New("no regIDs sent for unpausing")
	}

	for _, regID := range regIDs {
		response, err := a.sac.UnpauseAccount(ctx, &sapb.RegistrationID{Id: regID})
		if err != nil {
			return count, err
		}
		count = append(count, response.Count)
	}

	return count, nil
}

// readUnpauseAccountFile parses the contents of a file containing one account
// ID per into a slice of int64s. It will skip malformed records and continue
// processing until the end of file marker.
func (a *admin) readUnpauseAccountFile(filePath string) ([]int64, error) {
	fp, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening paused account data file: %w", err)
	}
	defer fp.Close()

	var unpauseAccounts []int64
	lineCounter := 0
	scanner := bufio.NewScanner(fp)
	for scanner.Scan() {
		lineCounter++
		regID, err := strconv.ParseInt(scanner.Text(), 10, 64)
		if err != nil {
			a.log.Infof("skipping: malformed account ID entry on line %d\n", lineCounter)
			continue
		}
		unpauseAccounts = append(unpauseAccounts, regID)
	}

	if err := scanner.Err(); err != nil {
		return nil, scanner.Err()
	}

	return unpauseAccounts, nil
}
