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
)

// subcommandUnpauseAccount encapsulates the "admin unpause-account" command.
type subcommandUnpauseAccount struct {
	batchFile string
	regID     int64
}

var _ subcommand = (*subcommandUnpauseAccount)(nil)

func (u *subcommandUnpauseAccount) Desc() string {
	return "Batch unpause a file containing multiple account IDs where each is separated by a newline."
}

func (u *subcommandUnpauseAccount) Flags(flag *flag.FlagSet) {
	flag.StringVar(&u.batchFile, "batch-file", "", "Path to a file containing multiple account IDs where each is separated by a newline")
	flag.Int64Var(&u.regID, "account", 0, "A single account ID to unpause")
}

func (u *subcommandUnpauseAccount) Run(ctx context.Context, a *admin) error {
	if u.batchFile == "" && u.regID == 0 {
		return errors.New("either the -batch-file or -account flag is required")
	}
	if u.batchFile != "" && u.regID != 0 {
		return errors.New("only one of -batch-file or -account flag should be used")
	}

	var regIDs []int64
	var err error
	if u.batchFile != "" {
		regIDs, err = a.readUnpauseAccountFile(u.batchFile)
		if err != nil {
			return err
		}
	} else {
		regIDs = []int64{u.regID}
	}

	err = a.unpauseAccounts(regIDs)
	if err != nil {
		return err
	}

	return nil
}

// unpauseAccount allows administratively unpausing all identifiers for an
// account.
func (a *admin) unpauseAccounts(regIDs []int64) error {
	if len(regIDs) <= 0 {
		return errors.New("cannot unpause accounts because no pauseData was sent")
	}

	for _, regID := range regIDs {
		_, err := a.sac.UnpauseAccount(context.Background(), &sapb.RegistrationID{Id: regID})
		if err != nil {
			return err
		}
	}

	return nil
}

// readUnpauseAccountFile parses the contents of a CSV into a slice of `csvData`
// objects. It will return an error if an individual record is malformed.
func (a *admin) readUnpauseAccountFile(filePath string) ([]int64, error) {
	fp, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening paused account data file: %w", err)
	}
	defer fp.Close()

	var unpauseAccounts []int64
	defer func() {
		var record string
		if len(unpauseAccounts) == 1 {
			record = "record"
		} else {
			record = "records"
		}
		fmt.Fprintf(os.Stderr, "detected %d valid %s from input file\n", len(unpauseAccounts), record)
	}()

	lineCounter := 1
	scanner := bufio.NewScanner(fp)
	for scanner.Scan() {
		regID, err := strconv.ParseInt(scanner.Text(), 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping: malformed account ID entry on line %d\n", lineCounter)
			continue
		}
		unpauseAccounts = append(unpauseAccounts, regID)
		lineCounter++
	}

	if err := scanner.Err(); err != nil {
		return nil, scanner.Err()
	}

	return unpauseAccounts, nil
}
