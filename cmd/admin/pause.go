package main

import (
	"context"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/letsencrypt/boulder/identifier"
)

// subcommandPauseBatch encapsulates the "admin pause-batch" commands.
type subcommandPauseBatch struct {
	file string
}

var _ subcommand = (*subcommandPauseBatch)(nil)

func (p *subcommandPauseBatch) Desc() string {
	return "Batch pause a CSV containing (account, identifier type, list of identifier strings)"
}

func (p *subcommandPauseBatch) Flags(flag *flag.FlagSet) {
	flag.StringVar(&p.file, "file", "", "Path to CSV file containing (account, identifier type, list of identifier strings)")
}

func (p *subcommandPauseBatch) Run(ctx context.Context, a *admin) error {
	if p.file == "" {
		return errors.New("the -file flag is required")
	}

	_, err := a.readPausedAccountFile(p.file)
	if err != nil {
		return err
	}

	// TODO: Fix
	return errors.New("no action to perform on the given CSV file was specified")
}

// subcommandUnpauseBatch encapsulates the "admin unpause-batch" commands.
type subcommandUnpauseBatch struct {
	file string
}

var _ subcommand = (*subcommandUnpauseBatch)(nil)

func (u *subcommandUnpauseBatch) Desc() string {
	return "Batch unpause a CSV containing (account, identifier type, list of identifier strings)"
}

func (u *subcommandUnpauseBatch) Flags(flag *flag.FlagSet) {
	flag.StringVar(&u.file, "file", "", "Path to CSV file containing (account, identifier type, list of identifier strings)")
}

func (u *subcommandUnpauseBatch) Run(ctx context.Context, a *admin) error {
	if u.file == "" {
		return errors.New("the -file flag is required")
	}

	_, err := a.readPausedAccountFile(u.file)
	if err != nil {
		return err
	}

	// TODO: Fix
	return errors.New("no action to perform on the given CSV file was specified")
}

// pauseData contains
type pauseData struct {
	accountID       int64
	identifierType  identifier.IdentifierType
	identifierValue []string
}

// readPausedAccountFile parses the contents of a CSV into a slice of
// `pauseData` objects. It will return an error if an individual record is
// malformed.
func (a *admin) readPausedAccountFile(filePath string) ([]pauseData, error) {
	fp, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening paused account data file: %w", err)
	}
	defer fp.Close()

	reader := csv.NewReader(fp)

	// identifierValue can have 1 or more entries
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true

	var data []pauseData

	// Parse file contents
	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			// Finished parsing the file.
			if len(record) == 0 {
				return nil, errors.New("no records found")
			}
			// TODO: return valid data or something
			return data, nil
		} else if err != nil {
			return nil, err
		}

		// Ensure the first column of each record can be parsed as a valid
		// accountID.
		recordID := record[0]
		accountID, err := strconv.ParseInt(recordID, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%q couldn't be parsed as an accountID due to: %s", recordID, err)
		}
		identifierType := identifier.IdentifierType(record[1])
		identifierValue := record[2:]

		fmt.Printf("Loaded: %d,%s,%s", accountID, identifierType, identifierValue[:])
	}
}
