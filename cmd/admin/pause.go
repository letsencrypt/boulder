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
	"strings"

	"github.com/letsencrypt/boulder/identifier"
	sapb "github.com/letsencrypt/boulder/sa/proto"
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

	identifiers, err := a.readPausedAccountFile(p.file)
	if err != nil {
		return err
	}

	err = a.pauseIdentifiers(identifiers)
	if err != nil {
		return err
	}

	return nil
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

	identifiers, err := a.readPausedAccountFile(u.file)
	if err != nil {
		return err
	}

	err = a.unpauseAccount(identifiers)
	if err != nil {
		return err
	}

	return nil
}

// csvData contains a golang representation of the data loaded in from a CSV
// file for pausing and unpausing.
type csvData struct {
	accountID       int64
	identifierType  identifier.IdentifierType
	identifierValue []string
}

// pauseIdentifiers allows administratively pausing a set of domain names for an
// account.
func (a *admin) pauseIdentifiers(incoming []csvData) error {
	if len(incoming) <= 0 {
		return errors.New("cannot pause identifiers because no pauseData was sent")
	}

	for _, data := range incoming {
		req := sapb.PauseRequest{
			RegistrationID: data.accountID,
			Identifiers: []*sapb.Identifier{{
				Type:  string(data.identifierType),
				Value: strings.Join(data.identifierValue, ","),
			},
			},
		}
		_, err := a.sac.PauseIdentifiers(context.Background(), &req)
		if err != nil {
			return err
		}
	}

	return nil
}

// unpauseAccount allows administratively unpausing all identifiers for an
// account.
func (a *admin) unpauseAccount(incoming []csvData) error {
	if len(incoming) <= 0 {
		return errors.New("cannot unpause accounts because no pauseData was sent")
	}

	for _, data := range incoming {
		req := sapb.RegistrationID{
			Id: data.accountID,
		}
		_, err := a.sac.UnpauseAccount(context.Background(), &req)
		if err != nil {
			return err
		}
	}

	return nil
}

// readPausedAccountFile parses the contents of a CSV into a slice of
// `pauseData` objects. It will return an error if an individual record is
// malformed.
func (a *admin) readPausedAccountFile(filePath string) ([]csvData, error) {
	fp, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening paused account data file: %w", err)
	}
	defer fp.Close()

	reader := csv.NewReader(fp)

	// identifierValue can have 1 or more entries
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true

	var parsedRecords []csvData
	lineCounter := 1

	defer func() {
		var record string
		if len(parsedRecords) == 1 {
			record = "record"
		} else {
			record = "records"
		}
		fmt.Fprintf(os.Stderr, "detected %d valid %s from input file\n", len(parsedRecords), record)
	}()

	// Process contents of the CSV file
	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			return parsedRecords, nil
		} else if err != nil {
			return nil, err
		}

		recordID := record[0]
		accountID, err := strconv.ParseInt(recordID, 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping: malformed accountID entry on line %d\n", lineCounter)
			continue
		}

		// Ensure that an identifier type is present, otherwise skip the line.
		if len(record[1]) == 0 {
			fmt.Fprintf(os.Stderr, "skipping: malformed identifierType entry on line %d\n", lineCounter)
			continue
		}

		// The remaining fields are the domain names, so make sure at least one
		// exists.
		if len(record) < 3 {
			fmt.Fprintf(os.Stderr, "skipping: malformed identifierValue entry on line %d\n", lineCounter)
			continue
		}

		parsedRecord := csvData{
			accountID:       accountID,
			identifierType:  identifier.IdentifierType(record[1]),
			identifierValue: record[2:],
		}
		parsedRecords = append(parsedRecords, parsedRecord)
		lineCounter++
	}
}
