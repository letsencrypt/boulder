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

// subcommandPauseIdentifier encapsulates the "admin pause-identifiers" command.
type subcommandPauseIdentifier struct {
	batchFile string
}

var _ subcommand = (*subcommandPauseIdentifier)(nil)

func (p *subcommandPauseIdentifier) Desc() string {
	return "Batch pause a CSV containing (account ID, identifier type, list of identifier strings)"
}

func (p *subcommandPauseIdentifier) Flags(flag *flag.FlagSet) {
	flag.StringVar(&p.batchFile, "batch-file", "", "Path to a CSV file containing (account ID, identifier type, list of identifier strings)")
}

func (p *subcommandPauseIdentifier) Run(ctx context.Context, a *admin) error {
	if p.batchFile == "" {
		return errors.New("the -batch-file flag is required")
	}

	identifiers, err := a.readPausedAccountFile(p.batchFile)
	if err != nil {
		return err
	}

	err = a.pauseIdentifiers(identifiers)
	if err != nil {
		return err
	}

	return nil
}

// pauseIdentifiers allows administratively pausing a set of domain names for an
// account.
func (a *admin) pauseIdentifiers(incoming []pauseCSVData) error {
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

// pauseCSVData contains a golang representation of the data loaded in from a
// CSV file for pausing.
type pauseCSVData struct {
	accountID       int64
	identifierType  identifier.IdentifierType
	identifierValue []string
}

// readPausedAccountFile parses the contents of a CSV into a slice of `csvData`
// objects. It will return an error if an individual record is malformed.
func (a *admin) readPausedAccountFile(filePath string) ([]pauseCSVData, error) {
	fp, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening paused account data file: %w", err)
	}
	defer fp.Close()

	reader := csv.NewReader(fp)

	// identifierValue can have 1 or more entries
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true

	var parsedRecords []pauseCSVData
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

		parsedRecord := pauseCSVData{
			accountID:       accountID,
			identifierType:  identifier.IdentifierType(record[1]),
			identifierValue: record[2:],
		}
		parsedRecords = append(parsedRecords, parsedRecord)
		lineCounter++
	}
}
