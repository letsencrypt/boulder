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
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

// subcommandPauseIdentifier encapsulates the "admin pause-identifiers" command.
type subcommandPauseIdentifier struct {
	batchFile string
}

var _ subcommand = (*subcommandPauseIdentifier)(nil)

func (p *subcommandPauseIdentifier) Desc() string {
	return "Administratively pause an account preventing it from attempting certificate issuance"
}

func (p *subcommandPauseIdentifier) Flags(flag *flag.FlagSet) {
	flag.StringVar(&p.batchFile, "batch-file", "", "Path to a CSV file containing (account ID, identifier type, identifier value)")
}

func (p *subcommandPauseIdentifier) Run(ctx context.Context, a *admin) error {
	if p.batchFile == "" {
		return errors.New("the -batch-file flag is required")
	}

	identifiers, err := a.readPausedAccountFile(p.batchFile)
	if err != nil {
		return err
	}

	_, err = a.pauseIdentifiers(ctx, identifiers)
	if err != nil {
		return err
	}

	return nil
}

// pauseIdentifiers allows administratively pausing a set of domain names for an
// account. It returns a slice of PauseIdentifiersResponse or an error.
func (a *admin) pauseIdentifiers(ctx context.Context, incoming []pauseCSVData) ([]*sapb.PauseIdentifiersResponse, error) {
	if len(incoming) <= 0 {
		return nil, errors.New("cannot pause identifiers because no pauseData was sent")
	}

	var responses []*sapb.PauseIdentifiersResponse
	for _, data := range incoming {
		req := sapb.PauseRequest{
			RegistrationID: data.accountID,
			Identifiers: []*sapb.Identifier{
				{
					Type:  string(data.identifierType),
					Value: data.identifierValue,
				},
			},
		}
		response, err := a.sac.PauseIdentifiers(ctx, &req)
		if err != nil {
			return nil, err
		}
		responses = append(responses, response)
	}

	return responses, nil
}

// pauseCSVData contains a golang representation of the data loaded in from a
// CSV file for pausing.
type pauseCSVData struct {
	accountID       int64
	identifierType  identifier.IdentifierType
	identifierValue string
}

// readPausedAccountFile parses the contents of a CSV into a slice of
// `pauseCSVData` objects and returns it or an error. It will skip malformed
// lines and continue processing until either the end of file marker is detected
// or other read error.
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
	lineCounter := 0

	// Process contents of the CSV file
	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}

		lineCounter++

		// We should have strictly 3 fields, note that just commas is considered
		// a valid CSV line.
		if len(record) != 3 {
			a.log.Infof("skipping: malformed line %d, should contain exactly 3 fields\n", lineCounter)
			continue
		}

		recordID := record[0]
		accountID, err := strconv.ParseInt(recordID, 10, 64)
		if err != nil || accountID == 0 {
			a.log.Infof("skipping: malformed accountID entry on line %d\n", lineCounter)
			continue
		}

		// Ensure that an identifier type is present, otherwise skip the line.
		if len(record[1]) == 0 {
			a.log.Infof("skipping: malformed identifierType entry on line %d\n", lineCounter)
			continue
		}

		if len(record[2]) == 0 {
			a.log.Infof("skipping: malformed identifierValue entry on line %d\n", lineCounter)
			continue
		}

		parsedRecord := pauseCSVData{
			accountID:       accountID,
			identifierType:  identifier.IdentifierType(record[1]),
			identifierValue: record[2],
		}
		parsedRecords = append(parsedRecords, parsedRecord)
	}
	a.log.Infof("detected %d valid record(s) from input file\n", len(parsedRecords))

	return parsedRecords, nil
}
