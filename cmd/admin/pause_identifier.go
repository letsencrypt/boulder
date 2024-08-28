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
	"sync"

	"github.com/letsencrypt/boulder/identifier"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/semaphore"
)

// subcommandPauseIdentifier encapsulates the "admin pause-identifiers" command.
type subcommandPauseIdentifier struct {
	batchFile   string
	maxInFlight int64
}

var _ subcommand = (*subcommandPauseIdentifier)(nil)

func (p *subcommandPauseIdentifier) Desc() string {
	return "Administratively pause an account preventing it from attempting certificate issuance"
}

func (p *subcommandPauseIdentifier) Flags(flag *flag.FlagSet) {
	flag.StringVar(&p.batchFile, "batch-file", "", "Path to a CSV file containing (account ID, identifier type, identifier value)")
	flag.Int64Var(&p.maxInFlight, "max-in-flight", 10, "The maximum number of concurrent pause requests to send to the SA")
}

func (p *subcommandPauseIdentifier) Run(ctx context.Context, a *admin) error {
	if p.batchFile == "" {
		return errors.New("the -batch-file flag is required")
	}

	identifiers, err := a.readPausedAccountFile(p.batchFile)
	if err != nil {
		return err
	}

	_, err = a.pauseIdentifiers(ctx, identifiers, p.maxInFlight)
	if err != nil {
		return err
	}

	return nil
}

// pauseIdentifiers pauses each account, identifier pair in the provided slice
// of pauseCSVData entries. It will pause up to maxInFlight identifiers at a
// time. If any errors occur while pausing, they will be gathered and returned
// as a single error.
func (a *admin) pauseIdentifiers(ctx context.Context, entries []pauseCSVData, maxInFlight int64) ([]*sapb.PauseIdentifiersResponse, error) {
	if len(entries) <= 0 {
		return nil, errors.New("cannot pause identifiers because no pauseData was sent")
	}

	accountToIdentifiers := make(map[int64][]*sapb.Identifier)
	for _, entry := range entries {
		accountToIdentifiers[entry.accountID] = append(accountToIdentifiers[entry.accountID], &sapb.Identifier{
			Type:  string(entry.identifierType),
			Value: entry.identifierValue,
		})
	}

	respChan := make(chan *sapb.PauseIdentifiersResponse, len(accountToIdentifiers))
	errorsChan := make(chan error, len(accountToIdentifiers))
	sem := semaphore.NewWeighted(maxInFlight, 0)

	var wg sync.WaitGroup
	for accountID, identifiers := range accountToIdentifiers {
		wg.Add(1)
		go func(accountID int64, identifiers []*sapb.Identifier) {
			defer wg.Done()

			err := sem.Acquire(ctx, 1)
			if err != nil {
				errorsChan <- fmt.Errorf("while acquiring semaphore to pause identifier(s) %q for account %d: %w", identifiers, accountID, err)
				return
			}
			defer sem.Release(1)

			response, err := a.sac.PauseIdentifiers(ctx, &sapb.PauseRequest{
				RegistrationID: accountID,
				Identifiers:    identifiers,
			})
			if err != nil {
				errorsChan <- fmt.Errorf("while pausing identifier(s) %q for account %d: %w", identifiers, accountID, err)
				return
			}
			respChan <- response
		}(accountID, identifiers)
	}

	wg.Wait()
	close(respChan)
	close(errorsChan)

	responses := make([]*sapb.PauseIdentifiersResponse, 0)
	for response := range respChan {
		responses = append(responses, response)
	}

	var errors []error
	for err := range errorsChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return responses, fmt.Errorf("one or more errors occurred while pausing: %v", errors)
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
