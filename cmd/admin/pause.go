package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/letsencrypt/boulder/identifier"
	rapb "github.com/letsencrypt/boulder/ra/proto"
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

// pauseData contains
type pauseData struct {
	accountID       int64
	identifierType  identifier.IdentifierType
	identifierValue []string
}

// pauseIdentifiers allows administratively pausing a set of domain names for an
// account.
func (a *admin) pauseIdentifiers(pd []pauseData) error {
	if len(pd) <= 0 {
		return errors.New("cannot pause identifiers because no pauseData was sent")
	}

	for _, data := range pd {
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
func (a *admin) unpauseAccount(pd []pauseData) error {
	if len(pd) <= 0 {
		return errors.New("cannot unpause accounts because no pauseData was sent")
	}

	for _, data := range pd {
		req := rapb.UnpauseAccountRequest{
			RegistrationID: data.accountID,
		}
		_, err := a.rac.UnpauseAccount(context.Background(), &req)
		if err != nil {
			return err
		}
	}

	return nil
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

	var parsedRecords []pauseData
	hashToPauseData := make(map[string]pauseData)
	lineCounter := 1

	defer func() {
		var record string
		if len(hashToPauseData) == 1 {
			record = "record"
		} else {
			record = "records"
		}
		fmt.Fprintf(os.Stderr, "detected %d valid %s from input file\n", len(hashToPauseData), record)
	}()

	// Process contents of the CSV file
	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			// Finished parsing the file.
			//if len(record) == 0 {
			//	return nil, errors.New("no records found")
			//}

			for _, value := range hashToPauseData {
				parsedRecords = append(parsedRecords, value)
			}

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
		identifierType := identifier.IdentifierType(record[1])

		if len(record) < 3 {
			fmt.Fprintf(os.Stderr, "skipping: malformed identifierValue entry on line %d\n", lineCounter)
			continue
		}
		// The remaining fields are the domain names.
		identifierValue := record[2:]
		slices.Sort(identifierValue)

		// Construct a hash over the parsed line from the CSV. The hash will be
		// used as a key mapping to a pauseData object containing the fields we
		// wish to operate on.
		hash := sha256.New()
		var recordBytes []byte
		recordBytes = append(recordBytes, byte(accountID))
		recordBytes = append(recordBytes, []byte(identifierType)...)
		recordBytes = append(recordBytes, []byte(strings.Join(identifierValue, ""))...)
		b64Hash := base64.StdEncoding.EncodeToString(hash.Sum(recordBytes))

		if _, ok := hashToPauseData[b64Hash]; !ok {
			hashToPauseData[b64Hash] = pauseData{
				accountID:       accountID,
				identifierType:  identifierType,
				identifierValue: identifierValue,
			}
		} else {
			fmt.Fprintf(os.Stderr, "skipping: duplicate entry on line %d: %d,%s,%s\n", lineCounter, accountID, identifierType, identifierValue[:])
		}
		lineCounter++
	}
}
