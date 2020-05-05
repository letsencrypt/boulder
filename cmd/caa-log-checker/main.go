package main

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/cmd"
)

func openFile(path string) (*bufio.Scanner, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	var reader io.Reader
	reader = f
	if strings.HasSuffix(path, ".gz") {
		reader, err = gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
	}
	scanner := bufio.NewScanner(reader)
	return scanner, nil
}

type issuanceEvent struct {
	SerialNumber string
	Names        []string
	ResponseTime time.Time
	Requester    int64
}

var raIssuanceLineRE = regexp.MustCompile(`Certificate request - successful JSON=(.*)`)

func checkIssuances(scanner *bufio.Scanner, checkedMap map[string][]time.Time, stderr *os.File) error {
	lNum := 0
	for scanner.Scan() {
		lNum++
		line := scanner.Text()
		matches := raIssuanceLineRE.FindStringSubmatch(line)
		if matches == nil {
			continue
		}
		if len(matches) != 2 {
			return fmt.Errorf("line %d: unexpected number of regex matches", lNum)
		}
		var ie issuanceEvent
		err := json.Unmarshal([]byte(matches[1]), &ie)
		if err != nil {
			return fmt.Errorf("line %d: failed to unmarshal JSON: %s", lNum, err)
		}
		var badNames []string
		for _, name := range ie.Names {
			nameOk := false
			for _, t := range checkedMap[name] {
				if t.Before(ie.ResponseTime) && t.After(ie.ResponseTime.Add(-8*time.Hour)) {
					nameOk = true
				}
			}
			if !nameOk {
				badNames = append(badNames, name)
			}
		}
		if len(badNames) > 0 {
			hash := hashNames(ie.Names)
			fmt.Fprintf(stderr, "Issuance missing CAA checks: issued at=%s, serial=%s, requester=%d, names hash=%x, names=%s, missing checks for names=%s\n", ie.ResponseTime, ie.SerialNumber, ie.Requester, hash, ie.Names, badNames)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func hashNames(names []string) []byte {
	names = uniqueLowerNames(names)
	hash := sha256.Sum256([]byte(strings.Join(names, ",")))
	return hash[:]
}

func uniqueLowerNames(names []string) (unique []string) {
	nameMap := make(map[string]int, len(names))
	for _, name := range names {
		nameMap[strings.ToLower(name)] = 1
	}

	unique = make([]string, 0, len(nameMap))
	for name := range nameMap {
		unique = append(unique, name)
	}
	sort.Strings(unique)
	return
}

var vaCAALineRE = regexp.MustCompile(`Checked CAA records for ([a-z0-9-.*]+), \[Present: (true|false)`)

func processVALog(checkedMap map[string][]time.Time, scanner *bufio.Scanner) error {
	lNum := 0
	for scanner.Scan() {
		lNum++
		line := scanner.Text()
		matches := vaCAALineRE.FindStringSubmatch(line)
		if matches == nil {
			continue
		}
		if len(matches) != 3 {
			return fmt.Errorf("line %d: unexpected number of regex matches", lNum)
		}
		domain := matches[1]
		labels := strings.Split(domain, ".")
		present := matches[2]

		datestampText := line[0:32]
		datestamp, err := time.Parse(time.RFC3339, datestampText)
		if err != nil {
			return fmt.Errorf("line %d: failed processing timestamp: %s", lNum, err)
		}

		checkedMap[domain] = append(checkedMap[domain], datestamp)
		// If we checked x.y.z, and the result was Present: false, that means we
		// also checked y.z and z, and found no records there.
		// We'll add y.z to the map, but not z (to save memory space, since we don't issue
		// for z).
		if present == "false" {
			for i := 1; i < len(labels)-1; i++ {
				parent := strings.Join(labels[i:], ".")
				checkedMap[parent] = append(checkedMap[parent], datestamp)
			}
		}
	}
	return scanner.Err()
}

func loadMap(paths []string) (map[string][]time.Time, error) {
	var checkedMap = make(map[string][]time.Time)

	for _, path := range paths {
		scanner, err := openFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to open %q: %s", path, err)
		}
		if err = processVALog(checkedMap, scanner); err != nil {
			return nil, fmt.Errorf("failed to process %q: %s", path, err)
		}
	}

	return checkedMap, nil
}

func main() {
	raLog := flag.String("ra-log", "", "Path to a single boulder-ra log file")
	vaLogs := flag.String("va-logs", "", "List of paths to boulder-va logs, separated by commas")
	flag.Parse()

	// Build a map from hostnames to a list of times those hostnames were checked
	// for CAA.
	checkedMap, err := loadMap(strings.Split(*vaLogs, ","))
	cmd.FailOnError(err, "failed while loading VA logs")

	raScanner, err := openFile(*raLog)
	cmd.FailOnError(err, fmt.Sprintf("failed to open %q", *raLog))

	err = checkIssuances(raScanner, checkedMap, os.Stderr)
	cmd.FailOnError(err, "failed while processing RA log")
}
