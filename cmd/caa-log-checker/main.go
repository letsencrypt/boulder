package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/cmd"
)

var debug = flag.Bool("debug", false, "Enable debug logging")

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
	Requester    int64

	issuanceTime time.Time
}

var raIssuanceLineRE = regexp.MustCompile(`Certificate request - successful JSON=(.*)`)

func parseTimestamp(line string) (time.Time, error) {
	datestampText := line[0:32]
	datestamp, err := time.Parse(time.RFC3339, datestampText)
	if err != nil {
		return time.Time{}, err
	}
	return datestamp, nil
}

func checkIssuances(scanner *bufio.Scanner, checkedMap map[string][]time.Time, timeTolerance time.Duration,
	earliest time.Time, latest time.Time, stderr *os.File) (bool, error) {
	linesRead := 0
	skipCount := 0
	evaluatedCount := 0
	foundErrors := false
	for scanner.Scan() {
		linesRead++
		line := scanner.Text()
		matches := raIssuanceLineRE.FindStringSubmatch(line)
		if matches == nil {
			continue
		}
		if len(matches) != 2 {
			return foundErrors, fmt.Errorf("line %d: unexpected number of regex matches", linesRead)
		}
		var ie issuanceEvent
		err := json.Unmarshal([]byte(matches[1]), &ie)
		if err != nil {
			return foundErrors, fmt.Errorf("line %d: failed to unmarshal JSON: %s", linesRead, err)
		}

		// populate the issuance time from the syslog timestamp, rather than the ResponseTime
		// member of the JSON. This makes testing a lot simpler because of how we mess with
		// time sometimes. Given these timestamps are generated on the same system they should
		// be tightly coupled anyway.
		ie.issuanceTime, err = parseTimestamp(line)
		if err != nil {
			return foundErrors, fmt.Errorf("line %d: failed to parse timestamp: %s", linesRead, err)
		}

		if !earliest.IsZero() && !latest.IsZero() &&
			(ie.issuanceTime.Before(earliest) || ie.issuanceTime.After(latest)) {
			skipCount++
			continue
		}
		evaluatedCount++

		var badNames []string
		var timeErrors []float64

		for _, name := range ie.Names {
			nameOk := false

			var minTimeError float64 = math.Inf(+1)

			for _, t := range checkedMap[name] {
				validStart := ie.issuanceTime.Add(-8 * time.Hour)
				validEnd := ie.issuanceTime
				if t.After(validStart) && t.Before(validEnd.Add(timeTolerance)) {
					nameOk = true
				} else if t.After(validStart) {
					// If the check didn't pass and the check is in the future, calculate how much tolerance
					// we'd need for it to pass, to make it easier to diagnose log timestamp desync.
					timeError := t.Sub(validEnd)
					// ...however only if its <1h, otherwise it's probably not a match
					if timeError < timeTolerance+time.Hour {
						minTimeError = math.Min(minTimeError, float64(timeError)/float64(time.Second))
					}
				}
			}
			if !nameOk {
				badNames = append(badNames, name)
				timeErrors = append(timeErrors, minTimeError)
			}
		}
		if len(badNames) > 0 {
			foundErrors = true
			fmt.Fprintf(stderr, "Issuance missing CAA checks: issued at=%s, serial=%s, requester=%d, names=%s, missing checks for names=%s, timeError=%.3f\n", ie.issuanceTime, ie.SerialNumber, ie.Requester, ie.Names, badNames, timeErrors)
		}
	}
	if err := scanner.Err(); err != nil {
		return foundErrors, err
	}
	if *debug {
		fmt.Fprintf(stderr, "Issuance log lines read %d evaluated %d skipped %d\n", linesRead, evaluatedCount, skipCount)
	}
	return foundErrors, nil
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

		datestamp, err := parseTimestamp(line)
		if err != nil {
			return fmt.Errorf("line %d: failed to parse timestamp: %s", lNum, err)
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
	logStdoutLevel := flag.Int("stdout-level", 6, "Minimum severity of messages to send to stdout")
	logSyslogLevel := flag.Int("syslog-level", 6, "Minimum severity of messages to send to syslog")
	raLog := flag.String("ra-log", "", "Path to a single boulder-ra log file")
	vaLogs := flag.String("va-logs", "", "List of paths to boulder-va logs, separated by commas")
	timeTolerance := flag.Duration("time-tolerance", 0, "How much slop to allow when comparing timestamps for ordering")
	earliestFlag := flag.String("earliest", "", "Day at which to start checking issuances "+
		"(inclusive). Formatted like '20060102' Optional. If specified, -latest is required.")
	latestFlag := flag.String("latest", "", "Day at which to stop checking issuances "+
		"(exclusive). Formatted like '20060102'. Optional. If specified, -earliest is required.")

	flag.Parse()

	if *timeTolerance < 0 {
		cmd.Fail("value of -time-tolerance must be non-negative")
	}

	var earliest time.Time
	var latest time.Time
	if *earliestFlag != "" || *latestFlag != "" {
		if *earliestFlag == "" || *latestFlag == "" {
			cmd.Fail("-earliest and -latest must be both set or both unset")
		}
		var err error
		earliest, err = time.Parse("20060102", *earliestFlag)
		cmd.FailOnError(err, "value of -earliest could not be parsed as date")
		latest, err = time.Parse("20060102", *latestFlag)
		cmd.FailOnError(err, "value of -latest could not be parsed as date")

		if earliest.After(latest) {
			cmd.Fail("earliest date must be before latest date")
		}
	}

	_ = cmd.NewLogger(cmd.SyslogConfig{
		StdoutLevel: *logStdoutLevel,
		SyslogLevel: *logSyslogLevel,
	})

	// Build a map from hostnames to a list of times those hostnames were checked
	// for CAA.
	checkedMap, err := loadMap(strings.Split(*vaLogs, ","))
	cmd.FailOnError(err, "failed while loading VA logs")

	raScanner, err := openFile(*raLog)
	cmd.FailOnError(err, fmt.Sprintf("failed to open %q", *raLog))

	foundErrors, err := checkIssuances(raScanner, checkedMap, *timeTolerance, earliest, latest, os.Stderr)
	cmd.FailOnError(err, "failed while processing RA log")

	if foundErrors {
		os.Exit(1)
	}
}
