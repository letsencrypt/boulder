package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/hpcloud/tail"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
)

func lineValid(text string) error {
	// Line format should match the following rsyslog omfile template:
	//
	//   template( name="LELogFormat" type="list" ) {
	//  	property(name="timereported" dateFormat="rfc3339")
	//  	constant(value=" ")
	//  	property(name="hostname" field.delimiter="46" field.number="1")
	//  	constant(value=" datacenter ")
	//  	property(name="syslogseverity")
	//  	constant(value=" ")
	//  	property(name="syslogtag")
	//  	property(name="msg" spifno1stsp="on" )
	//  	property(name="msg" droplastlf="on" )
	//  	constant(value="\n")
	//   }
	//
	// This should result in a log line that looks like this:
	//   timestamp hostname datacenter syslogseverity binary-name[pid]: checksum msg

	fields := strings.Split(text, " ")
	// Extract checksum from line
	if len(fields) < 6 {
		return errors.New("line doesn't match expected format")
	}
	checksum := fields[5]
	// Reconstruct just the message portion of the line
	line := strings.Join(fields[6:], " ")
	// Check the extracted checksum against the computed checksum
	if computedChecksum := blog.LogLineChecksum(line); checksum != computedChecksum {
		return fmt.Errorf("invalid checksum (expected %q, got %q)", computedChecksum, checksum)
	}
	return nil
}

func validateFile(filename string) error {
	file, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	badFile := false
	for i, line := range strings.Split(string(file), "\n") {
		if line == "" {
			continue
		}
		if err := lineValid(line); err != nil {
			badFile = true
			fmt.Fprintf(os.Stderr, "[line %d] %s: %s\n", i+1, err, line)
		}
	}

	if badFile {
		return errors.New("file contained invalid lines")
	}
	return nil
}

func main() {
	configPath := flag.String("config", "", "File path to the configuration file for this service")
	checkFile := flag.String("check-file", "", "File path to a file to directly validate, if this argument is provided the config will not be parsed and only this file will be inspected")
	flag.Parse()

	if *checkFile != "" {
		err := validateFile(*checkFile)
		cmd.FailOnError(err, "validation failed")
		return
	}

	var config struct {
		Syslog cmd.SyslogConfig
		Files  []string
	}
	configBytes, err := ioutil.ReadFile(*configPath)
	cmd.FailOnError(err, "failed to read config file")
	err = json.Unmarshal(configBytes, &config)
	cmd.FailOnError(err, "failed to parse config file")

	logger := cmd.NewLogger(config.Syslog)

	var tailers []*tail.Tail
	for _, filename := range config.Files {
		t, err := tail.TailFile(filename, tail.Config{
			ReOpen:    true,
			MustExist: true,
			Follow:    true,
		})
		cmd.FailOnError(err, "failed to tail file")
		defer t.Cleanup()

		go func() {
			for line := range t.Lines {
				if line.Err != nil {
					logger.Errf("error while tailing %s: %s", t.Filename, err)
					continue
				}
				if err := lineValid(line.Text); err != nil {
					logger.Errf("%s: %s %q", t.Filename, err, line.Text)
				}
			}
		}()

		tailers = append(tailers, t)
	}

	cmd.CatchSignals(logger, func() {
		for _, t := range tailers {
			err = t.Stop()
			cmd.FailOnError(err, fmt.Sprintf("failed to stop tailing file: %s", t.Filename))
		}
	})
}
