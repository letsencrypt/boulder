package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/hpcloud/tail"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
)

func lineValid(text string) bool {
	// Line format should match the following template:
	//   timestamp hostname datacenter level binary-name[pid]: checksum msg
	//
	// template( name="LELogFormat" type="list" ) {
	// 	property(name="timereported" dateFormat="rfc3339")
	// 	constant(value=" ")
	// 	property(name="hostname" field.delimiter="46" field.number="1")
	// 	constant(value=" slc ")
	// 	property(name="syslogseverity")
	// 	constant(value=" ")
	// 	property(name="syslogtag")
	// 	property(name="msg" spifno1stsp="on" )
	// 	property(name="msg" droplastlf="on" )
	// 	constant(value="\n")
	// }

	fields := strings.Split(text, " ")
	// Extract checksum from line
	checksum := fields[5]
	// Reconstruct just the message portion of the line
	line := strings.Join(fields[6:], " ")
	// Check the extracted checksum against the computed checksum
	return checksum == blog.LogLineChecksum(line)
}

func validateFile(filename string) error {
	file, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	for i, line := range strings.Split(string(file), "\n") {
		if line == "" {
			continue
		}
		if !lineValid(line) {
			fmt.Printf("bad checksum for line %d: %s\n", i+1, line)
		}
	}

	return nil
}

func main() {
	configPath := flag.String("config", "", "File path to the configuration file for this service")
	checkFile := flag.String("check-file", "", "File path to a file to directly validate, if this argument is provided the config will not be parsed and only this file will be inspected")
	flag.Parse()

	if *checkFile != "" {
		err := validateFile(*checkFile)
		cmd.FailOnError(err, "failed to validate file")
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
					fmt.Printf("bad bad tail: %s\n", err)
					continue
				}
				if !lineValid(line.Text) {
					fmt.Printf("bad checksum for line: %s\n", line.Text)
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
