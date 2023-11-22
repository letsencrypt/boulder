package validator

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nxadm/tail"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/letsencrypt/boulder/log"
)

var errInvalidChecksum = errors.New("invalid checksum length")

type Validator struct {
	tailers []*tail.Tail

	lineCounter *prometheus.CounterVec
	log         log.Logger
}

func New(logger log.Logger, stats prometheus.Registerer) *Validator {
	lineCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "log_lines",
		Help: "A counter of log lines processed, with status",
	}, []string{"filename", "status"})
	stats.MustRegister(lineCounter)

	return &Validator{log: logger, lineCounter: lineCounter}
}

// TailValidateFile takes a filename, and starts tailing it.
// An error is returned if the file couldn't be opened.
func (v *Validator) TailValidateFile(filename string) error {
	t, err := tail.TailFile(filename, tail.Config{
		ReOpen:        true,
		MustExist:     false, // sometimes files won't exist, so we must tolerate that
		Follow:        true,
		Logger:        tailLogger{v.log},
		CompleteLines: true,
	})
	if err != nil {
		return err
	}

	go func() {
		// Emit no more than 1 error line per second. This prevents consuming large
		// amounts of disk space in case there is problem that causes all log lines to
		// be invalid.
		outputLimiter := time.NewTicker(time.Second)
		defer outputLimiter.Stop()

		for line := range t.Lines {
			if line.Err != nil {
				v.log.Errf("error while tailing %s: %s", t.Filename, line.Err)
				continue
			}
			err := lineValid(line.Text)
			if err != nil {
				if errors.Is(err, errInvalidChecksum) {
					v.lineCounter.WithLabelValues(t.Filename, "invalid checksum length").Inc()
				} else {
					v.lineCounter.WithLabelValues(t.Filename, "bad").Inc()
				}
				select {
				case <-outputLimiter.C:
					v.log.Errf("%s: %s %q", t.Filename, err, line.Text)
				default:
				}
			} else {
				v.lineCounter.WithLabelValues(t.Filename, "ok").Inc()
			}
		}
	}()

	v.tailers = append(v.tailers, t)

	return nil
}

// Shutdown should be called before process shutdown
func (v *Validator) Shutdown() {
	for _, t := range v.tailers {
		// The tail module seems to have a race condition that will generate
		// errors like this on shutdown:
		// failed to stop tailing file: <filename>: Failed to detect creation of
		// <filename>: inotify watcher has been closed
		// This is probably related to the module's shutdown logic triggering the
		// "reopen" code path for files that are removed and then recreated.
		// These errors are harmless so we ignore them to allow clean shutdown.
		_ = t.Stop()
		t.Cleanup()
	}
}

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
	const errorPrefix = "log-validator:"
	// Extract checksum from line
	if len(fields) < 6 {
		return fmt.Errorf("%s line doesn't match expected format", errorPrefix)
	}
	checksum := fields[5]
	_, err := base64.RawURLEncoding.DecodeString(checksum)
	if err != nil || len(checksum) != 7 {
		return fmt.Errorf(
			"%s expected a 7 character base64 raw URL decodable string, got %q: %w",
			errorPrefix,
			checksum,
			errInvalidChecksum,
		)
	}

	// Reconstruct just the message portion of the line
	line := strings.Join(fields[6:], " ")

	// If we are fed our own output, treat it as always valid. This
	// prevents runaway scenarios where we generate ever-longer output.
	if strings.Contains(text, errorPrefix) {
		return nil
	}
	// Check the extracted checksum against the computed checksum
	if computedChecksum := log.LogLineChecksum(line); checksum != computedChecksum {
		return fmt.Errorf("%s invalid checksum (expected %q, got %q)", errorPrefix, computedChecksum, checksum)
	}
	return nil
}

// ValidateFile validates a single file and returns
func ValidateFile(filename string) error {
	file, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	badFile := false
	for i, line := range strings.Split(string(file), "\n") {
		if line == "" {
			continue
		}
		err := lineValid(line)
		if err != nil {
			badFile = true
			fmt.Fprintf(os.Stderr, "[line %d] %s: %s\n", i+1, err, line)
		}
	}

	if badFile {
		return errors.New("file contained invalid lines")
	}
	return nil
}
