package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/cmd/load-generator/wfe"
)

func main() {
	configPath := flag.String("config", "", "Path to configuration file for WFE load-generator")
	resultsPath := flag.String("results", "", "Path to latency results file")
	rateArg := flag.Int("rate", 0, "")
	runtimeArg := flag.String("runtime", "", "")
	deltaArg := flag.String("delta", "", "")
	flag.Parse()

	configBytes, err := ioutil.ReadFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read wfe config file %q: %s\n", &configPath, err)
		os.Exit(1)
	}
	var config wfe.Config
	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse wfe config file: %s\n", err)
		os.Exit(1)
	}

	if *resultsPath != "" {
		config.Results = *resultsPath
	}
	if *rateArg != 0 {
		config.Plan.Rate = int64(*rateArg)
	}
	if *runtimeArg != "" {
		config.Plan.Runtime = *runtimeArg
	}
	if *deltaArg != "" {
		config.Plan.RateDelta = *deltaArg
	}

	s, err := wfe.New(
		config.APIBase,
		config.CertKeySize,
		config.DomainBase,
		config.RealIP,
		config.MaxRegs,
		config.Results,
		config.RegEmail,
		config.Plan.Actions,
	)
	cmd.FailOnError(err, "Failed to create WFE generator")

	if config.ExternalState != "" {
		err = s.Restore(config.ExternalState)
		cmd.FailOnError(err, "Failed to load registration snapshot")
	}

	runtime, err := time.ParseDuration(config.Plan.Runtime)
	cmd.FailOnError(err, "Failed to parse plan runtime")

	var delta *wfe.RateDelta
	if config.Plan.RateDelta != "" {
		parts := strings.Split(config.Plan.RateDelta, "/")
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "RateDelta is malformed")
			os.Exit(1)
		}
		rate, err := strconv.Atoi(parts[0])
		cmd.FailOnError(err, "Failed to parse increase portion of RateDelta")
		period, err := time.ParseDuration(parts[1])
		cmd.FailOnError(err, "Failed to parse period portion of RateDelta")
		delta = &wfe.RateDelta{Inc: int64(rate), Period: period}
	}

	err = s.Run(config.HTTPOneAddr, config.TLSOneAddr, wfe.Plan{
		Runtime: runtime,
		Rate:    config.Plan.Rate,
		Delta:   delta,
	})
	cmd.FailOnError(err, "Failed to run WFE load generator")

	if config.ExternalState != "" && !config.DontSaveState {
		err = s.Snapshot(config.ExternalState)
		cmd.FailOnError(err, "Failed to save registration snapshot")
	}

	fmt.Println("[+] All done, bye bye ^_^")
}
