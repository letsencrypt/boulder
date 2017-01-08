package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/cmd/load-generator/wfe"
)

func usage(fs []*flag.FlagSet) {
	fmt.Fprintln(os.Stdout, "Usage:")
	for _, s := range fs {
		fmt.Fprint(os.Stderr, "\t[Section]\n")
		s.PrintDefaults()
	}
}

func main() {
	wfeArgs := flag.NewFlagSet("wfe", flag.ExitOnError)
	wfeConfigPath := wfeArgs.String("config", "", "Path to configuration file for WFE load-generator")

	ocspArgs := flag.NewFlagSet("ocsp", flag.ExitOnError)
	// ocspBase := ocspArgs.String("ocspBase", "http://localhost:4000", "The base URI of the OCSP responder")
	// ocspGetPlan := ocspArgs.String("getPlan", "", "Execution plan for OCSP GET generator,  Format is '{throughput},{duration for}:{next throughput},{duration for}' etc. E.g. '1,10m' or '2,5m:3,5m:4,5m:5,5m'")
	// ocspPostPlan := ocspArgs.String("postPlan", "", "Execution plan for OCSP GET generator,  Format is '{throughput},{duration for}:{next throughput},{duration for}' etc. E.g. '1,10m' or '2,5m:3,5m:4,5m:5,5m'")
	// ocspIssuer := ocspArgs.String("issuer", "", "Path to issuer to use to generate OCSP requests")
	// ocspResultsPath := ocspArgs.String("results", "", "Path to write results file to")
	// ocspSerialsPath := ocspArgs.String("serials", "", "Path to CSV file of serial numbers of use")

	if len(os.Args) <= 1 {
		fmt.Fprint(os.Stderr, "A sub-command is required\n\n")
		usage([]*flag.FlagSet{wfeArgs, ocspArgs})
		os.Exit(1)
	}

	switch os.Args[1] {
	case "wfe":
		err := wfeArgs.Parse(os.Args[2:])
		cmd.FailOnError(err, "Failed to parse arguments")

		configBytes, err := ioutil.ReadFile(*wfeConfigPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read wfe config file %q: %s\n", &wfeConfigPath, err)
			os.Exit(1)
		}
		var config wfe.Config
		err = json.Unmarshal(configBytes, &config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse wfe config file: %s\n", err)
			os.Exit(1)
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

		err = s.Run(config.HTTPOneAddr, config.TLSOneAddr, wfe.Plan{})
		cmd.FailOnError(err, "Failed to run WFE load generator")

		if config.ExternalState != "" && !config.DontSaveState {
			err = s.Snapshot(config.ExternalState)
			cmd.FailOnError(err, "Failed to save registration snapshot")
		}
	// case "ocsp":
	// 	err := ocspArgs.Parse(os.Args[2:])
	// 	cmd.FailOnError(err, "Failed to parse arguments")

	// 	getPlan, getRuntime, err := eventParser(*ocspGetPlan)
	// 	postPlan, postRuntime, err := eventParser(*ocspPostPlan)
	// 	var runtime time.Duration
	// 	if getRuntime < postRuntime {
	// 		runtime = postRuntime
	// 	} else {
	// 		runtime = getRuntime
	// 	}

	// 	cont, err := ioutil.ReadFile(*ocspSerialsPath)
	// 	cmd.FailOnError(err, "Failed to read serials file")
	// 	serials := strings.Split(string(cont), "\n")

	// 	s, err := responder.New(
	// 		*ocspBase,
	// 		getPlan,
	// 		postPlan,
	// 		*ocspIssuer,
	// 		*ocspResultsPath,
	// 		runtime,
	// 		serials,
	// 	)
	// 	cmd.FailOnError(err, "Failed to create OCSP-Responder generator")

	// 	s.Run()
	default:
		fmt.Fprintf(os.Stderr, "%s is a invalid command\n\n", os.Args[1])
		usage([]*flag.FlagSet{wfeArgs, ocspArgs})
		os.Exit(1)
	}
	fmt.Println("[+] All done, bye bye ^_^")
}
