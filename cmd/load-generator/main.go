package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/cmd/load-generator/responder"
	"github.com/letsencrypt/boulder/cmd/load-generator/wfe"
)

func eventParser(description string) ([]wfe.RatePeriod, time.Duration, error) {
	periods := []wfe.RatePeriod{}
	sections := strings.Split(description, ":")
	runtime := time.Duration(0)
	for _, s := range sections {
		fields := strings.Split(s, ",")
		if len(fields) != 2 {
			return nil, 0, fmt.Errorf("Invalid event format")
		}
		dur, err := time.ParseDuration(fields[1])
		if err != nil {
			return nil, 0, err
		}
		rate, err := strconv.Atoi(fields[0])
		if err != nil {
			return nil, 0, err
		}
		if rate <= 0 {
			return nil, 0, fmt.Errorf("rate must be a positive non-zero integer")
		}
		periods = append(periods, wfe.RatePeriod{
			For:  dur,
			Rate: int64(rate),
		})
		runtime += dur
	}
	return periods, runtime, nil
}

func usage(fs []*flag.FlagSet) {
	fmt.Fprintln(os.Stdout, "Usage:")
	for _, s := range fs {
		fmt.Fprint(os.Stderr, "\t[Section]\n")
		s.PrintDefaults()
	}
}

func main() {
	wfeArgs := flag.NewFlagSet("wfe", flag.ExitOnError)
	wfeAPIBase := wfeArgs.String("apiBase", "http://localhost:4000", "The base URI of boulder-wfe")
	wfeCertKeySize := wfeArgs.Int("certKeySize", 2048, "Bit size of the private key to sign certificates with")
	wfeDomainBase := wfeArgs.String("domainBase", "com", "Base label for randomly generated domains")
	wfeResultsPath := wfeArgs.String("results", "", "Path to write results file to")
	wfeChallRPCAddr := wfeArgs.String("challRPCAddr", "localhost:6060", "Address to send challenge RPC calls to")
	wfeHTTPOneAddr := wfeArgs.String("httpOneAddr", "localhost:5002", "Address for the http-01 challenge server to listen one")
	wfeDontRunChallSrv := wfeArgs.Bool("dontRunChallSrv", false, "Don't manage spawning and killing of the challenge server")
	wfeRealIP := wfeArgs.String("realIP", "", "Vale for the X-REAL-IP header")
	wfePlan := wfeArgs.String("plan", "", "Execution plan for WFE generator,  Format is '{throughput},{duration for}:{next throughput},{duration for}' etc. E.g. '1,10m' or '2,5m:3,5m:4,5m:5,5m'")
	wfeWarmupRegs := wfeArgs.Int("warmupRegs", 0, "Number of registrations to create as a warmup")
	wfeWarmupRegWorkers := wfeArgs.Int("warmupRegWorkers", 1, "Number of workers to use to create warmup registrations")
	wfeMaxRegs := wfeArgs.Int("maxRegs", 0, "Maximum number of registrations to create during the run")
	wfeLoadRegsPath := wfeArgs.String("loadRegs", "", "Path to load existing registration definitions from")
	wfeSaveRegsPath := wfeArgs.String("saveRegs", "", "Path to save existing/generated registration definitions to")
	wfeUserEmail := wfeArgs.String("userEmail", "test@example.com", "Email to user in the registration 'contacts' field, if empty no contacts are sent")

	ocspArgs := flag.NewFlagSet("ocsp", flag.ExitOnError)
	ocspBase := ocspArgs.String("ocspBase", "http://localhost:4000", "The base URI of the OCSP responder")
	ocspGetPlan := ocspArgs.String("getPlan", "", "Execution plan for OCSP GET generator,  Format is '{throughput},{duration for}:{next throughput},{duration for}' etc. E.g. '1,10m' or '2,5m:3,5m:4,5m:5,5m'")
	ocspPostPlan := ocspArgs.String("postPlan", "", "Execution plan for OCSP GET generator,  Format is '{throughput},{duration for}:{next throughput},{duration for}' etc. E.g. '1,10m' or '2,5m:3,5m:4,5m:5,5m'")
	ocspIssuer := ocspArgs.String("issuer", "", "Path to issuer to use to generate OCSP requests")
	ocspResultsPath := ocspArgs.String("results", "", "Path to write results file to")
	ocspSerialsPath := ocspArgs.String("serials", "", "Path to CSV file of serial numbers of use")

	challSrvArgs := flag.NewFlagSet("challSrv", flag.ExitOnError)
	challSrvRPCAddr := challSrvArgs.String("rpcAddr", "localhost:6060", "Address to listen on for RPC calls from WFE load-generator")
	challSrvHTTPOneAddr := challSrvArgs.String("httpOneAddr", "localhost:5002", "Address for the http-01 challenge server to listen on")

	if len(os.Args) <= 1 {
		fmt.Fprint(os.Stderr, "A sub-command is required\n\n")
		usage([]*flag.FlagSet{wfeArgs, ocspArgs, challSrvArgs})
		os.Exit(1)
	}

	switch os.Args[1] {
	case "wfe":
		wfeArgs.Parse(os.Args[2:])

		if *wfePlan == "" {
			fmt.Fprint(os.Stderr, "--plan is required\n\n")
			usage([]*flag.FlagSet{wfeArgs})
			os.Exit(1)
		}
		runPlan, runtime, err := eventParser(*wfePlan)
		cmd.FailOnError(err, "Failed to parse plan")

		s, err := wfe.New(
			*wfeChallRPCAddr,
			*wfeAPIBase,
			*wfeCertKeySize,
			*wfeDomainBase,
			runtime,
			*wfeRealIP,
			runPlan,
			*wfeMaxRegs,
			*wfeWarmupRegs,
			*wfeWarmupRegWorkers,
			*wfeResultsPath,
			*wfeUserEmail,
		)
		cmd.FailOnError(err, "Failed to create WFE generator")

		if *wfeLoadRegsPath != "" {
			err = s.Restore(*wfeLoadRegsPath)
			cmd.FailOnError(err, "Failed to load registration snapshot")
		}

		err = s.Run(os.Args[0], *wfeDontRunChallSrv, *wfeHTTPOneAddr)
		cmd.FailOnError(err, "Failed to run WFE load generator")

		if *wfeSaveRegsPath != "" {
			err = s.Snapshot(*wfeSaveRegsPath)
			cmd.FailOnError(err, "Failed to save registration snapshot")
		}
	case "ocsp":
		ocspArgs.Parse(os.Args[2:])

		getPlan, getRuntime, err := eventParser(*ocspGetPlan)
		postPlan, postRuntime, err := eventParser(*ocspPostPlan)
		var runtime time.Duration
		if getRuntime < postRuntime {
			runtime = postRuntime
		} else {
			runtime = getRuntime
		}

		cont, err := ioutil.ReadFile(*ocspSerialsPath)
		cmd.FailOnError(err, "Failed to read serials file")
		serials := strings.Split(string(cont), "\n")

		s, err := responder.New(
			*ocspBase,
			getPlan,
			postPlan,
			*ocspIssuer,
			*ocspResultsPath,
			runtime,
			serials,
		)
		cmd.FailOnError(err, "Failed to create OCSP-Responder generator")

		s.Run()
	case "challSrv":
		challSrvArgs.Parse(os.Args[2:])
		srv := wfe.NewChallSrv(*challSrvHTTPOneAddr, *challSrvRPCAddr)
		srv.Run()
	default:
		fmt.Fprintf(os.Stderr, "%s is a invalid command\n\n", os.Args[1])
		usage([]*flag.FlagSet{wfeArgs, ocspArgs, challSrvArgs})
		os.Exit(1)
	}
	fmt.Println("[+] All done, bye bye ^_^")
}
