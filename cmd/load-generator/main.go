package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/codegangsta/cli"

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

func main() {
	app := cli.NewApp()
	app.Name = "load-generator"
	app.Usage = "Load generating tool for boulders publicly facing services"
	app.Version = cmd.Version()
	app.Author = "Boulder contributors"
	app.Email = "ca-dev@letsencrypt.org"

	app.Commands = []cli.Command{
		{
			Name:  "wfe",
			Usage: "WFE generator",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "apiBase",
					Usage: "The base URI of boulder-wfe",
					Value: "http://localhost:4000",
				},
				cli.IntFlag{
					Name:  "rate",
					Usage: "The base rate (per second) at which to perform API actions",
					Value: 1,
				},
				cli.IntFlag{
					Name:  "certKeySize",
					Usage: "Bit size of the key to sign certificates with",
					Value: 2048,
				},
				cli.StringFlag{
					Name:  "domainBase",
					Usage: "Base label for randomly generated domains",
					Value: "com",
				},
				cli.StringFlag{
					Name:  "runtime",
					Usage: "",
				},
				cli.StringFlag{
					Name:  "latencyDataPath",
					Usage: "Filename of latency chart data to save",
				},
				cli.StringFlag{
					Name:  "termsURL",
					Usage: "The terms URL to agree too",
					Value: "http://127.0.0.1:4001/terms/v1",
				},
				cli.StringFlag{
					Name:  "challRPCAddr",
					Usage: "Address to send RPC calls",
					Value: "localhost:6060",
				},
				cli.StringFlag{
					Name:  "httpOneAddr",
					Usage: "Address for the http-0 challenge server to listen on",
					Value: "localhost:5002",
				},
				cli.BoolFlag{
					Name:  "dontRunChallSrv",
					Usage: "Don't manage spawning and killing of the challenge server",
				},
				cli.StringFlag{
					Name:  "realIP",
					Usage: "IP to set X-Real-IP header to",
				},
				cli.StringFlag{
					Name:  "plan",
					Usage: "Alternative to --rate and --runtime, allows definition of a test where the base action rate changes. Format is '{throughput},{duration for}:{next throughput},{duration for}' etc. E.g. '2,5m:3,5m:4,5m:5,5m'",
				},
			},
			Action: func(c *cli.Context) {
				var runtime time.Duration
				var rate int
				var runPlan []wfe.RatePeriod
				var err error
				if c.String("runtime") != "" && c.Int("rate") != 0 || c.String("plan") != "" {
					if c.String("plan") != "" {
						rate = 1
						runPlan, runtime, err = eventParser(c.String("plan"))
						cmd.FailOnError(err, "Failed to parse plan")
					} else {
						rate = c.Int("rate")
						runtime, err = time.ParseDuration(c.String("runtime"))
						cmd.FailOnError(err, "Failed to parse runtime")
					}
				} else {
					fmt.Println("Either (--runtime and --rate) or --plan is required")
					os.Exit(1)
				}

				s, err := wfe.New(
					c.String("challRPCAddr"),
					c.String("apiBase"),
					rate,
					c.Int("certKeySize"),
					c.String("domainBase"),
					runtime,
					c.String("termsURL"),
					c.String("realIP"),
					runPlan,
				)
				cmd.FailOnError(err, "Failed to create WFE generator")

				err = s.Run(os.Args[0], c.Bool("dontRunChallSrv"), c.String("httpOneAddr"))
				cmd.FailOnError(err, "Failed to run WFE load generator")
				err = s.Dump(c.String("latencyDataPath"))
				cmd.FailOnError(err, "Failed to dump latency data")
			},
		},
		{
			Name:  "ocsp-responder",
			Usage: "OCSP-Responder generator",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "ocspBase",
					Usage: "The base URI of ocsp responder",
					Value: "http://localhost:4000",
				},
				cli.IntFlag{
					Name:  "maxRequests",
					Usage: "The maximum number of OCSP request bodies to generate",
				},
				cli.IntFlag{
					Name:  "getRate",
					Usage: "",
				},
				cli.IntFlag{
					Name:  "postRate",
					Usage: "",
				},
				cli.StringFlag{
					Name:  "dbURI",
					Usage: "",
					Value: "mysql+tcp://sa@localhost:3306/boulder_sa_integration",
				},
				cli.StringFlag{
					Name:  "issuerPath",
					Usage: "",
				},
				cli.StringFlag{
					Name:  "runtime",
					Usage: "",
				},
				cli.StringFlag{
					Name:  "latencyDataPath",
					Usage: "Filename of latency chart data to save",
				},
			},
			Action: func(c *cli.Context) {
				runtime, err := time.ParseDuration(c.String("runtime"))
				cmd.FailOnError(err, "Failed to parse runtime")
				s, err := responder.New(
					c.Int("maxRequests"),
					c.String("ocspBase"),
					c.Int("getRate"),
					c.Int("postRate"),
					c.String("dbURI"),
					c.String("issuerPath"),
					runtime,
				)
				cmd.FailOnError(err, "Failed to create OCSP-Responder generator")

				s.Run()
				err = s.Dump(c.String("latencyDataPath"))
				cmd.FailOnError(err, "Failed to dump latency data")
			},
		},
		{
			Name:  "chall-srv",
			Usage: "The challenge server for WFE mode",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "rpcAddr",
					Usage: "Address to listen for RPC calls from WFE load-generator",
					Value: "localhost:6060",
				},
				cli.StringFlag{
					Name:  "httpOneAddr",
					Usage: "Address for the http-0 challenge server to listen on",
					Value: "localhost:5002",
				},
			},
			Action: func(c *cli.Context) {
				srv := wfe.NewChallSrv(c.String("httpOneAddr"), c.String("rpcAddr"))
				srv.Run()
			},
		},
	}

	err := app.Run(os.Args)
	cmd.FailOnError(err, "Failed to run load-generator")
}
