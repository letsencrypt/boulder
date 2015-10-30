package main

import (
	"os"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/codegangsta/cli"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/cmd/load-generator/responder"
	"github.com/letsencrypt/boulder/cmd/load-generator/wfe"
)

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
					Name:  "maxRegs",
					Usage: "Maximum number of registrations to generate",
					Value: 100,
				},
				cli.IntFlag{
					Name:  "certKeySize",
					Usage: "Bit size of the key to sign certificates with",
					Value: 2048,
				},
				cli.IntFlag{
					Name:  "httpOnePort",
					Usage: "Port to run the http-0 challenge server on",
					Value: 5002,
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
			},
			Action: func(c *cli.Context) {
				runtime, err := time.ParseDuration(c.String("runtime"))
				cmd.FailOnError(err, "Failed to parse runtime")
				s, err := wfe.New(
					c.Int("httpOnePort"),
					c.String("apiBase"),
					c.Int("rate"),
					c.Int("maxRegs"),
					c.Int("certKeySize"),
					c.String("domainBase"),
					runtime,
				)
				cmd.FailOnError(err, "Failed to create WFE generator")

				s.Run()
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
	}

	err := app.Run(os.Args)
	cmd.FailOnError(err, "Failed to run load-generator")
}
