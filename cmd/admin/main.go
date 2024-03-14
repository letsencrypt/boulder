// Package main provides the "admin" tool, which can perform various
// administrative actions (such as revoking certificates) against a Boulder
// deployment.
//
// Run "admin -h" for a list of flags and subcommands.
//
// Note that the admin tool runs in "dry-run" mode *by default*. All commands
// which mutate the database (either directly or via gRPC requests) will refuse
// to do so, and instead print log lines representing the work they would do,
// unless the "-dry-run=false" flag is passed.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/features"
)

type Config struct {
	Admin struct {
		// DB controls the admin tool's direct connection to the database.
		DB cmd.DBConfig
		// TLS controls the TLS client the admin tool uses for gRPC connections.
		TLS cmd.TLSConfig

		RAService *cmd.GRPCClientConfig
		SAService *cmd.GRPCClientConfig

		DebugAddr string

		Features features.Config
	}

	Syslog        cmd.SyslogConfig
	OpenTelemetry cmd.OpenTelemetryConfig
}

// main is the entry-point for the admin tool. We do not include admin in the
// suite of tools which are subcommands of the "boulder" binary, since it
// should be small and portable and standalone.
func main() {
	// Do setup as similarly as possible to all other boulder services, including
	// config parsing and stats and logging setup. However, the one downside of
	// not being bundled with the boulder binary is that we don't get config
	// validation for free.
	defer cmd.AuditPanic()

	configFile := flag.String("config", "", "Path to the configuration file for this service (required)")
	dryRun := flag.Bool("dry-run", true, "Print actions instead of mutating the database")

	subcommands := map[string]struct {
		desc string
		run  func(*admin, context.Context, []string) error
	}{
		"revoke-cert": {
			"Revoke one or more certificates",
			func(a *admin, ctx context.Context, args []string) error {
				return a.subcommandRevokeCert(ctx, args)
			},
		},
		"block-key": {
			"Block a keypair from any future issuance",
			func(a *admin, ctx context.Context, args []string) error {
				return a.subcommandBlockKey(ctx, args)
			},
		},
		"update-email": {
			"Change or remove an email address across all accounts",
			func(a *admin, ctx context.Context, args []string) error {
				return a.subcommandUpdateEmail(ctx, args)
			},
		},
	}

	defaultUsage := flag.Usage
	flag.Usage = func() {
		defaultUsage()
		fmt.Printf("\nSubcommands:\n")
		for name, command := range subcommands {
			fmt.Printf("  %s\n", name)
			fmt.Printf("\t%s\n", command.desc)
		}
		fmt.Print("\nYou can run \"admin -config /path/to/cfg.json <subcommand> -help\" to get usage for that subcommand.\n")
	}

	flag.Parse()

	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c Config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "parsing config file")

	scope, logger, oTelShutdown := cmd.StatsAndLogging(c.Syslog, c.OpenTelemetry, c.Admin.DebugAddr)
	defer oTelShutdown(context.Background())
	logger.Info(cmd.VersionString())

	features.Set(c.Admin.Features)

	a, err := newAdmin(c, *dryRun, cmd.Clock(), logger, scope)
	cmd.FailOnError(err, "constructing admin object")

	unparsedArgs := flag.Args()
	if len(unparsedArgs) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	subcommand, ok := subcommands[unparsedArgs[0]]
	if !ok {
		cmd.FailOnError(errors.New("no recognized subcommand name provided"), "")
	}

	if a.dryRun {
		a.log.AuditInfof("admin tool executing a dry-run with the following arguments: %s", strings.Join(unparsedArgs, " "))
	} else {
		a.log.AuditInfof("admin tool executing with the following arguments: %s", strings.Join(unparsedArgs, " "))
	}

	err = subcommand.run(a, context.Background(), unparsedArgs[1:])
	cmd.FailOnError(err, "executing subcommand")

	if a.dryRun {
		a.log.AuditInfof("admin tool has successfully completed executing a dry-run with the following arguments: %s", strings.Join(unparsedArgs, " "))
		a.log.Info("Dry run complete. Pass -dry-run=false to mutate the database.")
	} else {
		a.log.AuditInfof("admin tool has successfully completed executing with the following arguments: %s", strings.Join(unparsedArgs, " "))
	}
}
