package main

import (
	"flag"
	"fmt"
	"os"
	"path"

	_ "github.com/letsencrypt/boulder/cmd/admin-revoker"
	_ "github.com/letsencrypt/boulder/cmd/akamai-purger"
	_ "github.com/letsencrypt/boulder/cmd/bad-key-revoker"
	_ "github.com/letsencrypt/boulder/cmd/boulder-ca"
	_ "github.com/letsencrypt/boulder/cmd/boulder-observer"
	_ "github.com/letsencrypt/boulder/cmd/boulder-publisher"
	_ "github.com/letsencrypt/boulder/cmd/boulder-ra"
	_ "github.com/letsencrypt/boulder/cmd/boulder-sa"
	_ "github.com/letsencrypt/boulder/cmd/boulder-va"
	_ "github.com/letsencrypt/boulder/cmd/boulder-wfe2"
	_ "github.com/letsencrypt/boulder/cmd/caa-log-checker"
	_ "github.com/letsencrypt/boulder/cmd/ceremony"
	_ "github.com/letsencrypt/boulder/cmd/cert-checker"
	_ "github.com/letsencrypt/boulder/cmd/contact-auditor"
	_ "github.com/letsencrypt/boulder/cmd/crl-checker"
	_ "github.com/letsencrypt/boulder/cmd/crl-storer"
	_ "github.com/letsencrypt/boulder/cmd/crl-updater"
	_ "github.com/letsencrypt/boulder/cmd/expiration-mailer"
	_ "github.com/letsencrypt/boulder/cmd/id-exporter"
	_ "github.com/letsencrypt/boulder/cmd/log-validator"
	_ "github.com/letsencrypt/boulder/cmd/nonce-service"
	_ "github.com/letsencrypt/boulder/cmd/notify-mailer"
	_ "github.com/letsencrypt/boulder/cmd/ocsp-responder"
	_ "github.com/letsencrypt/boulder/cmd/ocsp-updater"
	_ "github.com/letsencrypt/boulder/cmd/orphan-finder"
	_ "github.com/letsencrypt/boulder/cmd/reversed-hostname-checker"
	_ "github.com/letsencrypt/boulder/cmd/rocsp-tool"

	"github.com/letsencrypt/boulder/cmd"
)

// readAndValidateConfigFile takes a file path as an argument and attempts to
// unmarshal the content of the file into a struct containing a configuration of
// a boulder component specified by name (e.g. boulder-ca, bad-key-revoker,
// etc.). Any config keys in the JSON file which do not correspond to expected
// keys in the config struct will result in errors. It also validates the config
// using the struct tags defined in the config struct.
func readAndValidateConfigFile(name, filename string) error {
	cv, err := cmd.LookupConfigValidator(name)
	if err != nil {
		return err
	}

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	if name == "boulder-observer" {
		// Only the boulder-observer uses YAML config files.
		return cmd.ValidateYAMLConfig(cv, file)
	}
	return cmd.ValidateJSONConfig(cv, file)
}

func main() {
	cmd.LookupCommand(path.Base(os.Args[0]))()
}

func init() {
	cmd.RegisterCommand("boulder", func() {
		if len(os.Args) <= 1 {
			fmt.Fprintf(os.Stderr, "Call with --list to list available subcommands. Run them like boulder <subcommand>.\n")
			return
		}
		subcommand := cmd.LookupCommand(os.Args[1])
		if subcommand == nil {
			fmt.Fprintf(os.Stderr, "Unknown subcommand '%s'.\n", os.Args[1])
			return
		}
		os.Args = os.Args[1:]
		subcommand()
	}, nil)
	// TODO(#6763): Move this inside of main().
	cmd.RegisterCommand("--list", func() {
		for _, c := range cmd.AvailableCommands() {
			if c != "boulder" && c != "--list" {
				fmt.Println(c)
			}
		}
	}, nil)
	// TODO(#6763): Move this inside of main().
	cmd.RegisterCommand("validate", func() {
		if len(os.Args) <= 1 {
			fmt.Fprintf(os.Stderr, "Call with --help to list usage.\n")
			os.Exit(1)
		}
		list := flag.Bool("list", false, "List available components to validate configuration for.")
		component := flag.String("component", "", "The name of the component to validate configuration for.")
		configFile := flag.String("config", "", "The path to the configuration file to validate.")
		flag.Parse()

		if *list {
			for _, c := range cmd.AvailableConfigValidators() {
				fmt.Println(c)
			}
			return
		}
		if *component == "" || *configFile == "" {
			fmt.Fprintf(os.Stderr, "Must provide a configuration file to validate.\n")
			os.Exit(1)
		}
		err := readAndValidateConfigFile(*component, *configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error validating configuration: %s\n", err)
			os.Exit(1)
		}
	}, nil)
}
