package main

import (
	"fmt"
	"os"
	"strings"

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
	_ "github.com/letsencrypt/boulder/cmd/orphan-finder"
	_ "github.com/letsencrypt/boulder/cmd/reversed-hostname-checker"
	_ "github.com/letsencrypt/boulder/cmd/rocsp-tool"
	"github.com/letsencrypt/boulder/core"

	"github.com/letsencrypt/boulder/cmd"
)

// readAndValidateConfigFile uses the ConfigValidator registered for the given
// command to validate the provided config file. If the command does not have a
// registered ConfigValidator, this function does nothing.
func readAndValidateConfigFile(name, filename string) error {
	cv := cmd.LookupConfigValidator(name)
	if cv == nil {
		return nil
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

// getConfigPath returns the path to the config file if it was provided as a
// command line flag. If the flag was not provided, it returns an empty string.
func getConfigPath() string {
	for i := 0; i < len(os.Args); i++ {
		arg := os.Args[i]
		if arg == "--config" || arg == "-config" {
			if i+1 < len(os.Args) {
				return os.Args[i+1]
			}
		}
		if strings.HasPrefix(arg, "--config=") {
			return strings.TrimPrefix(arg, "--config=")
		}
		if strings.HasPrefix(arg, "-config=") {
			return strings.TrimPrefix(arg, "-config=")
		}
	}
	return ""
}

var boulderUsage = fmt.Sprintf(`Usage: %s <subcommand> [flags]

  Each boulder component has its own subcommand. Use --list to see
  a list of the available components. Use <subcommand> --help to
  see the usage for a specific component.
`,
	core.Command())

func main() {
	var subcommand func()
	if core.Command() == "boulder" {
		// The operator is running the boulder binary directly.
		if len(os.Args) <= 1 {
			// No arguments passed.
			fmt.Fprint(os.Stderr, boulderUsage)
			return
		}

		if os.Args[1] == "--help" || os.Args[1] == "-help" {
			// Help flag passed.
			fmt.Fprint(os.Stderr, boulderUsage)
			return
		}

		if os.Args[1] == "--list" || os.Args[1] == "-list" {
			// List flag passed.
			for _, c := range cmd.AvailableCommands() {
				fmt.Println(c)
			}
			return
		}

		// Operator ran a boulder using a subcommand. Lookup the
		// subcommand.
		subcommand = cmd.LookupCommand(os.Args[1])
		if subcommand == nil {
			fmt.Fprintf(os.Stderr, "Unknown subcommand %q.\n", os.Args[1])
			os.Exit(1)
		}
	}

	configPath := getConfigPath()
	if configPath != "" {
		// Config flag passed.
		err := readAndValidateConfigFile(core.Command(), configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error validating config file %q: %s\n", configPath, err)
			os.Exit(1)
		}

	}
	if subcommand == nil {
		// Operator ran a boulder component using a symlink. Lookup the
		// subcommand using the name of the symlink.
		subcommand = cmd.LookupCommand(core.Command())
		if subcommand == nil {
			fmt.Fprintf(os.Stderr, "Unknown subcommand %q.\n", core.Command())
			os.Exit(1)
		}
	} else {
		// Operator ran a boulder component using a subcommand. Remove the
		// subcommand from the args before invoking the subcommand.
		os.Args = os.Args[1:]
	}
	subcommand()
}
