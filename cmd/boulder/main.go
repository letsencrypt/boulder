package main

import (
	"errors"
	"fmt"
	"os"

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

var errNoRegisteredConfig = fmt.Errorf("no config file registered for this command")

// readAndValidateConfigFile takes a file path as an argument and attempts to
// unmarshal the content of the file into a struct containing a configuration of
// a boulder component specified by name (e.g. boulder-ca, bad-key-revoker,
// etc.). Any config keys in the JSON file which do not correspond to expected
// keys in the config struct will result in errors. It also validates the config
// using the struct tags defined in the config struct.
func readAndValidateConfigFile(name, filename string) error {
	cv, err := cmd.LookupConfigValidator(name)
	if err != nil {
		return errNoRegisteredConfig
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

func skipConfigValidationSpecified() bool {
	for _, arg := range os.Args {
		if arg == "--skip-config-validation" || arg == "-skip-config-validation" {
			return true
		}
	}
	return false
}

// popFlagFromArgs removes the first instance of the given flag from os.Args,
// while maintaining the order of the remaining args. flag should NOT include
// the leading dashes (e.g. "config" not "--config"). If the flag is not found,
// this function does nothing. Note that this function does not remove any
// values passed after the associated flag.
func popFlagFromArgs(flag string) {
	for i, arg := range os.Args {
		if arg == "--"+flag || arg == "-"+flag {
			os.Args = append(os.Args[:i], os.Args[i+1:]...)
			return
		}
	}
}

// getConfigPath returns the path to the config file if it was provided as a
// command line flag. If the flag was not provided, it returns an empty string.
func getConfigPath() string {
	for i := 0; i < len(os.Args); i++ {
		if os.Args[i] == "--config" || os.Args[i] == "-config" {
			if i+1 < len(os.Args) {
				return os.Args[i+1]
			}
		}
	}
	return ""
}

var boulderUsage = fmt.Sprintf(`Usage: %s <subcommand> [flags]

  Each boulder component has its own subcommand. Use --list to see
  a list of the available components. Use <subcommand> --help to
  see the usage for a specific component. 

global flag(s):
  --skip-config-validation/ -skip-config-validation:
        Skip validation of the configuration file.
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

		subcommand = cmd.LookupCommand(os.Args[1])
		if subcommand == nil {
			fmt.Fprintf(os.Stderr, "Unknown subcommand '%s'.\n", os.Args[1])
			os.Exit(1)
		}
		// Remove the subcommand from the args before invoking the subcommand.
		os.Args = os.Args[1:]
	}

	configPath := getConfigPath()
	if configPath != "" && !skipConfigValidationSpecified() {
		err := readAndValidateConfigFile(core.Command(), configPath)
		if err != nil {
			if errors.Is(err, errNoRegisteredConfig) {
				// We don't strictly require a validator for every component
				// that accepts a config file.
				fmt.Fprintf(os.Stdout, "No config file registered for this command.\n")
			} else {
				fmt.Fprintf(os.Stderr, "Error validating config file %q: %v\n", configPath, err)
				os.Exit(1)
			}
		}

	}
	popFlagFromArgs("skip-config-validation")
	if subcommand == nil {
		// The operator used a symlink created by link.sh.
		cmd.LookupCommand(core.Command())()
	}
	subcommand()
}
