package notmain

import (
	"flag"
	"os"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/observer"
	"github.com/letsencrypt/boulder/strictyaml"
)

const cmdName = "boulder-observer"

func main() {
	configPath := flag.String(
		"config", "config.yml", "Path to boulder-observer configuration file")
	validate := flag.Bool("validate", false, "Validate the configuration file and exit")
	flag.Parse()

	if *validate {
		err := cmd.ReadAndValidateConfigFile(cmdName, *configPath)
		cmd.FailOnError(err, "Failed to validate config file")
		os.Exit(0)
	}

	configYAML, err := os.ReadFile(*configPath)
	cmd.FailOnError(err, "failed to read config file")

	// Parse the YAML config file.
	var config observer.ObsConf
	err = strictyaml.Unmarshal(configYAML, &config)

	if err != nil {
		cmd.FailOnError(err, "failed to parse YAML config")
	}

	// Make an `Observer` object.
	observer, err := config.MakeObserver()
	if err != nil {
		cmd.FailOnError(err, "config failed validation")
	}

	// Start the `Observer` daemon.
	observer.Start()
}

func init() {
	cmd.RegisterCommand(cmdName, main)
	cmd.RegisterConfig(cmdName, &cmd.ConfigValidator{Config: &observer.ObsConf{}})
}
