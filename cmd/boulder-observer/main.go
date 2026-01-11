package notmain

import (
	"flag"
	"os"

	"github.com/letsencrypt/validator/v10"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/observer"
	"github.com/letsencrypt/boulder/strictyaml"
)

func main() {
	debugAddr := flag.String("debug-addr", "", "Debug server address override")
	configPath := flag.String(
		"config", "config.yml", "Path to boulder-observer configuration file")
	flag.Parse()

	configYAML, err := os.ReadFile(*configPath)
	cmd.FailOnError(err, "failed to read config file")

	// Parse the YAML config file.
	var obsConf observer.ObsConf
	err = strictyaml.Unmarshal(configYAML, &obsConf)

	if *debugAddr != "" {
		obsConf.DebugAddr = *debugAddr
	}

	if err != nil {
		cmd.FailOnError(err, "failed to parse YAML config")
	}

	// Validate config using struct tags.
	validate := validator.New()
	validate.RegisterCustomTypeFunc(config.DurationCustomTypeFunc, config.Duration{})
	err = validate.Struct(obsConf)
	if err != nil {
		cmd.FailOnError(err, "config validation failed")
	}

	// Make an `Observer` object.
	obs, err := obsConf.MakeObserver()
	if err != nil {
		cmd.FailOnError(err, "config failed validation")
	}

	// Start the `Observer` daemon.
	obs.Start()
}

func init() {
	cmd.RegisterCommand("boulder-observer", main, &cmd.ConfigValidator{Config: &observer.ObsConf{}})
}
