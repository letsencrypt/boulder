package main

import (
	"errors"
	"flag"
	"io/ioutil"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/observer"
	"gopkg.in/yaml.v2"
)

func main() {
	configPath := flag.String(
		"config", "config.yaml", "Path to boulder-observer configuration file")
	flag.Parse()

	configYAML, err := ioutil.ReadFile(*configPath)
	cmd.FailOnError(err, "failed to read config file")

	// parse YAML config
	var config observer.ObsConf
	err = yaml.Unmarshal(configYAML, &config)
	if err != nil {
		cmd.FailOnError(err, "failed to parse yaml config")
	}

	if config.DebugAddr == "" {
		cmd.FailOnError(errors.New(""), "debugaddr is not defined")
	}

	// start monitoring and logging
	prom, logger := cmd.StatsAndLogging(config.Syslog, config.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	// validate config
	err = config.Validate(logger)
	if err != nil {
		cmd.FailOnError(err, "config failed validation")
	}

	// start daemon
	logger.Infof("Initializing boulder-observer daemon from config: %s", *configPath)
	logger.Debugf("Using config: %+v", config)
	observer := observer.New(config, logger, prom)
	observer.Start()
}
