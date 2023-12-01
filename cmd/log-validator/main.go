package notmain

import (
	"context"
	"encoding/json"
	"flag"
	"os"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/log/validator"
)

type Config struct {
	Files         []string `validate:"min=1,dive,required"`
	DebugAddr     string   `validate:"required,hostname_port"`
	Syslog        cmd.SyslogConfig
	OpenTelemetry cmd.OpenTelemetryConfig
}

func main() {
	configPath := flag.String("config", "", "File path to the configuration file for this service")
	checkFile := flag.String("check-file", "", "File path to a file to directly validate, if this argument is provided the config will not be parsed and only this file will be inspected")
	flag.Parse()

	if *checkFile != "" {
		err := validator.ValidateFile(*checkFile)
		cmd.FailOnError(err, "validation failed")
		return
	}

	configBytes, err := os.ReadFile(*configPath)
	cmd.FailOnError(err, "failed to read config file")
	var config Config
	err = json.Unmarshal(configBytes, &config)
	cmd.FailOnError(err, "failed to parse config file")

	stats, logger, oTelShutdown := cmd.StatsAndLogging(config.Syslog, config.OpenTelemetry, config.DebugAddr)
	defer oTelShutdown(context.Background())
	logger.Info(cmd.VersionString())

	v := validator.New(config.Files, logger, stats)
	defer v.Shutdown()

	cmd.WaitForSignal()
}

func init() {
	cmd.RegisterCommand("log-validator", main, &cmd.ConfigValidator{Config: &Config{}})
}
