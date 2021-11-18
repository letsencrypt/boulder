package ocsp_updater_config

import (
	"github.com/letsencrypt/boulder/cmd"
	rocsp_config "github.com/letsencrypt/boulder/rocsp/config"
)

// Config provides the various window tick times and batch sizes needed
// for the OCSP updater
type Config struct {
	cmd.ServiceConfig
	DB         cmd.DBConfig
	ReadOnlyDB cmd.DBConfig
	Redis      *rocsp_config.RedisConfig

	OldOCSPWindow    cmd.ConfigDuration
	OldOCSPBatchSize int

	OCSPMinTimeToExpiry          cmd.ConfigDuration
	ParallelGenerateOCSPRequests int

	SignFailureBackoffFactor float64
	SignFailureBackoffMax    cmd.ConfigDuration

	SerialSuffixShards string

	OCSPGeneratorService *cmd.GRPCClientConfig

	Features map[string]bool
}
