package main

import (
	"errors"

	"github.com/letsencrypt/boulder/cmd"
)

// CleanupConfig describes common configuration parameters shared by all cleanup
// jobs.
type CleanupConfig struct {
	// Enabled controls whether the janitor will run this cleanup job.
	Enabled bool
	// GracePeriod controls when a resource is old enough to be cleaned up.
	GracePeriod cmd.ConfigDuration
	// WorkSleep controls how long the janitor's work threads sleep between
	// finding no work and trying again. Defaults to a minute if not provided.
	WorkSleep cmd.ConfigDuration
	// BatchSize controls how many rows of the resource will be read from the DB
	// per-query.
	BatchSize int64
	// Parallelism controls how many independent go routines will run Delete
	// statements for old resources being cleaned up.
	Parallelism int
	// MaxDPS controls the maximum number of deletes which will be performed
	// per second in total for the resource's table across all of the parallel go
	// routines for this resource. This can be used to reduce the replication lag
	// caused by creating a very large numbers of delete statements.
	MaxDPS int
}

var (
	errInvalidGracePeriod   = errors.New("grace period must be > 0")
	errInvalidParallelism   = errors.New("parallelism must be > 0")
	errInvalidNegativeValue = errors.New("neither BatchSize or MaxDPS may be negative")
	errEmptyMetricsAddr     = errors.New("metricsAddr must not be empty")
)

// Valid checks the cleanup config is valid or returns an error.
func (c CleanupConfig) Valid() error {
	if c.GracePeriod.Duration <= 0 {
		return errInvalidGracePeriod
	}
	if c.Parallelism <= 0 {
		return errInvalidParallelism
	}
	if c.BatchSize < 0 || c.MaxDPS < 0 {
		return errInvalidNegativeValue
	}
	return nil
}

// Config describes the overall Janitor configuration.
type Config struct {
	Janitor struct {
		// Syslog holds common syslog configuration.
		Syslog cmd.SyslogConfig
		// DebugAddr controls the bind address for prometheus metrics, etc.
		DebugAddr string
		// Features holds potential Feature flags.
		Features map[string]bool
		// Common database connection configuration.
		cmd.DBConfig

		// Certificates describes a cleanup job for the certificates table.
		Certificates CleanupConfig

		// CertificateStatus describes a cleanup job for the certificateStatus table.
		CertificateStatus CleanupConfig

		// CertificatesPerName describes a cleanup job for the certificatesPerName table.
		CertificatesPerName CleanupConfig

		// KeyHashToSerial describes a cleanup job for the keyHashToSerial table.
		KeyHashToSerial CleanupConfig

		// Orders describes a cleanup job for the orders table and related rows
		// (requestedNames, orderToAuthz2, orderFqdnSets).
		Orders CleanupConfig
	}
}

// Valid checks that each of the cleanup job configurations are valid or returns
// an error.
func (c Config) Valid() error {
	if c.Janitor.DebugAddr == "" {
		return errEmptyMetricsAddr
	}
	jobConfigs := []CleanupConfig{
		c.Janitor.Certificates,
		c.Janitor.CertificateStatus,
		c.Janitor.CertificatesPerName,
		c.Janitor.KeyHashToSerial,
		c.Janitor.Orders,
	}
	for _, cc := range jobConfigs {
		if err := cc.Valid(); err != nil {
			return err
		}
	}
	return nil
}
