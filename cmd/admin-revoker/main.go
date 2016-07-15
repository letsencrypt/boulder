package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"os/user"
	"sort"
	"strconv"

	"golang.org/x/net/context"

	"github.com/cactus/go-statsd-client/statsd"
	gorp "gopkg.in/gorp.v1"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/sa"
)

const clientName = "AdminRevoker"

const usage = `
usage:
admin-revoker <command> --config <path> [args]

commands:
  serial-revoke   Revoke a single certificate by the hex serial number
  reg-revoke      Revoke all certificates associated with a registration ID
  list-reasons    List all revocation reason codes
  auth-revoke     Revoke all pending/valid authorizations for a domain
`

type config struct {
	Revoker struct {
		cmd.DBConfig
		// The revoker isn't a long running service, so doesn't get a full
		// ServiceConfig, just an AMQPConfig.
		AMQP *cmd.AMQPConfig
	}

	Statsd cmd.StatsdConfig

	Syslog cmd.SyslogConfig
}

func setupContext(c config) (rpc.RegistrationAuthorityClient, blog.Logger, *gorp.DbMap, rpc.StorageAuthorityClient, statsd.Statter) {
	stats, logger := cmd.StatsAndLogging(c.Statsd, c.Syslog)

	amqpConf := c.Revoker.AMQP
	rac, err := rpc.NewRegistrationAuthorityClient(clientName, amqpConf, stats)
	cmd.FailOnError(err, "Unable to create CA client")

	dbURL, err := c.Revoker.DBConfig.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	dbMap, err := sa.NewDbMap(dbURL, c.Revoker.DBConfig.MaxDBConns)
	cmd.FailOnError(err, "Couldn't setup database connection")
	go sa.ReportDbConnCount(dbMap, metrics.NewStatsdScope(stats, "AdminRevoker"))

	sac, err := rpc.NewStorageAuthorityClient(clientName, amqpConf, stats)
	cmd.FailOnError(err, "Failed to create SA client")

	return *rac, logger, dbMap, *sac, stats
}

func revokeBySerial(ctx context.Context, serial string, reasonCode core.RevocationCode, rac rpc.RegistrationAuthorityClient, logger blog.Logger, tx *gorp.Transaction) (err error) {
	if reasonCode < 0 || reasonCode == 7 || reasonCode > 10 {
		panic(fmt.Sprintf("Invalid reason code: %d", reasonCode))
	}

	certObj, err := tx.Get(core.Certificate{}, serial)
	if err != nil {
		return
	}
	certificate, ok := certObj.(*core.Certificate)
	if !ok {
		err = fmt.Errorf("Cast failure")
		return
	}
	cert, err := x509.ParseCertificate(certificate.DER)
	if err != nil {
		return
	}

	u, err := user.Current()
	err = rac.AdministrativelyRevokeCertificate(ctx, *cert, reasonCode, u.Username)
	if err != nil {
		return
	}

	logger.Info(fmt.Sprintf("Revoked certificate %s with reason '%s'", serial, core.RevocationReasons[reasonCode]))
	return
}

func revokeByReg(ctx context.Context, regID int64, reasonCode core.RevocationCode, rac rpc.RegistrationAuthorityClient, logger blog.Logger, tx *gorp.Transaction) (err error) {
	var certs []core.Certificate
	_, err = tx.Select(&certs, "SELECT serial FROM certificates WHERE registrationID = :regID", map[string]interface{}{"regID": regID})
	if err != nil {
		return
	}

	for _, cert := range certs {
		err = revokeBySerial(ctx, cert.Serial, reasonCode, rac, logger, tx)
		if err != nil {
			return
		}
	}

	return
}

// This abstraction is needed so that we can use sort.Sort below
type revocationCodes []core.RevocationCode

func (rc revocationCodes) Len() int           { return len(rc) }
func (rc revocationCodes) Less(i, j int) bool { return rc[i] < rc[j] }
func (rc revocationCodes) Swap(i, j int)      { rc[i], rc[j] = rc[j], rc[i] }

func main() {
	if len(os.Args) <= 2 {
		fmt.Fprintf(os.Stderr, usage)
		os.Exit(1)
	}

	command := os.Args[1]
	flagSet := flag.NewFlagSet(command, flag.ExitOnError)
	configFile := flagSet.String("config", "", "File path to the configuration file for this service")
	_ = flagSet.Parse(os.Args[2:])
	if *configFile == "" {
		fmt.Fprintf(os.Stderr, "%s\nargs:", usage)
		flagSet.PrintDefaults()
		os.Exit(1)
	}
	args := flagSet.Args()

	var c config
	err := cmd.ReadJSONFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	ctx := context.Background()
	switch command {
	case "serial-revoke":
		// 1: serial,  2: reasonCode
		serial := args[0]
		reasonCode, err := strconv.Atoi(args[1])
		cmd.FailOnError(err, "Reason code argument must be an integer")

		cac, logger, dbMap, _, _ := setupContext(c)

		tx, err := dbMap.Begin()
		if err != nil {
			cmd.FailOnError(sa.Rollback(tx, err), "Couldn't begin transaction")
		}

		err = revokeBySerial(ctx, serial, core.RevocationCode(reasonCode), cac, logger, tx)
		if err != nil {
			cmd.FailOnError(sa.Rollback(tx, err), "Couldn't revoke certificate")
		}

		err = tx.Commit()
		cmd.FailOnError(err, "Couldn't cleanly close transaction")

	case "reg-revoke":
		// 1: registration ID,  2: reasonCode
		regID, err := strconv.ParseInt(args[0], 10, 64)
		cmd.FailOnError(err, "Registration ID argument must be an integer")
		reasonCode, err := strconv.Atoi(args[1])
		cmd.FailOnError(err, "Reason code argument must be an integer")

		cac, logger, dbMap, sac, _ := setupContext(c)
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		defer logger.AuditPanic()

		tx, err := dbMap.Begin()
		if err != nil {
			cmd.FailOnError(sa.Rollback(tx, err), "Couldn't begin transaction")
		}

		_, err = sac.GetRegistration(ctx, regID)
		if err != nil {
			cmd.FailOnError(err, "Couldn't fetch registration")
		}

		err = revokeByReg(ctx, regID, core.RevocationCode(reasonCode), cac, logger, tx)
		if err != nil {
			cmd.FailOnError(sa.Rollback(tx, err), "Couldn't revoke certificate")
		}

		err = tx.Commit()
		cmd.FailOnError(err, "Couldn't cleanly close transaction")

	case "list-reasons":
		var codes revocationCodes
		for k := range core.RevocationReasons {
			codes = append(codes, k)
		}
		sort.Sort(codes)
		fmt.Printf("Revocation reason codes\n-----------------------\n\n")
		for _, k := range codes {
			fmt.Printf("%d: %s\n", k, core.RevocationReasons[k])
		}

	case "auth-revoke":
		domain := args[0]
		_, logger, _, sac, stats := setupContext(c)
		ident := core.AcmeIdentifier{Value: domain, Type: core.IdentifierDNS}
		authsRevoked, pendingAuthsRevoked, err := sac.RevokeAuthorizationsByDomain(ctx, ident)
		cmd.FailOnError(err, fmt.Sprintf("Failed to revoke authorizations for %s", ident.Value))
		logger.Info(fmt.Sprintf(
			"Revoked %d pending authorizations and %d final authorizations\n",
			authsRevoked,
			pendingAuthsRevoked,
		))
		stats.Inc("admin-revoker.revokedAuthorizations", authsRevoked, 1.0)
		stats.Inc("admin-revoker.revokedPendingAuthorizations", pendingAuthsRevoked, 1.0)

	default:
		fmt.Fprintf(os.Stderr, "%s\nargs:", usage)
		flagSet.PrintDefaults()
		os.Exit(1)
	}
}
