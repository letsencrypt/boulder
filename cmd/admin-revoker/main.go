package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/db"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	"github.com/letsencrypt/boulder/revocation"
	"github.com/letsencrypt/boulder/sa"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

const usageString = `
usage:
admin-revoker serial-revoke --config <path> <serial> <reason-code>
admin-revoker batched-serial-revoke --config <path> <serial-file-path> <reason-code> <parallelism>
admin-revoker reg-revoke --config <path> <registration-id> <reason-code>
admin-revoker list-reasons --config <path>

command descriptions:
  serial-revoke       Revoke a single certificate by the hex serial number
  batched-serial-revoke Revokes all certificates contained in a file of hex serial numbers
  reg-revoke          Revoke all certificates associated with a registration ID
  list-reasons        List all revocation reason codes

args:
  config    File path to the configuration file for this service
`

type config struct {
	Revoker struct {
		DB cmd.DBConfig
		// Similarly, the Revoker needs a TLSConfig to set up its GRPC client certs,
		// but doesn't get the TLS field from ServiceConfig, so declares its own.
		TLS cmd.TLSConfig

		RAService *cmd.GRPCClientConfig
		SAService *cmd.GRPCClientConfig

		Features map[string]bool
	}

	Syslog cmd.SyslogConfig
}

func setupContext(c config) (core.RegistrationAuthority, blog.Logger, *db.WrappedMap, core.StorageAuthority) {
	logger := cmd.NewLogger(c.Syslog)

	tlsConfig, err := c.Revoker.TLS.Load()
	cmd.FailOnError(err, "TLS config")

	clk := cmd.Clock()

	clientMetrics := bgrpc.NewClientMetrics(metrics.NoopRegisterer)
	raConn, err := bgrpc.ClientSetup(c.Revoker.RAService, tlsConfig, clientMetrics, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to RA")
	rac := bgrpc.NewRegistrationAuthorityClient(rapb.NewRegistrationAuthorityClient(raConn))

	dbURL, err := c.Revoker.DB.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	dbSettings := sa.DbSettings{
		MaxOpenConns:    c.Revoker.DB.MaxOpenConns,
		MaxIdleConns:    c.Revoker.DB.MaxIdleConns,
		ConnMaxLifetime: c.Revoker.DB.ConnMaxLifetime.Duration,
		ConnMaxIdleTime: c.Revoker.DB.ConnMaxIdleTime.Duration,
	}
	dbMap, err := sa.NewDbMap(dbURL, dbSettings)
	cmd.FailOnError(err, "Couldn't setup database connection")

	saConn, err := bgrpc.ClientSetup(c.Revoker.SAService, tlsConfig, clientMetrics, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to SA")
	sac := bgrpc.NewStorageAuthorityClient(sapb.NewStorageAuthorityClient(saConn))

	return rac, logger, dbMap, sac
}

func revokeCertificate(ctx context.Context, certObj core.Certificate, reasonCode revocation.Reason, rac core.RegistrationAuthority, logger blog.Logger) error {
	if reasonCode < 0 || reasonCode == 7 || reasonCode > 10 {
		panic(fmt.Sprintf("Invalid reason code: %d", reasonCode))
	}
	cert, err := x509.ParseCertificate(certObj.DER)
	if err != nil {
		return err
	}
	u, err := user.Current()
	if err != nil {
		return err
	}
	err = rac.AdministrativelyRevokeCertificate(ctx, *cert, reasonCode, u.Username)
	if err != nil {
		return err
	}
	logger.Infof("Revoked certificate %s with reason '%s'", certObj.Serial, revocation.ReasonToString[reasonCode])
	return nil
}

func revokeBySerial(ctx context.Context, serial string, reasonCode revocation.Reason, rac core.RegistrationAuthority, logger blog.Logger, dbMap db.Executor) error {
	certObj, err := sa.SelectCertificate(dbMap, serial)
	if err != nil {
		if db.IsNoRows(err) {
			return berrors.NotFoundError("certificate with serial %q not found", serial)
		}
		return err
	}
	return revokeCertificate(ctx, certObj, reasonCode, rac, logger)
}

func revokeByReg(ctx context.Context, regID int64, reasonCode revocation.Reason, rac core.RegistrationAuthority, logger blog.Logger, dbMap db.Executor) error {
	certObjs, err := sa.SelectCertificates(dbMap, "WHERE registrationID = :regID", map[string]interface{}{"regID": regID})
	if err != nil {
		return err
	}
	for _, certObj := range certObjs {
		err = revokeCertificate(ctx, certObj.Certificate, reasonCode, rac, logger)
		if err != nil {
			return err
		}
	}
	return nil
}

func revokeBatch(rac core.RegistrationAuthority, logger blog.Logger, dbMap *db.WrappedMap, serialPath string, reasonCode revocation.Reason, parallelism int) error {
	serials, err := ioutil.ReadFile(serialPath)
	if err != nil {
		return err
	}
	wg := new(sync.WaitGroup)
	work := make(chan string, parallelism)
	for i := 0; i < parallelism; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for serial := range work {
				// handle newlines gracefully
				if serial == "" {
					continue
				}
				err := revokeBySerial(context.Background(), serial, reasonCode, rac, logger, dbMap)
				if err != nil {
					logger.Errf("failed to revoke %q: %s", serial, err)
				}
			}
		}()
	}
	for _, serial := range strings.Split(string(serials), "\n") {
		if serial == "" {
			continue
		}
		work <- serial
	}
	close(work)
	wg.Wait()

	return nil
}

// This abstraction is needed so that we can use sort.Sort below
type revocationCodes []revocation.Reason

func (rc revocationCodes) Len() int           { return len(rc) }
func (rc revocationCodes) Less(i, j int) bool { return rc[i] < rc[j] }
func (rc revocationCodes) Swap(i, j int)      { rc[i], rc[j] = rc[j], rc[i] }

func main() {
	usage := func() {
		fmt.Fprint(os.Stderr, usageString)
		os.Exit(1)
	}
	if len(os.Args) <= 2 {
		usage()
	}

	command := os.Args[1]
	flagSet := flag.NewFlagSet(command, flag.ContinueOnError)
	configFile := flagSet.String("config", "", "File path to the configuration file for this service")
	err := flagSet.Parse(os.Args[2:])
	cmd.FailOnError(err, "Error parsing flagset")

	if *configFile == "" {
		usage()
	}

	var c config
	err = cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")
	err = features.Set(c.Revoker.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	ctx := context.Background()
	args := flagSet.Args()
	switch {
	case command == "batched-serial-revoke" && len(args) == 3:
		// 1: serial file path,  2: reasonCode, 3: parallelism
		serialPath := args[0]
		reasonCode, err := strconv.Atoi(args[1])
		cmd.FailOnError(err, "Reason code argument must be an integer")
		parallelism, err := strconv.Atoi(args[2])
		cmd.FailOnError(err, "parallelism argument must be an integer")
		if parallelism < 1 {
			cmd.Fail("parallelism argument must be >= 1")
		}

		rac, logger, dbMap, _ := setupContext(c)
		err = revokeBatch(rac, logger, dbMap, serialPath, revocation.Reason(reasonCode), parallelism)
		cmd.FailOnError(err, "Batch revocation failed")
	case command == "serial-revoke" && len(args) == 2:
		// 1: serial,  2: reasonCode
		serial := args[0]
		reasonCode, err := strconv.Atoi(args[1])
		cmd.FailOnError(err, "Reason code argument must be an integer")

		rac, logger, dbMap, _ := setupContext(c)

		_, err = db.WithTransaction(ctx, dbMap, func(txWithCtx db.Executor) (interface{}, error) {
			err := revokeBySerial(ctx, serial, revocation.Reason(reasonCode), rac, logger, txWithCtx)
			return nil, err
		})
		cmd.FailOnError(err, "Couldn't revoke certificate by serial")

	case command == "reg-revoke" && len(args) == 2:
		// 1: registration ID,  2: reasonCode
		regID, err := strconv.ParseInt(args[0], 10, 64)
		cmd.FailOnError(err, "Registration ID argument must be an integer")
		reasonCode, err := strconv.Atoi(args[1])
		cmd.FailOnError(err, "Reason code argument must be an integer")

		rac, logger, dbMap, sac := setupContext(c)
		defer logger.AuditPanic()

		_, err = sac.GetRegistration(ctx, regID)
		if err != nil {
			cmd.FailOnError(err, "Couldn't fetch registration")
		}

		_, err = db.WithTransaction(ctx, dbMap, func(txWithCtx db.Executor) (interface{}, error) {
			err := revokeByReg(ctx, regID, revocation.Reason(reasonCode), rac, logger, txWithCtx)
			return nil, err
		})
		cmd.FailOnError(err, "Couldn't revoke certificate by registration")

	case command == "list-reasons":
		var codes revocationCodes
		for k := range revocation.ReasonToString {
			codes = append(codes, k)
		}
		sort.Sort(codes)
		fmt.Printf("Revocation reason codes\n-----------------------\n\n")
		for _, k := range codes {
			fmt.Printf("%d: %s\n", k, revocation.ReasonToString[k])
		}

	default:
		usage()
	}
}
