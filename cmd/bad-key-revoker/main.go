package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	netmail "net/mail"
	"os"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/db"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/mail"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	"github.com/letsencrypt/boulder/revocation"
	"github.com/letsencrypt/boulder/sa"

	"google.golang.org/grpc"
)

type revoker interface {
	AdministrativelyRevokeCertificate(ctx context.Context, in *rapb.AdministrativelyRevokeCertificateRequest, opts ...grpc.CallOption) (*corepb.Empty, error)
}

type badKeyRevoker struct {
	dbMap                 *db.WrappedMap
	uncheckedBatchSize    int
	certificatesBatchSize int
	raClient              revoker
	mailer                mail.Mailer
}

type unchecked struct {
	ID        int
	KeyHash   []byte
	RevokedBy int64
}

func (bkr *badKeyRevoker) selectUncheckedRows() ([]unchecked, error) {
	var uncheckedRows []unchecked
	initialID := 0
	for {
		var batch []unchecked
		_, err := bkr.dbMap.Select(
			&batch,
			"SELECT id, keyHash, revokedBy FROM blockedKeys WHERE extantCertificatesChecked = false AND id > ? ORDER BY id LIMIT ?",
			initialID,
			bkr.uncheckedBatchSize,
		)
		if err != nil {
			if db.IsNoRows(err) {
				return uncheckedRows, nil
			}
			return nil, err
		}
		uncheckedRows = append(uncheckedRows, batch...)
		if len(batch) != bkr.uncheckedBatchSize {
			return uncheckedRows, nil
		}
		initialID = batch[len(batch)-1].ID
	}
}

type unrevoked struct {
	Serial         string
	DER            []byte
	RegistrationID int64
	RevokedBy      int64
}

var revokerName = "bad-key-revoker"

func (bkr *badKeyRevoker) findUnrevoked(row unchecked) ([]unrevoked, error) {
	var unrevokedCerts []unrevoked
	initialID := 0
	for {
		var batch []struct {
			ID         int
			CertSerial string
		}
		_, err := bkr.dbMap.Select(
			&batch,
			"SELECT id, certserial FROM keyHashToSerial WHERE keyHash = ? and id > ? ORDER BY id LIMIT ?",
			row.KeyHash,
			initialID,
			bkr.certificatesBatchSize,
		)
		if err != nil {
			if db.IsNoRows(err) {
				return unrevokedCerts, nil
			}
			return nil, err
		}
		for _, serial := range batch {
			var unrevokedCert unrevoked
			err = bkr.dbMap.SelectOne(
				&unrevokedCert,
				`SELECT cs.serial, c.registrationID, c.der FROM certificateStatus AS cs
				JOIN certificates AS c
				ON cs.serial = c.serial
				WHERE cs.serial = ? AND cs.isExpired = false AND cs.status != ?`,
				serial.CertSerial,
				string(core.StatusRevoked),
			)
			if err != nil {
				if db.IsNoRows(err) {
					continue
				}
				return nil, err
			}
			unrevokedCert.RevokedBy = row.RevokedBy
			unrevokedCerts = append(unrevokedCerts, unrevokedCert)
		}
		if len(batch) != bkr.certificatesBatchSize {
			return unrevokedCerts, nil
		}
		initialID = batch[len(batch)-1].ID
	}
}

func (bkr *badKeyRevoker) markRowChecked(row unchecked) error {
	_, err := bkr.dbMap.Exec("UPDATE blockedKeys SET extantCertificatesChecked = true WHERE keyHash = ?", row.KeyHash)
	return err
}

func (bkr *badKeyRevoker) resolveContacts(ids []int64) (map[int64]string, error) {
	idToEmail := map[int64]string{}
	for _, id := range ids {
		var emails struct {
			Contact []string
		}
		err := bkr.dbMap.SelectOne(&emails, "SELECT contact FROM registrations WHERE id = ?", id)
		if err != nil {
			return nil, err
		}
		if len(emails.Contact) == 0 {
			continue
		}
		idToEmail[id] = strings.TrimPrefix(emails.Contact[0], "mailto:")
	}
	return idToEmail, nil
}

var emailTemplate = template.Must(template.New("email-template").Parse(`Hello,

The public key associated with certificates which you have issued has been marked as compromised. As such we are required to revoke any certificates which contain this public key.

The following currently unexpired certificates that you've issued contain this public key and have been revoked:
{{range . -}}
{{.}}
{{end}}`))

var emailSubject = "Certificates you've issued have been revoked due to key compromise"

var maxSerials = 100

func (bkr *badKeyRevoker) sendMessages(mapping map[string][]string) error {
	err := bkr.mailer.Connect()
	if err != nil {
		return err
	}
	defer func() {
		_ = bkr.mailer.Close()
	}()
	for email, serials := range mapping {
		if len(serials) > maxSerials {
			more := len(serials) - maxSerials
			serials = serials[:maxSerials]
			serials = append(serials, fmt.Sprintf("and %d more certificates.", more))
		}
		message := bytes.NewBuffer(nil)
		err := emailTemplate.Execute(message, serials)
		if err != nil {
			return err
		}
		err = bkr.mailer.SendMail([]string{email}, emailSubject, message.String())
		if err != nil {
			return err
		}
	}
	return nil
}

var keyCompromiseCode = int64(revocation.KeyCompromise)

func (bkr *badKeyRevoker) invoke() (bool, error) {
	// find rows to work on
	uncheckedRows, err := bkr.selectUncheckedRows()
	if err != nil {
		return false, err
	}
	if len(uncheckedRows) == 0 {
		return true, nil
	}
	for _, row := range uncheckedRows {
		// find everything in keyHashToSerial with certificateStatus.status != revoked
		unrevokedCerts, err := bkr.findUnrevoked(row)
		if err != nil {
			return false, err
		}
		if len(unrevokedCerts) == 0 {
			// mark row as checked
			err = bkr.markRowChecked(row)
			if err != nil {
				return false, err
			}
			continue
		}
		// revoke all rows, record who issued the cert
		ownedBy := map[int64][]string{}
		for _, cert := range unrevokedCerts {
			_, err = bkr.raClient.AdministrativelyRevokeCertificate(context.Background(), &rapb.AdministrativelyRevokeCertificateRequest{
				Cert:      cert.DER,
				Code:      &keyCompromiseCode,
				AdminName: &revokerName,
			})
			if err != nil {
				return false, err
			}
			ownedBy[cert.RegistrationID] = append(ownedBy[cert.RegistrationID], cert.Serial)
		}
		// collect IDs
		var ids []int64
		for id := range ownedBy {
			ids = append(ids, id)
		}
		// get contacts for IDs
		idToEmail, err := bkr.resolveContacts(ids)
		if err != nil {
			return false, err
		}
		// merge any accounts with the same email
		emailToSerials := map[string][]string{}
		for id, email := range idToEmail {
			emailToSerials[email] = append(emailToSerials[email], ownedBy[id]...)
		}
		// don't send emails to the person who revoked the certificate
		if email, ok := idToEmail[row.RevokedBy]; ok {
			delete(emailToSerials, email)
		}
		err = bkr.sendMessages(emailToSerials)
		if err != nil {
			return false, err
		}
		// mark row as checked
		err = bkr.markRowChecked(row)
		if err != nil {
			return false, err
		}
	}
	return false, nil
}

func main() {
	var config struct {
		BadKeyRevoker struct {
			cmd.DBConfig
			cmd.SMTPConfig
			DebugAddr string

			TLS       cmd.TLSConfig
			RAService *cmd.GRPCClientConfig

			UncheckedBatchSize        int
			FindCertificatesBatchSize int

			Interval cmd.ConfigDuration

			From string
			// Path to a file containing a list of trusted root certificates for use
			// during the SMTP connection (as opposed to the gRPC connections).
			SMTPTrustedRootFile string
		}

		Syslog cmd.SyslogConfig
	}
	configPath := flag.String("config", "", "File path to the configuration file for this service")
	reconnBase := flag.Duration("reconnectBase", 1*time.Second, "Base sleep duration between reconnect attempts")
	reconnMax := flag.Duration("reconnectMax", 5*60*time.Second, "Max sleep duration between reconnect attempts after exponential backoff")
	flag.Parse()

	if *configPath == "" {
		flag.Usage()
		os.Exit(1)
	}
	err := cmd.ReadConfigFile(*configPath, &config)
	cmd.FailOnError(err, "Failed reading config file")

	scope, logger := cmd.StatsAndLogging(config.Syslog, config.BadKeyRevoker.DebugAddr)
	clk := cmd.Clock()

	dbURL, err := config.BadKeyRevoker.DBConfig.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	dbMap, err := sa.NewDbMap(dbURL, config.BadKeyRevoker.DBConfig.MaxDBConns)
	cmd.FailOnError(err, "Could not connect to database")
	sa.SetSQLDebug(dbMap, logger)
	sa.InitDBMetrics(dbMap, scope)

	tlsConfig, err := config.BadKeyRevoker.TLS.Load()
	cmd.FailOnError(err, "TLS config")

	clientMetrics := bgrpc.NewClientMetrics(scope)
	conn, err := bgrpc.ClientSetup(config.BadKeyRevoker.RAService, tlsConfig, clientMetrics, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to RA")
	rac := rapb.NewRegistrationAuthorityClient(conn)

	var smtpRoots *x509.CertPool
	if config.BadKeyRevoker.SMTPTrustedRootFile != "" {
		pem, err := ioutil.ReadFile(config.BadKeyRevoker.SMTPTrustedRootFile)
		cmd.FailOnError(err, "Loading trusted roots file")
		smtpRoots = x509.NewCertPool()
		if !smtpRoots.AppendCertsFromPEM(pem) {
			cmd.FailOnError(nil, "Failed to parse root certs PEM")
		}
	}

	fromAddress, err := netmail.ParseAddress(config.BadKeyRevoker.From)
	cmd.FailOnError(err, fmt.Sprintf("Could not parse from address: %s", config.BadKeyRevoker.From))

	smtpPassword, err := config.BadKeyRevoker.PasswordConfig.Pass()
	cmd.FailOnError(err, "Failed to load SMTP password")
	mailClient := mail.New(
		config.BadKeyRevoker.Server,
		config.BadKeyRevoker.Port,
		config.BadKeyRevoker.Username,
		smtpPassword,
		smtpRoots,
		*fromAddress,
		logger,
		scope,
		*reconnBase,
		*reconnMax,
	)

	bkr := &badKeyRevoker{
		dbMap:                 dbMap,
		uncheckedBatchSize:    config.BadKeyRevoker.UncheckedBatchSize,
		certificatesBatchSize: config.BadKeyRevoker.FindCertificatesBatchSize,
		raClient:              rac,
		mailer:                mailClient,
	}
	for {
		noWork, err := bkr.invoke()
		if err != nil {
			logger.Err(err.Error())
			continue
		}
		if noWork {
			time.Sleep(config.BadKeyRevoker.Interval.Duration)
		}
	}
}
