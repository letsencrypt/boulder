//go:build integration

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/eggsampler/acme/v3"
	_ "github.com/go-sql-driver/mysql"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/revocation"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
)

// getPrecertByName finds and parses a precertificate using the given hostname.
// It returns the most recent one.
func getPrecertByName(db *sql.DB, reversedName string) (*x509.Certificate, error) {
	reversedName = sa.EncodeIssuedName(reversedName)
	// Find the certificate from the precertificates table. We don't know the serial so
	// we have to look it up by name.
	var der []byte
	rows, err := db.Query(`
		SELECT der
		FROM issuedNames JOIN precertificates
		USING (serial)
		WHERE reversedName = ?
		ORDER BY issuedNames.id DESC
		LIMIT 1
	`, reversedName)
	for rows.Next() {
		err = rows.Scan(&der)
		if err != nil {
			return nil, err
		}
	}
	if der == nil {
		return nil, fmt.Errorf("no precertificate found for %q", reversedName)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// TestIssuanceCertStorageFailed tests what happens when a storage RPC fails
// during issuance. Specifically, it tests that case where we successfully
// prepared and stored a linting certificate plus metadata, but failed to store
// the corresponding final certificate after issuance completed.
//
// To do this, we need to mess with the database, because we want to cause
// a failure in one specific query, without control ever returning to the
// client. Fortunately we can do this with MySQL triggers.
//
// We also want to make sure we can revoke the precertificate, which we will
// assume exists (note that this different from the root program assumption
// that a final certificate exists for any precertificate, though it is
// similar in spirit).
func TestIssuanceCertStorageFailed(t *testing.T) {
	os.Setenv("DIRECTORY", "http://boulder.service.consul:4001/directory")

	db, err := sql.Open("mysql", vars.DBConnSAIntegrationFullPerms)
	test.AssertNotError(t, err, "failed to open db connection")

	if os.Getenv("USE_VITESS") == "false" {
		// This block is only necessary for ProxySQL + MariaDB and can be
		// deleted once we're fully migrated to Vitess + MySQL 8, where the
		// trigger is installed via test/vtcomboserver/install_trigger.sh.

		ctx := context.Background()
		_, err = db.ExecContext(ctx, `DROP TRIGGER IF EXISTS fail_ready`)
		test.AssertNotError(t, err, "failed to drop trigger")

		// Make a specific insert into certificates fail, for this test but not others.
		// To limit the effect to this one test, we make the trigger aware of a specific
		// hostname used in this test. Since the INSERT to the certificates table
		// doesn't include the hostname, we look it up in the issuedNames table, keyed
		// off of the serial.
		// NOTE: CREATE and DROP TRIGGER do not work in prepared statements. Go's
		// database/sql will automatically try to use a prepared statement if you pass
		// any arguments to Exec besides the query itself, so don't do that.
		_, err = db.ExecContext(ctx, `
		CREATE TRIGGER fail_ready
		BEFORE INSERT ON certificates
		FOR EACH ROW BEGIN
		DECLARE reversedName1 VARCHAR(255);
		SELECT reversedName
		    INTO reversedName1
			FROM issuedNames
			WHERE serial = NEW.serial
			    AND reversedName LIKE "com.wantserror.%";
		IF reversedName1 != "" THEN
			SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Pretend there was an error inserting into certificates';
		END IF;
		END
	`)
		test.AssertNotError(t, err, "failed to create trigger")

		defer db.ExecContext(ctx, `DROP TRIGGER IF EXISTS fail_ready`)
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "creating random cert key")

	// ---- Test revocation by serial ----
	revokeMeDomain := "revokeme.wantserror.com"
	// This should fail because the trigger prevented storing the final certificate.
	_, err = authAndIssue(nil, certKey, []acme.Identifier{{Type: "dns", Value: revokeMeDomain}}, true, "")
	test.AssertError(t, err, "expected authAndIssue to fail")

	cert, err := getPrecertByName(db, revokeMeDomain)
	test.AssertNotError(t, err, "failed to get certificate by name")

	// Revoke by invoking admin-revoker
	config := fmt.Sprintf("%s/%s", os.Getenv("BOULDER_CONFIG_DIR"), "admin.json")
	output, err := exec.Command(
		"./bin/admin",
		"-config", config,
		"-dry-run=false",
		"revoke-cert",
		"-serial", core.SerialToString(cert.SerialNumber),
		"-reason", "unspecified",
	).CombinedOutput()
	test.AssertNotError(t, err, fmt.Sprintf("revoking via admin-revoker: %s", string(output)))

	waitAndCheckRevoked(t, cert, nil, revocation.Unspecified)

	// ---- Test revocation by key ----
	blockMyKeyDomain := "blockmykey.wantserror.com"
	// This should fail because the trigger prevented storing the final certificate.
	_, err = authAndIssue(nil, certKey, []acme.Identifier{{Type: "dns", Value: blockMyKeyDomain}}, true, "")
	test.AssertError(t, err, "expected authAndIssue to fail")

	cert, err = getPrecertByName(db, blockMyKeyDomain)
	test.AssertNotError(t, err, "failed to get certificate by name")

	// Time to revoke! We'll do it by creating a different, successful certificate
	// with the same key, then revoking that certificate for keyCompromise.
	revokeClient, err := makeClient()
	test.AssertNotError(t, err, "creating second acme client")
	res, err := authAndIssue(nil, certKey, []acme.Identifier{{Type: "dns", Value: random_domain()}}, true, "")
	test.AssertNotError(t, err, "issuing second cert")

	err = revokeClient.RevokeCertificate(
		revokeClient.Account,
		res.certs[0],
		certKey,
		1,
	)
	test.AssertNotError(t, err, "revoking second certificate")

	waitAndCheckRevoked(t, res.certs[0], res.certs[1], revocation.KeyCompromise)
	waitAndCheckRevoked(t, cert, nil, revocation.KeyCompromise)

	// Try to issue again with the same key, expecting an error because of the key is blocked.
	_, err = authAndIssue(nil, certKey, []acme.Identifier{{Type: "dns", Value: "123.example.com"}}, true, "")
	test.AssertError(t, err, "expected authAndIssue to fail")
	if !strings.Contains(err.Error(), "public key is forbidden") {
		t.Errorf("expected issuance to be rejected with a bad pubkey")
	}
}
