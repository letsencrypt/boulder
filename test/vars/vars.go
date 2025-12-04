package vars

import (
	"fmt"
	"net"
	"os"
)

var dbAddr = func() string {
	addr := os.Getenv("DB_ADDR")
	if addr == "" {
		panic("environment variable DB_ADDR  must be set")
	}
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		panic(fmt.Sprintf("environment variable DB_ADDR (%s) is not a valid address with host and port: %s", addr, err))
	}
	return addr
}()

func dsn(user, database string) string {
	return fmt.Sprintf("%s@tcp(%s)/%s", user, dbAddr, database)
}

var (
	// DBConnSA is the sa database connection
	DBConnSA = dsn("sa", "boulder_sa_test")
	// DBConnSAMailer is the sa mailer database connection
	DBConnSAMailer = dsn("mailer", "boulder_sa_test")
	// DBConnSAFullPerms is the sa database connection with full perms
	DBConnSAFullPerms = dsn("test_setup", "boulder_sa_test")
	// DBConnSAIntegrationFullPerms is the sa database connection for the
	// integration test DB, with full perms
	DBConnSAIntegrationFullPerms = dsn("test_setup", "boulder_sa_integration")
	// DBInfoSchemaRoot is the root user and the information_schema connection.
	DBInfoSchemaRoot = dsn("root", "information_schema")
	// DBConnIncidents is the incidents database connection.
	DBConnIncidents = dsn("incidents_sa", "incidents_sa_test")
	// DBConnIncidentsFullPerms is the incidents database connection with full perms.
	DBConnIncidentsFullPerms = dsn("test_setup", "incidents_sa_test")
)
