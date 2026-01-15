package vars

import (
	"fmt"
	"os"
)

func dsn(user, database string) string {
	addr := os.Getenv("DB_ADDR")
	if addr == "" {
		addr = "unset DB_ADDR"
	}
	return fmt.Sprintf("%s@tcp(%s)/%s", user, addr, database)
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
