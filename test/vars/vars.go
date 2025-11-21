package vars

import (
	"fmt"
	"os"
)

var dbHost = os.Getenv("MYSQL_ADDR")

func formatURL(user, database string) string {
	return fmt.Sprintf("%s@tcp(%s)/%s", user, dbHost, database)
}

var (
	// DBConnSA is the sa database connection
	DBConnSA = formatURL("sa", "boulder_sa_test")
	// DBConnSAMailer is the sa mailer database connection
	DBConnSAMailer = formatURL("mailer", "boulder_sa_test")
	// DBConnSAFullPerms is the sa database connection with full perms
	DBConnSAFullPerms = formatURL("test_setup", "boulder_sa_test")
	// DBConnSAIntegrationFullPerms is the sa database connection for the
	// integration test DB, with full perms
	DBConnSAIntegrationFullPerms = formatURL("test_setup", "boulder_sa_integration")
	// DBInfoSchemaRoot is the root user and the information_schema connection.
	DBInfoSchemaRoot = formatURL("root", "information_schema")
	// DBConnIncidents is the incidents database connection.
	DBConnIncidents = formatURL("incidents_sa", "incidents_sa_test")
	// DBConnIncidentsFullPerms is the incidents database connection with full perms.
	DBConnIncidentsFullPerms = formatURL("test_setup", "incidents_sa_test")
)
