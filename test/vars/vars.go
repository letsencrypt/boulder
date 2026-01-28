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
	DBConnSA = dsn("sa", "boulder_sa")
	// DBConnSAFullPerms is the sa database connection with full perms
	DBConnSAFullPerms = dsn("test_setup", "boulder_sa")
	// DBInfoSchemaRoot is the root user and the information_schema connection.
	DBInfoSchemaRoot = dsn("root", "information_schema")
	// DBConnIncidents is the incidents database connection.
	DBConnIncidents = dsn("incidents_sa", "incidents_sa")
	// DBConnIncidentsFullPerms is the incidents database connection with full perms.
	DBConnIncidentsFullPerms = dsn("test_setup", "incidents_sa")
)
