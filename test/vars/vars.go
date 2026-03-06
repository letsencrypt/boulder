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
	config_variant := ""
	if os.Getenv("BOULDER_CONFIG_DIR") == "test/config-next" && database != "information_schema" {
		config_variant = "_next"
	}
	return fmt.Sprintf("%s@tcp(%s)/%s%s", user, addr, database, config_variant)
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
