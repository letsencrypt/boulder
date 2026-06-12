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
	configVariant := ""
	if os.Getenv("BOULDER_CONFIG_DIR") == "test/config-next" && database != "information_schema" {
		configVariant = "_next"
	}
	return fmt.Sprintf("%s@tcp(%s)/%s%s", user, addr, database, configVariant)
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
	// DBConnIncidentsAdmin is the incidents database connection with create/insert perms.
	DBConnIncidentsAdmin = dsn("incidents_sa_admin", "incidents_sa")
	// DBConnIncidentsFullPerms is the incidents database connection with full perms.
	DBConnIncidentsFullPerms = dsn("test_setup", "incidents_sa")
	// DBConnMTCMeta_44947_4_1_0_44FullPerms is the mtcmeta_44947_4_1_0_44 database
	// connection with full perms. It builds the DSN directly because mtcmeta has
	// no _next variant for dsn() to append.
	DBConnMTCMeta_44947_4_1_0_44FullPerms = fmt.Sprintf("test_setup@tcp(%s)/mtcmeta_44947_4_1_0_44", os.Getenv("DB_ADDR"))
)
