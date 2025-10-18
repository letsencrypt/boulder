//go:build integration

package integration

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/letsencrypt/boulder/test/vars"
)

var ignoredSlowLogPrefixes = []string{
	// These are used for test setup/teardown.
	"UPDATE crlShards SET leasedUntil",
	// These are used for test setup/teardown.
	"UPDATE authz2 SET attemptedAt",
}

var ignoredSlowLogFragments = []string{
	// We don't care about queries on information_schema.
	"information_schema",
	// We don't care about queries on performance_schema.
	"performance_schema",
	// We don't care about queries on mysql schema.
	"mysql.",
	// We don't care about queries on sys schema.
	"sys.",
	// We don't care about queries on gorp_migrations table.
	"gorp_migrations",
}

var ignoredSlowLogExactQueries = map[string]struct{}{
	// incidents table will always remain tiny
	"SELECT * FROM incidents WHERE enabled = 1": {},
}

func isIgnoredSlowLogEntry(entry string) bool {
	normalized := strings.TrimSpace(entry)
	for _, prefix := range ignoredSlowLogPrefixes {
		if strings.HasPrefix(normalized, prefix) {
			return true
		}
	}
	for _, fragment := range ignoredSlowLogFragments {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	if _, ignored := ignoredSlowLogExactQueries[normalized]; ignored {
		return true
	}
	return false
}

func buildSlowLogFailure(queries []string) error {
	var b strings.Builder
	b.WriteString("unexpected queries logged without indexes:\n")
	for _, q := range queries {
		b.WriteString("  ")
		b.WriteString(q)
		b.WriteString("\n")
	}
	return errors.New(b.String())
}

func assertNoUnexpectedSlowQueries(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, "FLUSH SLOW LOGS")
	if err != nil {
		return fmt.Errorf("slow query log check: flushing slow logs: %w", err)
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("slow query log check: acquiring connection: %w", err)
	}
	defer conn.Close()

	rows, err := conn.QueryContext(ctx, `
		SELECT sql_text
		FROM mysql.slow_log
		ORDER BY start_time
	`)
	if err != nil {
		return fmt.Errorf("slow query log check, querying slow_log: %w", err)
	}
	defer rows.Close()

	var offenders []string
	for rows.Next() {
		var sqlText string
		err = rows.Scan(&sqlText)
		if err != nil {
			return fmt.Errorf("slow query log check, scanning row: %w", err)
		}
		if isIgnoredSlowLogEntry(sqlText) {
			continue
		}
		offenders = append(offenders, strings.TrimSpace(sqlText))
	}
	err = rows.Err()
	if err != nil {
		return fmt.Errorf("slow query log check, iterating rows: %w", err)
	}

	if len(offenders) == 0 {
		return nil
	}

	return buildSlowLogFailure(offenders)
}

// configureSlowQueryLogging enables slow query logging to FILE and TABLE and
// turns on logging of queries not using indexes. It returns a function that
// restores the original settings.
func configureSlowQueryLogging(db *sql.DB) (func() error, error) {
	// Capture current settings.
	row := db.QueryRowContext(context.Background(), `
		SELECT @@GLOBAL.slow_query_log,
		       @@GLOBAL.log_queries_not_using_indexes,
		       @@GLOBAL.log_output
	`)

	type slowQueryConfig struct {
		slowQueryLog              string
		logQueriesNotUsingIndexes string
		logOutput                 string
	}

	var original slowQueryConfig
	err := row.Scan(&original.slowQueryLog, &original.logQueriesNotUsingIndexes, &original.logOutput)
	if err != nil {
		return nil, fmt.Errorf("fetching current slow query log settings: %w", err)
	}

	_, err = db.ExecContext(context.Background(), `
		SET GLOBAL slow_query_log = ON,
			GLOBAL log_queries_not_using_indexes = ON,
			GLOBAL log_output = 'FILE,TABLE'
	`)
	if err != nil {
		return nil, fmt.Errorf("executing slow query log setup: %w", err)
	}

	return func() error {
		sqlQuote := func(s string) string {
			return "'" + strings.ReplaceAll(strings.TrimSpace(s), "'", "''") + "'"
		}

		restoreStatements := []string{
			fmt.Sprintf("SET GLOBAL slow_query_log = %s", original.slowQueryLog),
			fmt.Sprintf("SET GLOBAL log_queries_not_using_indexes = %s", original.logQueriesNotUsingIndexes),
			fmt.Sprintf("SET GLOBAL log_output = %s", sqlQuote(original.logOutput)),
		}
		for _, statement := range restoreStatements {
			_, err := db.ExecContext(context.Background(), statement)
			if err != nil {
				return fmt.Errorf("restoring %q: %w", statement, err)
			}
		}

		_, err = db.ExecContext(context.Background(), "FLUSH SLOW LOGS")
		if err != nil {
			return fmt.Errorf("flushing slow query log: %w", err)
		}

		_, err = db.ExecContext(context.Background(), "TRUNCATE TABLE mysql.slow_log")
		if err != nil {
			return fmt.Errorf("truncating mysql.slow_log: %w", err)
		}
		return nil
	}, nil
}

func openSlowLogDatabase() (*sql.DB, error) {
	db, err := sql.Open("mysql", fmt.Sprintf("%s?parseTime=true&loc=UTC&timeout=5s&readTimeout=5s&writeTimeout=5s", vars.DBInfoSchemaRoot))
	if err != nil {
		return nil, fmt.Errorf("opening slow log connection: %w", err)
	}
	db.SetMaxOpenConns(5)
	db.SetConnMaxIdleTime(30 * time.Second)
	db.SetConnMaxLifetime(2 * time.Minute)
	return db, nil
}

func slowLogCheckSetupAndTeardown(m *testing.M, next func(*testing.M) int) int {
	if os.Getenv("BOULDER_CONFIG_DIR") != "test/config-next" {
		// Skip this setup/teardown if not running against the "next" config.
		return next(m)
	}

	db, err := openSlowLogDatabase()
	if err != nil {
		fmt.Fprintf(os.Stderr, "slow query log setup: %s\n", err)
		return 1
	}
	defer db.Close()

	restore, err := configureSlowQueryLogging(db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "slow query log configure: %s\n", err)
		return 1
	}
	defer func() {
		err := restore()
		if err != nil {
			fmt.Fprintf(os.Stderr, "slow query log restore: %s\n", err)
		}
	}()

	exitCode := next(m)

	err = assertNoUnexpectedSlowQueries(context.Background(), db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		exitCode = 1
	}

	return exitCode
}

type setupAndTeardown func(*testing.M, func(*testing.M) int) int

// runIntegrationTestsWithSetupAndTeardown runs m.Run() wrapped by the provided
// setupAndTeardown functions. Each function is applied in the order given, with
// the last function wrapping the earlier ones.
func runIntegrationTestsWithSetupAndTeardown(m *testing.M, sats ...setupAndTeardown) int {
	base := func(m *testing.M) int {
		return m.Run()
	}
	for _, sat := range sats {
		next := base
		base = func(m *testing.M) int {
			return sat(m, next)
		}
	}
	return base(m)
}

// TestMain is the main entry point for integration tests. It sets up and tears
// down any required state around the tests.
func TestMain(m *testing.M) {
	exitCode := runIntegrationTestsWithSetupAndTeardown(m, slowLogCheckSetupAndTeardown)
	// Here we can add more setupAndTeardown functions if needed in the future.
	os.Exit(exitCode)
}
