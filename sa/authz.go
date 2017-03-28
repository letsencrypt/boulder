package sa

import (
	"fmt"
	"strings"
	"time"

	"gopkg.in/go-gorp/gorp.v2"

	"github.com/letsencrypt/boulder/core"
)

var authorizationTables = []string{
	"authz",
	"pendingAuthorizations",
}

const getAuthorizationIDsMax = 1000

func getAuthorizationIDsByDomain(db *gorp.DbMap, tableName string, ident string, now time.Time) ([]string, error) {
	var allIDs []string
	_, err := db.Select(
		&allIDs,
		fmt.Sprintf(
			`SELECT id FROM %s
       WHERE identifier = :ident AND
       status != :invalid AND
       status != :revoked AND
       expires > :now
       LIMIT :limit`,
			tableName,
		),
		map[string]interface{}{
			"ident":   ident,
			"invalid": string(core.StatusInvalid),
			"revoked": string(core.StatusRevoked),
			"now":     now,
			"limit":   getAuthorizationIDsMax,
		},
	)
	if err != nil {
		return nil, err
	}
	return allIDs, nil
}

func revokeAuthorizations(db *gorp.DbMap, tableName string, authIDs []string) (int64, error) {
	stmtArgs := []interface{}{string(core.StatusRevoked)}
	qmarks := []string{}
	for _, id := range authIDs {
		stmtArgs = append(stmtArgs, id)
		qmarks = append(qmarks, "?")
	}
	idStmt := fmt.Sprintf("(%s)", strings.Join(qmarks, ", "))
	result, err := db.Exec(
		fmt.Sprintf(
			`UPDATE %s
       SET status = ?
       WHERE id IN %s`,
			tableName,
			idStmt,
		),
		stmtArgs...,
	)
	if err != nil {
		return 0, err
	}
	batchSize, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return batchSize, nil
}
