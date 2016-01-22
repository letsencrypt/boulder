package sa

import (
	"fmt"
	"strings"
	"time"

	gorp "github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"

	"github.com/letsencrypt/boulder/core"
)

var authorizationTables = []string{
	"authz",
	"pendingAuthorizations",
}

const getAuthorizationIDsMax = 1000

func getAuthorizationIDsByDomain(db *gorp.DbMap, ident string, now time.Time) ([]string, error) {
	var allIDs []string
	for _, tableName := range authorizationTables {
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
		if len(allIDs) == getAuthorizationIDsMax {
			break
		}
	}
	return allIDs, nil
}

func revokeAuthorizations(db *gorp.DbMap, authIDs []string) (int64, int64, error) {
	results := []int64{0, 0}
	stmtArgs := []interface{}{string(core.StatusRevoked)}
	qmarks := []string{}
	for _, id := range authIDs {
		stmtArgs = append(stmtArgs, id)
		qmarks = append(qmarks, "?")
	}
	idStmt := fmt.Sprintf("(%s)", strings.Join(qmarks, ", "))
	for i, tableName := range authorizationTables {
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
			return results[0], results[1], err
		}
		batchSize, err := result.RowsAffected()
		if err != nil {
			return results[0], results[1], err
		}
		results[i] = batchSize
	}
	return results[0], results[1], nil // final revoked, pending revoked
}
