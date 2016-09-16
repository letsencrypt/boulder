package sa

import (
	"fmt"
	"strings"
	"time"

	gorp "gopkg.in/gorp.v1"

	"github.com/letsencrypt/boulder/core"
)

var authorizationTables = []string{
	"authz",
	"pendingAuthorizations",
}

var pendingStatuses = []core.AcmeStatus{
	core.StatusPending,
	core.StatusProcessing,
	core.StatusUnknown,
}

const getAuthorizationIDsMax = 1000

func statusIsPending(status core.AcmeStatus) bool {
	for _, pendingStatus := range pendingStatuses {
		if status == pendingStatus {
			return true
		}
	}
	return false
}

func authzIdExists(tx *gorp.Transaction, id string) bool {
	var found bool
	for _, table := range authorizationTables {
		count, _ := tx.SelectInt(
			fmt.Sprintf("SELECT COUNT(1) FROM %s WHERE id = ?", table),
			id)
		if count > 0 {
			found = true
			break
		}
	}
	return found
}

/*
* getAuthz(tx, id) returns:
*   * an authorization
*   * the name of the table that the auth was read from
*   * an error (if any)
*
* The second return value, the table name, is used to support the temporary
* situation where an authz could be from the legacy pendingAuthorizations table,
* or from the authz table. Callers may need to know which table the authz came
* from to correctly perform UPDATEs and DELETEs. The table name return value can
* be removed once the pendingAuthorizations table is dropped and all authz are
* read from the authz table. For more information consult Issue 2162[0].
*
* [0] - https://github.com/letsencrypt/boulder/issues/2162
 */
func getAuthz(tx *gorp.Transaction, id string) (core.Authorization, string, error) {
	var authz core.Authorization
	var table string

	// First try to find a row from the `pendingAuthorizations` table with
	// a `pendingauthzModel{}`.
	authObj, err := tx.Get(pendingauthzModel{}, id)
	if err != nil {
		err = Rollback(tx, err)
		return authz, table, err
	}
	if authObj != nil {
		authD := *authObj.(*pendingauthzModel)
		authz = authD.Authorization
		table = "pendingAuthorizations"
	} else {
		// If that doesn't yield an authz, then try from the `authz` table with
		// a `authzModel{}`.
		authObj, err = tx.Get(authzModel{}, id)
		if err != nil {
			err = Rollback(tx, err)
			return authz, table, err
		}
		if authObj == nil {
			err = fmt.Errorf("No pendingAuthorization or authz with ID %s", id)
			err = Rollback(tx, err)
			return authz, table, err
		}
		authD := authObj.(*authzModel)
		authz = authD.Authorization
		table = "authz"
	}

	var challObjs []challModel
	_, err = tx.Select(
		&challObjs,
		getChallengesQuery,
		map[string]interface{}{"authID": authz.ID},
	)
	if err != nil {
		err = Rollback(tx, err)
		return authz, table, err
	}
	var challs []core.Challenge
	for _, c := range challObjs {
		chall, err := modelToChallenge(&c)
		if err != nil {
			err = Rollback(tx, err)
			return authz, table, err
		}
		challs = append(challs, chall)
	}
	authz.Challenges = challs

	return authz, table, nil
}

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
