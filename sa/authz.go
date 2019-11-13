package sa

import (
	"fmt"
	"time"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/db"
)

const getAuthorizationIDsMax = 1000

func getAuthorizationIDsByDomain(db db.Selector, tableName string, ident string, now time.Time) ([]string, error) {
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
