package janitor

import (
	"context"
	"fmt"

	"github.com/letsencrypt/boulder/db"
)

// deleteHandlers is a map of json-usable strings to actual functions, so that
// configs can specify a delete handler by name.
var deleteHandlers = map[string]func(*batchedDBJob, int64) error{
	"default":     deleteDefault,
	"deleteOrder": deleteOrder,
}

// deleteDefault performs a delete of the given ID from the batchedDBJob's
// table or returns an error. It does not use a transaction and assumes there
// are no foreign key constraints or referencing rows in other tables to manage.
func deleteDefault(j *batchedDBJob, id int64) error {
	// NOTE(@cpu): We throw away the sql.Result here without checking the rows
	// affected because the query is always specific to the ID auto-increment
	// primary key. If there are multiple rows with the same primary key MariaDB
	// has failed us deeply.
	query := fmt.Sprintf(`DELETE FROM %s WHERE id = ?`, j.table)
	if _, err := j.db.Exec(query, id); err != nil {
		return err
	}
	j.log.Debugf("deleted ID %d in table %q", id, j.table)
	deletedStat.WithLabelValues(j.table).Inc()
	return nil
}

// deleteOrder performs a delete of the given ID from the batchedDBJob's `orders`
// table or returns an error. It also deletes corresponding rows from three
// other tables which reference the `orders` table by foreign key.
func deleteOrder(j *batchedDBJob, orderID int64) error {
	ctx := context.Background()
	// Perform a multi-table delete inside of a transaction using the order ID.
	// Either all of the rows associated with the order ID will be deleted or the
	// transaction will be rolled back.
	_, err := db.WithTransaction(ctx, j.db, func(txWithCtx db.Executor) (interface{}, error) {
		// Delete table rows in the childTables that reference the order being deleted.
		childTables := []string{"requestedNames", "orderFqdnSets", "orderToAuthz2"}
		for _, t := range childTables {
			query := fmt.Sprintf(`DELETE FROM %s WHERE orderID = ?`, t)
			res, err := txWithCtx.Exec(query, orderID)
			if err != nil {
				return nil, err
			}
			affected, err := res.RowsAffected()
			if err != nil {
				return nil, err
			}
			deletedStat.WithLabelValues(t).Add(float64(affected))
		}
		// Finally delete the order itself
		if _, err := txWithCtx.Exec(`DELETE FROM orders WHERE id = ?`, orderID); err != nil {
			return nil, err
		}
		deletedStat.WithLabelValues("orders").Inc()
		j.log.Debugf("deleted order ID %d and associated rows", orderID)
		return nil, nil
	})
	return err
}
