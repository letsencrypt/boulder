package main

import (
	"context"
	"fmt"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/db"
	blog "github.com/letsencrypt/boulder/log"
)

type ordersJob struct {
	*batchedDBJob
}

func newOrdersJob(
	dbMap db.DatabaseMap,
	log blog.Logger,
	clk clock.Clock,
	config CleanupConfig) *batchedDBJob {
	purgeBefore := config.GracePeriod.Duration
	workQuery := `SELECT id, expires FROM orders
		 WHERE
		   id > :startID
		 LIMIT :limit`
	log.Debugf("Creating Orders job from config: %#v\n", config)
	j := &ordersJob{
		batchedDBJob: &batchedDBJob{
			db:          dbMap,
			log:         log,
			clk:         clk,
			purgeBefore: purgeBefore,
			workSleep:   config.WorkSleep.Duration,
			batchSize:   config.BatchSize,
			maxDPS:      config.MaxDPS,
			parallelism: config.Parallelism,
			table:       "orders",
			workQuery:   workQuery,
		},
	}
	j.batchedDBJob.deleteHandler = j.deleteOrder
	return j.batchedDBJob
}

func (j *ordersJob) deleteOrder(orderID int64) error {
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
