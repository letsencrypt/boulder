// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// For the applied DATETIME field to work properly with MySQL the DSN parameter
// "parseTime=true" is required (e.g. "user:pass@tcp(localhost:3306)/boulder?parseTime=true")
// otherwise sql.Row.Scan will throw an error ("[]uint8 -> time.Time is bad" or something).

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/codegangsta/cli"
	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/go-sql-driver/mysql"

	"github.com/letsencrypt/boulder/cmd"
)

type Migration struct {
	Id      int
	Desc    string   // Basic explanation of what the migration does
	UpSQL   []string
	DownSQL []string
}

func getYN(question string) (answer bool) {
	fmt.Printf("\n%s? [y/n]", question)
	var free bool
	for {
		var resp string
		fmt.Printf("\n# ")
		_, err := fmt.Scanf("%s", &resp)
		if err != nil {
			fmt.Printf("%s: Please enter y or n\n", err)
			continue
		}
		switch resp {
		case "yes":
			fallthrough
		case "YES":
			fallthrough
		case "Yes":
			fallthrough
		case "Y":
			fallthrough
		case "y":
			answer = true
			free = true
		case "no":
			fallthrough
		case "NO":
			fallthrough
		case "No":
			fallthrough
		case "N":
			fallthrough
		case "n":
			answer = false
			free = true
		default:
			fmt.Println("Please enter y or n")
		}
		if free {
			break
		}
	}
	return
}

func createMigrationTable(Sql *sql.DB) (err error) {
	tx, err := Sql.Begin()
	if err != nil {
		return
	}
	_, err = tx.Exec("CREATE TABLE IF NOT EXISTS migrations (id TEXT UNIQUE PRIMARY, description TEXT, applied DATETIME)")
	if err != nil {
		tx.Rollback()
		return
	}
	err = tx.Commit()
	return
}

// list applied migrations
func listMigrations(Sql *sql.DB) (err error) {
	rows, err := Sql.Query("SELECT id, description, applied FROM migrations")
	if err != nil {
		return
	}
	defer rows.Close()
	fmt.Println("# Currently applied migrations\n")
	for rows.Next() {
		var id         string
		var desc       string
		var appliedInt interface{}
		var applied    time.Time
		if err = rows.Scan(&id, &desc, &appliedInt); err != nil {
			return
		}
		applied, ok := appliedInt.(time.Time)
		if !ok {
			fmt.Println(ok, applied)
			return
		}
		fmt.Printf("%s: applied [%s]\n\t%s\n", id, applied, desc)
	}
	return
}

// apply new migration
func applyMigration(Sql *sql.DB, path string, yes bool) (err error) {
	id, migration, err := loadMigrationFile(path)
	if err != nil {
		return
	}

	fmt.Printf("[migration %d]\n", id)
	fmt.Printf("\tDescription: %s\n", migration.Desc)
	fmt.Printf("\n\tMigrate SQL:\n")
	for _, sqlLine := range migration.UpSQL {
		fmt.Printf("\t%s\n", sqlLine)
	}
	fmt.Printf("\n\tRevert SQL:\n")
	for _, sqlLine := range migration.DownSQL {
		fmt.Printf("\t%s\n", sqlLine)
	}
	if !yes {
		if answer := getYN("\nWould you like to apply this migration"); !answer {
			fmt.Println("Ok, bye!")
			return
		}
	}
	tx, err := Sql.Begin()
	if err != nil {
		return
	}
	for _, sqlStmt := range migration.UpSQL {
		_, err = tx.Exec(sqlStmt)
		if err != nil {
			tx.Rollback()
			return
		}
	}
	_, err = tx.Exec("INSERT INTO migrations (id, description, applied) VALUES (?, ?, ?)", id, migration.Desc, time.Now())
	if err != nil {
		tx.Rollback()
		return
	}
	err = tx.Commit()
	if err != nil {
		return
	}
	fmt.Printf("Migration %s applied\n", id)
	return
}

// apply all unapplied migrations
func applyAllMigrations(Sql *sql.DB, yes bool) (err error) {
	return
}

// revert last migration
func revertMigration(Sql *sql.DB) (err error) {
	var id      int
	var downSql string
	err = Sql.QueryRow("SELECT id, down FROM migrations ORDER BY id DESC LIMIT 1").Scan(&id, &downSql)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Println("No migrations to revert.")
			err = nil
		}
		return
	}
	tx, err := Sql.Begin()
	if err != nil {
		return
	}
	for _, sqlStmt := range strings.Split(downSql, ";") {
		_, err = tx.Exec(sqlStmt)
		if err != nil {
			tx.Rollback()
			return
		}
	}
	_, err = tx.Exec("DELETE FROM migrations WHERE id = ?", id)
	if err != nil {
		tx.Rollback()
		return
	}
	fmt.Printf("Migration %s reverted\n", id)
	err = tx.Commit()
	return
}

// revert to specific migration
func revertMigrationTo(Sql *sql.DB, id int, yes bool) (err error) {
	var revertCount int
	err = Sql.QueryRow("SELECT count(*) FROM migrations WHERE id > ?", id).Scan(&revertCount)
	if err != nil {
		return
	}
	if revertCount == 0 {
		fmt.Printf("There are no migrations after ID %d to revert\n", id)
	}
	if !yes {
		if answer := getYN(fmt.Sprintf("This will revert %d migrations, would you like to continue", revertCount)); !answer {
			fmt.Println("Ok, bye!")
			return
		}
	}
	for i := 0; i < revertCount; i++ {
		err = revertMigration(Sql)
		if err != nil {
			return
		}
	}
	return
}

func isApplied(Sql *sql.DB, id string) (applied bool, err error) {
	err = Sql.QueryRow("SELECT count(1) FROM migrations WHERE id = ?", id).Scan(&applied)
	return
}

func nameFromFile(mPath string) (name string) {
	filename := path.Base(mPath)
	name = filename[0:len(filename)-len(filepath.Ext(filename))]
	return
}

func loadMigrationFile(mPath string) (name string, migration Migration, err error) {
	migrationJSON, err := ioutil.ReadFile(mPath)
	if err != nil {
		return
	}
	err = json.Unmarshal(migrationJSON, &migration)
	if err != nil {
		return
	}
	name = nameFromFile(mPath)
	return
}

func setupContext(c *cli.Context) (db *sql.DB, err error) {
	configFileName := c.GlobalString("config")
	configJSON, err := ioutil.ReadFile(configFileName)
	cmd.FailOnError(err, "Unable to read config file")

	var config cmd.Config
	err = json.Unmarshal(configJSON, &config)
	cmd.FailOnError(err, "Failed to read configuration")

	db, err = sql.Open(config.SA.DBDriver, config.SA.DBName)
	cmd.FailOnError(err, "Failed to connect to SQL database")

	err = createMigrationTable(db)
	cmd.FailOnError(err, "Failed to create migration table")

	return
}

var version string = "0.0.1"

func main() {
	app := cli.NewApp()

	app.Name = "boulder-migrator"
	app.Version = version

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "config",
			Value:  "config.json",
			EnvVar: "BOULDER_CONFIG",
		},
		cli.StringFlag{
			Name:   "migration-dir",
			Value:  "something",
			EnvVar: "BOULDER_MIGRATION_DIR",
		},
		cli.BoolFlag{
			Name:  "yes",
			Usage: "automatically say yes to all prompts",
		},
	}

	app.Commands = []cli.Command{
		{
			Name: "list-applied",
			Usage: "List all currently applied migrations",
			Action: func(c *cli.Context) {
				db, err := setupContext(c)
				if err != nil {
					cmd.FailOnError(err, "Failed connecting to DB")
				}
				err = listMigrations(db)
				if err != nil {
					cmd.FailOnError(err, "Listing migrations failed")
				}
			},
		},
		{
			Name: "apply",
			Usage: "Apply a migration from a JSON migration file",
			Action: func(c *cli.Context) {
				db, err := setupContext(c)
				if err != nil {
					cmd.FailOnError(err, "Failed connecting to DB")
				}

				yes := c.GlobalBool("yes")
				err = applyMigration(db, c.Args().First(), yes)
				cmd.FailOnError(err, "Failed to apply migration")
			},
		},
		{
			Name: "revert-last",
			Usage: "Revert the last migration that was applied",
			Action: func(c *cli.Context) {
				db, err := setupContext(c)
				if err != nil {
					cmd.FailOnError(err, "Failed connecting to DB")
				}
				err = revertMigration(db)
				if err != nil {
					cmd.FailOnError(err, "Reverting last migration failed")
				}
			},
		},
		{
			Name: "revert-to",
			Usage: "Revert to a specific migration specified by its ID",
			Action: func(c *cli.Context) {
				db, err := setupContext(c)
				if err != nil {
					cmd.FailOnError(err, "Failed connecting to DB")
				}
				var id int
				_, err = fmt.Sscanf(c.Args().First(), "%d", &id)
				if err != nil {
					cmd.FailOnError(err, "ID is not an integer")
				}
				yes := c.GlobalBool("yes")
				err = revertMigrationTo(db, id, yes)
				if err != nil {
					cmd.FailOnError(err, fmt.Sprintf("Failed to revert to migration %s", id))
				}
			},
		},
	}

	err := app.Run(os.Args)
	cmd.FailOnError(err, "Failed to run application")
}
