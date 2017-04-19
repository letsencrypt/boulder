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
	"sort"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/codegangsta/cli"
	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/go-sql-driver/mysql"

	"github.com/letsencrypt/boulder/cmd"
)

type Migration struct {
	Desc    string
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
	_, err = tx.Exec("CREATE TABLE IF NOT EXISTS migrations (id CHAR(17) UNIQUE, description TEXT, applied DATETIME)")
	if err != nil {
		tx.Rollback()
		return
	}
	err = tx.Commit()
	return
}

var timestampFormat string = "20060102-150405"

func orderedMigrationList(migrationDir string) (sortedList []string, err error) {
	migrationList, err := ioutil.ReadDir(migrationDir)
	if err != nil {
		return
	}
	for  _, file := range migrationList {
		if strings.ToLower(filepath.Ext(file.Name())) != ".json" {
			continue
		}
		if file.Name() == "/" {
			continue
		}
		migrationName := nameFromFile(file.Name())
		_, err := time.Parse(timestampFormat, migrationName)
		if err != nil {
			continue
		}
		sortedList = append(sortedList, migrationName)
	}
	sort.Strings(sortedList)
	return
}

// list migrations
func listMigrations(Sql *sql.DB, migrationDir string) (err error) {
	migrationList, err := ioutil.ReadDir(migrationDir)
	if err != nil {
		return
	}
	fmt.Println("id             state\n--             -----")
	for _, file := range migrationList {
		if strings.ToLower(filepath.Ext(file.Name())) != ".json" {
			continue
		}
		name := nameFromFile(file.Name())
		var state   string
		var desc    string
		var applied bool
		applied, err = isApplied(Sql, name)
		if err != nil {
			return
		}
		if applied {
			var appliedInt interface{}
			err = Sql.QueryRow("SELECT description, applied FROM migrations WHERE id = ?", name).Scan(&desc, &appliedInt)
			if err != nil {
				return
			}
			var applied time.Time
			applied, ok := appliedInt.(time.Time)
			if !ok {
				return
			}
			state = fmt.Sprintf("Applied at %s", applied)
		} else {
			state = "Unapplied"
			var migration Migration
			migration, err = loadMigrationFile(path.Join(migrationDir, file.Name()))
			if err != nil {
				return
			}
			desc = migration.Desc
		}
		fmt.Printf("%s [%s]\n\t%s\n\n", name, state, desc)
	}
	return
}

// apply new migration
func applyMigration(Sql *sql.DB, id string, migrationDir string, yes bool) (err error) {
	mPath := path.Join(migrationDir, id+".json")
	migration, err := loadMigrationFile(mPath)
	if err != nil {
		return
	}
	if !yes {
		fmt.Printf("[migration %s]\n", id)
		fmt.Printf("\tDescription: %s\n", migration.Desc)
		fmt.Printf("\n\tMigrate SQL:\n")
		for _, sqlLine := range migration.UpSQL {
			fmt.Printf("\t\t%s\n", sqlLine)
		}
		fmt.Printf("\n\tRevert SQL:\n")
		for _, sqlLine := range migration.DownSQL {
			fmt.Printf("\t\t%s\n", sqlLine)
		}
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
func applyAllMigrations(Sql *sql.DB, migrationDir string, yes bool) (err error) {
	orderedMigrations, err := orderedMigrationList(migrationDir)
	if err != nil {
		return
	}
	for _, name := range orderedMigrations {
		var applied bool
		applied, err = isApplied(Sql, name)
		if err != nil {
			return
		}
		if !applied {
			err = applyMigration(Sql, name, migrationDir, yes)
			if err != nil {
				return
			}
		}
	}
	return
}

// revert last migration
func revertMigration(Sql *sql.DB, migrationDir string, yes bool) (err error) {
	var id string
	err = Sql.QueryRow("SELECT id FROM migrations ORDER BY id DESC LIMIT 1").Scan(&id)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Println("No migrations to revert.")
			err = nil
		}
		return
	}
	migration, err := loadMigrationFile(path.Join(migrationDir, id+".json"))
	if err != nil {
		return
	}
	if !yes {
		fmt.Printf("[migration %s]\n", id)
		fmt.Printf("\tDescription: %s\n", migration.Desc)
		fmt.Printf("\n\tRevert SQL:\n")
		for _, sqlLine := range migration.DownSQL {
			fmt.Printf("\t\t%s\n", sqlLine)
		}
		if answer := getYN("\nAre you sure you would like to revert this migration"); !answer {
			fmt.Println("Ok, bye!")
			return
		}
	}
	tx, err := Sql.Begin()
	if err != nil {
		return
	}
	for _, sqlStmt := range migration.DownSQL {
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
func revertMigrationTo(Sql *sql.DB, id string, migrationDir string, yes bool) (err error) {
	var revertCount int
	err = Sql.QueryRow("SELECT count(*) FROM migrations WHERE id > ? ORDER BY applied ASC", id).Scan(&revertCount)
	if err != nil {
		return
	}
	if revertCount == 0 {
		fmt.Printf("There are no migrations after ID %s to revert\n", id)
	}
	if yes {
		if answer := getYN(fmt.Sprintf("This will revert %d migrations, would you like to continue", revertCount)); !answer {
			fmt.Println("Ok, bye!")
			return
		}
	}
	for i := 0; i < revertCount; i++ {
		err = revertMigration(Sql, migrationDir, yes)
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

func nameFromFile(mPath string) string {
	filename := path.Base(mPath)
	return filename[0:len(filename)-len(filepath.Ext(filename))]
}

func loadMigrationFile(mPath string) (migration Migration, err error) {
	migrationJSON, err := ioutil.ReadFile(mPath)
	if err != nil {
		return
	}
	err = json.Unmarshal(migrationJSON, &migration)
	return
}

func setupContext(c *cli.Context) (db *sql.DB, dir string, err error) {
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

	dir = c.GlobalString("migration-dir")
	if dir == "" {
		err = fmt.Errorf("No migration directory specified [using --migration-dir or Env Var BOULDER_MIGRATION_DIR]")
	}

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
			EnvVar: "BOULDER_MIGRATION_DIR",
		},
		cli.BoolFlag{
			Name:  "yes",
			Usage: "automatically say yes to all prompts",
		},
	}

	app.Commands = []cli.Command{
		{
			Name: "list",
			Usage: "List all currently applied migrations",
			Action: func(c *cli.Context) {
				db, migrationDir, err := setupContext(c)
				if err != nil {
					cmd.FailOnError(err, "Failed connecting to DB")
				}
				err = listMigrations(db, migrationDir)
				if err != nil {
					cmd.FailOnError(err, "Listing migrations failed")
				}
			},
		},
		{
			Name: "apply",
			Usage: "Apply a single migration by ID",
			Action: func(c *cli.Context) {
				db, migrationDir, err := setupContext(c)
				if err != nil {
					cmd.FailOnError(err, "Failed connecting to DB")
				}
				yes := c.GlobalBool("yes")
				err = applyMigration(db, c.Args().First(), migrationDir, yes)
				cmd.FailOnError(err, "Failed to apply migration")
			},
		},
		{
			Name: "apply-all",
			Usage: "Apply all migrations currently unapplied",
			Action: func(c *cli.Context) {
				db, migrationDir, err := setupContext(c)
				if err != nil {
					cmd.FailOnError(err, "Failed connecting to DB")
				}
				yes := c.GlobalBool("yes")
				err = applyAllMigrations(db, migrationDir, yes)
				cmd.FailOnError(err, "Failed to apply all migrations")
			},
		},
		{
			Name: "revert-last",
			Usage: "Revert the last migration that was applied",
			Action: func(c *cli.Context) {
				db, migrationDir, err := setupContext(c)
				if err != nil {
					cmd.FailOnError(err, "Failed connecting to DB")
				}
				yes := c.GlobalBool("yes")
				err = revertMigration(db, migrationDir, yes)
				if err != nil {
					cmd.FailOnError(err, "Reverting last migration failed")
				}
			},
		},
		{
			Name: "revert-to",
			Usage: "Revert to a specific migration specified by its ID",
			Action: func(c *cli.Context) {
				db, migrationDir, err := setupContext(c)
				if err != nil {
					cmd.FailOnError(err, "Failed connecting to DB")
				}
				id := c.Args().First()
				yes := c.GlobalBool("yes")
				err = revertMigrationTo(db, id, migrationDir, yes)
				if err != nil {
					cmd.FailOnError(err, fmt.Sprintf("Failed to revert to migration %s", id))
				}
			},
		},
	}

	err := app.Run(os.Args)
	cmd.FailOnError(err, "Failed to run application")
}
