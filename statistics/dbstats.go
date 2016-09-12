// Copyright 2016 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package statistics

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/jmhodges/clock"
	"gopkg.in/gorp.v1"

	"github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
)

type DBStatsEngine struct {
	DB     *gorp.DbMap
	clk    clock.Clock
	Logger blog.Logger
	Window cmd.ConfigDuration
	Writer io.Writer
	Stats  statsd.Statter
}

type EncodedStats struct {
	CertsPerDayByStatus       []CertsPerDayByStatus
	ChallengeCounts           []ChallengeCounts
	RegistrationsPerDayByType []RegistrationsPerDayByType
}

type ChallengeCounts struct {
	Completions int64
	Type        string
}
type CertsPerDayByStatus struct {
	IssuedDate time.Time
	Revoked    int64
	StillValid int64
}

type RegistrationsPerDayByType struct {
	Anonymous   int64
	CreateDate  time.Time
	WithContact int64
}

func NewDBStatsEngine(dbMap *gorp.DbMap, stats statsd.Statter, clk clock.Clock, window cmd.ConfigDuration, writer io.Writer, logger blog.Logger) (*DBStatsEngine, error) {
	if dbMap == nil {
		return nil, fmt.Errorf("DB Map must not be nil")
	}

	engine := &DBStatsEngine{
		DB:     dbMap,
		Logger: logger,
		clk:    clk,
		Window: window,
		Writer: writer,
		Stats:  stats,
	}
	return engine, nil
}

func (stats *DBStatsEngine) certificatesIssuedPerDayByStatus() ([]CertsPerDayByStatus, error) {
	var counts []CertsPerDayByStatus
	_, err := stats.DB.Select(&counts,
		`SELECT
          DATE(c.issued) as IssuedDate,
          SUM(scs.status = 'good') as StillValid,
          SUM(scs.status = 'revoked') as Revoked
      FROM
        certificates AS c
          NATURAL JOIN
        certificateStatus AS scs
      WHERE c.expires > :now AND c.issued > DATE_SUB(:now, INTERVAL :window HOUR)
      GROUP BY DATE(c.issued);`,
		map[string]interface{}{
			"window": stats.Window.Hours(),
			"now":    stats.clk.Now(),
		})

	return counts, err
}

func (stats *DBStatsEngine) registrationsPerDayByType() ([]RegistrationsPerDayByType, error) {
	var counts []RegistrationsPerDayByType
	_, err := stats.DB.Select(&counts,
		`SELECT
          DATE(r.createdAt) as CreateDate,
          SUM(r.contact = 'null') as Anonymous,
          SUM(r.contact != 'null') as WithContact
      FROM
          registrations AS r
      WHERE
          r.createdAt > DATE_SUB(:now, INTERVAL :window HOUR)
      GROUP BY DATE(r.createdAt);`,
		map[string]interface{}{
			"window": stats.Window.Hours(),
			"now":    stats.clk.Now(),
		})

	return counts, err
}

func (stats *DBStatsEngine) challengeCounts() ([]ChallengeCounts, error) {
	// This would be better if there was a mechanism to select only recent
	// challenges, but there's no direct way of determining the insertion
	// date of challenges or authorizations, only their expiration which
	// is dependent on the challenge lifespan configuration at the time
	// it was inserted, which may be different than the current config.
	var counts []ChallengeCounts
	_, err := stats.DB.Select(&counts,
		`SELECT
          c.type AS Type,
          COUNT(1) AS Completions
      FROM
          authz AS a
            JOIN
          challenges AS c ON a.id = c.authorizationID
      WHERE
          c.status = 'valid' AND a.expires > :now
      GROUP BY c.type;`,
		map[string]interface{}{"now": stats.clk.Now()})

	return counts, err
}

func (stats *DBStatsEngine) Calculate() error {
	enc := json.NewEncoder(stats.Writer)

	var err error
	data := &EncodedStats{}

	data.RegistrationsPerDayByType, err = stats.registrationsPerDayByType()
	if err != nil {
		return fmt.Errorf("RegistrationsPerDayByType: %s", err)
	}
	data.CertsPerDayByStatus, err = stats.certificatesIssuedPerDayByStatus()
	if err != nil {
		return fmt.Errorf("CertsPerDayByStatus: %s", err)
	}
	data.ChallengeCounts, err = stats.challengeCounts()
	if err != nil {
		return fmt.Errorf("ChallengeCounts: %s", err)
	}

	return enc.Encode(data)
}
