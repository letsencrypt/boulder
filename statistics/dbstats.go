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
	OCSPAging                 OCSPAging
	OCSPUpdatesByDayAndHour   []OCSPUpdatesByDayAndHour
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

type OCSPUpdatesByDayAndHour struct {
	Day          time.Time
	Hour         int64
	NumResponses int64
}

type OCSPAging struct {
	Age12h int64
	Age24h int64
	Age36h int64
	Age48h int64
	Age60h int64
	Age72h int64
	Age84h int64
	Age96h int64
	Older  int64
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

func (stats *DBStatsEngine) ocspUpdatesByDayAndHour() ([]OCSPUpdatesByDayAndHour, error) {
	var counts []OCSPUpdatesByDayAndHour
	_, err := stats.DB.Select(&counts,
		`SELECT
          DATE(ocspLastUpdated) as Day,
          HOUR(ocspLastUpdated) as Hour,
          COUNT(1) as NumResponses
      FROM
          certificateStatus AS cs
            NATURAL JOIN
          certificates AS c
      WHERE
          c.expires > :now
      GROUP BY DATE(ocspLastUpdated) , HOUR(ocspLastUpdated);`,
		map[string]interface{}{"now": stats.clk.Now()})

	return counts, err
}

func (stats *DBStatsEngine) ocspAging() (OCSPAging, error) {
	var counts OCSPAging
	err := stats.DB.SelectOne(&counts,
		`SELECT
          IFNULL(SUM(IF(cs.ocspLastUpdated > :now - INTERVAL 12 HOUR,1,0)),0) AS age12h,
          IFNULL(SUM(IF(cs.ocspLastUpdated BETWEEN :now - INTERVAL 24 HOUR AND :now - INTERVAL 12 HOUR,1,0)),0) AS age24h,
          IFNULL(SUM(IF(cs.ocspLastUpdated BETWEEN :now - INTERVAL 36 HOUR AND :now - INTERVAL 24 HOUR,1,0)),0) AS age36h,
          IFNULL(SUM(IF(cs.ocspLastUpdated BETWEEN :now - INTERVAL 48 HOUR AND :now - INTERVAL 36 HOUR,1,0)),0) AS age48h,
          IFNULL(SUM(IF(cs.ocspLastUpdated BETWEEN :now - INTERVAL 60 HOUR AND :now - INTERVAL 48 HOUR,1,0)),0) AS age60h,
          IFNULL(SUM(IF(cs.ocspLastUpdated BETWEEN :now - INTERVAL 72 HOUR AND :now - INTERVAL 60 HOUR,1,0)),0) AS age72h,
          IFNULL(SUM(IF(cs.ocspLastUpdated BETWEEN :now - INTERVAL 84 HOUR AND :now - INTERVAL 72 HOUR,1,0)),0) AS age84h,
          IFNULL(SUM(IF(cs.ocspLastUpdated BETWEEN :now - INTERVAL 97 HOUR AND :now - INTERVAL 84 HOUR,1,0)),0) AS age96h,
          IFNULL(SUM(IF(cs.ocspLastUpdated < :now - INTERVAL 97 HOUR,1,0)),0) AS older
      FROM
          certificateStatus as cs
            NATURAL JOIN
          certificates AS c
      WHERE
          c.expires > :now;`,
		map[string]interface{}{"now": stats.clk.Now()})

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

func (stats *DBStatsEngine) runAndAppend(keyName string, dataMap map[string]interface{}, op func() (interface{}, error)) {
	data, err := op()
	if err != nil {
		stats.Logger.Err(fmt.Sprintf("Failed to execute %s: %s", keyName, err))
		return
	}
	dataMap[keyName] = data
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
	data.OCSPUpdatesByDayAndHour, err = stats.ocspUpdatesByDayAndHour()
	if err != nil {
		return fmt.Errorf("OCSPUpdatesByDayAndHour: %s", err)
	}
	data.OCSPAging, err = stats.ocspAging()
	if err != nil {
		return fmt.Errorf("OCSPAging: %s", err)
	}
	data.ChallengeCounts, err = stats.challengeCounts()
	if err != nil {
		return fmt.Errorf("ChallengeCounts: %s", err)
	}

	return enc.Encode(data)
}
