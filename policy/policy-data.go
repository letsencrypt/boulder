// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package policy

import (
	"fmt"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/sa"

	gorp "github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"
)

const whitelisted = "whitelist"
const blacklisted = "blacklist"

type domainRule struct {
	ID   int    `db:"id"`
	Rule string `db:"rule"`
	Type string `db:"type"`
}

// PolicyAuthorityDatabaseImpl enforces policy decisions based on various rule
// lists
type PolicyAuthorityDatabaseImpl struct {
	log   *blog.AuditLogger
	dbMap *gorp.DbMap
}

// NewPolicyAuthorityDatabaseImpl constructs a Policy Authority Database (and
// creates tables if they are non-existent)
func NewPolicyAuthorityDatabaseImpl(driver, name string) (padb core.PolicyAuthorityDatabase, err error) {
	logger := blog.GetAuditLogger()
	dbMap, err := sa.NewDbMap(driver, name)
	if err != nil {
		return nil, err
	}

	dbMap.AddTableWithName(domainRule{}, "ruleList").SetKeys(true, "ID").ColMap("Rule").SetUnique(true)

	err = dbMap.CreateTablesIfNotExists()
	if err != nil {
		return
	}

	padb = &PolicyAuthorityDatabaseImpl{
		dbMap: dbMap,
		log:   logger,
	}

	return padb, nil
}

// AddRule will add a whitelist or blacklist rule to the database
func (padb *PolicyAuthorityDatabaseImpl) AddRule(rule string, string string) error {
	tx, err := padb.dbMap.Begin()
	if err != nil {
		tx.Rollback()
		return err
	}
	r := domainRule{
		Rule: rule,
	}
	switch string {
	case blacklisted:
		r.Type = "blacklist"
	case whitelisted:
		r.Type = "whitelist"
	default:
		return fmt.Errorf("Unsupported rule type: %s", string)
	}
	err = tx.Insert(&r)
	if err != nil {
		tx.Rollback()
		return err
	}

	err = tx.Commit()
	return err
}

// CheckRules will query the database for white/blacklist rules that match host,
// if both whitelist and blacklist rules are found the whitelist will always win
func (padb *PolicyAuthorityDatabaseImpl) CheckRules(host string) error {
	var rules []domainRule
	_, err := padb.dbMap.Select(
		&rules,
		`SELECT type,rule FROM ruleList WHERE :host LIKE rule`,
		map[string]interface{}{"host": host},
	)
	if err != nil {
		return err
	}

	var wRules []string
	var bRules []string
	for _, rule := range rules {
		switch rule.Type {
		case blacklisted:
			bRules = append(bRules, rule.Rule)
		case whitelisted:
			wRules = append(wRules, rule.Rule)
		}
	}

	if len(wRules)+len(bRules) > 0 {
		padb.log.Info(fmt.Sprintf("Hostname [%s] matches rules, Whitelist: %s, Blacklist: %s", host, wRules, bRules))
		if len(wRules) > 0 {
			return nil
		}
		return BlacklistedError{}
	}

	return nil
}

// func (padb *PolicyAuthorityDatabaseImpl) IsBlacklisted(host string) (bool, error) {
// 	// Wrap in transaction so the blacklist doesn't change under us
// 	tx, err := padb.dbMap.Begin()
// 	if err != nil {
// 		tx.Rollback()
// 		return false, err
// 	}
//
// 	var count int
// 	_, err = tx.Select(
// 		&count,
// 		`SELECT COUNT(*) FROM ruleList WHERE :host LIKE rule AND type = 'blacklist'`,
// 		map[string]interface{}{"host": host},
// 	)
// 	if err != nil {
// 		return false, err
// 	}
//
// 	err = tx.Commit()
// 	return count > 0, err
// }
//
// func (padb *PolicyAuthorityDatabaseImpl) IsWhitelisted(host string) (bool, error) {
// 	// Wrap in transaction so the whitelist doesn't change under us
// 	tx, err := padb.dbMap.Begin()
// 	if err != nil {
// 		tx.Rollback()
// 		return false, err
// 	}
//
// 	var count int
// 	_, err = tx.Select(
// 		&count,
// 		`SELECT COUNT(*) FROM ruleList WHERE :host LIKE rule AND type = 'whitelist'`,
// 		map[string]interface{}{"host": host},
// 	)
// 	if err != nil {
// 		return false, err
// 	}
//
// 	err = tx.Commit()
// 	return count > 0, err
// }
