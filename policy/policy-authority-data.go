// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package policy

import (
	"database/sql"
	"fmt"
	"strings"

	blog "github.com/letsencrypt/boulder/log"

	gorp "github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"
)

const whitelisted = "whitelist"
const blacklisted = "blacklist"

// DomainRule ...
type DomainRule struct {
	Host string `db:"host"`
	Type string `db:"type"`
}

func reverseName(domain string) string {
	labels := strings.Split(domain, ".")
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return strings.Join(labels, ".")
}

// PolicyAuthorityDatabaseImpl enforces policy decisions based on various rule
// lists
type PolicyAuthorityDatabaseImpl struct {
	log   *blog.AuditLogger
	dbMap *gorp.DbMap
}

// NewPolicyAuthorityDatabaseImpl constructs a Policy Authority Database (and
// creates tables if they are non-existent)
func NewPolicyAuthorityDatabaseImpl(dbMap *gorp.DbMap) (padb *PolicyAuthorityDatabaseImpl, err error) {
	logger := blog.GetAuditLogger()

	dbMap.AddTableWithName(DomainRule{}, "ruleList").SetKeys(false, "Host")

	padb = &PolicyAuthorityDatabaseImpl{
		dbMap: dbMap,
		log:   logger,
	}

	return padb, nil
}

// LoadRules loads the whitelist and blacklist into the database in a transaction
// deleting any previous content
func (padb *PolicyAuthorityDatabaseImpl) LoadRules(rules []DomainRule) error {
	tx, err := padb.dbMap.Begin()
	if err != nil {
		tx.Rollback()
		return err
	}
	_, err = tx.Exec("DELETE FROM ruleList")
	if err != nil {
		tx.Rollback()
		return err
	}

	for _, r := range rules {
		r.Host = reverseName(r.Host)
		tx.Insert(&r)
	}

	err = tx.Commit()
	return err
}

// DumpRules retrieves all DomainRules in the database so they can be written to
// disk
func (padb *PolicyAuthorityDatabaseImpl) DumpRules() ([]DomainRule, error) {
	var dR []DomainRule
	_, err := padb.dbMap.Select(&dR, "SELECT * FROM ruleList")
	for _, r := range dR {
		r.Host = reverseName(r.Host)
	}

	return dR, err
}

func (padb *PolicyAuthorityDatabaseImpl) checkBlacklist(host string) error {
	var rule DomainRule
	// Use lexical odering to quickly find blacklisted root domains
	err := padb.dbMap.SelectOne(
		&rule,
		`SELECT * FROM ruleList WHERE :host >= host AND type = 'blacklist' ORDER BY host DESC LIMIT 1`,
		map[string]interface{}{"host": host},
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return err
	}

	if host == rule.Host || strings.HasPrefix(host, rule.Host+".") {
		return BlacklistedError{}
	}
	return nil
}

func (padb *PolicyAuthorityDatabaseImpl) checkWhitelist(host string) error {
	var rule DomainRule
	// Because of how rules are sorted if there is a relevant whitelist AND blacklist
	// rule we will catch them both, this query will return a maximum of two rules
	err := padb.dbMap.SelectOne(
		&rule,
		`SELECT * FROM ruleList WHERE :host = host AND type = 'whitelist' LIMIT 1`,
		map[string]interface{}{"host": host},
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("Domain name is not whitelisted for issuance")
		}
		return err
	}

	return nil
}

// CheckRules will query the database for white/blacklist rules that match host,
// if both whitelist and blacklist rules are found the blacklist will always win
func (padb *PolicyAuthorityDatabaseImpl) CheckRules(host string, requireWhitelisted bool) error {
	host = reverseName(host)
	if requireWhitelisted {
		err := padb.checkWhitelist(host)
		if err != nil {
			return err
		}
	}

	// This overrides the whitelist if a blacklist rule is found
	return padb.checkBlacklist(host)
}
