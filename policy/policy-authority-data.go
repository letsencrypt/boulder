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

type domainRule struct {
	Host string `db:"host"`
}

type BlacklistRule domainRule
type WhitelistRule domainRule

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

	dbMap.AddTableWithName(BlacklistRule{}, "blacklist").SetKeys(false, "Host")
	dbMap.AddTableWithName(WhitelistRule{}, "whitelist").SetKeys(false, "Host")

	padb = &PolicyAuthorityDatabaseImpl{
		dbMap: dbMap,
		log:   logger,
	}

	return padb, nil
}

// LoadRules loads the whitelist and blacklist into the database in a transaction
// deleting any previous content
func (padb *PolicyAuthorityDatabaseImpl) LoadRules(bRules []BlacklistRule, wRules []WhitelistRule) error {
	tx, err := padb.dbMap.Begin()
	if err != nil {
		tx.Rollback()
		return err
	}
	_, err = tx.Exec("DELETE FROM blacklist")
	if err != nil {
		tx.Rollback()
		return err
	}
	for _, r := range bRules {
		r.Host = reverseName(r.Host)
		tx.Insert(&r)
	}
	_, err = tx.Exec("DELETE FROM whitelist")
	if err != nil {
		tx.Rollback()
		return err
	}
	for _, r := range wRules {
		tx.Insert(&r)
	}

	err = tx.Commit()
	return err
}

// DumpRules retrieves all domainRules in the database so they can be written to
// disk
func (padb *PolicyAuthorityDatabaseImpl) DumpRules() ([]domainRule, error) {
	var dR []domainRule
	_, err := padb.dbMap.Select(&dR, "SELECT * FROM ruleList")
	for _, r := range dR {
		r.Host = reverseName(r.Host)
	}

	return dR, err
}

func (padb *PolicyAuthorityDatabaseImpl) allowedByBlacklist(host string) bool {
	var rule BlacklistRule
	// Use lexical ordering to quickly find blacklisted root domains
	err := padb.dbMap.SelectOne(
		&rule,
		`SELECT * FROM blacklist WHERE :host >= host ORDER BY host DESC LIMIT 1`,
		map[string]interface{}{"host": host},
	)
	fmt.Println(host, rule, err)
	if err != nil {
		if err == sql.ErrNoRows {
			return true
		}
		return false
	}
	if host == rule.Host || strings.HasPrefix(host, rule.Host+".") {
		return false
	}
	return true
}

func (padb *PolicyAuthorityDatabaseImpl) allowedByWhitelist(host string) bool {
	var rule WhitelistRule
	err := padb.dbMap.SelectOne(
		&rule,
		`SELECT * FROM whitelist WHERE :host = host LIMIT 1`,
		map[string]interface{}{"host": host},
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return false
		}
		return false
	}
	return true
}

// CheckHostLists will query the database for white/blacklist rules that match host,
// if both whitelist and blacklist rules are found the blacklist will always win
func (padb *PolicyAuthorityDatabaseImpl) CheckHostLists(host string, requireWhitelisted bool) error {
	if requireWhitelisted {
		if !padb.allowedByWhitelist(host) {
			// return fmt.Errorf("Domain is not whitelisted for issuance")
			return WhitelistedError{}
		}
	}
	// Overrides the whitelist if a blacklist rule is found
	host = reverseName(host)
	if !padb.allowedByBlacklist(host) {
		// return fmt.Errorf("Domain is blacklisted for issuance")
		return BlacklistedError{}
	}
	return nil
}
