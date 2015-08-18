// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package policy

import (
	"fmt"
	"strings"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/sa"

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
func NewPolicyAuthorityDatabaseImpl(name string) (padb *PolicyAuthorityDatabaseImpl, err error) {
	logger := blog.GetAuditLogger()
	dbMap, err := sa.NewDbMap(name)
	if err != nil {
		return nil, err
	}

	dbMap.AddTableWithName(DomainRule{}, "ruleList").SetKeys(false, "Host")

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

// CheckRules will query the database for white/blacklist rules that match host,
// if both whitelist and blacklist rules are found the whitelist will always win
func (padb *PolicyAuthorityDatabaseImpl) CheckRules(host string, requireWhitelisted bool) error {
	host = reverseName(host)
	var rules []DomainRule
	_, err := padb.dbMap.Select(
		&rules,
		`SELECT * FROM ruleList WHERE :host >= host ORDER BY host ASC`,
		map[string]interface{}{"host": host},
	)
	if err != nil {
		return err
	}

	var wRules []string
	var bRules []string
	for _, r := range rules {
		switch r.Type {
		case blacklisted:
			if strings.HasPrefix(host, r.Host+".") || host == r.Host {
				bRules = append(bRules, r.Host)
			}
		case whitelisted:
			if host == r.Host {
				wRules = append(wRules, r.Host)
			}
		}
	}

	if requireWhitelisted && len(wRules) == 0 {
		return fmt.Errorf("Domain name is not whitelisted for issuance")
	} else if len(wRules)+len(bRules) > 0 {
		padb.log.Info(fmt.Sprintf("Hostname [%s] matches rules, Whitelist: %s, Blacklist: %s", host, wRules, bRules))
		if len(wRules) > 0 {
			return nil
		}
		return BlacklistedError{}
	}

	return nil
}
