// Copyright 2016 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package statistics

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/square/go-jose"
	"golang.org/x/net/context"
	gorp "gopkg.in/gorp.v1"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
)

var log = blog.UseMock()
var ctx = context.Background()
var certCounter int64

type TestLogger struct {
	*testing.T
}

func (testLog *TestLogger) Printf(format string, args ...interface{}) {
	testLog.Logf(format, args)
}

// initSA constructs a r/w SQLStorageAuthority and a clean up function
// that should be defer'ed to the end of the test.
func initSA(t *testing.T) (*gorp.DbMap, *sa.SQLStorageAuthority, clock.FakeClock, func()) {
	dbMap, err := sa.NewDbMap(vars.DBConnSA, 0)
	test.AssertNotError(t, err, "Should not error")

	fc := clock.NewFake()
	fc.Set(time.Date(2015, 3, 4, 5, 0, 0, 0, time.UTC))

	sa, err := sa.NewSQLStorageAuthority(dbMap, fc, log)
	test.AssertNotError(t, err, "Should not error")

	if testing.Verbose() && !testing.Short() {
		dbMap.TraceOn("r/w", &TestLogger{t})
	}

	cleanUp := test.ResetSATestDatabase(t)
	return dbMap, sa, fc, cleanUp
}

func parseConfigDuration(durationString string) cmd.ConfigDuration {
	duration, _ := time.ParseDuration(durationString)
	return cmd.ConfigDuration{Duration: duration}
}

func updateOCSP(t *testing.T, rwMap *gorp.DbMap, serial string, updateDate time.Time) {
	_, err := rwMap.Exec(
		`UPDATE certificateStatus
     SET ocspResponse=?,ocspLastUpdated=?
     WHERE serial=?`,
		[]byte{},
		updateDate,
		serial,
	)
	test.AssertNotError(t, err, "Should not error")
}

func addCertificate(t *testing.T, rwMap *gorp.DbMap, saObj *sa.SQLStorageAuthority, ctx context.Context, regID int64, issueDate time.Time) *big.Int {
	testKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "Should not error")

	expiry := issueDate.AddDate(0, 0, 7)
	serial := big.NewInt(certCounter)
	certCounter += 1
	rawCert := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		NotBefore:    issueDate,
		NotAfter:     expiry,
		DNSNames:     []string{"example-a.com"},
		SerialNumber: serial,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &rawCert, &rawCert, &testKey.PublicKey, testKey)
	test.AssertNotError(t, err, "Should not error")

	_, err = saObj.AddCertificate(ctx, certDER, regID)
	test.AssertNotError(t, err, "Should not error")

	updateOCSP(t, rwMap, core.SerialToString(serial), issueDate)
	return serial
}

func addRegistration(t *testing.T, sa core.StorageAdder, date time.Time) core.Registration {
	contact, err := core.ParseAcmeURL("mailto:foo@example.com")
	test.AssertNotError(t, err, "unable to parse contact link")

	contacts := []*core.AcmeURL{contact}
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	test.AssertNotError(t, err, "unable to generate key")

	reg, err := sa.NewRegistration(context.Background(), core.Registration{
		Key:       jose.JsonWebKey{Key: privKey.Public()},
		Contact:   contacts,
		InitialIP: net.ParseIP("88.77.66.11"),
		CreatedAt: date,
	})
	test.AssertNotError(t, err, "Should not error")
	return reg
}

func TestNil(t *testing.T) {
	stats := mocks.NewStatter()
	duration := parseConfigDuration("5h")
	log := blog.UseMock()
	fc := clock.NewFake()

	var outBuf bytes.Buffer

	_, err := NewDBStatsEngine(nil, stats, fc, duration, &outBuf, log)
	test.AssertError(t, err, "Engine construction should have errored")
}

func TestCalculateEmptyDB(t *testing.T) {
	stats := mocks.NewStatter()
	duration := parseConfigDuration("5h")
	log := blog.UseMock()
	fc := clock.NewFake()

	var outBuf bytes.Buffer

	dbMap, err := sa.NewDbMap(vars.DBConnSAStats, 0)
	test.AssertNotError(t, err, "Should not error")

	engine, err := NewDBStatsEngine(dbMap, stats, fc, duration, &outBuf, log)
	test.AssertNotError(t, err, "Engine construction should have been OK")

	err = engine.Calculate()
	test.AssertNotError(t, err, "Should not error")

	// Decode the JSON and ensure it's valid
	test.Assert(t, outBuf.Len() > 0, "Should have output")
	jdec := json.NewDecoder(&outBuf)

	var resultObj EncodedStats
	err = jdec.Decode(&resultObj)

	test.Assert(t, len(resultObj.CertsPerDayByStatus) == 0, "CertsPerDayByStatus should be empty")
	test.Assert(t, len(resultObj.ChallengeCounts) == 0, "ChallengeCounts should be empty")
	test.Assert(t, len(resultObj.OCSPUpdatesByDayAndHour) == 0, "OCSPUpdatesByDayAndHour should be empty")
	test.Assert(t, len(resultObj.RegistrationsPerDayByType) == 0, "RegistrationsPerDayByType should be empty")
}

func TestCalculateCertsPerDayByStatus(t *testing.T) {
	stats := mocks.NewStatter()
	log := blog.UseMock()
	duration := parseConfigDuration("999h")
	var outBuf bytes.Buffer

	// Prepare DB
	rwMap, saObj, fc, cleanUp := initSA(t)
	defer cleanUp()

	reg := addRegistration(t, saObj, fc.Now())

	// Add one certificate
	firstSerial := addCertificate(t, rwMap, saObj, ctx, reg.ID, fc.Now())

	dbMap, err := sa.NewDbMap(vars.DBConnSAStats, 0)
	test.AssertNotError(t, err, "Should not error")

	if testing.Verbose() && !testing.Short() {
		dbMap.TraceOn("r/o", &TestLogger{t})
	}

	engine, err := NewDBStatsEngine(dbMap, stats, fc, duration, &outBuf, log)
	test.AssertNotError(t, err, "Engine construction should have been OK")

	err = engine.Calculate()
	test.AssertNotError(t, err, "Should not error")

	// Decode the JSON and ensure it's valid
	test.Assert(t, outBuf.Len() > 0, "Should have output")
	jdec := json.NewDecoder(&outBuf)

	var resultObj EncodedStats
	err = jdec.Decode(&resultObj)
	test.AssertNotError(t, err, "Should not error")

	test.Assert(t, len(resultObj.CertsPerDayByStatus) > 0, "CertsPerDayByStatus shouldn't be empty")
	test.Assert(t, resultObj.CertsPerDayByStatus[0].IssuedDate.Sub(fc.Now()).Hours() < 24, "Date should be within 24 hours of reference date")
	test.AssertEquals(t, resultObj.CertsPerDayByStatus[0].StillValid, int64(1))
	test.AssertEquals(t, resultObj.CertsPerDayByStatus[0].Revoked, int64(0))

	// Add more certificates to the same day
	for i := 0; i < 32; i++ {
		dur, _ := time.ParseDuration("1m")
		fc.Add(dur)
		_ = addCertificate(t, rwMap, saObj, ctx, reg.ID, fc.Now())
	}

	err = engine.Calculate()
	test.AssertNotError(t, err, "Should not error")
	test.Assert(t, outBuf.Len() > 0, "Should have output")
	jdec = json.NewDecoder(&outBuf)

	err = jdec.Decode(&resultObj)
	test.AssertNotError(t, err, "Should not error")

	test.Assert(t, len(resultObj.CertsPerDayByStatus) > 0, "CertsPerDayByStatus shouldn't be empty")
	test.Assert(t, resultObj.CertsPerDayByStatus[0].IssuedDate.Sub(fc.Now()).Hours() < 24, "Date should be within 24 hours of reference date")
	test.AssertEquals(t, resultObj.CertsPerDayByStatus[0].StillValid, int64(33))
	test.AssertEquals(t, resultObj.CertsPerDayByStatus[0].Revoked, int64(0))

	// Add more certificates, one per day
	for i := 0; i < 6; i++ {
		dur, _ := time.ParseDuration("24h")
		fc.Add(dur)
		_ = addCertificate(t, rwMap, saObj, ctx, reg.ID, fc.Now())
	}

	err = engine.Calculate()
	test.AssertNotError(t, err, "Should not error")
	test.Assert(t, outBuf.Len() > 0, "Should have output")
	jdec = json.NewDecoder(&outBuf)

	err = jdec.Decode(&resultObj)
	test.AssertNotError(t, err, "Should not error")

	t.Logf("%+v \n", resultObj)

	test.Assert(t, len(resultObj.CertsPerDayByStatus) > 0, "CertsPerDayByStatus shouldn't be empty")
	test.Assert(t, resultObj.CertsPerDayByStatus[0].IssuedDate.Sub(fc.Now()).Hours() < 24, "Date should be within 24 hours of reference date")
	test.AssertEquals(t, resultObj.CertsPerDayByStatus[0].StillValid, int64(33))
	test.AssertEquals(t, resultObj.CertsPerDayByStatus[0].Revoked, int64(0))
	for i := 1; i < 6; i++ {
		test.AssertEquals(t, resultObj.CertsPerDayByStatus[i].StillValid, int64(1))
		test.AssertEquals(t, resultObj.CertsPerDayByStatus[i].Revoked, int64(0))
	}

	// Revoke a certificate
	err = saObj.MarkCertificateRevoked(ctx, core.SerialToString(firstSerial), core.RevocationCode(1))
	test.AssertNotError(t, err, "Should not error on revocation")

	err = engine.Calculate()
	test.AssertNotError(t, err, "Should not error")
	test.Assert(t, outBuf.Len() > 0, "Should have output")
	jdec = json.NewDecoder(&outBuf)

	err = jdec.Decode(&resultObj)
	test.AssertNotError(t, err, "Should not error")
	test.AssertEquals(t, resultObj.CertsPerDayByStatus[0].StillValid, int64(32))
	test.AssertEquals(t, resultObj.CertsPerDayByStatus[0].Revoked, int64(1))

	// Move forward one more day, so that the first certs expire
	dur, _ := time.ParseDuration("24h")
	fc.Add(dur)

	// Now there should be just one cert on the first day
	err = engine.Calculate()
	test.AssertNotError(t, err, "Should not error")
	test.Assert(t, outBuf.Len() > 0, "Should have output")
	jdec = json.NewDecoder(&outBuf)

	err = jdec.Decode(&resultObj)
	test.AssertNotError(t, err, "Should not error")
	test.AssertEquals(t, resultObj.CertsPerDayByStatus[0].StillValid, int64(1))
	test.AssertEquals(t, resultObj.CertsPerDayByStatus[0].Revoked, int64(0))
}

func TestRegistrationsPerDayByType(t *testing.T) {
	stats := mocks.NewStatter()
	log := blog.UseMock()
	duration := parseConfigDuration("999h")
	var outBuf bytes.Buffer

	// Prepare DB
	_, saObj, fc, cleanUp := initSA(t)
	defer cleanUp()

	dbMap, err := sa.NewDbMap(vars.DBConnSAStats, 0)
	test.AssertNotError(t, err, "Should not error")

	if testing.Verbose() && !testing.Short() {
		dbMap.TraceOn("r/o", &TestLogger{t})
	}

	engine, err := NewDBStatsEngine(dbMap, stats, fc, duration, &outBuf, log)
	test.AssertNotError(t, err, "Engine construction should have been OK")
	_ = addRegistration(t, saObj, fc.Now())

	err = engine.Calculate()
	test.AssertNotError(t, err, "Should not error")
	test.Assert(t, outBuf.Len() > 0, "Should have output")
	jdec := json.NewDecoder(&outBuf)

	var resultObj EncodedStats
	err = jdec.Decode(&resultObj)
	test.AssertNotError(t, err, "Should not error")

	test.Assert(t, resultObj.RegistrationsPerDayByType[0].CreateDate.Sub(fc.Now()).Hours() < 24, "Date should be within 24 hours of reference date")
	test.AssertEquals(t, resultObj.RegistrationsPerDayByType[0].WithContact, int64(1))

	// Add more registations, one per day
	for i := 0; i < 14; i++ {
		dur, _ := time.ParseDuration("24h")
		fc.Add(dur)
		_ = addRegistration(t, saObj, fc.Now())
	}

	err = engine.Calculate()
	test.AssertNotError(t, err, "Should not error")
	test.Assert(t, outBuf.Len() > 0, "Should have output")
	jdec = json.NewDecoder(&outBuf)

	err = jdec.Decode(&resultObj)
	test.AssertNotError(t, err, "Should not error")
	t.Logf("%+v \n", resultObj)
	for i := 0; i < 15; i++ {
		test.AssertEquals(t, resultObj.RegistrationsPerDayByType[i].WithContact, int64(1))
		test.AssertEquals(t, resultObj.RegistrationsPerDayByType[i].Anonymous, int64(0))
	}
}

func TestOCSPUpdates(t *testing.T) {
	stats := mocks.NewStatter()
	log := blog.UseMock()
	duration := parseConfigDuration("0h") // Unused
	var outBuf bytes.Buffer

	// Prepare DB
	rwMap, saObj, fc, cleanUp := initSA(t)
	defer cleanUp()

	dbMap, err := sa.NewDbMap(vars.DBConnSAStats, 0)
	test.AssertNotError(t, err, "Should not error")

	if testing.Verbose() && !testing.Short() {
		dbMap.TraceOn("r/o", &TestLogger{t})
	}

	engine, err := NewDBStatsEngine(dbMap, stats, fc, duration, &outBuf, log)
	test.AssertNotError(t, err, "Engine construction should have been OK")

	reg := addRegistration(t, saObj, fc.Now())

	// Certificates
	for i := 0; i < 24; i++ {
		dur, _ := time.ParseDuration("1h")
		fc.Add(dur)
		_ = addCertificate(t, rwMap, saObj, ctx, reg.ID, fc.Now())
	}

	err = engine.Calculate()
	test.AssertNotError(t, err, "Should not error")
	test.Assert(t, outBuf.Len() > 0, "Should have output")
	jdec := json.NewDecoder(&outBuf)

	var resultObj EncodedStats
	err = jdec.Decode(&resultObj)
	test.AssertNotError(t, err, "Should not error")

	for i := 0; i < 24; i++ {
		test.AssertEquals(t, resultObj.OCSPUpdatesByDayAndHour[i].NumResponses, int64(1))
		// StartHour=5, and we pre-increment the clock (+1). Mod 24 to constrain to hour of day.
		test.AssertEquals(t, resultObj.OCSPUpdatesByDayAndHour[i].Hour, int64((i+5+1)%24))
	}

	// Add another certificate to now
	_ = addCertificate(t, rwMap, saObj, ctx, reg.ID, fc.Now())

	err = engine.Calculate()
	test.AssertNotError(t, err, "Should not error")
	test.Assert(t, outBuf.Len() > 0, "Should have output")
	jdec = json.NewDecoder(&outBuf)

	err = jdec.Decode(&resultObj)
	test.AssertNotError(t, err, "Should not error")

	test.AssertEquals(t, resultObj.OCSPUpdatesByDayAndHour[23].NumResponses, int64(2))

	// Now also evaluate the OCSPAging
	test.AssertEquals(t, resultObj.OCSPAging.Age12h, int64(13))
	test.AssertEquals(t, resultObj.OCSPAging.Age24h, int64(12))

	// Move forward 96 hours
	dur, _ := time.ParseDuration("96h")
	fc.Add(dur)

	err = engine.Calculate()
	test.AssertNotError(t, err, "Should not error")
	test.Assert(t, outBuf.Len() > 0, "Should have output")
	jdec = json.NewDecoder(&outBuf)

	err = jdec.Decode(&resultObj)
	test.AssertNotError(t, err, "Should not error")

	test.AssertEquals(t, resultObj.OCSPAging.Age96h, int64(3))
	test.AssertEquals(t, resultObj.OCSPAging.Older, int64(22))
}

func TestChallengeCounts(t *testing.T) {
	stats := mocks.NewStatter()
	log := blog.UseMock()
	duration := parseConfigDuration("0h") // Unused
	var outBuf bytes.Buffer

	// Prepare DB
	_, saObj, fc, cleanUp := initSA(t)
	defer cleanUp()

	dbMap, err := sa.NewDbMap(vars.DBConnSAStats, 0)
	test.AssertNotError(t, err, "Should not error")

	if testing.Verbose() && !testing.Short() {
		dbMap.TraceOn("r/o", &TestLogger{t})
	}

	engine, err := NewDBStatsEngine(dbMap, stats, fc, duration, &outBuf, log)
	test.AssertNotError(t, err, "Engine construction should have been OK")

	reg := addRegistration(t, saObj, fc.Now())

	futureExpiryTime := fc.Now().AddDate(0, 0, 7)

	for i := 0; i < 10; i++ {
		authz, err := saObj.NewPendingAuthorization(ctx, core.Authorization{
			RegistrationID: reg.ID,
			Challenges:     []core.Challenge{core.HTTPChallenge01(&reg.Key)},
			Expires:        &futureExpiryTime,
		})
		test.AssertNotError(t, err, "Should not error")

		// Mark some challenges as done
		authz.Challenges[0].Status = core.StatusValid

		err = saObj.FinalizeAuthorization(ctx, authz)
		test.AssertNotError(t, err, "Should not error")
	}

	var resultObj EncodedStats
	err = engine.Calculate()
	test.AssertNotError(t, err, "Should not error")
	test.Assert(t, outBuf.Len() > 0, "Should have output")
	jdec := json.NewDecoder(&outBuf)

	err = jdec.Decode(&resultObj)
	test.AssertNotError(t, err, "Should not error")

	test.AssertEquals(t, resultObj.ChallengeCounts[0].Type, "http-01")
	test.AssertEquals(t, resultObj.ChallengeCounts[0].Completions, int64(10))

	// Add more valid challenges
	for i := 0; i < 10; i++ {
		authz, err := saObj.NewPendingAuthorization(ctx, core.Authorization{
			RegistrationID: reg.ID,
			Challenges:     []core.Challenge{core.DNSChallenge01(&reg.Key), core.TLSSNIChallenge01(&reg.Key)},
			Expires:        &futureExpiryTime,
		})
		test.AssertNotError(t, err, "Should not error")

		// Mark both challenges as done
		authz.Challenges[0].Status = core.StatusValid
		authz.Challenges[1].Status = core.StatusValid

		err = saObj.FinalizeAuthorization(ctx, authz)
		test.AssertNotError(t, err, "Should not error")
	}

	err = engine.Calculate()
	test.AssertNotError(t, err, "Should not error")
	test.Assert(t, outBuf.Len() > 0, "Should have output")
	jdec = json.NewDecoder(&outBuf)
	err = jdec.Decode(&resultObj)
	test.AssertNotError(t, err, "Should not error")

	t.Logf("%+v", resultObj.ChallengeCounts)
	test.AssertEquals(t, resultObj.ChallengeCounts[0].Type, "dns-01")
	test.AssertEquals(t, resultObj.ChallengeCounts[0].Completions, int64(10))
	test.AssertEquals(t, resultObj.ChallengeCounts[1].Type, "http-01")
	test.AssertEquals(t, resultObj.ChallengeCounts[1].Completions, int64(10))
	test.AssertEquals(t, resultObj.ChallengeCounts[2].Type, "tls-sni-01")
	test.AssertEquals(t, resultObj.ChallengeCounts[2].Completions, int64(10))

	// Add invalid challenges
	for i := 0; i < 10; i++ {
		authz, err := saObj.NewPendingAuthorization(ctx, core.Authorization{
			RegistrationID: reg.ID,
			Challenges:     []core.Challenge{core.DNSChallenge01(&reg.Key), core.TLSSNIChallenge01(&reg.Key)},
			Expires:        &futureExpiryTime,
		})
		test.AssertNotError(t, err, "Should not error")

		// Mark both challenges as done
		authz.Challenges[0].Status = core.StatusInvalid
		authz.Challenges[1].Status = core.StatusPending

		err = saObj.FinalizeAuthorization(ctx, authz)
		test.AssertNotError(t, err, "Should not error")
	}

	err = engine.Calculate()
	test.AssertNotError(t, err, "Should not error")
	test.Assert(t, outBuf.Len() > 0, "Should have output")
	jdec = json.NewDecoder(&outBuf)
	err = jdec.Decode(&resultObj)
	test.AssertNotError(t, err, "Should not error")

	t.Logf("%+v", resultObj.ChallengeCounts)
	test.AssertEquals(t, resultObj.ChallengeCounts[0].Type, "dns-01")
	test.AssertEquals(t, resultObj.ChallengeCounts[0].Completions, int64(10))
	test.AssertEquals(t, resultObj.ChallengeCounts[1].Type, "http-01")
	test.AssertEquals(t, resultObj.ChallengeCounts[1].Completions, int64(10))
	test.AssertEquals(t, resultObj.ChallengeCounts[2].Type, "tls-sni-01")
	test.AssertEquals(t, resultObj.ChallengeCounts[2].Completions, int64(10))
}
