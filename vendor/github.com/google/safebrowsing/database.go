// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package safebrowsing

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/gob"
	"errors"
	"log"
	"math/rand"
	"os"
	"sync"
	"time"

	pb "github.com/google/safebrowsing/internal/safebrowsing_proto"
)

// jitter is the maximum amount of time that we expect an API list update to
// actually take. We add this time to the update period time to give some
// leeway before declaring the database as stale.
const (
	maxRetryDelay  = 24 * time.Hour
	baseRetryDelay = 15 * time.Minute
	jitter         = 30 * time.Second
)

// database tracks the state of the threat lists published by the Safe Browsing
// API. Since the global blacklist is constantly changing, the contents of the
// database needs to be periodically synced with the Safe Browsing servers in
// order to provide protection for the latest threats.
//
// The process for updating the database is as follows:
//	* At startup, if a database file is provided, then load it. If loaded
//	properly (not corrupted and not stale), then set tfu as the contents.
//	Otherwise, pull a new threat list from the Safe Browsing API.
//	* Periodically, synchronize the database with the Safe Browsing API.
//	This uses the State fields to update only parts of the threat list that have
//	changed since the last sync.
//	* Anytime tfu is updated, generate a new tfl.
//
// The process for querying the database is as follows:
//	* Check if the requested full hash matches any partial hash in tfl.
//	If a match is found, return a set of ThreatDescriptors with a partial match.
type database struct {
	config *Config

	// threatsForUpdate maps ThreatDescriptors to lists of partial hashes.
	// This data structure is in a format that is easily updated by the API.
	// It is also the form that is written to disk.
	tfu threatsForUpdate
	mu  sync.Mutex // Protects tfu

	// threatsForLookup maps ThreatDescriptors to sets of partial hashes.
	// This data structure is in a format that is easily queried.
	tfl threatsForLookup
	ml  sync.RWMutex // Protects tfl, err, and last

	err             error         // Last error encountered
	readyCh         chan struct{} // Used for waiting until not in an error state.
	last            time.Time     // Last time the threat list were synced
	updateAPIErrors uint          // Number of times we attempted to contact the api and failed

	log *log.Logger
}

type threatsForUpdate map[ThreatDescriptor]partialHashes
type partialHashes struct {
	// Since the Hashes field is only needed when storing to disk and when
	// updating, this field is cleared except for when it is in use.
	// This is done to reduce memory usage as the contents of this can be
	// regenerated from the tfl.
	Hashes hashPrefixes

	SHA256 []byte // The SHA256 over Hashes
	State  []byte // Arbitrary binary blob to synchronize state with API
}

type threatsForLookup map[ThreatDescriptor]hashSet

// databaseFormat is a light struct used only for gob encoding and decoding.
// As written to disk, the format of the database file is basically the gzip
// compressed version of the gob encoding of databaseFormat.
type databaseFormat struct {
	Table threatsForUpdate
	Time  time.Time
}

// Init initializes the database from the specified file in config.DBPath.
// It reports true if the database was successfully loaded.
func (db *database) Init(config *Config, logger *log.Logger) bool {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.setError(errors.New("not intialized"))
	db.config = config
	db.log = logger
	if db.config.DBPath == "" {
		db.log.Printf("no database file specified")
		db.setError(errors.New("no database loaded"))
		return false
	}
	dbf, err := loadDatabase(db.config.DBPath)
	if err != nil {
		db.log.Printf("load failure: %v", err)
		db.setError(err)
		return false
	}
	// Validate that the database threat list stored on disk is not too stale.
	if db.isStale(dbf.Time) {
		db.log.Printf("database loaded is stale")
		db.ml.Lock()
		defer db.ml.Unlock()
		db.setStale()
		return false
	}
	// Validate that the database threat list stored on disk is at least a
	// superset of the specified configuration.
	tfuNew := make(threatsForUpdate)
	for _, td := range db.config.ThreatLists {
		if row, ok := dbf.Table[td]; ok {
			tfuNew[td] = row
		} else {
			db.log.Printf("database configuration mismatch, missing %v", td)
			db.setError(errors.New("database configuration mismatch"))
			return false
		}
	}
	db.tfu = tfuNew
	db.generateThreatsForLookups(dbf.Time)
	return true
}

// Status reports the health of the database. The database is considered faulted
// if there was an error during update or if the last update has gone stale. If
// in a faulted state, the db may repair itself on the next Update.
func (db *database) Status() error {
	db.ml.RLock()
	defer db.ml.RUnlock()

	if db.err != nil {
		return db.err
	}
	if db.isStale(db.last) {
		db.setStale()
		return db.err
	}
	return nil
}

// UpdateLag reports the amount of time in between when we expected to run
// a database update and the current time
func (db *database) UpdateLag() time.Duration {
	lag := db.SinceLastUpdate()
	if lag < db.config.UpdatePeriod {
		return 0
	}
	return lag - db.config.UpdatePeriod
}

// SinceLastUpdate gives the duration since the last database update
func (db *database) SinceLastUpdate() time.Duration {
	db.ml.RLock()
	defer db.ml.RUnlock()

	return db.config.now().Sub(db.last)
}

// Ready returns a channel that's closed when the database is ready for queries.
func (db *database) Ready() <-chan struct{} {
	return db.readyCh
}

// Update synchronizes the local threat lists with those maintained by the
// global Safe Browsing API servers. If the update is successful, Status should
// report a nil error.
func (db *database) Update(ctx context.Context, api api) (time.Duration, bool) {
	db.mu.Lock()
	defer db.mu.Unlock()

	// Construct the request.
	var numTypes int
	var s []*pb.FetchThreatListUpdatesRequest_ListUpdateRequest
	for _, td := range db.config.ThreatLists {
		var state []byte
		if row, ok := db.tfu[td]; ok {
			state = row.State
		}

		s = append(s, &pb.FetchThreatListUpdatesRequest_ListUpdateRequest{
			ThreatType:      pb.ThreatType(td.ThreatType),
			PlatformType:    pb.PlatformType(td.PlatformType),
			ThreatEntryType: pb.ThreatEntryType(td.ThreatEntryType),
			Constraints: &pb.FetchThreatListUpdatesRequest_ListUpdateRequest_Constraints{
				SupportedCompressions: db.config.compressionTypes},
			State: state,
		})
		numTypes++
	}
	req := &pb.FetchThreatListUpdatesRequest{
		Client: &pb.ClientInfo{
			ClientId:      db.config.ID,
			ClientVersion: db.config.Version,
		},
		ListUpdateRequests: s,
	}

	// Query the API for the threat list and update the database.
	last := db.config.now()
	resp, err := api.ListUpdate(ctx, req)
	if err != nil {
		db.log.Printf("ListUpdate failure (%d): %v", db.updateAPIErrors+1, err)
		db.setError(err)
		// backoff strategy: MIN((2**N-1 * 15 minutes) * (RAND + 1), 24 hours)
		n := 1 << db.updateAPIErrors
		delay := time.Duration(float64(n) * (rand.Float64() + 1) * float64(baseRetryDelay))
		if delay > maxRetryDelay {
			delay = maxRetryDelay
		}
		db.updateAPIErrors++
		return delay, false
	}
	db.updateAPIErrors = 0

	// add jitter to wait time to avoid all servers lining up
	nextUpdateWait := db.config.UpdatePeriod + time.Duration(rand.Int31n(60)-30)*time.Second
	if resp.MinimumWaitDuration != nil {
		serverMinWait := time.Duration(resp.MinimumWaitDuration.Seconds)*time.Second + time.Duration(resp.MinimumWaitDuration.Nanos)
		if serverMinWait > nextUpdateWait {
			nextUpdateWait = serverMinWait
			db.log.Printf("Server requested next update in %v", nextUpdateWait)
		}
	}
	if len(resp.ListUpdateResponses) != numTypes {
		db.setError(errors.New("safebrowsing: threat list count mismatch"))
		db.log.Printf("invalid server response: got %d, want %d threat lists",
			len(resp.ListUpdateResponses), numTypes)
		return nextUpdateWait, false
	}

	// Update the threat database with the response.
	db.generateThreatsForUpdate()
	if err := db.tfu.update(resp); err != nil {
		db.setError(err)
		db.log.Printf("update failure: %v", err)
		db.tfu = nil
		return nextUpdateWait, false
	}
	dbf := databaseFormat{make(threatsForUpdate), last}
	for td, phs := range db.tfu {
		// Copy of partialHashes before generateThreatsForLookups clobbers it.
		dbf.Table[td] = phs
	}
	db.generateThreatsForLookups(last)

	// Regenerate the database and store it.
	if db.config.DBPath != "" {
		// Semantically, we ignore save errors, but we do log them.
		if err := saveDatabase(db.config.DBPath, dbf); err != nil {
			db.log.Printf("save failure: %v", err)
		}
	}

	return nextUpdateWait, true
}

// Lookup looks up the full hash in the threat list and returns a partial
// hash and a set of ThreatDescriptors that may match the full hash.
func (db *database) Lookup(hash hashPrefix) (h hashPrefix, tds []ThreatDescriptor) {
	if !hash.IsFull() {
		panic("hash is not full")
	}

	db.ml.RLock()
	for td, hs := range db.tfl {
		if n := hs.Lookup(hash); n > 0 {
			h = hash[:n]
			tds = append(tds, td)
		}
	}
	db.ml.RUnlock()
	return h, tds
}

// setError clears the database state and sets the last error to be err.
//
// This assumes that the db.mu lock is already held.
func (db *database) setError(err error) {
	db.tfu = nil

	db.ml.Lock()
	if db.err == nil {
		db.readyCh = make(chan struct{})
	}
	db.tfl, db.err, db.last = nil, err, time.Time{}
	db.ml.Unlock()
}

// isStale checks whether the last successful update should be considered stale.
// Staleness is defined as being older than two of the configured update periods
// plus jitter.
func (db *database) isStale(lastUpdate time.Time) bool {
	if db.config.now().Sub(lastUpdate) > 2*(db.config.UpdatePeriod+jitter) {
		return true
	}
	return false
}

// setStale sets the error state to a stale message, without clearing
// the database state.
//
// This assumes that the db.ml lock is already held.
func (db *database) setStale() {
	if db.err == nil {
		db.readyCh = make(chan struct{})
	}
	db.err = errStale
}

// clearError clears the db error state, and unblocks any callers of
// WaitUntilReady.
//
// This assumes that the db.mu lock is already held.
func (db *database) clearError() {
	db.ml.Lock()
	defer db.ml.Unlock()

	if db.err != nil {
		close(db.readyCh)
	}
	db.err = nil
}

// generateThreatsForUpdate regenerates the threatsForUpdate hashes from
// the threatsForLookup. We do this to avoid holding onto the hash lists for
// a long time, needlessly occupying lots of memory.
//
// This assumes that the db.mu lock is already held.
func (db *database) generateThreatsForUpdate() {
	if db.tfu == nil {
		db.tfu = make(threatsForUpdate)
	}

	db.ml.RLock()
	for td, hs := range db.tfl {
		phs := db.tfu[td]
		phs.Hashes = hs.Export()
		db.tfu[td] = phs
	}
	db.ml.RUnlock()
}

// generateThreatsForLookups regenerates the threatsForLookup data structure
// from the threatsForUpdate data structure and stores the last timestamp.
// Since the hashes are effectively stored as a set inside the threatsForLookup,
// we clear out the hashes slice in threatsForUpdate so that it can be GCed.
//
// This assumes that the db.mu lock is already held.
func (db *database) generateThreatsForLookups(last time.Time) {
	tfl := make(threatsForLookup)
	for td, phs := range db.tfu {
		var hs hashSet
		hs.Import(phs.Hashes)
		tfl[td] = hs

		phs.Hashes = nil // Clear hashes to keep memory usage low
		db.tfu[td] = phs
	}

	db.ml.Lock()
	wasBad := db.err != nil
	db.tfl, db.last = tfl, last
	db.ml.Unlock()

	if wasBad {
		db.clearError()
		db.log.Printf("database is now healthy")
	}
}

// saveDatabase saves the database threat list to a file.
func saveDatabase(path string, db databaseFormat) (err error) {
	var file *os.File
	file, err = os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := file.Close(); err == nil {
			err = cerr
		}
	}()

	gz, err := gzip.NewWriterLevel(file, gzip.BestCompression)
	if err != nil {
		return err
	}
	defer func() {
		if zerr := gz.Close(); err == nil {
			err = zerr
		}
	}()

	encoder := gob.NewEncoder(gz)
	if err = encoder.Encode(db); err != nil {
		return err
	}
	return nil
}

// loadDatabase loads the database state from a file.
func loadDatabase(path string) (db databaseFormat, err error) {
	var file *os.File
	file, err = os.Open(path)
	if err != nil {
		return db, err
	}
	defer func() {
		if cerr := file.Close(); err == nil {
			err = cerr
		}
	}()

	gz, err := gzip.NewReader(file)
	if err != nil {
		return db, err
	}
	defer func() {
		if zerr := gz.Close(); err == nil {
			err = zerr
		}
	}()

	decoder := gob.NewDecoder(gz)
	if err = decoder.Decode(&db); err != nil {
		return db, err
	}
	for _, dv := range db.Table {
		if !bytes.Equal(dv.SHA256, dv.Hashes.SHA256()) {
			return db, errors.New("safebrowsing: threat list SHA256 mismatch")
		}
	}
	return db, nil
}

// update updates the threat list according to the API response.
func (tfu threatsForUpdate) update(resp *pb.FetchThreatListUpdatesResponse) error {
	// For each update response do the removes and adds
	for _, m := range resp.GetListUpdateResponses() {
		td := ThreatDescriptor{
			PlatformType:    PlatformType(m.PlatformType),
			ThreatType:      ThreatType(m.ThreatType),
			ThreatEntryType: ThreatEntryType(m.ThreatEntryType),
		}

		phs, ok := tfu[td]
		switch m.ResponseType {
		case pb.FetchThreatListUpdatesResponse_ListUpdateResponse_PARTIAL_UPDATE:
			if !ok {
				return errors.New("safebrowsing: partial update received for non-existent key")
			}
		case pb.FetchThreatListUpdatesResponse_ListUpdateResponse_FULL_UPDATE:
			if len(m.Removals) > 0 {
				return errors.New("safebrowsing: indices to be removed included in a full update")
			}
			phs = partialHashes{}
		default:
			return errors.New("safebrowsing: unknown response type")
		}

		// Hashes must be sorted for removal logic to work properly.
		phs.Hashes.Sort()

		for _, removal := range m.Removals {
			idxs, err := decodeIndices(removal)
			if err != nil {
				return err
			}

			for _, i := range idxs {
				if i < 0 || i >= int32(len(phs.Hashes)) {
					return errors.New("safebrowsing: invalid removal index")
				}
				phs.Hashes[i] = ""
			}
		}

		// If any removal was performed, compact the list of hashes.
		if len(m.Removals) > 0 {
			compactHashes := phs.Hashes[:0]
			for _, h := range phs.Hashes {
				if h != "" {
					compactHashes = append(compactHashes, h)
				}
			}
			phs.Hashes = compactHashes
		}

		for _, addition := range m.Additions {
			hashes, err := decodeHashes(addition)
			if err != nil {
				return err
			}
			phs.Hashes = append(phs.Hashes, hashes...)
		}

		// Hashes must be sorted for SHA256 checksum to be correct.
		phs.Hashes.Sort()
		if err := phs.Hashes.Validate(); err != nil {
			return err
		}

		if cs := m.GetChecksum(); cs != nil {
			phs.SHA256 = cs.Sha256
		}
		if !bytes.Equal(phs.SHA256, phs.Hashes.SHA256()) {
			return errors.New("safebrowsing: threat list SHA256 mismatch")
		}

		phs.State = m.NewClientState
		tfu[td] = phs
	}
	return nil
}
