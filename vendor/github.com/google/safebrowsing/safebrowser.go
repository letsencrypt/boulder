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

// Package safebrowsing implements a client for the Safe Browsing API v4.
//
// API v4 emphasizes efficient usage of the network for bandwidth-constrained
// applications such as mobile devices. It achieves this by maintaining a small
// portion of the server state locally such that some queries can be answered
// immediately without any network requests. Thus, fewer API calls made, means
// less bandwidth is used.
//
// At a high-level, the implementation does the following:
//
//	            hash(query)
//	                 |
//	            _____V_____
//	           |           | No
//	           | Database  |-----+
//	           |___________|     |
//	                 |           |
//	                 | Maybe?    |
//	            _____V_____      |
//	       Yes |           | No  V
//	     +-----|   Cache   |---->+
//	     |     |___________|     |
//	     |           |           |
//	     |           | Maybe?    |
//	     |      _____V_____      |
//	     V Yes |           | No  V
//	     +<----|    API    |---->+
//	     |     |___________|     |
//	     V                       V
//	(Yes, unsafe)            (No, safe)
//
// Essentially the query is presented to three major components: The database,
// the cache, and the API. Each of these may satisfy the query immediately,
// or may say that it does not know and that the query should be satisfied by
// the next component. The goal of the database and cache is to satisfy as many
// queries as possible to avoid using the API.
//
// Starting with a user query, a hash of the query is performed to preserve
// privacy regarded the exact nature of the query. For example, if the query
// was for a URL, then this would be the SHA256 hash of the URL in question.
//
// Given a query hash, we first check the local database (which is periodically
// synced with the global Safe Browsing API servers). This database will either
// tell us that the query is definitely safe, or that it does not have
// enough information.
//
// If we are unsure about the query, we check the local cache, which can be used
// to satisfy queries immediately if the same query had been made recently.
// The cache will tell us that the query is either safe, unsafe, or unknown
// (because the it's not in the cache or the entry expired).
//
// If we are still unsure about the query, then we finally query the API server,
// which is guaranteed to return to us an authoritative answer, assuming no
// networking failures.
//
// For more information, see the API developer's guide:
//	https://developers.google.com/safe-browsing/
package safebrowsing

import (
	"errors"
	"io"
	"io/ioutil"
	"log"
	"sync/atomic"
	"time"

	pb "github.com/google/safebrowsing/internal/safebrowsing_proto"
)

const (
	// DefaultServerURL is the default URL for the Safe Browsing API.
	DefaultServerURL = "safebrowsing.googleapis.com"

	// DefaultUpdatePeriod is the default period for how often SafeBrowser will
	// reload its blacklist database.
	DefaultUpdatePeriod = 30 * time.Minute

	// DefaultID and DefaultVersion are the default client ID and Version
	// strings to send with every API call.
	DefaultID      = "GoSafeBrowser"
	DefaultVersion = "1.0.0"
)

// Errors specific to this package.
var (
	errClosed = errors.New("safebrowsing: handler is closed")
	errStale  = errors.New("safebrowsing: threat list is stale")
)

// ThreatType is an enumeration type for threats classes. Examples of threat
// classes are malware, social engineering, etc.
type ThreatType uint16

func (tt ThreatType) String() string { return pb.ThreatType(tt).String() }

// List of ThreatType constants.
const (
	ThreatType_Malware                       = ThreatType(pb.ThreatType_MALWARE)
	ThreatType_SocialEngineering             = ThreatType(pb.ThreatType_SOCIAL_ENGINEERING)
	ThreatType_UnwantedSoftware              = ThreatType(pb.ThreatType_UNWANTED_SOFTWARE)
	ThreatType_PotentiallyHarmfulApplication = ThreatType(pb.ThreatType_POTENTIALLY_HARMFUL_APPLICATION)
)

// PlatformType is an enumeration type for platform classes. Examples of
// platform classes are Windows, Linux, Android, etc.
type PlatformType uint16

func (pt PlatformType) String() string { return pb.PlatformType(pt).String() }

// List of PlatformType constants.
const (
	PlatformType_AnyPlatform  = PlatformType(pb.PlatformType_ANY_PLATFORM)
	PlatformType_AllPlatforms = PlatformType(pb.PlatformType_ALL_PLATFORMS)

	PlatformType_Windows = PlatformType(pb.PlatformType_WINDOWS)
	PlatformType_Linux   = PlatformType(pb.PlatformType_LINUX)
	PlatformType_Android = PlatformType(pb.PlatformType_ANDROID)
	PlatformType_OSX     = PlatformType(pb.PlatformType_OSX)
	PlatformType_iOS     = PlatformType(pb.PlatformType_IOS)
	PlatformType_Chrome  = PlatformType(pb.PlatformType_CHROME)
)

// ThreatEntryType is an enumeration type for threat entries. Examples of
// threat entries are via URLs, binary digests, and IP address ranges.
type ThreatEntryType uint16

func (tet ThreatEntryType) String() string { return pb.ThreatEntryType(tet).String() }

// List of ThreatEntryType constants.
const (
	ThreatEntryType_URL = ThreatEntryType(pb.ThreatEntryType_URL)

	// These below are not supported yet.
	ThreatEntryType_Executable = ThreatEntryType(pb.ThreatEntryType_EXECUTABLE)
	ThreatEntryType_IPRange    = ThreatEntryType(pb.ThreatEntryType_IP_RANGE)
)

// DefaultThreatLists is the default list of threat lists that SafeBrowser
// will maintain. Do not modify this variable.
var DefaultThreatLists = []ThreatDescriptor{
	{ThreatType_Malware, PlatformType_AnyPlatform, ThreatEntryType_URL},
	{ThreatType_SocialEngineering, PlatformType_AnyPlatform, ThreatEntryType_URL},
	{ThreatType_UnwantedSoftware, PlatformType_AnyPlatform, ThreatEntryType_URL},
}

// A ThreatDescriptor describes a given threat, which itself is composed of
// several parameters along different dimensions: ThreatType, PlatformType, and
// ThreatEntryType.
type ThreatDescriptor struct {
	ThreatType      ThreatType
	PlatformType    PlatformType
	ThreatEntryType ThreatEntryType
}

// A URLThreat is a specialized ThreatDescriptor for the URL threat
// entry type.
type URLThreat struct {
	Pattern string
	ThreatDescriptor
}

// Config sets up the SafeBrowser object.
type Config struct {
	// ServerURL is the URL for the Safe Browsing API server.
	// If empty, it defaults to DefaultServerURL.
	ServerURL string

	// APIKey is the key used to authenticate with the Safe Browsing API
	// service. This field is required.
	APIKey string

	// ID and Version are client metadata associated with each API request to
	// identify the specific implementation of the client.
	// They are similar in usage to the "User-Agent" in an HTTP request.
	// If empty, these default to DefaultID and DefaultVersion, respectively.
	ID      string
	Version string

	// DBPath is a path to a persistent database file.
	// If empty, SafeBrowser operates in a non-persistent manner.
	// This means that blacklist results will not be cached beyond the lifetime
	// of the SafeBrowser object.
	DBPath string

	// UpdatePeriod determines how often we update the internal list database.
	// If zero value, it defaults to DefaultUpdatePeriod.
	UpdatePeriod time.Duration

	// ThreatLists determines which threat lists that SafeBrowser should
	// subscribe to. The threats reported by LookupURLs will only be ones that
	// are specified by this list.
	// If empty, it defaults to DefaultThreatLists.
	ThreatLists []ThreatDescriptor

	// Logger is an io.Writer that allows SafeBrowser to write debug information
	// intended for human consumption.
	// If empty, no logs will be written.
	Logger io.Writer

	// compressionTypes indicates how the threat entry sets can be compressed.
	compressionTypes []pb.CompressionType

	api api
	now func() time.Time
}

// setDefaults configures Config to have default parameters.
// It reports whether the current configuration is valid.
func (c *Config) setDefaults() bool {
	if c.ServerURL == "" {
		c.ServerURL = DefaultServerURL
	}
	if len(c.ThreatLists) == 0 {
		c.ThreatLists = DefaultThreatLists
	}
	if c.UpdatePeriod <= 0 {
		c.UpdatePeriod = DefaultUpdatePeriod
	}
	if c.compressionTypes == nil {
		c.compressionTypes = []pb.CompressionType{pb.CompressionType_RAW, pb.CompressionType_RICE}
	}
	return true
}

func (c Config) copy() Config {
	c2 := c
	c2.ThreatLists = append([]ThreatDescriptor(nil), c.ThreatLists...)
	c2.compressionTypes = append([]pb.CompressionType(nil), c.compressionTypes...)
	return c2
}

// SafeBrowser is a client implementation of API v4.
//
// It provides a set of lookup methods that allows the user to query whether
// certain entries are considered a threat. The implementation manages all of
// local database and caching that would normally be needed to interact
// with the API server.
type SafeBrowser struct {
	config Config
	stats  Stats
	api    api
	db     database
	c      cache

	lists map[ThreatDescriptor]bool

	log *log.Logger

	closed uint32
	done   chan bool // Signals that the updater routine should stop
}

// Stats records statistics regarding SafeBrowser's operation.
type Stats struct {
	QueriesByDatabase int64 // Number of queries satisfied by the database alone
	QueriesByCache    int64 // Number of queries satisfied by the cache alone
	QueriesByAPI      int64 // Number of queries satisfied by an API call
	QueriesFail       int64 // Number of queries that could not be satisfied
}

// NewSafeBrowser creates a new SafeBrowser.
//
// The conf struct allows the user to configure many aspects of the
// SafeBrowser's operation.
func NewSafeBrowser(conf Config) (*SafeBrowser, error) {
	conf = conf.copy()
	if !conf.setDefaults() {
		return nil, errors.New("safebrowsing: invalid configuration")
	}

	// Create the SafeBrowsing object.
	if conf.api == nil {
		var err error
		conf.api, err = newNetAPI(conf.ServerURL, conf.APIKey)
		if err != nil {
			return nil, err
		}
	}
	if conf.now == nil {
		conf.now = time.Now
	}
	sb := &SafeBrowser{
		config: conf,
		api:    conf.api,
		c:      cache{now: conf.now},
	}

	// TODO: Verify that config.ThreatLists is a subset of the list obtained
	// by "/v4/threatLists" API endpoint.

	// Convert threat lists slice to a map for O(1) lookup.
	sb.lists = make(map[ThreatDescriptor]bool)
	for _, td := range conf.ThreatLists {
		sb.lists[td] = true
	}

	// Setup the logger.
	w := conf.Logger
	if conf.Logger == nil {
		w = ioutil.Discard
	}
	sb.log = log.New(w, "safebrowsing: ", log.Ldate|log.Ltime|log.Lshortfile)

	// If database file is provided, use that to initialize.
	if !sb.db.Init(&sb.config, sb.log) {
		sb.db.Update(sb.api)
	}

	// Start the background list updater.
	sb.done = make(chan bool)
	go sb.updater(conf.UpdatePeriod)
	return sb, nil
}

// Status reports the status of SafeBrowser. It returns some statistics
// regarding the operation, and an error representing the status of its
// internal state. Most errors are transient and will recover themselves
// after some period.
func (sb *SafeBrowser) Status() (Stats, error) {
	stats := Stats{
		QueriesByDatabase: atomic.LoadInt64(&sb.stats.QueriesByDatabase),
		QueriesByCache:    atomic.LoadInt64(&sb.stats.QueriesByCache),
		QueriesByAPI:      atomic.LoadInt64(&sb.stats.QueriesByAPI),
		QueriesFail:       atomic.LoadInt64(&sb.stats.QueriesFail),
	}
	return stats, sb.db.Status()
}

// LookupURLs looks up the provided URLs. It returns a list of threats, one for
// every URL requested, and an error if any occurred. It is safe to call this
// method concurrently.
//
// The outer dimension is across all URLs requested, and will always have the
// same length as urls regardless of whether an error occurs or not.
// The inner dimension is across every fragment that a given URL produces.
// For some URL at index i, one can check for a hit on any blacklist by
// checking if len(threats[i]) > 0.
// The ThreatEntryType field in the inner ThreatDescriptor will be set to
// ThreatEntryType_URL as this is a URL lookup.
//
// If an error occurs, the caller should treat the threats list returned as a
// best-effort response to the query. The results may be stale or be partial.
func (sb *SafeBrowser) LookupURLs(urls []string) (threats [][]URLThreat, err error) {
	threats = make([][]URLThreat, len(urls))

	if atomic.LoadUint32(&sb.closed) != 0 {
		return threats, errClosed
	}
	if err := sb.db.Status(); err != nil {
		sb.log.Printf("inconsistent database: %v", err)
		atomic.AddInt64(&sb.stats.QueriesFail, int64(len(urls)))
		return threats, err
	}

	// TODO: There are some optimizations to be made here:
	//	1.) We could force a database update if it is in error.
	//  However, we must ensure that we perform some form of rate-limiting.
	//	2.) We should batch all of the partial hashes together such that we
	//	call api.HashLookup only once.

	for i, url := range urls {
		hashes, err := generateHashes(url)
		if err != nil {
			sb.log.Printf("error generating hashes: %v", err)
			atomic.AddInt64(&sb.stats.QueriesFail, int64(len(urls)-i))
			return threats, err
		}

		// Construct the follow-up request being made to the server.
		// In the request, we only ask for partial hashes for privacy reasons.
		req := &pb.FindFullHashesRequest{
			Client: &pb.ClientInfo{
				ClientId:      sb.config.ID,
				ClientVersion: sb.config.Version,
			},
			ThreatInfo: &pb.ThreatInfo{},
		}
		ttm := make(map[pb.ThreatType]bool)
		ptm := make(map[pb.PlatformType]bool)
		tetm := make(map[pb.ThreatEntryType]bool)
		for fullHash, pattern := range hashes {
			// Lookup in database according to threat list.
			partialHash, unsureThreats := sb.db.Lookup(fullHash)
			if len(unsureThreats) == 0 {
				atomic.AddInt64(&sb.stats.QueriesByDatabase, 1)
				continue // There are definitely no threats for this full hash
			}

			// Lookup in cache according to recently seen values.
			cachedThreats, cr := sb.c.Lookup(fullHash)
			switch cr {
			case positiveCacheHit:
				// The cache remembers this full hash as a threat.
				// The threats we return to the client is the set intersection
				// of unsureThreats and cachedThreats.
				for _, td := range unsureThreats {
					if _, ok := cachedThreats[td]; ok {
						threats[i] = append(threats[i], URLThreat{
							Pattern:          pattern,
							ThreatDescriptor: td,
						})
					}
				}
			case negativeCacheHit:
				// This is cached as a non-threat.
				atomic.AddInt64(&sb.stats.QueriesByCache, 1)
				continue
			default:
				// The cache knows nothing about this full hash, so we must make
				// a request for it.
				for _, td := range unsureThreats {
					ttm[pb.ThreatType(td.ThreatType)] = true
					ptm[pb.PlatformType(td.PlatformType)] = true
					tetm[pb.ThreatEntryType(td.ThreatEntryType)] = true
				}
				req.ThreatInfo.ThreatEntries = append(req.ThreatInfo.ThreatEntries,
					&pb.ThreatEntry{Hash: []byte(partialHash)})
			}
		}
		for tt := range ttm {
			req.ThreatInfo.ThreatTypes = append(req.ThreatInfo.ThreatTypes, tt)
		}
		for pt := range ptm {
			req.ThreatInfo.PlatformTypes = append(req.ThreatInfo.PlatformTypes, pt)
		}
		for tet := range tetm {
			req.ThreatInfo.ThreatEntryTypes = append(req.ThreatInfo.ThreatEntryTypes, tet)
		}

		// All results are known, so just continue.
		if len(req.ThreatInfo.ThreatEntries) == 0 {
			atomic.AddInt64(&sb.stats.QueriesByCache, 1)
			continue
		}

		// Actually query the Safe Browsing API for exact full hash matches.
		resp, err := sb.api.HashLookup(req)
		if err != nil {
			sb.log.Printf("HashLookup failure: %v", err)
			atomic.AddInt64(&sb.stats.QueriesFail, int64(len(urls)-i))
			return threats, err
		}

		// Update the cache.
		sb.c.Update(req, resp)

		// Pull the information the client cares about out of the response.
		for _, tm := range resp.GetMatches() {
			fullHash := hashPrefix(tm.GetThreat().Hash)
			if !fullHash.IsFull() {
				continue
			}
			if pattern, ok := hashes[fullHash]; ok {
				td := ThreatDescriptor{
					ThreatType:      ThreatType(tm.ThreatType),
					PlatformType:    PlatformType(tm.PlatformType),
					ThreatEntryType: ThreatEntryType(tm.ThreatEntryType),
				}
				if !sb.lists[td] {
					continue
				}
				threats[i] = append(threats[i], URLThreat{
					Pattern:          pattern,
					ThreatDescriptor: td,
				})
			}
		}
		atomic.AddInt64(&sb.stats.QueriesByAPI, 1)
	}
	return threats, nil
}

// TODO: Add other types of lookup when available.
//	func (sb *SafeBrowser) LookupBinaries(digests []string) (threats []BinaryThreat, err error)
//	func (sb *SafeBrowser) LookupAddresses(addrs []string) (threats [][]AddressThreat, err error)

// updater is a blocking method that periodically updates the local database.
// This should be run as a separate goroutine and will be automatically stopped
// when sb.Close is called.
func (sb *SafeBrowser) updater(period time.Duration) {
	ticker := time.NewTicker(period)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sb.log.Printf("background threat list update")
			sb.c.Purge()
			sb.db.Update(sb.api)
		case <-sb.done:
			return
		}
	}
}

// Close cleans up all resources.
// This method must not be called concurrently with other lookup methods.
func (sb *SafeBrowser) Close() error {
	if atomic.LoadUint32(&sb.closed) == 0 {
		atomic.StoreUint32(&sb.closed, 1)
		close(sb.done)
	}
	return nil
}
