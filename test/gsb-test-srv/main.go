package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/golang/protobuf/proto"
	"github.com/letsencrypt/boulder/cmd"
	gsb "github.com/letsencrypt/boulder/test/gsb-test-srv/proto"
)

// testSrv implements a bare bones mock Google Safe Browsing server. The `hits`
// and `list` fields are protected against concurrent updates using `mu`.
type testSrv struct {
	apiKey string
	list   safebrowsingList
	hits   map[string]int
	mu     *sync.RWMutex
}

const (
	protoMime = "application/x-protobuf"
)

// defaultUnsafeURLs is the list of URLs that we return a "unsafe" response for.
var defaultUnsafeURLs = []string{
	"honest.achmeds.discount.hosting.com",
}

// emptyThreatListUpdateResp is an empty threat list update response for padding
// responses out to include the correct number of list updates clients expect
var emptyThreatListUpdateResp = &gsb.FetchThreatListUpdatesResponse_ListUpdateResponse{
	ThreatType:      gsb.ThreatType_MALWARE,
	PlatformType:    gsb.PlatformType_ANY_PLATFORM,
	ThreatEntryType: gsb.ThreatEntryType_URL,
	ResponseType:    gsb.FetchThreatListUpdatesResponse_ListUpdateResponse_FULL_UPDATE,
	/*
	 * This is the SHA256 hash of `[]byte{}`, e.g. of an empty list of additions
	 */
	Checksum: &gsb.Checksum{
		Sha256: []byte{
			0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8,
			0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
			0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
		},
	},
}

// unmarshalPB unmarshals a request body into a protocol buffer message
func unmarshalPB(req *http.Request, pbReq proto.Message) error {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return err
	}
	if err := proto.Unmarshal(body, pbReq); err != nil {
		return err
	}
	return nil
}

// marshalPB marshals a protocol buffer message into a response body
func marshalPB(resp http.ResponseWriter, pbResp proto.Message) error {
	resp.Header().Set("Content-Type", protoMime)
	body, err := proto.Marshal(pbResp)
	if err != nil {
		return err
	}
	if _, err := resp.Write(body); err != nil {
		return err
	}
	return nil
}

// listEntry represents an entry on the safe browsing list. Each entry is a hash
// constructed out of the URL.
type listEntry struct {
	hash string
	url  string
}

// newListEntry creates a listEntry out of a URL
func newListEntry(url string) listEntry {
	hash := sha256.New()
	hash.Write([]byte(url))
	return listEntry{
		hash: string(hash.Sum(nil)),
		url:  url,
	}
}

// safebrowsingList is a sorted slice of listEntries.
type safebrowsingList []listEntry

// sha256 returns the hash of the overall list contents
func (list safebrowsingList) sha256() []byte {
	hash := sha256.New()
	for _, entry := range list {
		hash.Write([]byte(entry.hash))
	}
	return hash.Sum(nil)
}

// bytes returns the overall safebrowsing list's entries all coverted to bytes
// and concatenated together
func (list safebrowsingList) bytes() []byte {
	var buf []byte
	for _, entry := range list {
		buf = append(buf, []byte(entry.hash)...)
	}
	return buf
}

// Len: implements the interface required for Sorting & Search
func (list safebrowsingList) Len() int           { return len(list) }
func (list safebrowsingList) Less(i, j int) bool { return list[i].hash < list[j].hash }
func (list safebrowsingList) Swap(i, j int)      { list[i], list[j] = list[j], list[i] }

// sort() will sort a safebrowsingList in place with sort.Sort
func (list safebrowsingList) sort() { sort.Sort(list) }

// findByHash searches an already sorted safebrowsingList and returns the entry
// with hash equal to the provided hash, or nil if none is found
func (list safebrowsingList) findByHash(h string) *listEntry {
	i := sort.Search(len(list), func(i int) bool {
		return list[i].hash >= h
	})
	if i < len(list) && list[i].hash == h {
		return &list[i]
	}
	return nil
}

// dbUpdateResponse creates a Google Safe Browsing threat list update response
// that includes each of the test server's list entries
func (t *testSrv) dbUpdateResponse() *gsb.FetchThreatListUpdatesResponse {
	// First we construct an overall update response to populate
	updateResp := &gsb.FetchThreatListUpdatesResponse{}

	// Next, we create the full update type list update response, with an
	// initially blank list of threat entries to process as list additions
	addResponse := &gsb.FetchThreatListUpdatesResponse_ListUpdateResponse{
		// We use the MALWARE type, ignoring platform and sending URLs
		ThreatType:      gsb.ThreatType_MALWARE,
		PlatformType:    gsb.PlatformType_ANY_PLATFORM,
		ThreatEntryType: gsb.ThreatEntryType_URL,
		// We want this to be a "FULL UPDATE" to populate the intial DB contents
		ResponseType: gsb.FetchThreatListUpdatesResponse_ListUpdateResponse_FULL_UPDATE,
		Additions: []*gsb.ThreatEntrySet{
			&gsb.ThreatEntrySet{},
		},
	}

	// Next, we create the threat entry additions, initially leaving the raw hashes empty
	additions := []*gsb.ThreatEntrySet{
		&gsb.ThreatEntrySet{
			// Our responses aren't compressed
			CompressionType: gsb.CompressionType_RAW,
			RawHashes: &gsb.RawHashes{
				// We send full SHA256 hashes as "prefixes"
				PrefixSize: sha256.Size,
			},
		},
	}

	// Lock the mutex for reading the threat list
	t.mu.RLock()
	defer t.mu.RUnlock()

	// Convert the list to bytes
	hashes := t.list.bytes()
	// Populate the raw hashes with the list bytes
	additions[0].RawHashes.RawHashes = hashes
	// Update the add response to have the populated additions
	addResponse.Additions = additions
	// Update the add responses' checksum to be that of the overall list
	addResponse.Checksum = &gsb.Checksum{Sha256: t.list.sha256()}

	/*
	 * The `sblookup` client is hardcoded to expect exactly three list update
	 * responses, one for each of the threat types it cares about. Boulder isn't
	 * as picky, but its nice to be able to test this server using the `sblookup`
	 * utility.
	 *
	 * To make this client happy we send two empty updates before the non-empty one
	 * Its important to send these in the order empty, empty, non-empty because
	 * each sblookup update response squashes the previous' contents (Unclear why)
	 */
	updateResp.ListUpdateResponses = []*gsb.FetchThreatListUpdatesResponse_ListUpdateResponse{
		emptyThreatListUpdateResp,
		emptyThreatListUpdateResp,
		addResponse,
	}
	return updateResp
}

// threatListUpdateFetch handles a GSB client asking for a threat list update
func (t *testSrv) threatListUpdateFetch(w http.ResponseWriter, r *http.Request) {
	// Unmarshal the request from the client - we ignore the contents for now and
	// unmarshal just to check the syntax of the request
	updateReq := &gsb.FetchThreatListUpdatesRequest{}
	err := unmarshalPB(r, updateReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Compute an update response based on the testSrv's list
	updateResp := t.dbUpdateResponse()
	// Marshal it as a response
	err = marshalPB(w, updateResp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("Processed threatListUpdateFetch for client\n")
}

// fullHashesFind handles a GSB client asking for a specific hash to be looked
// up in the list because it matched a local prefix.
func (t *testSrv) fullHashesFind(w http.ResponseWriter, r *http.Request) {
	// Unmarshal the request from the client - we use this to determine which hash
	// they were looking for
	findReq := &gsb.FindFullHashesRequest{}
	err := unmarshalPB(r, findReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// At a minimum we need a ThreatInfo with at least one ThreatEntries
	if findReq.ThreatInfo == nil || findReq.ThreatInfo.ThreatEntries == nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	te := findReq.ThreatInfo.ThreatEntries
	if len(te) < 1 {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	threat := te[0]

	// We start by populating an empty hash lookup response
	resp := &gsb.FindFullHashesResponse{
		MinimumWaitDuration: &gsb.Duration{
			Seconds: 1,
		},
		NegativeCacheDuration: &gsb.Duration{
			Seconds: 1,
		},
	}

	// Next we Lock mutex for reading the threat list and try to find the hash
	// being inquired about.
	t.mu.RLock()
	var match *listEntry
	match = t.list.findByHash(string(threat.Hash))
	// Restore read lock immediately
	t.mu.RUnlock()

	if match != nil {
		// If there was a match we need to update the response to have a ThreatMatch
		resp.Matches = []*gsb.ThreatMatch{
			&gsb.ThreatMatch{
				ThreatType:      gsb.ThreatType_MALWARE,
				PlatformType:    gsb.PlatformType_ANY_PLATFORM,
				ThreatEntryType: gsb.ThreatEntryType_URL,
				Threat: &gsb.ThreatEntry{
					Hash: []byte(match.hash),
					Url:  match.url,
				},
				CacheDuration: &gsb.Duration{
					Seconds: 1,
				},
			},
		}
		// We also have to lock the mutex for writing and update the server `hits`
		// to track that someone asked about an entry on the list
		t.mu.Lock()
		defer t.mu.Unlock()
		t.hits[match.url] += 1
		log.Printf("Lookup hit for %q. Count: %d\n", match.url, t.hits[match.url])
	}

	// Finally we return the response to the client
	err = marshalPB(w, resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("Processed fullHashesFind for client\n")
}

// getHits returns a JSON object describing how many times each URL on the mock
// safebrowsing list was asked about by a client. E.g.
// ```
// {
//   "evil.com": 2,
//   "example.com": 0
// }
// ```
func (t *testSrv) getHits(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Lock the mutex for reading
	t.mu.RLock()
	defer t.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	body, err := json.Marshal(t.hits)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := w.Write(body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("Processed /hits request for client\n")
}

// gsbHandler creates an http.HandlerFunc that wraps the `inner` handler. The
// wrapper will check that the request is a POST, has the correct content-type,
// and that the `key` GET parameter matches the server's API key.
func (t *testSrv) gsbHandler(inner http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The HTTP method must be POST
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// The Content-Type must be the protocol buffers mime type
		if r.Header.Get("Content-Type") != protoMime {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// There must be a "key" URL parameter with the correct API key
		// TODO(@cpu): Send back a protocol-correct bad auth response
		key := r.URL.Query().Get("key")
		if key != t.apiKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		inner(w, r)
	})
}

// start() sets up the HTTP muxer and spawns a Go routine to ListenAndServe
func (t *testSrv) start(listenAddr string) {
	mux := http.NewServeMux()
	mux.Handle("/v4/threatListUpdates:fetch", t.gsbHandler(t.threatListUpdateFetch))
	mux.Handle("/v4/fullHashes:find", t.gsbHandler(t.fullHashesFind))
	mux.Handle("/hits", http.HandlerFunc(t.getHits))

	go func() {
		err := http.ListenAndServe(listenAddr, mux)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err.Error())
			return
		}
	}()
}

// newTestServer constructs a testSrv instance with its list constructed from
// the provided slice of strings.
func newTestServer(apiKey string, unsafeURLs []string) testSrv {
	var initialList safebrowsingList
	for _, s := range unsafeURLs {
		// The safe browsing library looks up URLs with a trailing slash and expects
		// the DB contents/hashes to reflect that. We add the slash here as required
		if !strings.HasSuffix(s, "/") {
			s += "/"
		}
		initialList = append(initialList, newListEntry(s))
	}
	initialList.sort()

	return testSrv{
		apiKey: apiKey,
		hits:   make(map[string]int),
		mu:     new(sync.RWMutex),
		list:   initialList,
	}
}

// main() processes command line flags, creates, and starts a `testSrv`
func main() {
	key := flag.String("apikey", "", "API key for client access")
	listen := flag.String("listenAddress", ":6000", "Listen address for HTTP server")
	flag.Parse()

	log.SetPrefix("gsb-test-srv: ")

	if *key == "" {
		log.Fatal("Error: -apikey must not be empty\n")
		os.Exit(1)
	}

	log.Printf("Starting GSB Test Server on %q\n", *listen)
	ts := newTestServer(*key, defaultUnsafeURLs)
	ts.start(*listen)

	cmd.CatchSignals(nil, nil)
}
