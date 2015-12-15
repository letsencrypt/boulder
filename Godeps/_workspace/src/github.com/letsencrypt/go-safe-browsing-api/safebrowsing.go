/*
Copyright (c) 2013, Richard Johnson
Copyright (c) 2014, Kilian Gilonne
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package safebrowsing

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	//	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

type HostHash string
type LookupHash string

type SafeBrowsing struct {
	DataDir string

	Key             string
	Client          string
	AppVersion      string
	ProtocolVersion string

	UpdateDelay int
	LastUpdated time.Time

	Lists   map[string]*SafeBrowsingList
	Cache   map[HostHash]*FullHashCache
	request func(string, string, bool) (*http.Response, error)

	Logger logger
}

var SupportedLists map[string]bool = map[string]bool{
	"goog-malware-shavar":  true,
	"googpub-phish-shavar": true,
}

var Logger logger = new(DefaultLogger)
var Client string = "api"
var AppVersion string = "1.5.2"
var ProtocolVersion string = "3.0"
var OfflineMode bool = false
var Transport *http.Transport = &http.Transport{}

func NewSafeBrowsing(apiKey string, dataDirectory string) (sb *SafeBrowsing, err error) {
	sb = &SafeBrowsing{
		Key:             apiKey,
		Client:          Client,
		AppVersion:      AppVersion,
		ProtocolVersion: ProtocolVersion,
		DataDir:         dataDirectory,
		Lists:           make(map[string]*SafeBrowsingList),
		Cache:           make(map[HostHash]*FullHashCache),
		request:         request,
		Logger:          Logger,
	}

	// if the dataDirectory does not currently exist, have a go at creating it:
	err = os.MkdirAll(dataDirectory, os.ModeDir|0700)
	if err != nil {
		sb.Logger.Error(
			"Directory \"%s\" does not exist, and I was unable to create it!",
			dataDirectory)
	}

	// if we are in offline mode we want to just load up the lists we
	// currently have and work with that
	if OfflineMode {
		for listName, _ := range SupportedLists {
			fileName := sb.DataDir + "/" + listName + ".dat"
			tmpList := newSafeBrowsingList(listName, fileName)
			tmpList.Logger = sb.Logger
			err := tmpList.load(nil)
			if err != nil {
				sb.Logger.Warn("Error loading list %s: %s", listName, err)
				continue
			}
			sb.Lists[listName] = tmpList
		}
		//		debug.FreeOSMemory()
		return sb, nil
	}

	// normal mode, contact the server for updates, etc.
	err = sb.UpdateProcess()

	return sb, err
}

func (sb *SafeBrowsing) UpdateProcess() (err error) {

	sb.Logger.Info("Requesting list of lists from server...")
	err = sb.requestSafeBrowsingLists()
	if err != nil {
		return err
	}
	err = sb.loadExistingData()
	if err != nil {
		return err
	}
	err, status := sb.update()
	if (err != nil) && (status != 503) {
		return err
	} else if status == 503 {
		sb.Logger.Warn("GSB service temporarily unavailable")
	}

	go sb.reloadLoop()
	return nil
}

func (sb *SafeBrowsing) requestSafeBrowsingLists() (err error) {
	//	defer debug.FreeOSMemory()

	url := fmt.Sprintf(
		"https://safebrowsing.google.com/safebrowsing/list?"+
			"client=%s&key=%s&appver=%s&pver=%s",
		sb.Client, sb.Key, sb.AppVersion, sb.ProtocolVersion)

	listresp, err := sb.request(url, "", true)
	if err != nil {
		return err
	}
	if listresp.StatusCode == 503 {
		sb.requestSafeBrowsingLists()
	} else if listresp.StatusCode != 200 {
		return fmt.Errorf("Unexpected server response code: %d", listresp.StatusCode)
	}
	return sb.processSafeBrowsingLists(listresp.Body)
}

func (sb *SafeBrowsing) processSafeBrowsingLists(body io.Reader) (err error) {
	buf := bytes.Buffer{}
	if _, err = buf.ReadFrom(body); err != nil {
		return fmt.Errorf("Unable to read list data: %s", err)
	}
	for _, listName := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if _, exists := SupportedLists[listName]; !exists {
			continue
		}
		fileName := sb.DataDir + "/" + listName + ".dat"
		tmpList := newSafeBrowsingList(listName, fileName)
		tmpList.Logger = sb.Logger
		sb.Lists[listName] = tmpList
	}
	return nil
}

func (sb *SafeBrowsing) loadExistingData() error {

	sb.Logger.Info("Loading existing data....")
	for _, sbl := range sb.Lists {
		err := sbl.load(nil)
		if err != nil {
			return fmt.Errorf("Error loading list from %s: %s", sb.DataDir, err)
		}
		//		debug.FreeOSMemory()
	}
	return nil
}

func (sb *SafeBrowsing) update() (err error, status int) {

	sb.Logger.Info("Requesting updates...")
	if err, status = sb.requestRedirectList(); err != nil {
		return fmt.Errorf("Unable to retrieve updates: %s", err.Error()), status
	}

	for listName, list := range sb.Lists {
		if err = list.loadDataFromRedirectLists(); err != nil {
			return fmt.Errorf("Unable to process updates for %s: %s", listName, err.Error()), status
		}
	}

	// update the last updated time
	sb.LastUpdated = time.Now()
	return nil, status
}

func (sb *SafeBrowsing) requestRedirectList() (err error, status int) {
	//	defer debug.FreeOSMemory()

	url := fmt.Sprintf(
		"https://safebrowsing.google.com/safebrowsing/downloads?"+
			"client=%s&key=%s&appver=%s&pver=%s",
		sb.Client, sb.Key, sb.AppVersion, sb.ProtocolVersion)

	listsStr := ""
	for list, sbl := range sb.Lists {
		listsStr += string(list) + ";"
		addChunkRange := sbl.ChunkRanges[CHUNK_TYPE_ADD]
		if addChunkRange != "" {
			listsStr += "a:" + addChunkRange + ":"
		}
		subChunkRange := sbl.ChunkRanges[CHUNK_TYPE_SUB]
		if subChunkRange != "" {
			listsStr += "s:" + subChunkRange
		}
		listsStr += "\n"
	}
	redirects, err := sb.request(url, listsStr, true)
	if err != nil {
		return err, 0
	}
	defer redirects.Body.Close()
	if redirects.StatusCode != 200 {
		tmp := &bytes.Buffer{}
		tmp.ReadFrom(redirects.Body)
		return fmt.Errorf("Unexpected server response code: %d\n%s", redirects.StatusCode, tmp), redirects.StatusCode
	}
	if err = sb.processRedirectList(redirects.Body); err != nil {
		return err, redirects.StatusCode
	}
	return nil, redirects.StatusCode
}

func (sb *SafeBrowsing) processRedirectList(buf io.Reader) error {
	//	defer debug.FreeOSMemory()

	scanner := bufio.NewScanner(buf)
	//initialize temporary var
	var currentListName string
	var RedirectList []string = nil
	currentDeletes := make(map[ChunkData_ChunkType]map[ChunkNum]bool)
	currentDeletes[CHUNK_TYPE_ADD] = make(map[ChunkNum]bool)
	currentDeletes[CHUNK_TYPE_SUB] = make(map[ChunkNum]bool)

	for scanner.Scan() {
		line := scanner.Text()
		bits := strings.SplitN(line, ":", 2)
		switch bits[0] {
		case "n":
			updateDelayStr := bits[1]
			updateDelay, err := strconv.Atoi(updateDelayStr)
			if err != nil {
				return fmt.Errorf("Unable to parse timeout: %s", err)
			}
			sb.UpdateDelay = updateDelay
		case "r":
			// we need to reset full!
			sb.reset()
			// the docs say to request again, so we do that...
			err, _ := sb.requestRedirectList()
			return err
		case "i":
			if RedirectList != nil {
				// save to DataRedirects
				sb.Lists[currentListName].DataRedirects = RedirectList
				sb.Lists[currentListName].DeleteChunks = currentDeletes
			}
			// reinitialize temporary var
			RedirectList = make([]string, 0)
			currentDeletes = make(map[ChunkData_ChunkType]map[ChunkNum]bool)
			currentDeletes[CHUNK_TYPE_ADD] = make(map[ChunkNum]bool, 0)
			currentDeletes[CHUNK_TYPE_SUB] = make(map[ChunkNum]bool, 0)
			currentListName = bits[1]
		case "u":
			RedirectList = append(RedirectList, "https://"+bits[1])
		case "ad":
			addDeletes, err := parseChunkRange(bits[1])
			if err != nil {
				return fmt.Errorf("Error parsing delete add chunks range: %s", err)
			}
			currentDeletes[CHUNK_TYPE_ADD] = addDeletes
		case "sd":
			subDeletes, err := parseChunkRange(bits[1])
			if err != nil {
				return fmt.Errorf("Error parsing delete sub chunks range: %s", err)
			}
			currentDeletes[CHUNK_TYPE_SUB] = subDeletes
		default:
			continue
		}
		//		debug.FreeOSMemory()
	}

	// add the final list
	sb.Lists[currentListName].DataRedirects = RedirectList
	sb.Lists[currentListName].DeleteChunks = currentDeletes
	if err := scanner.Err(); err != nil && err != io.EOF {
		return fmt.Errorf("Unable to parse list response: %s", err)
	}
	return nil
}

func (sb *SafeBrowsing) reset() {

	for _, sbl := range sb.Lists {
		sbl.Lookup = NewTrie()
		sbl.FullHashes = NewTrie()
		sbl.FullHashRequested = NewTrie()
		sbl.DataRedirects = make([]string, 0)
		sbl.DeleteChunks = make(map[ChunkData_ChunkType]map[ChunkNum]bool)
		sbl.DeleteChunks[CHUNK_TYPE_ADD] = make(map[ChunkNum]bool, 0)
		sbl.DeleteChunks[CHUNK_TYPE_SUB] = make(map[ChunkNum]bool, 0)
		// kill off the chunks
		sbl.ChunkRanges = map[ChunkData_ChunkType]string{
			CHUNK_TYPE_ADD: "",
			CHUNK_TYPE_SUB: "",
		}
		// delete any files we have loaded for this map
		if sbl.FileName != "" {
			os.Remove(sbl.FileName)
		}
		//		debug.FreeOSMemory()
	}
}

func (sb *SafeBrowsing) reloadLoop() {

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomFloat := r.Float64()
	for {
		// wait the update delay
		duration := time.Duration(sb.UpdateDelay) * time.Second
		sb.Logger.Info("Next update in %d seconds", sb.UpdateDelay)
		time.Sleep(duration)
		err, status := sb.update()
		for x := 0; status == 503; x++ {
			// first we wait 1 min, than some time between 30-60 mins
			// doubling until we stop at 480 mins or succeed
			mins := (30 * (randomFloat + 1) * float64(x)) + 1
			if mins > 480 {
				mins = 480
			}
			sb.Logger.Warn(
				"Update failed, in back-off mode (waiting %d mins): %s",
				mins,
				err,
			)
			time.Sleep(time.Duration(mins) * time.Minute)
			err, status = sb.update()
		}
		//		debug.FreeOSMemory()
	}
}
