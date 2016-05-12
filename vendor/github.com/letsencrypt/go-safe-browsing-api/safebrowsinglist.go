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
	"encoding/gob"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	//	"runtime/debug"
	"sync"
)

//import "encoding/hex"

type SafeBrowsingList struct {
	Name     string
	FileName string

	DataRedirects []string
	DeleteChunks  map[ChunkData_ChunkType]map[ChunkNum]bool
	ChunkRanges   map[ChunkData_ChunkType]string

	// lookup map only contain prefix hash
	Lookup            *HatTrie
	FullHashRequested *HatTrie
	FullHashes        *HatTrie

	Logger logger
	// fsLock is wrapped around the filesystem modifications and a call to
	// updateLock to prevent more than one set of fs modifications happening at
	// once.
	fsLock *sync.Mutex
	// updateLock prevents more than one pointer swap
	updateLock *sync.RWMutex
}

func newSafeBrowsingList(name string, filename string) (sbl *SafeBrowsingList) {
	sbl = &SafeBrowsingList{
		Name:              name,
		FileName:          filename,
		DataRedirects:     make([]string, 0),
		Lookup:            NewTrie(),
		FullHashRequested: NewTrie(),
		FullHashes:        NewTrie(),
		DeleteChunks:      make(map[ChunkData_ChunkType]map[ChunkNum]bool),
		Logger:            &DefaultLogger{},
		fsLock:            new(sync.Mutex),
		updateLock:        new(sync.RWMutex),
	}
	sbl.DeleteChunks[CHUNK_TYPE_ADD] = make(map[ChunkNum]bool)
	sbl.DeleteChunks[CHUNK_TYPE_SUB] = make(map[ChunkNum]bool)
	return sbl
}

func (sbl *SafeBrowsingList) loadDataFromRedirectLists() error {
	//	defer debug.FreeOSMemory()

	if len(sbl.DataRedirects) < 1 {
		sbl.Logger.Info("No pending updates available")
		return nil
	}

	newChunks := make([]*ChunkData, 0)

	for _, url := range sbl.DataRedirects {
		response, err := request(url, "", false)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			return fmt.Errorf("Unexpected server response code: %d",
				response.StatusCode)
		}
		data, err := ioutil.ReadAll(response.Body)
		length := uint32(len(data))
		len := length
		for len != 0 {
			chunk, new_len, err := ReadChunk(data[(length-len):], len)
			if err != nil {
				return err
			}
			len = new_len
			newChunks = append(newChunks, chunk)
		}
	}
	if newChunks[0] == nil {
		return fmt.Errorf("No chunk : empty redirect file")
	}
	return sbl.load(newChunks)
}

func (sbl *SafeBrowsingList) load(newChunks []*ChunkData) (err error) {
	//	defer debug.FreeOSMemory()

	sbl.Logger.Info("Reloading %s", sbl.Name)
	sbl.fsLock.Lock()
	defer sbl.fsLock.Unlock()

	//  get the input stream
	f, err := os.Open(sbl.FileName)
	if err != nil && !os.IsNotExist(err) {
		sbl.Logger.Warn("Error opening data file for reading, assuming empty: %s", err)
	}
	close_file := func(f *os.File) {
		if f != nil {
			f.Close()
		}
	}
	defer close_file(f)

	var dec *gob.Decoder = nil
	if f != nil {
		dec = gob.NewDecoder(f)
	}

	// open the file again for output
	fOut, err := os.Create(sbl.FileName + ".tmp")
	if err != nil {
		return fmt.Errorf("Error opening file: %s", err)
	}
	close_tmp_file := func(fout *os.File, fileName string) {
		if fout != nil {
			fOut.Close()
			os.Remove(fileName + ".tmp")
		}
	}
	defer close_tmp_file(fOut, sbl.FileName)

	enc := gob.NewEncoder(fOut)

	// the chunks we loaded for the next request to the server
	addChunkIndexes := make(map[ChunkNum]bool)
	subChunkIndexes := make(map[ChunkNum]bool)

	// reset the lookup map
	newEntryCount := 0
	subEntryCount := 0
	deletedChunkCount := 0
	addedChunkCount := len(newChunks)

	// load existing chunk
	if dec != nil {
		for {
			chunk := &ChunkData{}
			err = dec.Decode(&chunk)
			if err != nil {
				break
			}
			cast := ChunkNum(chunk.GetChunkNumber())
			if _, exists := sbl.DeleteChunks[chunk.GetChunkType()][cast]; exists {
				// skip this chunk, we've been instructed to delete it
				deletedChunkCount++
				continue
			} else if chunk.GetChunkType() == CHUNK_TYPE_ADD && chunk.GetPrefixType() == PREFIX_4B {
				addChunkIndexes[cast] = true
				newEntryCount += len(chunk.Hashes) / PREFIX_4B_SZ
			} else if chunk.GetChunkType() == CHUNK_TYPE_ADD && chunk.GetPrefixType() == PREFIX_32B {
				addChunkIndexes[cast] = true
				newEntryCount += len(chunk.Hashes) / PREFIX_32B_SZ
			} else if chunk.GetChunkType() == CHUNK_TYPE_SUB && chunk.GetPrefixType() == PREFIX_4B {
				subChunkIndexes[cast] = true
				subEntryCount += len(chunk.Hashes) / PREFIX_4B_SZ
			} else if chunk.GetChunkType() == CHUNK_TYPE_SUB && chunk.GetPrefixType() == PREFIX_32B {
				subChunkIndexes[cast] = true
				subEntryCount += len(chunk.Hashes) / PREFIX_32B_SZ
			} else {
				sbl.Logger.Warn("Chunk not decoded properly")
			}

			if enc != nil {
				err = enc.Encode(chunk)
				if err != nil {
					return err
				}
			}
			sbl.updateLookupMap(chunk)
		}
		if err != io.EOF {
			return err
		}
	}
	// add on any new chunks
	if newChunks != nil {
		for _, chunk := range newChunks {
			cast := ChunkNum(chunk.GetChunkNumber())
			if _, exists := sbl.DeleteChunks[chunk.GetChunkType()][cast]; exists {
				// skip this chunk, we've been instructed to delete it
				addedChunkCount--
				continue
			} else if chunk.GetChunkType() == CHUNK_TYPE_ADD && chunk.GetPrefixType() == PREFIX_4B {
				addChunkIndexes[cast] = true
				newEntryCount += len(chunk.Hashes) / PREFIX_4B_SZ
			} else if chunk.GetChunkType() == CHUNK_TYPE_ADD && chunk.GetPrefixType() == PREFIX_32B {
				addChunkIndexes[cast] = true
				newEntryCount += len(chunk.Hashes) / PREFIX_32B_SZ
			} else if chunk.GetChunkType() == CHUNK_TYPE_SUB && chunk.GetPrefixType() == PREFIX_4B {
				subChunkIndexes[cast] = true
				subEntryCount += len(chunk.Hashes) / PREFIX_4B_SZ
			} else if chunk.GetChunkType() == CHUNK_TYPE_SUB && chunk.GetPrefixType() == PREFIX_32B {
				subChunkIndexes[cast] = true
				subEntryCount += len(chunk.Hashes) / PREFIX_32B_SZ
			} else {
				sbl.Logger.Warn("Unknow chunk type")
				addedChunkCount--
				continue
			}

			if enc != nil {
				err = enc.Encode(chunk)
				if err != nil {
					return err
				}
			}
			sbl.updateLookupMap(chunk)
		}
	}

	// now close off our files, discard the old and keep the new
	if f != nil {
		err = os.Remove(sbl.FileName)
		if err != nil {
			return err
		}
	}
	err = os.Rename(sbl.FileName+".tmp", sbl.FileName)
	if err != nil {
		return err
	}

	sbl.ChunkRanges = map[ChunkData_ChunkType]string{
		CHUNK_TYPE_ADD: buildChunkRanges(addChunkIndexes),
		CHUNK_TYPE_SUB: buildChunkRanges(subChunkIndexes),
	}
	sbl.DeleteChunks = make(map[ChunkData_ChunkType]map[ChunkNum]bool)

	sbl.Logger.Info("Loaded %d existing add chunks and %d sub chunks "+
		"(~ %d hashes added, ~ %d hashes removed), deleted %d chunks, added %d new chunks.",
		len(addChunkIndexes),
		len(subChunkIndexes),
		newEntryCount,
		subEntryCount,
		deletedChunkCount,
		addedChunkCount,
	)
	return nil
}

func (sbl *SafeBrowsingList) updateLookupMap(chunk *ChunkData) {
	hashlen := 0
	hasheslen := len(chunk.Hashes)

	if chunk.GetPrefixType() == PREFIX_4B {
		hashlen = PREFIX_4B_SZ
	}
	if chunk.GetPrefixType() == PREFIX_32B {
		hashlen = PREFIX_32B_SZ
	}

	for i := 0; (i + hashlen) <= hasheslen; i += hashlen {
		hash := chunk.Hashes[i:(i + hashlen)]
		// We may have to make this more fine grained
		sbl.updateLock.Lock()
		switch hashlen {
		case PREFIX_4B_SZ:
			// we are a hash-prefix
			prefix := string(hash)
			switch chunk.GetChunkType() {
			case CHUNK_TYPE_ADD:
				sbl.Lookup.Set(prefix)
			case CHUNK_TYPE_SUB:
				sbl.Lookup.Delete(prefix)
				i := sbl.FullHashes.Iterator()
				for key := i.Next(); key != ""; key = i.Next() {
					keyPrefix := key[0:len(prefix)]
					if keyPrefix == prefix {
						sbl.FullHashes.Delete(key)
					}
				}
			}
		case PREFIX_32B_SZ:
			// we are a full-length hash
			lookupHash := string(hash)
			switch chunk.GetChunkType() {
			case CHUNK_TYPE_ADD:
				//                              sbl.Logger.Debug("Adding full length hash: %s",
				//                                      hex.EncodeToString([]byte(lookupHash)))
				sbl.FullHashes.Set(lookupHash)
			case CHUNK_TYPE_SUB:
				//                              sbl.Logger.Debug("sub full length hash: %s",
				//                                      hex.EncodeToString([]byte(lookupHash)))
				sbl.FullHashes.Delete(lookupHash)
			}
		}
		sbl.updateLock.Unlock()

	}
}
