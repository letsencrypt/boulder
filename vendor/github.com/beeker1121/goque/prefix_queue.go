package goque

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"os"
	"sync"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
)

// prefixDelimiter defines the delimiter used to separate a prefix from an
// item ID within the LevelDB database. We use the lowest possible value for
// a single byte, 0x00 (null), as the delimiter.
const prefixDelimiter byte = '\x00'

// queue defines the unique queue for a prefix.
type queue struct {
	Head uint64
	Tail uint64
}

// Length returns the total number of items in the queue.
func (q *queue) Length() uint64 {
	return q.Tail - q.Head
}

// PrefixQueue is a standard FIFO (first in, first out) queue that separates
// each given prefix into its own queue.
type PrefixQueue struct {
	sync.RWMutex
	DataDir string
	db      *leveldb.DB
	size    uint64
	isOpen  bool
}

// OpenPrefixQueue opens a prefix queue if one exists at the given directory.
// If one does not already exist, a new prefix queue is created.
func OpenPrefixQueue(dataDir string) (*PrefixQueue, error) {
	var err error

	// Create a new Queue.
	pq := &PrefixQueue{
		DataDir: dataDir,
		db:      &leveldb.DB{},
		isOpen:  false,
	}

	// Open database for the prefix queue.
	pq.db, err = leveldb.OpenFile(dataDir, nil)
	if err != nil {
		return nil, err
	}

	// Check if this Goque type can open the requested data directory.
	ok, err := checkGoqueType(dataDir, goquePrefixQueue)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrIncompatibleType
	}

	// Set isOpen and return.
	pq.isOpen = true
	return pq, pq.init()
}

// Enqueue adds an item to the queue.
func (pq *PrefixQueue) Enqueue(prefix, value []byte) (*Item, error) {
	pq.Lock()
	defer pq.Unlock()

	// Check if queue is closed.
	if !pq.isOpen {
		return nil, ErrDBClosed
	}

	// Get the queue for this prefix.
	q, err := pq.getOrCreateQueue(prefix)
	if err != nil {
		return nil, err
	}

	// Create new Item.
	item := &Item{
		ID:    q.Tail + 1,
		Key:   generateKeyPrefixID(prefix, q.Tail+1),
		Value: value,
	}

	// Add it to the queue.
	if err := pq.db.Put(item.Key, item.Value, nil); err != nil {
		return nil, err
	}

	// Increment tail position and prefix queue size.
	q.Tail++
	pq.size++

	// Save the queue.
	if err := pq.saveQueue(prefix, q); err != nil {
		return nil, err
	}

	// Save main prefix queue data.
	if err := pq.save(); err != nil {
		return nil, err
	}

	return item, nil
}

// EnqueueString is a helper function for Enqueue that accepts the prefix and
// value as a string rather than a byte slice.
func (pq *PrefixQueue) EnqueueString(prefix, value string) (*Item, error) {
	return pq.Enqueue([]byte(prefix), []byte(value))
}

// EnqueueObject is a helper function for Enqueue that accepts any
// value type, which is then encoded into a byte slice using
// encoding/gob.
//
// Objects containing pointers with zero values will decode to nil
// when using this function. This is due to how the encoding/gob
// package works. Because of this, you should only use this function
// to encode simple types.
func (pq *PrefixQueue) EnqueueObject(prefix []byte, value interface{}) (*Item, error) {
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}

	return pq.Enqueue(prefix, buffer.Bytes())
}

// EnqueueObjectAsJSON is a helper function for Enqueue that accepts
// any value type, which is then encoded into a JSON byte slice using
// encoding/json.
//
// Use this function to handle encoding of complex types.
func (pq *PrefixQueue) EnqueueObjectAsJSON(prefix []byte, value interface{}) (*Item, error) {
	jsonBytes, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	return pq.Enqueue(prefix, jsonBytes)
}

// Dequeue removes the next item in the prefix queue and returns it.
func (pq *PrefixQueue) Dequeue(prefix []byte) (*Item, error) {
	pq.Lock()
	defer pq.Unlock()

	// Check if queue is closed.
	if !pq.isOpen {
		return nil, ErrDBClosed
	}

	// Get the queue for this prefix.
	q, err := pq.getQueue(prefix)
	if err != nil {
		return nil, err
	}

	// Try to get the next item in the queue.
	item, err := pq.getItemByPrefixID(prefix, q.Head+1)
	if err != nil {
		return nil, err
	}

	// Remove this item from the queue.
	if err := pq.db.Delete(item.Key, nil); err != nil {
		return nil, err
	}

	// Increment head position and decrement prefix queue size.
	q.Head++
	pq.size--

	// Save the queue.
	if err := pq.saveQueue(prefix, q); err != nil {
		return nil, err
	}

	// Save main prefix queue data.
	if err := pq.save(); err != nil {
		return nil, err
	}

	return item, nil
}

// DequeueString is a helper function for Dequeue that accepts the prefix as a
// string rather than a byte slice.
func (pq *PrefixQueue) DequeueString(prefix string) (*Item, error) {
	return pq.Dequeue([]byte(prefix))
}

// Peek returns the next item in the given queue without removing it.
func (pq *PrefixQueue) Peek(prefix []byte) (*Item, error) {
	pq.RLock()
	defer pq.RUnlock()

	// Check if queue is closed.
	if !pq.isOpen {
		return nil, ErrDBClosed
	}

	// Get the queue for this prefix.
	q, err := pq.getQueue(prefix)
	if err != nil {
		return nil, err
	}

	return pq.getItemByPrefixID(prefix, q.Head+1)
}

// PeekString is a helper function for Peek that accepts the prefix as a
// string rather than a byte slice.
func (pq *PrefixQueue) PeekString(prefix string) (*Item, error) {
	return pq.Peek([]byte(prefix))
}

// PeekByID returns the item with the given ID without removing it.
func (pq *PrefixQueue) PeekByID(prefix []byte, id uint64) (*Item, error) {
	pq.RLock()
	defer pq.RUnlock()

	// Check if queue is closed.
	if !pq.isOpen {
		return nil, ErrDBClosed
	}

	return pq.getItemByPrefixID(prefix, id)
}

// PeekByIDString is a helper function for Peek that accepts the prefix as a
// string rather than a byte slice.
func (pq *PrefixQueue) PeekByIDString(prefix string, id uint64) (*Item, error) {
	return pq.PeekByID([]byte(prefix), id)
}

// Update updates an item in the given queue without changing its position.
func (pq *PrefixQueue) Update(prefix []byte, id uint64, newValue []byte) (*Item, error) {
	pq.Lock()
	defer pq.Unlock()

	// Check if queue is closed.
	if !pq.isOpen {
		return nil, ErrDBClosed
	}

	// Get the queue for this prefix.
	q, err := pq.getQueue(prefix)
	if err != nil {
		return nil, err
	}

	// Check if item exists in queue.
	if id <= q.Head || id > q.Tail {
		return nil, ErrOutOfBounds
	}

	// Create new Item.
	item := &Item{
		ID:    id,
		Key:   generateKeyPrefixID(prefix, id),
		Value: newValue,
	}

	// Update this item in the queue.
	if err := pq.db.Put(item.Key, item.Value, nil); err != nil {
		return nil, err
	}

	return item, nil
}

// UpdateString is a helper function for Update that accepts the prefix and
// value as a string rather than a byte slice.
func (pq *PrefixQueue) UpdateString(prefix string, id uint64, value string) (*Item, error) {
	return pq.Update([]byte(prefix), id, []byte(value))
}

// UpdateObject is a helper function for Update that accepts any
// value type, which is then encoded into a byte slice using
// encoding/gob.
//
// Objects containing pointers with zero values will decode to nil
// when using this function. This is due to how the encoding/gob
// package works. Because of this, you should only use this function
// to encode simple types.
func (pq *PrefixQueue) UpdateObject(prefix []byte, id uint64, newValue interface{}) (*Item, error) {
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	if err := enc.Encode(newValue); err != nil {
		return nil, err
	}
	return pq.Update(prefix, id, buffer.Bytes())
}

// UpdateObjectAsJSON is a helper function for Update that accepts
// any value type, which is then encoded into a JSON byte slice using
// encoding/json.
//
// Use this function to handle encoding of complex types.
func (pq *PrefixQueue) UpdateObjectAsJSON(prefix []byte, id uint64, newValue interface{}) (*Item, error) {
	jsonBytes, err := json.Marshal(newValue)
	if err != nil {
		return nil, err
	}

	return pq.Update(prefix, id, jsonBytes)
}

// Length returns the total number of items in the prefix queue.
func (pq *PrefixQueue) Length() uint64 {
	return pq.size
}

// Close closes the LevelDB database of the prefix queue.
func (pq *PrefixQueue) Close() error {
	pq.Lock()
	defer pq.Unlock()

	// Check if queue is already closed.
	if !pq.isOpen {
		return nil
	}

	// Close the LevelDB database.
	if err := pq.db.Close(); err != nil {
		return err
	}

	// Reset size and set isOpen to false.
	pq.size = 0
	pq.isOpen = false

	return nil
}

// Drop closes and deletes the LevelDB database of the prefix queue.
func (pq *PrefixQueue) Drop() error {
	if err := pq.Close(); err != nil {
		return err
	}

	return os.RemoveAll(pq.DataDir)
}

// getQueue gets the unique queue for the given prefix.
func (pq *PrefixQueue) getQueue(prefix []byte) (*queue, error) {
	// Try to get the queue gob value.
	qval, err := pq.db.Get(generateKeyPrefixData(prefix), nil)
	if err == errors.ErrNotFound {
		return nil, ErrEmpty
	} else if err != nil {
		return nil, err
	}

	// Decode gob to our queue type.
	q := &queue{}
	buffer := bytes.NewBuffer(qval)
	dec := gob.NewDecoder(buffer)
	return q, dec.Decode(q)
}

// getOrCreateQueue gets the unique queue for the given prefix. If one does not
// already exist, a new queue is created.
func (pq *PrefixQueue) getOrCreateQueue(prefix []byte) (*queue, error) {
	// Try to get the queue gob value.
	qval, err := pq.db.Get(generateKeyPrefixData(prefix), nil)
	if err == errors.ErrNotFound {
		return &queue{}, nil
	} else if err != nil {
		return nil, err
	}

	// Decode gob to our queue type.
	q := &queue{}
	buffer := bytes.NewBuffer(qval)
	dec := gob.NewDecoder(buffer)
	return q, dec.Decode(q)
}

// savePrefixQueue saves the given queue for the given prefix.
func (pq *PrefixQueue) saveQueue(prefix []byte, q *queue) error {
	// Encode the queue using gob.
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	if err := enc.Encode(q); err != nil {
		return err
	}

	// Save it to the database.
	return pq.db.Put(generateKeyPrefixData(prefix), buffer.Bytes(), nil)
}

// save saves the main prefix queue data.
func (pq *PrefixQueue) save() error {
	val := make([]byte, 8)
	binary.BigEndian.PutUint64(val, pq.size)
	return pq.db.Put(pq.getDataKey(), val, nil)
}

// getDataKey generates the main prefix queue data key.
func (pq *PrefixQueue) getDataKey() []byte {
	var key []byte
	key = append(key, prefixDelimiter)
	return append(key, []byte(":main_data")...)
}

// getItemByPrefixID returns an item, if found, for the given prefix and ID.
func (pq *PrefixQueue) getItemByPrefixID(prefix []byte, id uint64) (*Item, error) {
	// Check if empty.
	if pq.size == 0 {
		return nil, ErrEmpty
	}

	// Get the queue for this prefix.
	q, err := pq.getQueue(prefix)
	if err != nil {
		return nil, err
	}

	// Check if out of bounds.
	if id <= q.Head || id > q.Tail {
		return nil, ErrOutOfBounds
	}

	// Get item from database.
	item := &Item{
		ID:  id,
		Key: generateKeyPrefixID(prefix, id),
	}

	if item.Value, err = pq.db.Get(item.Key, nil); err != nil {
		return nil, err
	}

	return item, nil
}

// init initializes the prefix queue data.
func (pq *PrefixQueue) init() error {
	// Get the main prefix queue data.
	val, err := pq.db.Get(pq.getDataKey(), nil)
	if err == errors.ErrNotFound {
		return nil
	} else if err != nil {
		return err
	}

	pq.size = binary.BigEndian.Uint64(val)
	return nil
}

// generateKeyPrefixData generates a data key using the given prefix. This key
// should be used to get the stored queue struct for the given prefix.
func generateKeyPrefixData(prefix []byte) []byte {
	return append(prefix, []byte(":data")...)
}

// generateKeyPrefixID generates a key using the given prefix and ID.
func generateKeyPrefixID(prefix []byte, id uint64) []byte {
	// Handle the prefix.
	key := append(prefix, prefixDelimiter)

	// Handle the item ID.
	key = append(key, idToKey(id)...)

	return key
}
