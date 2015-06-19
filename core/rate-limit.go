// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"time"
)

type queue struct {
	size  int
	front int
	back  int
	data  []int64
}

func newQueue(size int) queue {
	return queue{
		size:  size,
		front: 0,
		back:  0,
		data:  make([]int64, size+1, size+1),
	}
}

func (q queue) Length() int {
	if q.front <= q.back {
		return q.back - q.front
	} else {
		return q.back - q.front + q.size + 1
	}
}

func (q queue) Head() int64 {
	return q.data[q.front]
}

func (q queue) Tail() int64 {
	if q.back == 0 {
		return q.data[q.size]
	} else {
		return q.data[q.back-1]
	}
}

func (q queue) Full() bool {
	return q.Length() >= q.size
}

func (q *queue) Push(x int64) {
	if q.Full() {
		// Fails silently; caller must check
		return
	}

	q.data[q.back] = x
	q.back = (q.back + 1) % (q.size + 1)
}

func (q *queue) Pop() (x int64) {
	if q.Length() == 0 {
		// Fails silently; caller must check
		return
	}

	x = q.data[q.front]
	q.front = (q.front + 1) % (q.size + 1)
	return
}

func (q *queue) Clear() {
	q.front = 0
	q.back = 0
}

// A RateLimiter limits each identified thing to a certain
// number of attempts per ID per unit time.  It is defined
// by the following parameters:
// * numQueues - the number of queues it will maintain
// * queueSize - the number of attempts remembered for each ID
// * window - how long each entry remains in the queue
//
// In effect, the each of `numQueues` IDs is limited to no
// more than queueSize attempts within the window.
//
// Each time an attempt is made for an ID:
// * If the ID has a queue and there is space in it, the attempt
//   is logged in the queue for that ID
// * If there are more queues remaining, a new queue is assigned
//   for that ID, and the attempt is logged there
// * Otherwise, the attempt is denied and forgotten
//
// On every attempt, we clean out old entries so that queue space
// and queues are freed up. All memory is pre-allocated on
// construction, so the size of this structure is constant.
//
// To use this structure, you may need to define a map from your
// identifier of choice to an integer ID value
//
// Application-layer things that might make sense as rate-
// limiting identifiers:
// * Account keys (at new-reg)
// * Email addresses (at new-reg)
// * label.PSL names (at new-authz)
// * full names (at new-cert, on a different time scale than the above)
type RateLimit struct {
	numQueues int
	queueSize int
	window    time.Duration

	labels map[int64]int // id -> queue index
	used   map[int]int64 // queue index -> id
	free   queue
	queues []queue
}

func NewRateLimit(numQueues, queueSize int, window time.Duration) RateLimit {
	rl := RateLimit{}
	rl.Resize(numQueues, queueSize, window)
	return rl
}

func (rl *RateLimit) Resize(numQueues, queueSize int, window time.Duration) {
	// Reset all the state variables
	rl.numQueues = numQueues
	rl.queueSize = queueSize
	rl.window = window

	rl.labels = map[int64]int{}
	rl.used = map[int]int64{}

	rl.free = newQueue(numQueues)
	rl.queues = make([]queue, numQueues, numQueues)
	for i := 0; i < numQueues; i += 1 {
		rl.queues[i] = newQueue(queueSize)
		rl.free.Push(int64(i))
	}
	return
}

func (rl *RateLimit) Trim() {
	now := time.Now()
	for i := range rl.queues {
		for rl.queues[i].Length() > 0 && now.Sub(time.Unix(rl.queues[i].Head(), 0)) > rl.window {
			rl.queues[i].Pop()
		}

		id, wasInUse := rl.used[i]
		if rl.queues[i].Length() == 0 && wasInUse {
			delete(rl.labels, id)
			delete(rl.used, i)
			rl.free.Push(int64(i))
		}
	}
}

func (rl *RateLimit) AcceptableNow(id int64) bool {
	// Always allow in degenerate cases
	if rl.numQueues == 0 || rl.queueSize == 0 || rl.window == 0 {
		return true
	}

	// Age off old events
	rl.Trim()

	now := time.Now().Unix()
	qid, known := rl.labels[id]
	if known {
		if rl.queues[qid].Full() {
			return false
		}

		rl.queues[qid].Push(now)
		return true
	} else if rl.free.Length() > 0 {
		qid = int(rl.free.Pop())
		rl.labels[id] = qid
		rl.used[qid] = id
		rl.queues[qid].Push(now)
		return true
	}

	return false
}

func (rl *RateLimit) Clear() {
	rl.labels = map[int64]int{}
	rl.used = map[int]int64{}
	rl.free.Clear()
	for i := range rl.queues {
		rl.queues[i].Clear()
		rl.free.Push(int64(i))
	}
}

// This function maps a string to the high-order 64 bits of its
// SHA-1 digest value
func StringToRateLimitID(value string) int64 {
	h := sha256.New()
	h.Write([]byte(value))
	d := h.Sum(nil)
	return int64(binary.BigEndian.Uint64(d[:8]))
}

func KeyToRateLimitID(key crypto.PublicKey) int64 {
	d64, err := KeyDigest(key)
	if err != nil {
		// XXX Map bad keys to 0
		return 0
	}

	// Ignoring error because we're just undoing what KeyDigest does
	d, _ := base64.StdEncoding.DecodeString(d64)
	return int64(binary.BigEndian.Uint64(d[:8]))
}
