package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/letsencrypt/boulder/cmd"
)

// startTime is used as a universal starting point against which other times
// can be compared, because the Go zero time is too far in the past for math
// to work correctly. The significance of 2009-11-10 23:00:00 is left as an
// exercise to the reader.
var startTime = time.Date(2009, time.November, 10, 23, 00, 00, 0, time.UTC)

type crlUpdater struct {
	numShards         int
	lookbackPeriod    time.Duration
	lookforwardPeriod time.Duration
}

// getShardBoundaries computes the start (inclusive) and end (exclusive) times
// for a given integer-indexed CRL shard. The idea here is that shards should be
// stable. Picture a timeline, divided into chunks. Number those chunks from 0
// to cu.numShards, then repeat the cycle when you run out of numbers:
//
//	   chunk:  5     0     1     2     3     4     5     0     1     2     3
//	...-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----...
//	                         ^  ^-atTime                         ^
//	   atTime-lookbackPeriod-┘          atTime+lookforwardPeriod-┘
//
// The width of each chunk is determined by dividing the total time window we
// care about (lookbackPeriod+lookforwardPeriod) by the number of shards we
// want (numShards).
//
// Even as "now" (atTime) moves forward, and the total window of expiration
// times that we care about moves forward, the boundaries of each chunk remain
// stable:
//
//	   chunk:  5     0     1     2     3     4     5     0     1     2     3
//	...-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----...
//	                                 ^  ^-atTime                         ^
//	           atTime-lookbackPeriod-┘          atTime+lookforwardPeriod-┘
//
// However, note that at essentially all times the window includes parts of two
// different instances of the chunk which appears at its ends. For example,
// in the second diagram above, the window includes almost all of the middle
// chunk labeled "3", but also includes just a little bit of the rightmost chunk
// also labeled "3".
//
// In order to handle this case, this function always treats the *leftmost*
// (i.e. earliest) chunk with the given ID that has *any* overlap with the
// current window as the current shard. It returns the boundaries of this chunk
// as the boundaries of the desired shard. In the diagram below, even though
// there is another chunk with ID "1" near the right-hand edge of the window,
// that chunk is ignored.
//
//	   shard:           |  1  |  2  |  3  |  4  |  5  |  0  |
//	...-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----...
//	                         ^  ^-atTime                         ^
//	   atTime-lookbackPeriod-┘          atTime+lookforwardPeriod-┘
//
// This means that the lookforwardPeriod MUST be configured large enough that
// there is a buffer of at least one whole chunk width between the actual
// furthest-future expiration (generally atTime+90d) and the right-hand edge of
// the window (atTime+lookforwardPeriod).
func (cu *crlUpdater) getShardBoundaries(atTime time.Time, shardIdx int) (time.Time, time.Time) {
	// Ensure that the given shard index falls within the space of acceptable indices.
	shardIdx = shardIdx % cu.numShards

	// fmt.Println()
	// fmt.Println(atTime)

	// Compute the width of the full window.
	windowWidth := cu.lookbackPeriod + cu.lookforwardPeriod

	// fmt.Println(atTime.Sub(time.Time{}))
	// fmt.Println(atTime.Sub(time.Time{}).Nanoseconds())
	// fmt.Println(atTime.Sub(startTime))
	// fmt.Println(atTime.Sub(startTime).Nanoseconds())
	// fmt.Println(windowWidth)
	// fmt.Println(windowWidth.Nanoseconds())

	// Compute the amount of time between the left-hand edge of the most recent
	// "0" chunk and the current time.
	atTimeOffset := time.Duration(atTime.Sub(startTime).Nanoseconds() % windowWidth.Nanoseconds())
	// Compute the left-hand edge of the most recent "0" chunk.
	zeroStart := atTime.Add(-atTimeOffset)

	// fmt.Println(atTimeOffset)
	// fmt.Println(zeroStart)

	// Compute the width of a single shard.
	shardWidth := time.Duration(windowWidth.Nanoseconds() / int64(cu.numShards))
	// Compute the amount of time between the left-hand edge of the most recent
	// "0" chunk and the left-hand edge of the desired chunk.
	shardOffset := time.Duration(int64(shardIdx) * shardWidth.Nanoseconds())
	// Compute the left-hand edge of the most recent chunk with the given index.
	shardStart := zeroStart.Add(shardOffset)
	// Compute the right-hand edge of the most recent chunk with the given index.
	shardEnd := shardStart.Add(shardWidth)

	// But the shard boundaries we just computed might be for a chunk that is
	// completely behind the left-hand edge of our current window. If they are,
	// bump them forward by one window width to bring them inside our window.
	if shardEnd.Before(atTime.Add(-cu.lookbackPeriod)) {
		shardStart = shardStart.Add(windowWidth)
		shardEnd = shardEnd.Add(windowWidth)
	}
	return shardStart, shardEnd
}

func main() {
	numShards := flag.Int("numShards", 128, "Number of partitions of the CRL")
	certLifetimeStr := flag.String("certLifetime", "2160h", "Lifetime of a cert")
	updatePeriodStr := flag.String("updatePeriod", "6h", "How frequently the updater runs")
	flag.Parse()

	certLifetime, err := time.ParseDuration(*certLifetimeStr)
	cmd.FailOnError(err, "parsing certLifetime flag")

	updatePeriod, err := time.ParseDuration(*updatePeriodStr)
	cmd.FailOnError(err, "parsing updatePeriod flag")

	// This code taken directly from //crl/updater.New().
	lookbackPeriod := 4 * updatePeriod
	tentativeShardWidth := (lookbackPeriod + certLifetime).Nanoseconds() / int64(*numShards)
	lookforwardPeriod := certLifetime + time.Duration(4*tentativeShardWidth)
	window := lookbackPeriod + lookforwardPeriod
	offset := window.Nanoseconds() % int64(*numShards)
	if offset != 0 {
		lookforwardPeriod += time.Duration(int64(*numShards) - offset)
	}

	cu := crlUpdater{
		numShards:         *numShards,
		lookbackPeriod:    lookbackPeriod,
		lookforwardPeriod: lookforwardPeriod,
	}

	now := time.Now()
	for i := 0; i < cu.numShards; i++ {
		fmt.Printf("Shard %02d:\n", i)
		atTime := now
		for j := 0; j < 10; j++ {
			atTime = atTime.Add(updatePeriod)
			left, right := cu.getShardBoundaries(atTime, i)
			fmt.Printf(
				"  %s: %s - %s\n",
				atTime.Format(time.RFC3339), left.Format(time.RFC3339), right.Format(time.RFC3339))
		}
	}
}
