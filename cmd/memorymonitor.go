package cmd

import (
	"fmt"
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"time"

	blog "github.com/letsencrypt/boulder/log"
)

// memoryCheckPeriod indicates how frequently we'll check for high-memory-usage conditions.
const memoryCheckPeriod = 10 * time.Second

// profileDumpPeriod limits how frequently we will dump profiles to disk.
const profileDumpPeriod = 1 * time.Hour

// MemoryMonitor runs a loop, checking every 10 seconds if memory use is greater
// than GOMEMLIMIT. If so, it dumps memory and goroutine profiles to temporary files
// created by os.CreateTemp, at most once per hour.
//
// If GOMEMLIMIT is unset, returns immediately.
func MemoryMonitor() {
	memLimit := debug.SetMemoryLimit(-1)
	if memLimit == math.MaxInt64 {
		return
	}
	memLimitU64 := uint64(memLimit) //nolint:gosec // G115: memLimit is not negative

	var memStats runtime.MemStats
	ticker := time.NewTicker(memoryCheckPeriod)
	for {
		<-ticker.C

		runtime.ReadMemStats(&memStats)

		if memStats.Sys-memStats.HeapReleased > memLimitU64 {
			logger := blog.Get()
			err := writeProfile(logger, "heap")
			if err != nil {
				logger.Errf("writing heap profile: %s", err)
			}
			err = writeProfile(logger, "goroutine")
			if err != nil {
				logger.Errf("writing goroutine profile: %s", err)
			}

			time.Sleep(profileDumpPeriod)
		}
	}
}

func writeProfile(logger blog.Logger, typ string) error {
	datestamp := time.Now().Format("20060102T150405")
	profileFile, err := os.CreateTemp("", fmt.Sprintf("boulder-profile-%s-%s.pprof", typ, datestamp))
	if err != nil {
		return fmt.Errorf("creating profile file: %s", err)
	}
	defer profileFile.Close()
	logger.Infof("Writing %s profile to %s", typ, profileFile.Name())
	err = pprof.Lookup(typ).WriteTo(profileFile, 0)
	if err != nil {
		return fmt.Errorf("writing profile: %s", err)
	}
	return nil
}
