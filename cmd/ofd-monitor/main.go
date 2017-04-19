package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/metrics"
)

type config struct {
	Programs map[string]string // program name: pid file path
}

func readPF(path string) (int, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(bytes)))
}

func checkOFD(pid int) (int, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return 0, err
	}
	names, err := f.Readdirnames(0)
	if err != nil {
		return 0, err
	}
	return len(names), nil
}

func main() {
	cPath := flag.String("config", "", "")
	d := flag.Duration("interval", time.Minute, "")
	statsdAddr := flag.String("statsdAddr", "localhost:8125", "")
	flag.Parse()

	cBytes, err := ioutil.ReadFile(*cPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read configuration file '%s': %s\n", *cPath, err)
		os.Exit(1)
	}
	var c config
	err = json.Unmarshal(cBytes, &c)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse configuration file '%s': %s\n", *cPath, err)
		os.Exit(1)
	}

	m, err := metrics.NewStatter(*statsdAddr, "Boulder")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create StatsD client: %s\n", err)
		os.Exit(1)
	}

	for n, p := range c.Programs {
		go func(name, path string) {
			for {
				pid, err := readPF(path)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to read PID file for '%s' at '%s': %s", name, path, err)
					continue
				}
				ofd, err := checkOFD(pid)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to read FD directory for '%s' with PID '%d': %s", name, pid, err)
					continue
				}
				m.Gauge(fmt.Sprintf("OpenFD.%s.%d", name, pid), int64(ofd), 1.0)
				time.Sleep(*d)
			}
		}(n, p)
	}
}
