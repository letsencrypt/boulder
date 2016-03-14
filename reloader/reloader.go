// Package reloader provides a method to load a file whenever it changes.
package reloader

import (
	"io/ioutil"
	"os"
	"time"
)

// Wrap time.Tick so we can override it in tests.
var makeTicker = func() (func(), <-chan time.Time) {
	t := time.NewTicker(1 * time.Second)
	return t.Stop, t.C
}

// Reloader represents an ongoing reloader task.
type Reloader struct {
	stopChan chan<- struct{}
}

// Stop stops an active reloader, release its resources.
func (r *Reloader) Stop() {
	r.stopChan <- struct{}{}
}

// New loads the filename provided, and calls the callback.  It then spawns a
// goroutine to check for updates to that file, calling the callback again with
// any new contents. The first load, and the first call to callback, are run
// synchronously, so it is easy for the caller to check for errors and fail
// fast. New will return an error if it occurs on the first load. Otherwise all
// errors are sent to the callback.
func New(filename string, callback func([]byte, error) error) (*Reloader, error) {
	fileInfo, err := os.Stat(filename)
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	stopChan := make(chan struct{})
	tickerStop, tickChan := makeTicker()
	loop := func() {
		for {
			select {
			case <-stopChan:
				tickerStop()
				return
			case <-tickChan:
				currentFileInfo, err := os.Stat(filename)
				if err != nil {
					callback(nil, err)
					continue
				}
				if currentFileInfo.ModTime().After(fileInfo.ModTime()) {
					b, err := ioutil.ReadFile(filename)
					if err != nil {
						callback(nil, err)
						continue
					}
					fileInfo = currentFileInfo
					callback(b, nil)
				}
			}
		}
	}
	err = callback(b, nil)
	go loop()
	return &Reloader{stopChan}, err
}
