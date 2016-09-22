package latency

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type point struct {
	Sent     time.Time `json:"sent"`
	Finished time.Time `json:"finished"`
	Took     int64     `json:"took"`
	PType    string    `json:"type"`
	Action   string    `json:"action"`
}

// File holds per endpoint metrics
type File struct {
	metrics chan *point
	f       *os.File
	die     chan struct{}
}

// New returns a new latency metrics file
func New(filename string) (*File, error) {
	fmt.Printf("[+] Opening results file %s\n", filename)
	file, err := os.OpenFile(filename, os.O_RDWR|os.O_APPEND|os.O_CREATE, os.ModePerm)
	if err != nil {
		return nil, err
	}
	f := &File{
		metrics: make(chan *point, 2048),
		die:     make(chan struct{}, 1),
		f:       file,
	}
	go f.write()
	return f, nil
}

func (f *File) write() {
	for {
		select {
		case p := <-f.metrics:
			data, err := json.Marshal(p)
			if err != nil {
				panic(err)
			}
			_, err = f.f.Write(append(data, []byte("\n")...))
			if err != nil {
				panic(err)
			}
		case <-f.die:
			return
		}
	}
}

// Add writes a point to the file
func (f *File) Add(action string, sent, finished time.Time, pType string) {
	f.metrics <- &point{
		Sent:     sent,
		Finished: finished,
		Took:     finished.Sub(sent).Nanoseconds(),
		PType:    pType,
		Action:   action,
	}
}

// Close stops f.write() and closes the file, any remaining metrics will be discarded
func (f *File) Close() {
	f.die <- struct{}{}
	_ = f.f.Close()
}
