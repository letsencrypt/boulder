package latency

import (
	"sync"
	"time"
)

type point struct {
	Sent     time.Time `json:"sent"`
	Finished time.Time `json:"finished"`
	Took     int64     `json:"took"`
	PType    string    `json:"type"`
}

// Map stuff
type Map struct {
	mu      *sync.Mutex
	Metrics map[string][]point `json:"metrics"`
	Started time.Time          `json:"started"`
	Stopped time.Time          `json:"stopped"`
}

// New returns a new latency metrics map
func New() *Map {
	return &Map{
		mu:      new(sync.Mutex),
		Metrics: make(map[string][]point),
	}
}

// Add stuff
func (m *Map) Add(endpoint string, sent, finished time.Time, pType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, found := m.Metrics[endpoint]; !found {
		m.Metrics[endpoint] = []point{}
	}
	m.Metrics[endpoint] = append(m.Metrics[endpoint], point{
		Sent:     sent,
		Finished: finished,
		Took:     finished.Sub(sent).Nanoseconds(),
		PType:    pType,
	})
}
