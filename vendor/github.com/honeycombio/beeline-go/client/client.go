// Package client is used to store the state of the libhoney client
// that sends all beeline events, and provides wrappers of libhoney API
// functions that are safe to use even if the client is not initialized.
package client

import (
	libhoney "github.com/honeycombio/libhoney-go"
	"github.com/honeycombio/libhoney-go/transmission"
)

var client = &libhoney.Client{}

// Set the active libhoney client used by the beeline
func Set(c *libhoney.Client) {
	client = c
}

// Get returns the libhoney client used by the beeline
func Get() *libhoney.Client {
	return client
}

// Close the libhoney client
func Close() {
	if client != nil {
		client.Close()
	}
}

// Flush all pending events in the libhoney client
func Flush() {
	if client != nil {
		client.Flush()
	}
}

// AddField adds the given field at the client level
func AddField(name string, val interface{}) {
	if client != nil {
		client.AddField(name, val)
	}
}

func NewBuilder() *libhoney.Builder {
	if client != nil {
		return client.NewBuilder()
	}
	return &libhoney.Builder{}
}

func TxResponses() chan transmission.Response {
	if client != nil {
		client.TxResponses()
	}

	c := make(chan transmission.Response)
	close(c)
	return c
}
