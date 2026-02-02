package observer

import (
	"context"

	"github.com/letsencrypt/boulder/blog"
	"github.com/letsencrypt/boulder/cmd"
	_ "github.com/letsencrypt/boulder/observer/probers/crl"
	_ "github.com/letsencrypt/boulder/observer/probers/dns"
	_ "github.com/letsencrypt/boulder/observer/probers/http"
	_ "github.com/letsencrypt/boulder/observer/probers/tcp"
	_ "github.com/letsencrypt/boulder/observer/probers/tls"
)

// Observer is the steward of goroutines started for each `monitor`.
type Observer struct {
	logger   *blog.LogContext
	monitors []*monitor
	shutdown func(ctx context.Context)
}

// Start spins off a goroutine for each monitor, and waits for a signal to exit
func (o Observer) Start() {
	for _, mon := range o.monitors {
		go mon.start(o.logger)
	}

	defer o.shutdown(context.Background())
	cmd.WaitForSignal()
}
