package ctpolicy

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	pubpb "github.com/letsencrypt/boulder/publisher/proto"
)

// CTPolicy is used to hold information about SCTs required from various
// groupings
type CTPolicy struct {
	pub    core.Publisher
	groups [][]cmd.LogDescription
	log    blog.Logger
}

// New creates a new CTPolicy struct
func New(pub core.Publisher, groups [][]cmd.LogDescription, log blog.Logger) *CTPolicy {
	return &CTPolicy{
		pub:    pub,
		groups: groups,
		log:    log,
	}
}

type result struct {
	sct core.SCTDER
	err error
}

// race submits an SCT to each log in a group and waits for the first response back,
// once it has the first SCT it cancels all of the other submissions and returns.
// It allows up to len(group)-1 of the submissions to fail as we only care about
// getting a single SCT.
func (ctp *CTPolicy) race(ctx context.Context, cert core.CertDER, group []cmd.LogDescription) (core.SCTDER, error) {
	results := make(chan result, len(group))
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	for _, l := range group {
		go func(l cmd.LogDescription) {
			sct, err := ctp.pub.SubmitToSingleCTWithResult(subCtx, &pubpb.Request{
				LogURL:       &l.URI,
				LogPublicKey: &l.Key,
				Der:          cert,
			})
			if err != nil {
				// Only log the error if it is not a result of canceling subCtx
				if err != context.Canceled {
					ctp.log.Warning(fmt.Sprintf("ct submission to %q failed: %s", l.URI, err))
				}
				results <- result{err: err}
				return
			}
			results <- result{sct: sct.Sct}
		}(l)
	}

	numErr := 0
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case res := <-results:
			if res.sct != nil {
				// Return the very first SCT we get back and cancel any other
				// in progress work.
				cancel()
				return res.sct, nil
			}
			// We will continue waiting for an SCT until we've seen the same number
			// of errors as there are logs in the group as we may still get a SCT
			// back from another log.
			numErr++
			if numErr == len(group) {
				return nil, errors.New("all submissions for group failed")
			}
		}
	}
}

// GetSCTs attempts to retrieve a SCT from each configured grouping of logs and returns
// the set of SCTs to the caller.
func (ctp *CTPolicy) GetSCTs(ctx context.Context, cert core.CertDER) ([]core.SCTDER, error) {
	results := make(chan result, len(ctp.groups))
	wg := new(sync.WaitGroup)
	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	for _, g := range ctp.groups {
		wg.Add(1)
		go func(g []cmd.LogDescription) {
			defer wg.Done()
			sct, err := ctp.race(subCtx, cert, g)
			// Only one of these will be non-nil
			results <- result{sct: sct, err: err}
		}(g)
	}

	go func() {
		// The for loop below is blocked on the results channel being open,
		// once all of the goroutines spawned above are finished and any
		// writes to the channel have been completed close it so that the
		// loop can break.
		wg.Wait()
		close(results)
	}()

	ret := []core.SCTDER{}
	for res := range results {
		// If any one group fails to get a SCT then we fail out immediately
		// cancel any other in progress work as we can't continue
		if res.err != nil {
			cancel()
			return nil, res.err
		}
		ret = append(ret, res.sct)
	}
	return ret, nil
}
