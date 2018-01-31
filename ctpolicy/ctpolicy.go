package ctpolicy

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
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
			sct, err := ctp.pub.SubmitToSingleCTWithResult(subCtx, l.URI, l.Key, cert)
			if err != nil {
				// NOTE(@roland): I'm not sure if calling cancel() will trigger context.DeadlineExceeded
				// errors here, but I think it will. Probably in that case we should ignore those errors
				// but that will mask cases where we are _actually_ timing out regularly... ¯\_(ツ)_/¯
				ctp.log.Warning(fmt.Sprintf("ct submission to %q failed: %s", l.URI, err))
				results <- result{err: err}
				return
			}
			select {
			case results <- result{sct: sct}:
			case <-subCtx.Done():
			}
		}(l)
	}

	numErr := 0
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case res := <-results:
			if res.sct != nil {
				cancel()
				return res.sct, nil
			}
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
			if err != nil {
				results <- result{err: err}
				return
			}
			results <- result{sct: sct}
		}(g)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	ret := []core.SCTDER{}
	for res := range results {
		if res.err != nil {
			cancel()
			return nil, res.err
		}
		ret = append(ret, res.sct)
	}
	return ret, nil
}
