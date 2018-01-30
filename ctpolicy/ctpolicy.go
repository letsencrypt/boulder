package ctpolicy

import (
	"context"
	"errors"
	// glog "log"
	"sync"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
)

// CTPolicy is used to hold information about SCTs required from various
// groupings
type CTPolicy struct {
	pub    core.Publisher
	groups [][]cmd.LogDescription
}

func New(pub core.Publisher, groups [][]cmd.LogDescription) *CTPolicy {
	return &CTPolicy{
		pub:    pub,
		groups: groups,
	}
}

// race submits an SCT to each log in a group and waits for the first response back,
// once it has the first SCT it cancels all of the other submissions and returns.
// It allows up to len(group)-1 of the submissions to fail as we only care about
// getting a single SCT.
func (ctp *CTPolicy) race(ctx context.Context, cert []byte, group []cmd.LogDescription) ([]byte, error) {
	scts := make(chan []byte, 1)
	errs := make(chan error, len(group))
	subCtx, cancel := context.WithCancel(ctx)
	for _, l := range group {
		go func() {
			sct, err := ctp.pub.SubmitToSingleCTWithResult(subCtx, l.URI, l.Key, cert)
			if err != nil {
				errs <- err
				return
			}
			select {
			case scts <- sct:
			case <-subCtx.Done():
			}
		}()
	}

	numErr := 0
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case sct := <-scts:
			cancel()
			return sct, nil
		case <-errs:
			// glog.Printf("submission failed: %s\n", err)
			numErr++
			if numErr == len(group) {
				return nil, errors.New("all submissions for group failed")
			}
		}
	}
}

// GetSCTs attempts to retrieve a SCT from each configured grouping of logs and returns
// the set of SCTs to the caller.
func (ctp *CTPolicy) GetSCTs(ctx context.Context, cert []byte) ([][]byte, error) {
	retCh := make(chan []byte, len(ctp.groups))
	wg := new(sync.WaitGroup)
	errs := make(chan error, len(ctp.groups))
	subCtx, cancel := context.WithCancel(ctx)
	for _, v := range ctp.groups {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sct, err := ctp.race(subCtx, cert, v)
			if err != nil {
				errs <- err
				return
			}
			retCh <- sct
		}()
	}

	done := make(chan bool, 1)
	go func() {
		wg.Wait()
		done <- true
		close(retCh)
	}()
	for {
		select {
		case err := <-errs:
			// cannot continue if one of the groups failed, cancel other RPCs as well
			cancel()
			return nil, err
		case <-done:
			ret := [][]byte{}
			for sct := range retCh {
				ret = append(ret, sct)
			}
			return ret, nil
		}
	}
}
