package ctpolicy

import (
	"context"
	"errors"
	"fmt"

	"github.com/letsencrypt/boulder/canceled"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	pubpb "github.com/letsencrypt/boulder/publisher/proto"
)

// CTPolicy is used to hold information about SCTs required from various
// groupings
type CTPolicy struct {
	pub           core.Publisher
	groups        []cmd.CTGroup
	informational []cmd.LogDescription
	finalLogs     []*pubpb.Log
	log           blog.Logger
}

// New creates a new CTPolicy struct
func New(pub core.Publisher, groups []cmd.CTGroup, informational []cmd.LogDescription, log blog.Logger) *CTPolicy {
	var finalLogs []*pubpb.Log
	for _, group := range groups {
		for _, log := range group.Logs {
			if log.SubmitFinalCert {
				finalLogs = append(finalLogs, &pubpb.Log{
					URL:       &log.URI,
					PublicKey: &log.Key,
				})
			}
		}
	}
	for _, log := range informational {
		if log.SubmitFinalCert {
			finalLogs = append(finalLogs, &pubpb.Log{
				URL:       &log.URI,
				PublicKey: &log.Key,
			})
		}
	}

	return &CTPolicy{
		pub:           pub,
		groups:        groups,
		informational: informational,
		finalLogs:     finalLogs,
		log:           log,
	}
}

type result struct {
	sct []byte
	err error
}

// race submits an SCT to each log in a group and waits for the first response back,
// once it has the first SCT it cancels all of the other submissions and returns.
// It allows up to len(group)-1 of the submissions to fail as we only care about
// getting a single SCT.
func (ctp *CTPolicy) race(ctx context.Context, cert core.CertDER, group cmd.CTGroup) ([]byte, error) {
	results := make(chan result, len(group.Logs))
	var subCtx context.Context
	var cancel func()
	if features.Enabled(features.CancelCTSubmissions) {
		subCtx, cancel = context.WithCancel(ctx)
	} else {
		subCtx, cancel = ctx, func() {}
	}
	defer cancel()
	isPrecert := features.Enabled(features.EmbedSCTs)
	for _, l := range group.Logs {
		go func(l cmd.LogDescription) {
			sct, err := ctp.pub.SubmitToSingleCTWithResult(subCtx, &pubpb.Request{
				LogURL:       &l.URI,
				LogPublicKey: &l.Key,
				Der:          cert,
				Precert:      &isPrecert,
			})
			if err != nil {
				// Only log the error if it is not a result of canceling subCtx
				if !canceled.Is(err) {
					ctp.log.Warning(fmt.Sprintf("ct submission to %q failed: %s", l.URI, err))
				}
				results <- result{err: err}
				return
			}
			results <- result{sct: sct.Sct}
		}(l)
	}

	for i := 0; i < len(group.Logs); i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case res := <-results:
			if res.sct != nil {
				// Return the very first SCT we get back. Returning triggers
				// the defer'd context cancellation method.
				return res.sct, nil
			}
			// We will continue waiting for an SCT until we've seen the same number
			// of errors as there are logs in the group as we may still get a SCT
			// back from another log.
		}
	}
	return nil, errors.New("all submissions failed")
}

// GetSCTs attempts to retrieve a SCT from each configured grouping of logs and returns
// the set of SCTs to the caller.
func (ctp *CTPolicy) GetSCTs(ctx context.Context, cert core.CertDER) (core.SCTDERs, error) {
	results := make(chan result, len(ctp.groups))
	var subCtx context.Context
	var cancel func()
	if features.Enabled(features.CancelCTSubmissions) {
		subCtx, cancel = context.WithCancel(ctx)
	} else {
		subCtx, cancel = ctx, func() {}
	}
	defer cancel()
	for i, g := range ctp.groups {
		go func(i int, g cmd.CTGroup) {
			sct, err := ctp.race(subCtx, cert, g)
			// Only one of these will be non-nil
			if err != nil {
				results <- result{err: berrors.MissingSCTsError("CT log group %q: %s", g.Name, err)}
			}
			results <- result{sct: sct}
		}(i, g)
	}
	isPrecert := features.Enabled(features.EmbedSCTs)
	for _, log := range ctp.informational {
		go func(l cmd.LogDescription) {
			_, err := ctp.pub.SubmitToSingleCTWithResult(subCtx, &pubpb.Request{
				LogURL:       &l.URI,
				LogPublicKey: &l.Key,
				Der:          cert,
				Precert:      &isPrecert,
			})
			if err != nil {
				ctp.log.Warning(fmt.Sprintf("ct submission to informational log %q failed: %s", l.URI, err))
			}
		}(log)
	}

	var ret core.SCTDERs
	for i := 0; i < len(ctp.groups); i++ {
		res := <-results
		// If any one group fails to get a SCT then we fail out immediately
		// cancel any other in progress work as we can't continue
		if res.err != nil {
			// Returning triggers the defer'd context cancellation method
			return nil, res.err
		}
		ret = append(ret, res.sct)
	}
	return ret, nil
}

// SubmitFinalCert ...
func (ctp *CTPolicy) SubmitFinalCert(ctx context.Context, cert []byte) {
	// Any errors will be logged at the publisher
	err := ctp.pub.SubmitToMultipleCT(ctx, &pubpb.MultipleRequest{Cert: cert, Logs: ctp.finalLogs})
	if err != nil {
		ctp.log.Err(fmt.Sprintf("SubmitToMultipleCT RPC failed: %s", err))
	}
}
