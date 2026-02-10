package probers

import (
	"context"
	"fmt"

	"github.com/letsencrypt/boulder/config"
)

type MockProber struct {
	name    string
	kind    string
	took    config.Duration
	success bool
}

func (p MockProber) Name() string {
	return p.name
}

func (p MockProber) Kind() string {
	return p.kind
}

func (p MockProber) Probe(ctx context.Context) error {
	if !p.success {
		return fmt.Errorf("oops!")
	}
	return nil
}
