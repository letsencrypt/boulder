package main

import (
	"fmt"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/db"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	"github.com/letsencrypt/boulder/sa"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/prometheus/client_golang/prometheus"
)

// admin holds all of the external connections necessary to perform admin
// actions on a boulder deployment.
type admin struct {
	rac   rapb.RegistrationAuthorityClient
	sac   sapb.StorageAuthorityClient
	dbMap *db.WrappedMap

	dryRun bool

	clk clock.Clock
	log blog.Logger
}

// newAdmin constructs a new admin object on the heap and returns a pointer to
// it.
func newAdmin(c Config, dryRun bool, clk clock.Clock, logger blog.Logger, scope prometheus.Registerer) (*admin, error) {
	// Unlike most boulder service constructors, this does all of its own gRPC
	// and database connection setup. If this is broken out into its own package
	// (outside the //cmd/ directory) those pieces of setup should stay behind
	// in //cmd/admin/main.go, to match other boulder services.
	tlsConfig, err := c.Admin.TLS.Load(scope)
	if err != nil {
		return nil, fmt.Errorf("loading TLS config: %w", err)
	}

	raConn, err := bgrpc.ClientSetup(c.Admin.RAService, tlsConfig, scope, clk)
	if err != nil {
		return nil, fmt.Errorf("creating RA gRPC client: %w", err)
	}
	rac := rapb.NewRegistrationAuthorityClient(raConn)

	saConn, err := bgrpc.ClientSetup(c.Admin.SAService, tlsConfig, scope, clk)
	if err != nil {
		return nil, fmt.Errorf("creating SA gRPC client: %w", err)
	}
	sac := sapb.NewStorageAuthorityClient(saConn)

	dbMap, err := sa.InitWrappedDb(c.Admin.DB, nil, logger)
	if err != nil {
		return nil, fmt.Errorf("creating database connection: %w", err)
	}

	return &admin{
		rac:    rac,
		sac:    sac,
		dbMap:  dbMap,
		dryRun: dryRun,
		clk:    clk,
		log:    logger,
	}, nil
}
