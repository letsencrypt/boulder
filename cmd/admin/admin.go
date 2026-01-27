package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/jmhodges/clock"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

// admin holds all of the external connections necessary to perform admin
// actions on a boulder deployment.
type admin struct {
	rac   adminRAClient
	sac   adminSAClient
	saroc sapb.StorageAuthorityReadOnlyClient

	clk clock.Clock
	log blog.Logger
}

// adminRAClient defines the subset of RA methods that the admin tool relies on.
type adminRAClient interface {
	AdministrativelyRevokeCertificate(context.Context, *rapb.AdministrativelyRevokeCertificateRequest, ...grpc.CallOption) (*emptypb.Empty, error)
}

// adminSAClient defines the subset of SA methods that the admin tool relies on.
type adminSAClient interface {
	AddBlockedKey(context.Context, *sapb.AddBlockedKeyRequest, ...grpc.CallOption) (*emptypb.Empty, error)
	AddRateLimitOverride(context.Context, *sapb.AddRateLimitOverrideRequest, ...grpc.CallOption) (*sapb.AddRateLimitOverrideResponse, error)
	DisableRateLimitOverride(context.Context, *sapb.DisableRateLimitOverrideRequest, ...grpc.CallOption) (*emptypb.Empty, error)
	EnableRateLimitOverride(context.Context, *sapb.EnableRateLimitOverrideRequest, ...grpc.CallOption) (*emptypb.Empty, error)
	PauseIdentifiers(context.Context, *sapb.PauseRequest, ...grpc.CallOption) (*sapb.PauseIdentifiersResponse, error)
	UnpauseAccount(context.Context, *sapb.RegistrationID, ...grpc.CallOption) (*sapb.Count, error)
}

// newAdmin constructs a new admin object on the heap and returns a pointer to
// it.
func newAdmin(configFile string, dryRun bool) (*admin, error) {
	// Unlike most boulder service constructors, this does all of its own config
	// parsing and dependency setup. If this is broken out into its own package
	// (outside the //cmd/ directory) those pieces of setup should stay behind
	// in //cmd/admin/main.go, to match other boulder services.
	var c Config
	err := cmd.ReadConfigFile(configFile, &c)
	if err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	scope, logger, oTelShutdown := cmd.StatsAndLogging(c.Syslog, c.OpenTelemetry, "")
	defer oTelShutdown(context.Background())
	cmd.LogStartup(logger)

	clk := clock.New()
	features.Set(c.Admin.Features)

	tlsConfig, err := c.Admin.TLS.Load(scope)
	if err != nil {
		return nil, fmt.Errorf("loading TLS config: %w", err)
	}

	var rac adminRAClient = dryRunRAC{log: logger}
	if !dryRun {
		raConn, err := bgrpc.ClientSetup(c.Admin.RAService, tlsConfig, scope, clk)
		if err != nil {
			return nil, fmt.Errorf("creating RA gRPC client: %w", err)
		}
		rac = rapb.NewRegistrationAuthorityClient(raConn)
	}

	saConn, err := bgrpc.ClientSetup(c.Admin.SAService, tlsConfig, scope, clk)
	if err != nil {
		return nil, fmt.Errorf("creating SA gRPC client: %w", err)
	}
	saroc := sapb.NewStorageAuthorityReadOnlyClient(saConn)

	var sac adminSAClient = dryRunSAC{log: logger}
	if !dryRun {
		sac = sapb.NewStorageAuthorityClient(saConn)
	}

	return &admin{
		rac:   rac,
		sac:   sac,
		saroc: saroc,
		clk:   clk,
		log:   logger,
	}, nil
}

// findActiveInputMethodFlag returns a single key from setInputs with a value of `true`,
// if exactly one exists. Otherwise it returns an error.
func findActiveInputMethodFlag(setInputs map[string]bool) (string, error) {
	var activeFlags []string
	for flag, isSet := range setInputs {
		if isSet {
			activeFlags = append(activeFlags, flag)
		}
	}

	if len(activeFlags) == 0 {
		return "", errors.New("at least one input method flag must be specified")
	} else if len(activeFlags) > 1 {
		return "", fmt.Errorf("more than one input method flag specified: %v", activeFlags)
	}

	return activeFlags[0], nil
}
