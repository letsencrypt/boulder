package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os/user"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/privatekey"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

// subcommandBlockKey encapsulates the "admin block-key" command.
func (a *admin) subcommandBlockKey(ctx context.Context, args []string) error {
	subflags := flag.NewFlagSet("block-key", flag.ExitOnError)
	privKey := subflags.String("private-key", "", "Block issuance for the pubkey corresponding to this private key")
	comment := subflags.String("comment", "", "Additional context to add to database comment column")
	_ = subflags.Parse(args)

	if *privKey == "" {
		return errors.New("the -private-key flag is required")
	}

	spkiHash, err := a.spkiHashFromPrivateKey(*privKey)
	if err != nil {
		return err
	}

	err = a.blockSPKIHash(ctx, spkiHash, *comment)
	if err != nil {
		return err
	}

	return nil
}

func (a *admin) spkiHashFromPrivateKey(keyFile string) ([]byte, error) {
	_, publicKey, err := privatekey.Load(keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading private key file: %w", err)
	}

	spkiHash, err := core.KeyDigest(publicKey)
	if err != nil {
		return nil, fmt.Errorf("computing SPKI hash: %w", err)
	}

	return spkiHash[:], nil
}

func (a *admin) blockSPKIHash(ctx context.Context, spkiHash []byte, comment string) error {
	exists, err := a.saroc.KeyBlocked(ctx, &sapb.SPKIHash{KeyHash: spkiHash})
	if err != nil {
		return fmt.Errorf("checking if key is already blocked: %w", err)
	}
	if exists.Exists {
		return errors.New("the provided key already exists in the 'blockedKeys' table")
	}

	stream, err := a.saroc.GetSerialsByKey(ctx, &sapb.SPKIHash{KeyHash: spkiHash})
	if err != nil {
		return fmt.Errorf("setting up stream of serials from SA: %s", err)
	}

	var count int
	for {
		_, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("streaming serials from SA: %s", err)
		}
		count++
	}

	a.log.Infof("Found %d unexpired certificates matching the provided key", count)

	u, err := user.Current()
	if err != nil {
		return fmt.Errorf("getting admin username: %w", err)
	}

	_, err = a.sac.AddBlockedKey(ctx, &sapb.AddBlockedKeyRequest{
		KeyHash:   spkiHash[:],
		Added:     timestamppb.New(a.clk.Now()),
		Source:    "admin-revoker",
		Comment:   fmt.Sprintf("%s: %s", u.Username, comment),
		RevokedBy: 0,
	})
	if err != nil {
		return fmt.Errorf("blocking key: %w", err)
	}

	return nil
}
