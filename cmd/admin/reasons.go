package main

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/letsencrypt/boulder/revocation"
	"golang.org/x/exp/maps"
)

// subcommandListReasons encapsulates the "admin list-reasons" command.
func (a *admin) subcommandListReasons(_ context.Context, args []string) error {
	if len(args) != 0 {
		return errors.New("list-reasons does not take any flags or arguments")
	}

	codes := maps.Keys(revocation.AdminAllowedReasons)
	slices.Sort(codes)

	fmt.Printf("\nRevocation reason codes\n-----------------------\n")
	for _, k := range codes {
		fmt.Printf("%d: %s\n", k, revocation.ReasonToString[k])
	}

	return nil
}
