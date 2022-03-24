package va

import (
	"context"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/probs"
)

func (va *ValidationAuthorityImpl) validateTrustedJWT(
	ctx context.Context,
	ident identifier.ACMEIdentifier,
	challenge core.Challenge,
) ([]core.ValidationRecord, *probs.ProblemDetails) {
	//TODO GB: Hier valideren dat token OK is?
	return []core.ValidationRecord{{
		Hostname: "example",
	}}, nil
}
