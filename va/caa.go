package va

import (
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	vapb "github.com/letsencrypt/boulder/va/proto"
	"golang.org/x/net/context"
)

func (va *ValidationAuthorityImpl) IsCAAValid(
	ctx context.Context,
	req *vapb.IsCAAValidRequest,
) (*vapb.IsCAAValidResponse, error) {
	prob := va.checkCAA(ctx, core.AcmeIdentifier{
		Type:  core.IdentifierDNS,
		Value: *req.Domain,
	})

	if prob != nil {
		typ := string(prob.Type)
		return &vapb.IsCAAValidResponse{
			Problem: &corepb.ProblemDetails{
				ProblemType: &typ,
				Detail:      &prob.Detail,
			},
		}, nil
	}
	return &vapb.IsCAAValidResponse{}, nil
}
