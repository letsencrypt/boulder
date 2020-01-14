package wfe2

import (
	"net/http"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/web"
)

func requiredStale(req *http.Request, logEvent *web.RequestEvent) bool {
	return req.Method == http.MethodGet && strings.HasPrefix(logEvent.Endpoint, getAPIPrefix)
}

func (wfe *WebFrontEndImpl) staleEnoughToGETOrder(order *corepb.Order) *probs.ProblemDetails {
	return wfe.staleEnoughToGET("Order", time.Unix(*order.Created, 0))
}

func (wfe *WebFrontEndImpl) staleEnoughToGETCert(cert core.Certificate) *probs.ProblemDetails {
	return wfe.staleEnoughToGET("Certificate", cert.Issued)
}

func (wfe *WebFrontEndImpl) staleEnoughToGET(resourceType string, createDate time.Time) *probs.ProblemDetails {
	if wfe.clk.Since(createDate) < wfe.staleTimeout {
		return probs.Unauthorized(
			"%s is too new for GET API. "+
				"You should only use this non-standard API to access resources created more than %s ago",
			resourceType,
			wfe.staleTimeout)
	}
	return nil
}
