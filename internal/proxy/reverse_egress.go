package proxy

import (
	"net/http"

	"github.com/Resinat/Resin/internal/routing"
)

type reverseEgress struct {
	transport *http.Transport
	route     routing.RouteResult
	hasRoute  bool
}

func (p *ReverseProxy) selectEgress(decision ReverseRequestDecision, parsed *parsedPath, account string) (reverseEgress, *ProxyError) {
	if p.bypass != nil && p.bypass.ShouldBypass(parsed.Host) {
		return reverseEgress{transport: p.transportPool.Direct(p.metricsSink, decision.TLSProfile)}, nil
	}
	routed, routeErr := resolvePlatformRoutedOutbound(p.router, p.pool, decision.Platform, account, parsed.Host)
	if routeErr != nil {
		return reverseEgress{}, routeErr
	}
	return reverseEgress{
		transport: p.transportPool.GetWithProfile(routed.Route.NodeHash, routed.Outbound, p.metricsSink, decision.TLSProfile),
		route:     routed.Route,
		hasRoute:  true,
	}, nil
}
