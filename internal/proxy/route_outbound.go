package proxy

import (
	"github.com/Resinat/Resin/internal/outbound"
	"github.com/Resinat/Resin/internal/platform"
	"github.com/Resinat/Resin/internal/routing"
	"github.com/sagernet/sing-box/adapter"
)

type routedOutbound struct {
	Route    routing.RouteResult
	Outbound adapter.Outbound
}

func resolveRoutedOutbound(
	router *routing.Router,
	pool outbound.PoolAccessor,
	platformName string,
	account string,
	target string,
) (routedOutbound, *ProxyError) {
	result, err := router.RouteRequest(platformName, account, target)
	if err != nil {
		return routedOutbound{}, mapRouteError(err)
	}
	return loadRoutedOutbound(pool, result)
}

func resolvePlatformRoutedOutbound(
	router *routing.Router,
	pool outbound.PoolAccessor,
	platform *platform.Platform,
	account string,
	target string,
) (routedOutbound, *ProxyError) {
	result, err := router.RoutePlatformRequest(platform, account, target)
	if err != nil {
		return routedOutbound{}, mapRouteError(err)
	}
	return loadRoutedOutbound(pool, result)
}

func loadRoutedOutbound(pool outbound.PoolAccessor, result routing.RouteResult) (routedOutbound, *ProxyError) {
	entry, ok := pool.GetEntry(result.NodeHash)
	if !ok {
		return routedOutbound{}, ErrNoAvailableNodes
	}
	obPtr := entry.Outbound.Load()
	if obPtr == nil {
		return routedOutbound{}, ErrNoAvailableNodes
	}

	return routedOutbound{
		Route:    result,
		Outbound: *obPtr,
	}, nil
}
