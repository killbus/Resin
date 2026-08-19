package proxy

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Resinat/Resin/internal/node"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

type OutboundTransportConfig struct {
	MaxIdleConns        int
	MaxIdleConnsPerHost int
	IdleConnTimeout     time.Duration
}

const (
	defaultTransportMaxIdleConns        = 1024
	defaultTransportMaxIdleConnsPerHost = 64
	defaultTransportIdleConnTimeout     = 90 * time.Second
)

func normalizeOutboundTransportConfig(cfg OutboundTransportConfig) OutboundTransportConfig {
	if cfg.MaxIdleConns <= 0 {
		cfg.MaxIdleConns = defaultTransportMaxIdleConns
	}
	if cfg.MaxIdleConnsPerHost <= 0 {
		cfg.MaxIdleConnsPerHost = defaultTransportMaxIdleConnsPerHost
	}
	if cfg.IdleConnTimeout <= 0 {
		cfg.IdleConnTimeout = defaultTransportIdleConnTimeout
	}
	return cfg
}

// OutboundTransportPool manages reusable outbound HTTP transports keyed by node hash.
// A single instance should be shared by forward/reverse proxies so keep-alive pools
// are reused and can be evicted on node removal.
type OutboundTransportPool struct {
	config           OutboundTransportConfig
	transports       *xsync.Map[transportProfileKey, *http.Transport]
	direct           *xsync.Map[string, *http.Transport]
	policyMu         sync.Mutex
	policyGeneration uint64
	policyProfiles   map[string]struct{}
}

type transportProfileKey struct {
	node    node.Hash
	profile string
}

func newOutboundTransportPool() *OutboundTransportPool {
	return NewOutboundTransportPool(OutboundTransportConfig{})
}

func newOutboundTransportPoolWithConfig(cfg OutboundTransportConfig) *OutboundTransportPool {
	return NewOutboundTransportPool(cfg)
}

// NewOutboundTransportPool creates a transport pool with normalized settings.
func NewOutboundTransportPool(cfg OutboundTransportConfig) *OutboundTransportPool {
	return &OutboundTransportPool{
		config:         normalizeOutboundTransportConfig(cfg),
		transports:     xsync.NewMap[transportProfileKey, *http.Transport](),
		direct:         xsync.NewMap[string, *http.Transport](),
		policyProfiles: make(map[string]struct{}),
	}
}

// Get returns a reusable transport for the given node hash.
func (p *OutboundTransportPool) Get(
	hash node.Hash,
	ob adapter.Outbound,
	sink MetricsEventSink,
) *http.Transport {
	return p.GetWithProfile(hash, ob, sink, verifyTLSProfile())
}

func (p *OutboundTransportPool) GetWithProfile(hash node.Hash, ob adapter.Outbound, sink MetricsEventSink, profile tlsProfile) *http.Transport {
	p.policyMu.Lock()
	defer p.policyMu.Unlock()
	if !p.profileCacheableLocked(profile) {
		transport := p.newReusableOutboundTransport(ob, sink, profile)
		transport.DisableKeepAlives = true
		return transport
	}
	key := transportProfileKey{node: hash, profile: profile.key}
	transport, _ := p.transports.LoadOrCompute(key, func() (*http.Transport, bool) {
		return p.newReusableOutboundTransport(ob, sink, profile), false
	})
	return transport
}

func (p *OutboundTransportPool) Direct(sink MetricsEventSink, profile tlsProfile) *http.Transport {
	p.policyMu.Lock()
	defer p.policyMu.Unlock()
	if !p.profileCacheableLocked(profile) {
		transport := newDirectHTTPTransportWithProfile(p.config, sink, profile)
		transport.DisableKeepAlives = true
		return transport
	}
	transport, _ := p.direct.LoadOrCompute(profile.key, func() (*http.Transport, bool) {
		return newDirectHTTPTransportWithProfile(p.config, sink, profile), false
	})
	return transport
}

func (p *OutboundTransportPool) profileCacheableLocked(profile tlsProfile) bool {
	if profile.key == verifyTLSProfile().key {
		return true
	}
	if p.policyGeneration == 0 {
		return true
	}
	if profile.generation != p.policyGeneration {
		return false
	}
	_, ok := p.policyProfiles[profile.key]
	return ok
}

// PublishTLSProfiles is the transport-cache linearization point for a policy
// snapshot. Acquisition uses the same mutex, so a request that captured an old
// generation can drain with a fresh non-cached transport but can never reinsert
// its obsolete profile after publication.
func (p *OutboundTransportPool) PublishTLSProfiles(generation uint64, active map[string]struct{}) {
	p.policyMu.Lock()
	defer p.policyMu.Unlock()
	if generation < p.policyGeneration {
		return
	}
	p.policyGeneration = generation
	p.policyProfiles = make(map[string]struct{}, len(active))
	for key := range active {
		p.policyProfiles[key] = struct{}{}
	}
	p.retireInactiveProfilesLocked()
}

func (p *OutboundTransportPool) retireInactiveProfilesLocked() {
	p.transports.Range(func(key transportProfileKey, transport *http.Transport) bool {
		if key.profile == verifyTLSProfile().key {
			return true
		}
		if _, active := p.policyProfiles[key.profile]; !active {
			if removed, ok := p.transports.LoadAndDelete(key); ok && removed != nil {
				removed.CloseIdleConnections()
			}
		}
		return true
	})
	p.direct.Range(func(key string, transport *http.Transport) bool {
		if key == verifyTLSProfile().key {
			return true
		}
		if _, active := p.policyProfiles[key]; !active {
			if removed, ok := p.direct.LoadAndDelete(key); ok && removed != nil {
				removed.CloseIdleConnections()
			}
		}
		return true
	})
}

// Evict closes idle connections for one node transport and removes it from pool.
func (p *OutboundTransportPool) Evict(hash node.Hash) {
	p.policyMu.Lock()
	defer p.policyMu.Unlock()
	p.transports.Range(func(key transportProfileKey, transport *http.Transport) bool {
		if key.node == hash {
			if removed, ok := p.transports.LoadAndDelete(key); ok && removed != nil {
				removed.CloseIdleConnections()
			}
		}
		return true
	})
}

// RetireProfile removes one obsolete policy profile from routed and direct
// indexes and closes its idle connections. In-flight connections retain their
// captured transport and drain naturally.
func (p *OutboundTransportPool) RetireProfile(profileKey string) {
	if profileKey == "" || profileKey == verifyTLSProfile().key {
		return
	}
	p.policyMu.Lock()
	defer p.policyMu.Unlock()
	delete(p.policyProfiles, profileKey)
	p.transports.Range(func(key transportProfileKey, transport *http.Transport) bool {
		if key.profile == profileKey {
			if removed, ok := p.transports.LoadAndDelete(key); ok && removed != nil {
				removed.CloseIdleConnections()
			}
		}
		return true
	})
	if transport, ok := p.direct.LoadAndDelete(profileKey); ok && transport != nil {
		transport.CloseIdleConnections()
	}
}

// CloseAll closes idle connections and clears all pooled transports.
func (p *OutboundTransportPool) CloseAll() {
	p.policyMu.Lock()
	defer p.policyMu.Unlock()
	p.transports.Range(func(_ transportProfileKey, transport *http.Transport) bool {
		if transport != nil {
			transport.CloseIdleConnections()
		}
		return true
	})
	p.transports.Clear()
	p.direct.Range(func(_ string, transport *http.Transport) bool {
		if transport != nil {
			transport.CloseIdleConnections()
		}
		return true
	})
	p.direct.Clear()
}

func (p *OutboundTransportPool) newReusableOutboundTransport(ob adapter.Outbound, sink MetricsEventSink, profile tlsProfile) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := ob.DialContext(ctx, network, M.ParseSocksaddr(addr))
			if err != nil {
				// Sing-box outbounds may connect to the selected node and perform
				// target negotiation in this single call. Preserve any explicit
				// nested evidence, but do not manufacture node causality here.
				return nil, &OpaqueRoutedDialFailure{Err: err}
			}
			if sink != nil {
				sink.OnConnectionLifecycle(ConnectionOutbound, ConnectionOpen)
				conn = newCountingConn(conn, sink)
			}
			return conn, nil
		},
		TLSClientConfig:     profile.tlsConfig(),
		DisableKeepAlives:   false,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        p.config.MaxIdleConns,
		MaxIdleConnsPerHost: p.config.MaxIdleConnsPerHost,
		IdleConnTimeout:     p.config.IdleConnTimeout,
	}
}

func newDirectHTTPTransport(cfg OutboundTransportConfig, sink MetricsEventSink) *http.Transport {
	return newDirectHTTPTransportWithProfile(cfg, sink, verifyTLSProfile())
}

func newDirectHTTPTransportWithProfile(cfg OutboundTransportConfig, sink MetricsEventSink, profile tlsProfile) *http.Transport {
	cfg = normalizeOutboundTransportConfig(cfg)
	dialer := &net.Dialer{}
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if sink != nil {
				sink.OnConnectionLifecycle(ConnectionOutbound, ConnectionOpen)
				conn = newCountingConn(conn, sink)
			}
			return conn, nil
		},
		TLSClientConfig:     profile.tlsConfig(),
		DisableKeepAlives:   false,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        cfg.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.MaxIdleConnsPerHost,
		IdleConnTimeout:     cfg.IdleConnTimeout,
	}
}
