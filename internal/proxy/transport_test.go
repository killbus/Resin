package proxy

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/node"
	resinoutbound "github.com/Resinat/Resin/internal/outbound"
	"github.com/Resinat/Resin/internal/routing"
	"github.com/Resinat/Resin/internal/tlspolicy"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

type noopOutbound struct {
	adapter.Outbound
}

type versionedTestOutbound struct {
	noopOutbound
	version atomic.Uint64
}

func (n *versionedTestOutbound) RoutingVersion() uint64 { return n.version.Load() }

func TestTransportPoolChangesWithOutboundMode(t *testing.T) {
	pool := newOutboundTransportPool()
	ob := new(versionedTestOutbound)
	ob.version.Store(1)
	hash := node.Hash{7}
	first := mustGetTransport(t, pool, hash, ob, nil)
	ob.version.Store(2)
	second := mustGetTransport(t, pool, hash, ob, nil)
	if first == second {
		t.Fatal("new mode reused old HTTP connections")
	}
	if mustGetTransport(t, pool, hash, ob, nil) != second {
		t.Fatal("same mode did not reuse its transport")
	}
	stale := new(versionedTestOutbound)
	stale.version.Store(1)
	if transport, err := pool.Get(hash, stale, nil); transport != nil || err != ErrNoAvailableNodes {
		t.Fatalf("stale version reused another mode: %v %v", transport, err)
	}
	if mustGetTransport(t, pool, hash, ob, nil) != second {
		t.Fatal("stale caller rolled the pool back")
	}

}

func (n *noopOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("not used in transport-pool tests")
}

func (n *noopOutbound) Tag() string  { return "noop" }
func (n *noopOutbound) Type() string { return "noop" }

func TestOutboundDialPreservesContextWithoutOuterHTTPTrace(t *testing.T) {
	type contextKey struct{}
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), contextKey{}, "preserved"), time.Second)
	defer cancel()
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GetConn: func(string) {}})
	var dialContext context.Context
	ob := &mockOutbound{dialFunc: func(inner context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
		dialContext = inner
		if httptrace.ContextClientTrace(inner) != nil {
			t.Error("outer HTTP trace leaked into protocol dial")
		}
		if inner.Value(contextKey{}) != "preserved" || inner.Done() != ctx.Done() {
			t.Error("protocol dial lost request context data or cancellation")
		}
		deadline, ok := inner.Deadline()
		want, _ := ctx.Deadline()
		if !ok || !deadline.Equal(want) {
			t.Error("protocol dial lost deadline")
		}
		return nil, errors.New("dial failed")
	}}
	transport := newOutboundTransportPool().newReusableOutboundTransport(ob, nil, verifyTLSProfile())
	_, _ = transport.DialContext(ctx, "tcp", "example.com:443")
	cancel()
	if dialContext == nil || dialContext.Err() != context.Canceled {
		t.Fatal("dial context did not follow cancellation")
	}
	if httptrace.ContextClientTrace(ctx) == nil {
		t.Fatal("protocol dial modified the original request trace")
	}
}

func TestOutboundTransportPool_ReusesByNodeHash(t *testing.T) {
	pool := newOutboundTransportPool()
	hash := node.Hash{1}

	t1 := mustGetTransport(t, pool, hash, &noopOutbound{}, nil)
	t2 := mustGetTransport(t, pool, hash, &noopOutbound{}, nil)

	if t1 != t2 {
		t.Fatal("expected same transport instance for identical node hash")
	}
}

func TestOutboundTransportPool_SplitsByNodeHash(t *testing.T) {
	pool := newOutboundTransportPool()
	ob := &noopOutbound{}
	hash1 := node.Hash{1}
	hash2 := node.Hash{2}

	base := mustGetTransport(t, pool, hash1, ob, nil)
	byNodeHash := mustGetTransport(t, pool, hash2, ob, nil)
	if base == byNodeHash {
		t.Fatal("expected different transport for different node hash")
	}
}

func TestOutboundTransportPool_UsesKeepAliveTransport(t *testing.T) {
	pool := newOutboundTransportPool()
	ob := &noopOutbound{}
	hash := node.Hash{1}

	transport := mustGetTransport(t, pool, hash, ob, nil)
	if transport.DisableKeepAlives {
		t.Fatal("expected keep-alive enabled transport")
	}
}

func TestOutboundTransportPool_EvictRemovesNodeTransport(t *testing.T) {
	pool := newOutboundTransportPool()
	hash := node.Hash{1}
	ob := &noopOutbound{}

	t1 := mustGetTransport(t, pool, hash, ob, nil)
	pool.Evict(hash)
	t2 := mustGetTransport(t, pool, hash, ob, nil)

	if t1 == t2 {
		t.Fatal("expected a new transport after evict")
	}
}

func TestOutboundTransportPool_AppliesConfiguredLimits(t *testing.T) {
	pool := newOutboundTransportPoolWithConfig(OutboundTransportConfig{
		MaxIdleConns:        9,
		MaxIdleConnsPerHost: 3,
		IdleConnTimeout:     12 * time.Second,
	})
	ob := &noopOutbound{}
	hash := node.Hash{1}

	transport := mustGetTransport(t, pool, hash, ob, nil)
	if transport.MaxIdleConns != 9 {
		t.Fatalf("MaxIdleConns: got %d, want %d", transport.MaxIdleConns, 9)
	}
	if transport.MaxIdleConnsPerHost != 3 {
		t.Fatalf("MaxIdleConnsPerHost: got %d, want %d", transport.MaxIdleConnsPerHost, 3)
	}
	if transport.IdleConnTimeout != 12*time.Second {
		t.Fatalf("IdleConnTimeout: got %s, want %s", transport.IdleConnTimeout, 12*time.Second)
	}
}

func TestOutboundTransportPool_CloseAllClearsEntries(t *testing.T) {
	pool := newOutboundTransportPool()
	ob := &noopOutbound{}

	hashA := node.Hash{1}
	hashB := node.Hash{2}
	t1 := mustGetTransport(t, pool, hashA, ob, nil)
	_ = mustGetTransport(t, pool, hashB, ob, nil)

	pool.CloseAll()

	t2 := mustGetTransport(t, pool, hashA, ob, nil)
	if t1 == t2 {
		t.Fatal("expected a new transport after CloseAll")
	}
}

func mustGetTransport(t *testing.T, pool *OutboundTransportPool, hash node.Hash, ob adapter.Outbound, sink MetricsEventSink) *http.Transport {
	t.Helper()
	transport, err := pool.Get(hash, ob, sink)
	if err != nil {
		t.Fatal(err)
	}
	return transport
}

// Pause after Get has read the old cache entry but before it enters Compute,
// ensuring that both cache lookup paths reject newer versions for an old call.
func TestTransportPoolRejectsStaleVersionDuringCacheUpdate(t *testing.T) {
	pool := newOutboundTransportPool()
	defer pool.CloseAll()
	hash := node.Hash{8}
	initial := new(versionedTestOutbound)
	initial.version.Store(0)
	mustGetTransport(t, pool, hash, initial, nil)
	stale := &blockedVersionOutbound{entered: make(chan struct{}), release: make(chan struct{})}
	result := make(chan *ProxyError, 1)
	go func() {
		tr, err := pool.Get(hash, stale, nil)
		if tr != nil {
			result <- nil
			return
		}
		result <- err
	}()
	<-stale.entered
	current := new(versionedTestOutbound)
	current.version.Store(2)
	expected := mustGetTransport(t, pool, hash, current, nil)
	close(stale.release)
	if err := <-result; err != ErrNoAvailableNodes {
		t.Fatalf("stale caller accepted current transport: %v", err)
	}
	if mustGetTransport(t, pool, hash, current, nil) != expected {
		t.Fatal("stale caller replaced the new cache entry")
	}
}

type blockedVersionOutbound struct {
	noopOutbound
	entered, release chan struct{}
}

func (n *blockedVersionOutbound) RoutingVersion() uint64 { close(n.entered); <-n.release; return 1 }
func TestOutboundTransportPoolIsolatesAndRetiresTLSProfiles(t *testing.T) {
	pool := newOutboundTransportPool()
	hash := node.Hash{1}
	ob := &noopOutbound{}
	verify := verifyTLSProfile()
	bypass, err := compileTLSProfile(tlspolicy.ResolvedPolicy{
		ConfiguredMode:   tlspolicy.ModeBypass,
		EffectiveMode:    tlspolicy.ModeBypass,
		PlatformID:       "platform",
		NormalizedTarget: "example.com:443",
		PolicyID:         "rule",
		PolicyVersion:    1,
	})
	if err != nil {
		t.Fatal(err)
	}

	mustGet := func(profile tlsProfile) *http.Transport {
		transport, getErr := pool.GetWithProfile(hash, ob, nil, profile)
		if getErr != nil {
			t.Fatal(getErr)
		}
		return transport
	}
	verifyTransport := mustGet(verify)
	bypassTransport := mustGet(bypass)
	if verifyTransport == bypassTransport {
		t.Fatal("forward VERIFY and reverse BYPASS shared a routed transport")
	}
	if verifyTransport.TLSClientConfig != nil {
		t.Fatal("forward transport received a reverse non-VERIFY TLS profile")
	}
	if bypassTransport != mustGet(bypass) {
		t.Fatal("identical BYPASS profile was not reused")
	}
	directBypass := pool.Direct(nil, bypass)
	pool.RetireProfile(bypass.key)
	if bypassTransport == mustGet(bypass) {
		t.Fatal("retired routed profile was reused")
	}
	if directBypass == pool.Direct(nil, bypass) {
		t.Fatal("retired direct profile was reused")
	}
	if verifyTransport != mustGet(verify) {
		t.Fatal("retiring BYPASS also retired canonical VERIFY")
	}
}

func TestPolicyPublicationPreventsObsoleteProfileReinsertion(t *testing.T) {
	for _, egress := range []string{"direct", "routed"} {
		for _, mutation := range []string{"rebind", "revoke"} {
			t.Run(egress+"/"+mutation, func(t *testing.T) {
				pool := newOutboundTransportPool()
				hash := node.Hash{7}
				ob := &noopOutbound{}
				oldPolicy := tlspolicy.ResolvedPolicy{
					SnapshotGeneration: 1,
					ConfiguredMode:     tlspolicy.ModeBypass, EffectiveMode: tlspolicy.ModeBypass,
					PlatformID: "platform", PolicyID: "rule", PolicyVersion: 1,
				}
				oldProfile, err := compileTLSProfile(oldPolicy)
				if err != nil {
					t.Fatal(err)
				}
				pool.PublishTLSProfiles(1, map[string]struct{}{oldProfile.key: {}})
				var original *http.Transport
				if egress == "direct" {
					original = pool.Direct(nil, oldProfile)
				} else {
				profileTransport, profileErr := pool.GetWithProfile(hash, ob, nil, oldProfile)
				if profileErr != nil {
					t.Fatal(profileErr)
				}
				original = profileTransport
				}

				captured := make(chan struct{})
				release := make(chan struct{})
				acquired := make(chan *http.Transport, 1)
				go func(profile tlsProfile) {
					close(captured)
					<-release
					if egress == "direct" {
						acquired <- pool.Direct(nil, profile)
					} else {
					profileTransport, getErr := pool.GetWithProfile(hash, ob, nil, profile)
					if getErr != nil {
						t.Error(getErr)
						return
					}
					acquired <- profileTransport
					}
				}(oldProfile)
				<-captured

				active := map[string]struct{}{}
				if mutation == "rebind" {
					newPolicy := oldPolicy
					newPolicy.SnapshotGeneration = 2
					newPolicy.PolicyVersion = 2
					newProfile, err := compileTLSProfile(newPolicy)
					if err != nil {
						t.Fatal(err)
					}
					active[newProfile.key] = struct{}{}
				}
				pool.PublishTLSProfiles(2, active)
				close(release)
				stale := <-acquired
				if stale == original {
					t.Fatal("post-publication old capture reused the retired cached transport")
				}
				if !stale.DisableKeepAlives {
					t.Fatal("non-cached stale transport can retain an unowned idle connection")
				}
				if _, ok := pool.direct.Load(oldProfile.key); ok {
					t.Fatal("obsolete direct profile survived publication")
				}
				foundRouted := false
			pool.transports.Range(func(key transportProfileKey, _ outboundTransportEntry) bool {
					foundRouted = foundRouted || key.profile == oldProfile.key
					return true
				})
				if foundRouted {
					t.Fatal("obsolete routed profile survived publication")
				}
			})
		}
	}
}

type failingNodeOutbound struct {
	noopOutbound
	err error
}

func (o *failingNodeOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, o.err
}

func TestRoutedDialBoundaryKeepsOpaqueErrorsNonNode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want FailureAttribution
	}{
		{name: "generic", err: errors.New("adapter failed"), want: FailureUnknown},
		{name: "refused", err: syscall.ECONNREFUSED, want: FailureUnknown},
		{name: "net op", err: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNRESET}, want: FailureUnknown},
		{name: "EOF", err: io.EOF, want: FailureUnknown},
		{name: "timeout", err: context.DeadlineExceeded, want: FailureUnknown},
		{name: "x509", err: x509.UnknownAuthorityError{}, want: FailureUnknown},
		{name: "caller canceled", err: context.Canceled, want: FailureClient},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pool := newOutboundTransportPool()
			transport, getErr := pool.Get(node.Hash{9}, &failingNodeOutbound{err: tc.err}, nil)
			if getErr != nil {
				t.Fatal(getErr)
			}
			_, err := transport.DialContext(context.Background(), "tcp", "example.com:443")
			var opaque *OpaqueRoutedDialFailure
			if !errors.As(err, &opaque) || opaque.Err != tc.err {
				t.Fatalf("routed dial error %T was not the original opaque failure: %v", err, err)
			}
			var evidence *NodeTransportFailure
			if errors.As(err, &evidence) {
				t.Fatalf("opaque routed dial manufactured node evidence: %v", err)
			}
			assessment := (defaultFailureAttributor{}).Assess(err, ReverseRequestDecision{})
			if assessment.Attribution != tc.want || assessment.NegativeNodeHealth {
				t.Fatalf("routed dial assessment = %+v, want attribution %s without negative health", assessment, tc.want)
			}
		})
	}
}

func TestRoutedDialBoundaryPreservesExplicitNodeEvidence(t *testing.T) {
	sentinel := errors.New("lower-layer node failure")
	pool := newOutboundTransportPool()
	transport, getErr := pool.Get(node.Hash{10}, &failingNodeOutbound{err: &NodeTransportFailure{Err: sentinel}}, nil)
	if getErr != nil {
		t.Fatal(getErr)
	}
	_, err := transport.DialContext(context.Background(), "tcp", "example.com:443")
	var opaque *OpaqueRoutedDialFailure
	var evidence *NodeTransportFailure
	if !errors.As(err, &opaque) || !errors.As(err, &evidence) || !errors.Is(err, sentinel) {
		t.Fatalf("explicit nested node evidence was not preserved: %v", err)
	}
	assessment := (defaultFailureAttributor{}).Assess(err, ReverseRequestDecision{})
	if assessment.Attribution != FailureNode || !assessment.NegativeNodeHealth {
		t.Fatalf("explicit node assessment = %+v", assessment)
	}

	health := &mockPassiveHealthRecorder{done: make(chan struct{}, 1)}
	feedback := reverseHealthFeedback{health: health}
	feedback.RecordFailure(&routing.RouteResult{PlatformID: "platform", NodeHash: node.Hash{10}}, assessment, node.RelayInfo{}, sentinel)
	select {
	case <-health.done:
	case <-time.After(time.Second):
		t.Fatal("explicit node evidence did not reach negative health feedback")
	}
	if health.passiveCalls.Load() != 1 || health.success {
		t.Fatalf("explicit node feedback = calls %d success %v", health.passiveCalls.Load(), health.success)
	}
}

func TestSingboxProxyTargetFailuresRemainOpaqueAndDoNotPenalizeNode(t *testing.T) {
	tests := []struct {
		name     string
		buildRaw func(t *testing.T) (json.RawMessage, func())
	}{
		{name: "SOCKS5 reply code 5", buildRaw: socks5RefusalOutbound},
		{name: "HTTP CONNECT 502", buildRaw: httpConnectBadGatewayOutbound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, closeServer := tc.buildRaw(t)
			defer closeServer()
			builder, err := resinoutbound.NewSingboxBuilderWithConfig(resinoutbound.SingboxBuilderConfig{DNSUpstreams: []string{"local"}})
			if err != nil {
				t.Fatalf("create sing-box builder: %v", err)
			}
			defer builder.Close()
			ob, err := builder.Build(raw)
			if err != nil {
				t.Fatalf("build sing-box outbound: %v", err)
			}
			if closer, ok := ob.(io.Closer); ok {
				defer closer.Close()
			}

			transport, getErr := newOutboundTransportPool().Get(node.Hash{11}, ob, nil)
			if getErr != nil {
				t.Fatal(getErr)
			}
			_, err = transport.DialContext(context.Background(), "tcp", "example.com:443")
			if err == nil {
				t.Fatal("expected proxy target negotiation failure")
			}
			var opaque *OpaqueRoutedDialFailure
			var evidence *NodeTransportFailure
			if !errors.As(err, &opaque) || errors.As(err, &evidence) {
				t.Fatalf("sing-box target failure had unsafe evidence: %T %v", err, err)
			}
			assessment := (defaultFailureAttributor{}).Assess(err, ReverseRequestDecision{})
			if assessment.Attribution != FailureUnknown || assessment.NegativeNodeHealth {
				t.Fatalf("sing-box target failure assessment = %+v", assessment)
			}
			health := &mockPassiveHealthRecorder{}
			feedback := reverseHealthFeedback{health: health}
			feedback.RecordFailure(&routing.RouteResult{PlatformID: "platform", NodeHash: node.Hash{11}}, assessment, node.RelayInfo{}, opaque.Err)
			if health.passiveCalls.Load() != 0 {
				t.Fatalf("opaque target failure recorded %d negative health updates", health.passiveCalls.Load())
			}
		})
	}
}

func TestReverseHealthFeedbackRetainsRoutedSuccess(t *testing.T) {
	health := &mockPassiveHealthRecorder{done: make(chan struct{}, 1)}
	feedback := reverseHealthFeedback{health: health}
	feedback.RecordSuccess(&routing.RouteResult{PlatformID: "platform", NodeHash: node.Hash{12}}, node.RelayInfo{})
	select {
	case <-health.done:
	case <-time.After(time.Second):
		t.Fatal("routed success did not reach positive health feedback")
	}
	if health.passiveCalls.Load() != 1 || !health.success {
		t.Fatalf("routed success feedback = calls %d success %v", health.passiveCalls.Load(), health.success)
	}
}

func socks5RefusalOutbound(t *testing.T) (json.RawMessage, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		done <- serveSOCKS5Refusal(conn)
	}()
	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	var port int
	if _, err := fmt.Sscanf(portText, "%d", &port); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	raw := json.RawMessage(fmt.Sprintf(`{"type":"socks","tag":"target-refusal","server":%q,"server_port":%d,"version":"5"}`, host, port))
	return raw, func() {
		_ = listener.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("scripted SOCKS5 server: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("scripted SOCKS5 server did not finish")
		}
	}
}

func serveSOCKS5Refusal(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != 5 {
		return fmt.Errorf("greeting version = %d", header[0])
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return err
	}
	request := make([]byte, 4)
	if _, err := io.ReadFull(conn, request); err != nil {
		return err
	}
	if request[0] != 5 || request[1] != 1 {
		return fmt.Errorf("request header = %v", request)
	}
	addressLength := 0
	switch request[3] {
	case 1:
		addressLength = 4
	case 3:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return err
		}
		addressLength = int(length[0])
	case 4:
		addressLength = 16
	default:
		return fmt.Errorf("address type = %d", request[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, addressLength+2)); err != nil {
		return err
	}
	_, err := conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

func httpConnectBadGatewayOutbound(t *testing.T) (json.RawMessage, func()) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			t.Errorf("proxy method = %s, want CONNECT", r.Method)
		}
		w.WriteHeader(http.StatusBadGateway)
	}))
	parsed, err := url.Parse(server.URL)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	var port int
	if _, err := fmt.Sscanf(portText, "%d", &port); err != nil {
		server.Close()
		t.Fatal(err)
	}
	raw := json.RawMessage(fmt.Sprintf(`{"type":"http","tag":"target-bad-gateway","server":%q,"server_port":%d}`, host, port))
	return raw, server.Close
}
