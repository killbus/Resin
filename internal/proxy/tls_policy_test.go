package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/platform"
	"github.com/Resinat/Resin/internal/routing"
	"github.com/Resinat/Resin/internal/tlspolicy"
	M "github.com/sagernet/sing/common/metadata"
)

func unrelatedCertificatePEM(t *testing.T) []byte {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: "unrelated root"},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

type mutableTLSEvaluator struct {
	mu     sync.RWMutex
	policy tlspolicy.ResolvedPolicy
	err    error
	calls  atomic.Int32
}

type strictVerifyEvaluator struct{}

func (strictVerifyEvaluator) Resolve(platformID, target string) (tlspolicy.ResolvedPolicy, error) {
	return tlspolicy.VerifyPolicy(platformID, target), nil
}

type blockingTLSEvaluator struct {
	started chan struct{}
	release chan struct{}
	policy  tlspolicy.ResolvedPolicy
}

func (e *blockingTLSEvaluator) Resolve(_, _ string) (tlspolicy.ResolvedPolicy, error) {
	close(e.started)
	<-e.release
	return e.policy, nil
}

func (e *mutableTLSEvaluator) Resolve(_, _ string) (tlspolicy.ResolvedPolicy, error) {
	e.calls.Add(1)
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.policy, e.err
}

func (e *mutableTLSEvaluator) set(policy tlspolicy.ResolvedPolicy) {
	e.mu.Lock()
	e.policy = policy
	e.mu.Unlock()
}

func testResolvedPolicy(mode tlspolicy.Mode, target string) tlspolicy.ResolvedPolicy {
	return tlspolicy.ResolvedPolicy{
		ConfiguredMode:   mode,
		EffectiveMode:    mode,
		PolicyID:         "rule-id",
		PolicyVersion:    3,
		PlatformID:       "platform-id",
		NormalizedTarget: target,
		Reason:           "must not enter request logs",
	}
}

func TestReverseResolverRejectsMissingPlatformBeforePolicyEvaluation(t *testing.T) {
	evaluator := &mutableTLSEvaluator{}
	resolver := NewReverseRequestResolver(&mockPlatformLookup{}, evaluator, nil)
	if _, err := resolver.Resolve("missing", "https", "example.com:443"); err != ErrPlatformNotFound {
		t.Fatalf("resolve error = %v, want ErrPlatformNotFound", err)
	}
	if evaluator.calls.Load() != 0 {
		t.Fatalf("policy evaluator calls = %d, want 0", evaluator.calls.Load())
	}

	rp := NewReverseProxy(ReverseProxyConfig{
		ProxyToken:         "tok",
		PlatformLookup:     &mockPlatformLookup{},
		TLSPolicyEvaluator: evaluator,
		ProxyBypassRules:   []string{"*"},
		Events:             newMockEventEmitter(),
	})
	emitter := rp.events.(*mockEventEmitter)
	req := httptest.NewRequest(http.MethodGet, "/tok/missing:acct/https/Example.COM/path", nil)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound || evaluator.calls.Load() != 0 {
		t.Fatalf("status=%d evaluator calls=%d", rec.Code, evaluator.calls.Load())
	}
	logEntry := <-emitter.logCh
	if logEntry.NormalizedTarget != "example.com:443" || logEntry.AuthorizationDecision != reverseAuthorizationDeniedPlatform || logEntry.EgressMode != "" {
		t.Fatalf("missing-platform audit = %+v", logEntry)
	}
}

func TestReverseResolverHoldsPublicationReadGateAcrossPlatformAndPolicyCapture(t *testing.T) {
	gate := &sync.RWMutex{}
	plat := platform.NewPlatform("platform-id", "plat", nil, nil)
	evaluator := &blockingTLSEvaluator{
		started: make(chan struct{}),
		release: make(chan struct{}),
		policy:  testResolvedPolicy(tlspolicy.ModeBypass, "example.com:443"),
	}
	rp := NewReverseProxy(ReverseProxyConfig{
		PlatformLookup:     &mockPlatformLookup{platformNames: map[string]*platform.Platform{"plat": plat}},
		TLSPolicyEvaluator: evaluator,
		PublicationGate:    gate,
	})
	if rp.resolver.publicationGate != gate {
		t.Fatal("reverse proxy did not pass the shared publication gate to its resolver")
	}

	decisionCh := make(chan ReverseRequestDecision, 1)
	errorCh := make(chan *ProxyError, 1)
	go func() {
		decision, err := rp.resolver.Resolve("plat", "https", "example.com:443")
		decisionCh <- decision
		errorCh <- err
	}()
	<-evaluator.started

	writerAcquired := make(chan struct{})
	writerStarted := make(chan struct{})
	go func() {
		close(writerStarted)
		gate.Lock()
		close(writerAcquired)
		gate.Unlock()
	}()
	<-writerStarted
	select {
	case <-writerAcquired:
		t.Fatal("publication writer acquired the gate before policy capture completed")
	case <-time.After(30 * time.Millisecond):
	}

	close(evaluator.release)
	decision := <-decisionCh
	if err := <-errorCh; err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if decision.Platform != plat || decision.Policy.EffectiveMode != tlspolicy.ModeBypass {
		t.Fatalf("captured decision = %+v", decision)
	}
	select {
	case <-writerAcquired:
	case <-time.After(time.Second):
		t.Fatal("publication writer remained blocked after request capture completed")
	}
}

func TestReverseResolverRejectsIndeterminatePolicyBeforeEgress(t *testing.T) {
	evaluator := &mutableTLSEvaluator{err: errors.New("policy snapshot unavailable")}
	feedback := &countingReverseHealthFeedback{}
	plat := platform.NewPlatform("platform-id", "plat", nil, nil)
	rp := NewReverseProxy(ReverseProxyConfig{
		ProxyToken:         "tok",
		PlatformLookup:     &mockPlatformLookup{platformNames: map[string]*platform.Platform{"plat": plat}},
		TLSPolicyEvaluator: evaluator,
		ProxyBypassRules:   []string{"*"},
		Events:             newMockEventEmitter(),
		HealthFeedback:     feedback,
	})
	emitter := rp.events.(*mockEventEmitter)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tok/plat:acct/https/example.com/path", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if evaluator.calls.Load() != 1 {
		t.Fatalf("policy evaluator calls=%d, want 1", evaluator.calls.Load())
	}
	if feedback.failures.Load() != 0 || feedback.successes.Load() != 0 {
		t.Fatalf("indeterminate policy emitted health feedback: failure=%d success=%d", feedback.failures.Load(), feedback.successes.Load())
	}
	logEntry := <-emitter.logCh
	if logEntry.AuthorizationDecision != reverseAuthorizationDeniedIndeterminate || logEntry.EgressMode != "" || logEntry.NodeHash != "" {
		t.Fatalf("indeterminate-policy audit=%+v", logEntry)
	}
}

type countingReverseHealthFeedback struct {
	failures  atomic.Int32
	successes atomic.Int32
}

func (f *countingReverseHealthFeedback) RecordFailure(*routing.RouteResult, FailureAssessment) {
	f.failures.Add(1)
}

func (f *countingReverseHealthFeedback) RecordSuccess(*routing.RouteResult) {
	f.successes.Add(1)
}

func TestReverseBypassOutcomeAndExpiryRetireIdleProfile(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	host := strings.TrimPrefix(upstream.URL, "https://")
	target, err := tlspolicy.NormalizeTarget(host)
	if err != nil {
		t.Fatal(err)
	}
	policy := testResolvedPolicy(tlspolicy.ModeBypass, target)
	evaluator := &mutableTLSEvaluator{policy: policy}
	emitter := newMockEventEmitter()
	plat := platform.NewPlatform("platform-id", "plat", nil, nil)
	rp := NewReverseProxy(ReverseProxyConfig{
		ProxyToken:         "tok",
		PlatformLookup:     &mockPlatformLookup{platformNames: map[string]*platform.Platform{"plat": plat}},
		TLSPolicyEvaluator: evaluator,
		ProxyBypassRules:   []string{"127.*"},
		Events:             emitter,
	})
	path := fmt.Sprintf("/tok/plat:acct/https/%s/", host)

	first := httptest.NewRecorder()
	rp.ServeHTTP(first, httptest.NewRequest(http.MethodGet, path, nil))
	if first.Code != http.StatusOK {
		t.Fatalf("BYPASS status=%d body=%s", first.Code, first.Body.String())
	}
	firstLog := <-emitter.logCh
	if firstLog.PlatformID != "platform-id" || firstLog.TLSPolicyID != "rule-id" ||
		firstLog.TLSPolicyVersion != 3 || firstLog.TLSConfiguredMode != "BYPASS" ||
		firstLog.TLSEffectiveMode != "BYPASS" || firstLog.TLSExpired || !firstLog.NetOK ||
		firstLog.NormalizedTarget != target || firstLog.AuthorizationDecision != reverseAuthorizationAllowed || firstLog.EgressMode != "DIRECT" {
		t.Fatalf("BYPASS outcome = %+v", firstLog)
	}

	expired := policy
	expired.EffectiveMode = tlspolicy.ModeVerify
	expired.Expired = true
	expired.ExpiresAt = func() *time.Time { value := time.Now().Add(-time.Minute); return &value }()
	evaluator.set(expired)
	second := httptest.NewRecorder()
	rp.ServeHTTP(second, httptest.NewRequest(http.MethodGet, path, nil))
	if second.Code != http.StatusBadGateway {
		t.Fatalf("expired BYPASS status=%d body=%s", second.Code, second.Body.String())
	}
	secondLog := <-emitter.logCh
	if secondLog.TLSConfiguredMode != "BYPASS" || secondLog.TLSEffectiveMode != "VERIFY" || !secondLog.TLSExpired || secondLog.NetOK {
		t.Fatalf("expired outcome = %+v", secondLog)
	}
	if secondLog.FailureAttribution != string(FailureTargetIdentity) {
		t.Fatalf("failure attribution = %q", secondLog.FailureAttribution)
	}
}

func TestCustomCAProfileAugmentsSystemRootsAndIsProfileIsolated(t *testing.T) {
	trusted := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer trusted.Close()
	host := strings.TrimPrefix(trusted.URL, "https://")
	target, err := tlspolicy.NormalizeTarget(host)
	if err != nil {
		t.Fatal(err)
	}
	trustedPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: trusted.Certificate().Raw})
	wrongPEM := unrelatedCertificatePEM(t)
	policy := testResolvedPolicy(tlspolicy.ModeTrustCustomCA, target)
	policy.BundleFingerprint = "trusted"
	policy.CanonicalPEM = trustedPEM
	profile, err := compileTLSProfile(policy)
	if err != nil {
		t.Fatal(err)
	}
	if profile.config == nil || profile.config.RootCAs == nil || profile.config.InsecureSkipVerify {
		t.Fatalf("custom profile did not preserve verification: %+v", profile.config)
	}
	systemRoots, err := x509.SystemCertPool()
	if err != nil {
		t.Fatal(err)
	}
	if got, minimum := len(profile.config.RootCAs.Subjects()), len(systemRoots.Subjects())+1; got < minimum {
		t.Fatalf("custom roots contain %d subjects, want at least %d system plus custom subjects", got, minimum)
	}

	evaluator := &mutableTLSEvaluator{policy: policy}
	plat := platform.NewPlatform("platform-id", "plat", nil, nil)
	rp := NewReverseProxy(ReverseProxyConfig{
		ProxyToken:         "tok",
		PlatformLookup:     &mockPlatformLookup{platformNames: map[string]*platform.Platform{"plat": plat}},
		TLSPolicyEvaluator: evaluator,
		ProxyBypassRules:   []string{"127.*"},
		Events:             NoOpEventEmitter{},
	})
	path := fmt.Sprintf("/tok/plat:acct/https/%s/", host)
	success := httptest.NewRecorder()
	rp.ServeHTTP(success, httptest.NewRequest(http.MethodGet, path, nil))
	if success.Code != http.StatusNoContent {
		t.Fatalf("trusted custom CA status=%d body=%s", success.Code, success.Body.String())
	}

	policy.PolicyVersion++
	policy.BundleFingerprint = "wrong"
	policy.CanonicalPEM = wrongPEM
	evaluator.set(policy)
	failure := httptest.NewRecorder()
	rp.ServeHTTP(failure, httptest.NewRequest(http.MethodGet, path, nil))
	if failure.Code != http.StatusBadGateway {
		t.Fatalf("wrong custom CA status=%d body=%s", failure.Code, failure.Body.String())
	}
}

func TestCustomCARejectsWrongSANAndIncompleteChain(t *testing.T) {
	t.Run("wrong SAN", func(t *testing.T) {
		upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer upstream.Close()
		rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw})
		policy := testResolvedPolicy(tlspolicy.ModeTrustCustomCA, "localhost:443")
		policy.BundleFingerprint = "server-cert"
		policy.CanonicalPEM = rootPEM
		profile, err := compileTLSProfile(policy)
		if err != nil {
			t.Fatal(err)
		}
		transport := newDirectHTTPTransportWithProfile(OutboundTransportConfig{}, nil, profile)
		port := strings.TrimPrefix(upstream.URL, "https://127.0.0.1:")
		_, err = (&http.Client{Transport: transport}).Get("https://localhost:" + port)
		var hostnameErr x509.HostnameError
		if !errors.As(err, &hostnameErr) {
			t.Fatalf("wrong-SAN error = %T %v, want x509.HostnameError", err, err)
		}
	})

	t.Run("incomplete intermediate chain", func(t *testing.T) {
		upstream, rootPEM := newIncompleteChainTLSServer(t)
		defer upstream.Close()
		host := strings.TrimPrefix(upstream.URL, "https://")
		policy := testResolvedPolicy(tlspolicy.ModeTrustCustomCA, host)
		policy.BundleFingerprint = "root-only"
		policy.CanonicalPEM = rootPEM
		profile, err := compileTLSProfile(policy)
		if err != nil {
			t.Fatal(err)
		}
		transport := newDirectHTTPTransportWithProfile(OutboundTransportConfig{}, nil, profile)
		_, err = (&http.Client{Transport: transport}).Get(upstream.URL)
		var unknownAuthority x509.UnknownAuthorityError
		if !errors.As(err, &unknownAuthority) {
			t.Fatalf("incomplete-chain error = %T %v, want x509.UnknownAuthorityError", err, err)
		}
	})
}

func newIncompleteChainTLSServer(t *testing.T) (*httptest.Server, []byte) {
	t.Helper()
	now := time.Now().UTC()
	makeKey := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return pub, priv
	}
	rootPub, rootPriv := makeKey()
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1001), Subject: pkix.Name{CommonName: "root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPub, rootPriv)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	intermediatePub, intermediatePriv := makeKey()
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1002), Subject: pkix.Name{CommonName: "intermediate"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, rootCert, intermediatePub, rootPriv)
	if err != nil {
		t.Fatal(err)
	}
	intermediateCert, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatal(err)
	}
	leafPub, leafPriv := makeKey()
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1003), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediateCert, leafPub, intermediatePriv)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	// Deliberately omit intermediateDER from Certificate. The client trusts only
	// rootDER, so no alternative/system-root path can complete this chain.
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafPriv}}}
	server.StartTLS()
	return server, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
}

func TestRoutedCustomCATLSMatchesDirectPolicySemantics(t *testing.T) {
	env := newProxyE2EEnv(t)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	upstreamAddress := strings.TrimPrefix(upstream.URL, "https://")
	dialer := &net.Dialer{}
	setProxyE2EOutboundDialFunc(t, env, func(ctx context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
		return dialer.DialContext(ctx, network, upstreamAddress)
	})
	target, err := tlspolicy.NormalizeTarget(upstreamAddress)
	if err != nil {
		t.Fatal(err)
	}
	policy := testResolvedPolicy(tlspolicy.ModeTrustCustomCA, target)
	policy.PlatformID = "plat-id"
	policy.BundleFingerprint = "routed-root"
	policy.CanonicalPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw})
	emitter := newMockEventEmitter()
	rp := NewReverseProxy(ReverseProxyConfig{
		ProxyToken: "tok", Router: env.router, Pool: env.pool, PlatformLookup: env.pool,
		TLSPolicyEvaluator: &mutableTLSEvaluator{policy: policy}, Events: emitter,
	})
	recorder := httptest.NewRecorder()
	rp.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/tok/plat:acct/https/%s/", upstreamAddress), nil))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("routed custom CA status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	logEntry := <-emitter.logCh
	if logEntry.EgressMode != "ROUTED" || logEntry.TLSEffectiveMode != string(tlspolicy.ModeTrustCustomCA) || !logEntry.NetOK {
		t.Fatalf("routed custom CA audit = %+v", logEntry)
	}
}

func TestFailureAttributionAndHealthFeedbackFailClosed(t *testing.T) {
	attributor := defaultFailureAttributor{}
	identity := attributor.Assess(errors.New("generic target failure"), ReverseRequestDecision{})
	if identity.Attribution != FailureUnknown || identity.NegativeNodeHealth {
		t.Fatalf("generic assessment = %+v", identity)
	}
	nodeAssessment := attributor.Assess(&NodeTransportFailure{Err: errors.New("proved node path failure")}, ReverseRequestDecision{})
	if nodeAssessment.Attribution != FailureNode || !nodeAssessment.NegativeNodeHealth {
		t.Fatalf("node assessment = %+v", nodeAssessment)
	}

	health := &mockPassiveHealthRecorder{done: make(chan struct{}, 1)}
	feedback := reverseHealthFeedback{health: health}
	route := &routing.RouteResult{PlatformID: "platform-id"}
	feedback.RecordFailure(nil, nodeAssessment)
	feedback.RecordFailure(route, identity)
	if health.passiveCalls.Load() != 0 {
		t.Fatalf("ineligible failure recorded %d health updates", health.passiveCalls.Load())
	}
	feedback.RecordFailure(route, nodeAssessment)
	select {
	case <-health.done:
	case <-time.After(time.Second):
		t.Fatal("eligible node failure was not recorded")
	}
	if health.passiveCalls.Load() != 1 || health.success {
		t.Fatalf("health feedback = calls %d success %v", health.passiveCalls.Load(), health.success)
	}
}
