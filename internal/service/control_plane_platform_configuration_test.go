package service

import (
	"errors"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/config"
	"github.com/Resinat/Resin/internal/state"
	"github.com/Resinat/Resin/internal/subscription"
	"github.com/Resinat/Resin/internal/tlspolicy"
	"github.com/Resinat/Resin/internal/topology"
)

func TestPlatformConfigurationCoordinatorValidatesBeforeCommitAndReturnsAuthoritativeState(t *testing.T) {
	root := t.TempDir()
	engine, closer, err := state.PersistenceBootstrap(filepath.Join(root, "state"), filepath.Join(root, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closer.Close() })
	pool := topology.NewGlobalNodePool(topology.PoolConfig{
		GeoLookup:              func(netip.Addr) string { return "us" },
		MaxLatencyTableEntries: 16,
		MaxConsecutiveFailures: func() int { return 3 },
		LatencyDecayWindow:     func() time.Duration { return 10 * time.Minute },
	})
	registry := tlspolicy.NewCABundleRegistry(engine, time.Now)
	policies, err := tlspolicy.NewPolicyService(engine, registry, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	cp := &ControlPlaneService{
		Engine: engine, Pool: pool, CABundles: registry, TLSPolicy: policies,
		EnvCfg: &config.EnvConfig{
			DefaultPlatformStickyTTL:                        30 * time.Minute,
			DefaultPlatformRegexFilters:                     []string{},
			DefaultPlatformRegionFilters:                    []string{},
			DefaultPlatformReverseProxyMissAction:           "TREAT_AS_EMPTY",
			DefaultPlatformReverseProxyEmptyAccountBehavior: "RANDOM",
			DefaultPlatformAllocationPolicy:                 "BALANCED",
		},
	}
	name := "coordinator-initial"
	created, err := cp.CreatePlatform(CreatePlatformRequest{Name: &name})
	if err != nil {
		t.Fatal(err)
	}
	reason := "approved exception"
	response, err := cp.UpdatePlatformConfiguration(created.ID, 1, UpdatePlatformConfigurationRequest{
		Platform: configurationTestFields("coordinator-updated"),
		TLSPolicy: &PlatformConfigurationPolicyInput{
			ExpectedVersion: 0,
			Mutation: tlspolicy.Mutation{
				Mode: tlspolicy.ModeBypass, Reason: &reason, ExpirySet: true,
			},
		},
	}, tlspolicy.AuditContext{RequestID: "aggregate-save"})
	if err != nil {
		t.Fatal(err)
	}
	if response.ConfigVersion != 2 || response.Platform.Name != "coordinator-updated" ||
		response.TLSPolicy.Mode != tlspolicy.ModeBypass || response.TLSPolicy.Version != 1 {
		t.Fatalf("authoritative response = %+v", response)
	}
	published, ok := pool.GetPlatform(created.ID)
	if !ok || published.Name != "coordinator-updated" {
		t.Fatalf("published platform = %+v ok=%v", published, ok)
	}

	invalidFields := configurationTestFields("must-not-persist")
	invalidFields.StickyTTL = "not-a-duration"
	if _, err := cp.UpdatePlatformConfiguration(created.ID, 2, UpdatePlatformConfigurationRequest{
		Platform: invalidFields,
		TLSPolicy: &PlatformConfigurationPolicyInput{
			ExpectedVersion: 1,
			Mutation:        tlspolicy.Mutation{Mode: tlspolicy.ModeVerify},
		},
	}, tlspolicy.AuditContext{}); err == nil {
		t.Fatal("expected invalid Platform configuration to fail")
	}
	after, err := cp.GetPlatformConfiguration(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.ConfigVersion != 2 || after.Platform.Name != "coordinator-updated" ||
		after.TLSPolicy.Mode != tlspolicy.ModeBypass || after.TLSPolicy.Version != 1 {
		t.Fatalf("state changed after validation failure: %+v", after)
	}
	history, err := cp.TLSPolicyHistory(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || history[0].RequestID != "aggregate-save" {
		t.Fatalf("history after validation failure = %+v", history)
	}
}

func TestCreatePlatformPublishesRuntimeAndTLSPolicyUnderOneGate(t *testing.T) {
	root := t.TempDir()
	engine, closer, err := state.PersistenceBootstrap(filepath.Join(root, "state"), filepath.Join(root, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closer.Close() })
	subMgr := topology.NewSubscriptionManager()
	sub := subscription.NewSubscription("publication-sub", "publication-sub", "https://example.com/sub", true, false)
	subMgr.Register(sub)
	pool := topology.NewGlobalNodePool(topology.PoolConfig{
		SubLookup:              subMgr.Lookup,
		GeoLookup:              func(netip.Addr) string { return "us" },
		MaxLatencyTableEntries: 16,
		MaxConsecutiveFailures: func() int { return 3 },
		LatencyDecayWindow:     func() time.Duration { return 10 * time.Minute },
	})
	registry := tlspolicy.NewCABundleRegistry(engine, time.Now)
	policies, err := tlspolicy.NewPolicyService(engine, registry, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	gate := &sync.RWMutex{}
	cp := &ControlPlaneService{
		Engine: engine, Pool: pool, CABundles: registry, TLSPolicy: policies, PublicationGate: gate,
		EnvCfg: &config.EnvConfig{
			DefaultPlatformStickyTTL:                        30 * time.Minute,
			DefaultPlatformRegexFilters:                     []string{},
			DefaultPlatformRegionFilters:                    []string{},
			DefaultPlatformReverseProxyMissAction:           "TREAT_AS_EMPTY",
			DefaultPlatformReverseProxyEmptyAccountBehavior: "RANDOM",
			DefaultPlatformAllocationPolicy:                 "BALANCED",
		},
	}
	initialGeneration := policies.Snapshot().Generation
	name := "atomic-create-publication"
	reason := "approved create exception"

	gate.RLock()
	createDone := make(chan struct {
		platform *PlatformResponse
		err      error
	}, 1)
	go func() {
		created, createErr := cp.CreatePlatform(CreatePlatformRequest{
			Name: &name,
			TLSPolicy: &PlatformConfigurationPolicyInput{
				ExpectedVersion: 0,
				Mutation: tlspolicy.Mutation{
					Mode: tlspolicy.ModeBypass, Reason: &reason, ExpirySet: true,
				},
			},
		})
		createDone <- struct {
			platform *PlatformResponse
			err      error
		}{platform: created, err: createErr}
	}()

	var persistedID string
	deadline := time.Now().Add(time.Second)
	for persistedID == "" {
		rows, listErr := cp.ListPlatforms()
		if listErr != nil {
			gate.RUnlock()
			t.Fatal(listErr)
		}
		for _, row := range rows {
			if row.Name == name {
				persistedID = row.ID
				break
			}
		}
		if time.Now().After(deadline) {
			gate.RUnlock()
			t.Fatal("platform create did not commit while waiting for publication gate")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case result := <-createDone:
		gate.RUnlock()
		t.Fatalf("create completed while publication reader was active: %+v", result)
	case <-time.After(30 * time.Millisecond):
	}
	if _, ok := pool.GetPlatformByName(name); ok {
		gate.RUnlock()
		t.Fatal("runtime Platform became visible before publication")
	}
	resolved, err := policies.Resolve(persistedID, "example.com:443", time.Now())
	if err != nil {
		gate.RUnlock()
		t.Fatal(err)
	}
	if resolved.EffectiveMode != tlspolicy.ModeVerify || policies.Snapshot().Generation != initialGeneration {
		gate.RUnlock()
		t.Fatalf("TLS snapshot published before Platform: policy=%+v generation=%d", resolved, policies.Snapshot().Generation)
	}

	// The candidate Platform was rebuilt before the SQL transaction. A node
	// becoming routable while publication is blocked must still be present in
	// the first runtime view exposed after the gate opens.
	routableHash := addRoutableNodeForSubscription(
		t,
		pool,
		sub,
		[]byte(`{"type":"ss","server":"1.1.1.1","port":443}`),
		"203.0.113.10",
	)

	gate.RUnlock()
	select {
	case result := <-createDone:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.platform == nil || result.platform.ID != persistedID {
			t.Fatalf("created Platform = %+v, want id=%s", result.platform, persistedID)
		}
	case <-time.After(time.Second):
		t.Fatal("create remained blocked after publication reader released")
	}
	published, ok := pool.GetPlatformByName(name)
	if !ok {
		t.Fatal("runtime Platform was not published")
	}
	if !published.View().Contains(routableHash) {
		t.Fatal("runtime Platform published with a stale routable view")
	}
	resolved, err = policies.Resolve(persistedID, "example.com:443", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if resolved.EffectiveMode != tlspolicy.ModeBypass || policies.Snapshot().Generation != initialGeneration+1 {
		t.Fatalf("published TLS policy=%+v generation=%d", resolved, policies.Snapshot().Generation)
	}
}

func TestCreatePlatformMapsPolicyStoreFailureToInternal(t *testing.T) {
	root := t.TempDir()
	engine, closer, err := state.PersistenceBootstrap(filepath.Join(root, "state"), filepath.Join(root, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	pool := topology.NewGlobalNodePool(topology.PoolConfig{
		GeoLookup:              func(netip.Addr) string { return "us" },
		MaxLatencyTableEntries: 16,
		MaxConsecutiveFailures: func() int { return 3 },
		LatencyDecayWindow:     func() time.Duration { return 10 * time.Minute },
	})
	registry := tlspolicy.NewCABundleRegistry(engine, time.Now)
	policies, err := tlspolicy.NewPolicyService(engine, registry, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	cp := &ControlPlaneService{
		Engine: engine, Pool: pool, CABundles: registry, TLSPolicy: policies,
		EnvCfg: &config.EnvConfig{
			DefaultPlatformStickyTTL:                        30 * time.Minute,
			DefaultPlatformRegexFilters:                     []string{},
			DefaultPlatformRegionFilters:                    []string{},
			DefaultPlatformReverseProxyMissAction:           "TREAT_AS_EMPTY",
			DefaultPlatformReverseProxyEmptyAccountBehavior: "RANDOM",
			DefaultPlatformAllocationPolicy:                 "BALANCED",
		},
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}

	name := "closed-store-create"
	_, err = cp.CreatePlatform(CreatePlatformRequest{Name: &name})
	assertServiceErrorCode(t, err, "INTERNAL")
}

func TestUpdatePlatformConfigurationMapsPersistenceFailureToInternal(t *testing.T) {
	root := t.TempDir()
	engine, closer, err := state.PersistenceBootstrap(filepath.Join(root, "state"), filepath.Join(root, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	pool := topology.NewGlobalNodePool(topology.PoolConfig{
		GeoLookup:              func(netip.Addr) string { return "us" },
		MaxLatencyTableEntries: 16,
		MaxConsecutiveFailures: func() int { return 3 },
		LatencyDecayWindow:     func() time.Duration { return 10 * time.Minute },
	})
	registry := tlspolicy.NewCABundleRegistry(engine, time.Now)
	policies, err := tlspolicy.NewPolicyService(engine, registry, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	cp := &ControlPlaneService{
		Engine: engine, Pool: pool, CABundles: registry, TLSPolicy: policies,
		EnvCfg: &config.EnvConfig{
			DefaultPlatformStickyTTL:                        30 * time.Minute,
			DefaultPlatformRegexFilters:                     []string{},
			DefaultPlatformRegionFilters:                    []string{},
			DefaultPlatformReverseProxyMissAction:           "TREAT_AS_EMPTY",
			DefaultPlatformReverseProxyEmptyAccountBehavior: "RANDOM",
			DefaultPlatformAllocationPolicy:                 "BALANCED",
		},
	}
	name := "closed-store-update"
	created, err := cp.CreatePlatform(CreatePlatformRequest{Name: &name})
	if err != nil {
		t.Fatal(err)
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = cp.UpdatePlatformConfiguration(created.ID, 1, UpdatePlatformConfigurationRequest{
		Platform: configurationTestFields("closed-store-updated"),
	}, tlspolicy.AuditContext{})
	assertServiceErrorCode(t, err, "INTERNAL")
}

func TestDeletePlatformPublishesPoolAndTLSSnapshotUnderGate(t *testing.T) {
	root := t.TempDir()
	engine, closer, err := state.PersistenceBootstrap(filepath.Join(root, "state"), filepath.Join(root, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closer.Close() })
	pool := topology.NewGlobalNodePool(topology.PoolConfig{
		GeoLookup:              func(netip.Addr) string { return "us" },
		MaxLatencyTableEntries: 16,
		MaxConsecutiveFailures: func() int { return 3 },
		LatencyDecayWindow:     func() time.Duration { return 10 * time.Minute },
	})
	registry := tlspolicy.NewCABundleRegistry(engine, time.Now)
	policies, err := tlspolicy.NewPolicyService(engine, registry, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	gate := &sync.RWMutex{}
	cp := &ControlPlaneService{
		Engine: engine, Pool: pool, CABundles: registry, TLSPolicy: policies, PublicationGate: gate,
		EnvCfg: &config.EnvConfig{
			DefaultPlatformStickyTTL:                        30 * time.Minute,
			DefaultPlatformRegexFilters:                     []string{},
			DefaultPlatformRegionFilters:                    []string{},
			DefaultPlatformReverseProxyMissAction:           "TREAT_AS_EMPTY",
			DefaultPlatformReverseProxyEmptyAccountBehavior: "RANDOM",
			DefaultPlatformAllocationPolicy:                 "BALANCED",
		},
	}
	name := "delete-publication"
	created, err := cp.CreatePlatform(CreatePlatformRequest{Name: &name})
	if err != nil {
		t.Fatal(err)
	}
	reason := "temporary upstream exception"
	if _, err := cp.CreateTLSPolicy(created.ID, tlspolicy.Mutation{
		Mode: tlspolicy.ModeBypass, Reason: &reason, ExpirySet: true,
	}, tlspolicy.AuditContext{}); err != nil {
		t.Fatal(err)
	}

	gate.RLock()
	deleteDone := make(chan error, 1)
	go func() { deleteDone <- cp.DeletePlatform(created.ID) }()

	deadline := time.Now().Add(time.Second)
	for {
		_, err := engine.GetPlatformConfiguration(created.ID)
		if errors.Is(err, state.ErrNotFound) {
			break
		}
		if err != nil {
			gate.RUnlock()
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			gate.RUnlock()
			t.Fatal("platform deletion did not commit while waiting for publication gate")
		}
		time.Sleep(time.Millisecond)
	}

	select {
	case err := <-deleteDone:
		gate.RUnlock()
		t.Fatalf("platform deletion completed while publication reader was active: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	if _, ok := pool.GetPlatform(created.ID); !ok {
		gate.RUnlock()
		t.Fatal("runtime Platform disappeared before the publication boundary")
	}
	resolved, err := policies.Resolve(created.ID, "example.com:443", time.Now())
	if err != nil {
		gate.RUnlock()
		t.Fatal(err)
	}
	if resolved.EffectiveMode != tlspolicy.ModeBypass {
		gate.RUnlock()
		t.Fatalf("TLS mode changed before the publication boundary: %s", resolved.EffectiveMode)
	}

	gate.RUnlock()
	select {
	case err := <-deleteDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("platform deletion remained blocked after publication reader released")
	}
	if _, ok := pool.GetPlatform(created.ID); ok {
		t.Fatal("runtime Platform remained registered after deletion")
	}
	resolved, err = policies.Resolve(created.ID, "example.com:443", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if resolved.EffectiveMode != tlspolicy.ModeVerify {
		t.Fatalf("TLS policy remained active after deletion: %s", resolved.EffectiveMode)
	}
}

func configurationTestFields(name string) PlatformConfigurationFields {
	return PlatformConfigurationFields{
		Name: name, StickyTTL: "45m", RegexFilters: []string{}, RegionFilters: []string{},
		ReverseProxyMissAction: "TREAT_AS_EMPTY", ReverseProxyEmptyAccountBehavior: "RANDOM",
		AllocationPolicy: "BALANCED",
	}
}
