package tlspolicy

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/platform"
)

type memoryPolicyStore struct {
	mu       sync.Mutex
	policies map[string]PolicyRecord
	history  []PolicyEvent
}

func newMemoryPolicyStore() *memoryPolicyStore {
	return &memoryPolicyStore{policies: map[string]PolicyRecord{}}
}

func (s *memoryPolicyStore) ListTLSPolicies() ([]PolicyRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PolicyRecord, 0, len(s.policies))
	for _, policy := range s.policies {
		out = append(out, policy)
	}
	return out, nil
}

func (s *memoryPolicyStore) GetTLSPolicy(platformID string) (PolicyRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	policy, ok := s.policies[platformID]
	if !ok {
		return PolicyRecord{}, ErrNotFound
	}
	return policy, nil
}

func (s *memoryPolicyStore) CreateTLSPolicy(policy PolicyRecord, event PolicyEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.policies[policy.PlatformID]; exists {
		return ErrConflict
	}
	s.policies[policy.PlatformID] = policy
	s.history = append(s.history, event)
	return nil
}

func (s *memoryPolicyStore) ReplaceTLSPolicy(platformID string, expectedVersion int64, policy PolicyRecord, event PolicyEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.policies[platformID]
	if !ok || current.Version != expectedVersion {
		return ErrConflict
	}
	s.policies[platformID] = policy
	s.history = append(s.history, event)
	return nil
}

func (s *memoryPolicyStore) DeleteTLSPolicy(platformID string, expectedVersion int64, event PolicyEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.policies[platformID]
	if !ok || current.Version != expectedVersion {
		return ErrConflict
	}
	delete(s.policies, platformID)
	s.history = append(s.history, event)
	return nil
}

func (s *memoryPolicyStore) DeletePlatformWithTLSHistory(platformID string, audit AuditContext) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if policy, ok := s.policies[platformID]; ok {
		delete(s.policies, platformID)
		s.history = append(s.history, PolicyEvent{EventKind: "PLATFORM_DELETE_POLICY", PolicyID: policy.ID, PlatformID: platformID, Old: SnapshotPolicy(policy), RequestID: audit.RequestID})
	}
	return nil
}

func (s *memoryPolicyStore) ListTLSPolicyHistory(platformID string) ([]PolicyEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []PolicyEvent
	for _, event := range s.history {
		if platformID == "" || event.PlatformID == platformID {
			out = append(out, event)
		}
	}
	return out, nil
}

func TestPolicyServiceUnionBypassGovernanceExpiryCASAndHistory(t *testing.T) {
	base := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	clock := base
	caStore := newMemoryCABundleStore()
	registry := NewCABundleRegistry(caStore, func() time.Time { return clock })
	caPEM, _ := testCertificatePEM(t, "policy-ca", true)
	bundle, _, err := registry.Import(caPEM, AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	store := newMemoryPolicyStore()
	policy, err := NewPolicyService(store, registry, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}

	custom, err := policy.Create("platform-id", "platform", Mutation{Mode: ModeTrustCustomCA, BundleID: bundle.ID}, AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if custom.Version != 1 || custom.BundleID != bundle.ID || custom.Reason != "" || custom.ExpiresAt != nil {
		t.Fatalf("custom rule = %+v", custom)
	}
	resolved, err := policy.Resolve("platform-id", "private.example:443", clock)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.EffectiveMode != ModeTrustCustomCA || len(resolved.CanonicalPEM) == 0 {
		t.Fatalf("resolved custom policy = %+v", resolved)
	}
	secondTarget, err := policy.Resolve("platform-id", "other.example:443", clock)
	if err != nil || secondTarget.EffectiveMode != ModeTrustCustomCA || secondTarget.NormalizedTarget != "other.example:443" {
		t.Fatalf("same platform policy did not apply to second target: %+v err=%v", secondTarget, err)
	}

	expires := base.Add(time.Hour)
	reason := " temporary exception "
	bypass, err := policy.Replace(custom.PlatformID, 1, Mutation{Mode: ModeBypass, Reason: &reason, ExpirySet: true, ExpiresAt: &expires}, AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if bypass.BundleID != "" || bypass.BundleFingerprint != "" || bypass.Reason != "temporary exception" || bypass.Version != 2 {
		t.Fatalf("bypass replacement = %+v", bypass)
	}
	for _, tc := range []struct {
		name       string
		now        time.Time
		wantMode   Mode
		wantExpiry bool
	}{
		{"before", expires.Add(-time.Nanosecond), ModeBypass, false},
		{"equal", expires, ModeVerify, true},
		{"after", expires.Add(time.Nanosecond), ModeVerify, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := policy.Resolve("platform-id", "private.example:443", tc.now)
			if err != nil {
				t.Fatal(err)
			}
			if got.EffectiveMode != tc.wantMode || got.Expired != tc.wantExpiry || got.ConfiguredMode != ModeBypass {
				t.Fatalf("resolved = %+v", got)
			}
		})
	}

	unchanged, err := policy.Replace(custom.PlatformID, 2, Mutation{Mode: ModeBypass}, AuditContext{})
	if err != nil {
		t.Fatalf("unchanged expiry/reason should be retained: %v", err)
	}
	if unchanged.Reason != "temporary exception" || unchanged.ExpiresAt == nil || !unchanged.ExpiresAt.Equal(expires) {
		t.Fatalf("retained bypass = %+v", unchanged)
	}
	extended := expires.Add(time.Hour)
	if _, err := policy.Replace(custom.PlatformID, 3, Mutation{Mode: ModeBypass, ExpirySet: true, ExpiresAt: &extended}, AuditContext{}); err == nil {
		t.Fatal("extension without a new reason succeeded")
	}
	newReason := "extended after vendor confirmation"
	extendedRule, err := policy.Replace(custom.PlatformID, 3, Mutation{Mode: ModeBypass, Reason: &newReason, ExpirySet: true, ExpiresAt: &extended}, AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Replace(custom.PlatformID, extendedRule.Version, Mutation{Mode: ModeBypass, ExpirySet: true}, AuditContext{}); err == nil {
		t.Fatal("temporary-to-permanent conversion without a new reason succeeded")
	}
	blank := "  "
	if _, err := policy.Replace(custom.PlatformID, extendedRule.Version, Mutation{Mode: ModeBypass, Reason: &blank, ExpirySet: true}, AuditContext{}); err == nil {
		t.Fatal("explicit blank reason succeeded")
	}
	permanentReason := "approved permanent exception"
	permanent, err := policy.Replace(custom.PlatformID, extendedRule.Version, Mutation{Mode: ModeBypass, Reason: &permanentReason, ExpirySet: true}, AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if permanent.ExpiresAt != nil || permanent.Reason != permanentReason {
		t.Fatalf("permanent rule = %+v", permanent)
	}
	if _, err := policy.Replace(custom.PlatformID, 1, Mutation{Mode: ModeTrustCustomCA, BundleID: bundle.ID}, AuditContext{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale CAS error = %v, want ErrConflict", err)
	}
	history, err := policy.History("platform-id")
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 5 {
		t.Fatalf("history length = %d, want 5", len(history))
	}
	if history[0].New == nil || history[len(history)-1].New == nil || history[len(history)-1].New.Version != permanent.Version {
		t.Fatalf("history versions = %+v", history)
	}
}

func TestValidatePolicyRejectsPersistedVerifyAndCrossModeFields(t *testing.T) {
	base := PolicyRecord{ID: "policy", PlatformID: "platform", PlatformName: "name", Version: 1}
	tests := []PolicyRecord{
		base,
		func() PolicyRecord { v := base; v.Mode = ModeVerify; return v }(),
		func() PolicyRecord {
			v := base
			v.Mode = ModeTrustCustomCA
			v.BundleID = "bundle"
			v.BundleFingerprint = "fingerprint"
			v.Reason = "forbidden"
			return v
		}(),
		func() PolicyRecord {
			v := base
			v.Mode = ModeBypass
			v.Reason = "reason"
			v.BundleID = "forbidden"
			return v
		}(),
		func() PolicyRecord { v := base; v.Mode = ModeBypass; v.Reason = " "; return v }(),
	}
	for i, rule := range tests {
		if err := ValidatePolicy(rule); err == nil {
			t.Fatalf("case %d unexpectedly valid: %+v", i, rule)
		}
	}
	defaultPolicy := base
	defaultPolicy.PlatformID = platform.DefaultPlatformID
	defaultPolicy.Mode = ModeBypass
	defaultPolicy.Reason = "forbidden"
	if err := ValidatePolicy(defaultPolicy); !errors.Is(err, ErrDefaultPlatform) {
		t.Fatalf("Default validation error = %v, want ErrDefaultPlatform", err)
	}

	service, err := NewPolicyService(newMemoryPolicyStore(), nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	reason := "forbidden"
	if _, err := service.Create(platform.DefaultPlatformID, platform.DefaultPlatformName, Mutation{
		Mode: ModeBypass, Reason: &reason, ExpirySet: true,
	}, AuditContext{}); !errors.Is(err, ErrDefaultPlatform) {
		t.Fatalf("Default mutation error = %v, want ErrDefaultPlatform", err)
	}
}

type capturedPolicyTimer struct {
	stopped bool
}

func (t *capturedPolicyTimer) Stop() bool {
	wasActive := !t.stopped
	t.stopped = true
	return wasActive
}

func TestPolicyServicePublishesAtExactBypassExpiry(t *testing.T) {
	base := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	clock := base
	var scheduledDelay time.Duration
	var scheduledCallback func()
	schedule := func(delay time.Duration, callback func()) policyTimer {
		scheduledDelay = delay
		scheduledCallback = callback
		return &capturedPolicyTimer{}
	}
	store := newMemoryPolicyStore()
	policy, err := newPolicyService(store, nil, func() time.Time { return clock }, schedule)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := base.Add(15 * time.Minute)
	reason := "bounded exception"
	rule, err := policy.Create("platform-id", "platform", Mutation{
		Mode: ModeBypass, Reason: &reason, ExpirySet: true, ExpiresAt: &expiresAt,
	}, AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	before := policy.Snapshot()
	profileKey := profileKeyForPolicy(rule)
	if _, ok := before.ProfileKeys()[profileKey]; !ok {
		t.Fatal("unexpired BYPASS profile was not published active")
	}
	if scheduledDelay != 15*time.Minute || scheduledCallback == nil {
		t.Fatalf("expiry schedule = %v callback=%v", scheduledDelay, scheduledCallback != nil)
	}

	publications := 0
	policy.AddSnapshotListener(func(old, next *Snapshot) {
		publications++
		if old.Generation != before.Generation || next.Generation <= old.Generation {
			t.Fatalf("publication generations old=%d next=%d", old.Generation, next.Generation)
		}
	})
	clock = expiresAt
	scheduledCallback()

	after := policy.Snapshot()
	if publications != 1 {
		t.Fatalf("expiry publications = %d, want 1", publications)
	}
	if _, ok := after.ProfileKeys()[profileKey]; ok {
		t.Fatal("expired BYPASS profile remained active at exact expiry")
	}
	resolved, err := policy.Resolve("platform-id", "private.example:443", clock)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.SnapshotGeneration != after.Generation || resolved.EffectiveMode != ModeVerify || !resolved.Expired {
		t.Fatalf("resolved at exact expiry = %+v", resolved)
	}
}

func TestPolicyServiceListenerRunsBeforeSnapshotBecomesVisible(t *testing.T) {
	base := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	store := newMemoryPolicyStore()
	policy, err := NewPolicyService(store, nil, func() time.Time { return base })
	if err != nil {
		t.Fatal(err)
	}
	old := policy.Snapshot()
	policy.AddSnapshotListener(func(listenerOld, next *Snapshot) {
		if listenerOld != old || policy.Snapshot() != old {
			t.Fatal("candidate snapshot became visible before dependent cache publication")
		}
		if next.Generation <= old.Generation {
			t.Fatalf("candidate generation=%d old=%d", next.Generation, old.Generation)
		}
	})
	reason := "bounded exception"
	if _, err := policy.Create("platform-id", "platform", Mutation{
		Mode: ModeBypass, Reason: &reason, ExpirySet: true,
	}, AuditContext{}); err != nil {
		t.Fatal(err)
	}
	if policy.Snapshot() == old {
		t.Fatal("candidate snapshot was not published after listeners completed")
	}
}

func TestPolicyServiceConcurrentVersionCASHasSingleWinner(t *testing.T) {
	base := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	store := newMemoryPolicyStore()
	policy, err := NewPolicyService(store, nil, func() time.Time { return base })
	if err != nil {
		t.Fatal(err)
	}
	reason := "initial"
	rule, err := policy.Create("platform-id", "platform", Mutation{
		Mode: ModeBypass, Reason: &reason, ExpirySet: true,
	}, AuditContext{})
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	for _, value := range []string{"replacement-a", "replacement-b"} {
		value := value
		go func() {
			<-start
			_, replaceErr := policy.Replace(rule.PlatformID, rule.Version, Mutation{Mode: ModeBypass, Reason: &value}, AuditContext{})
			results <- replaceErr
		}()
	}
	close(start)
	succeeded, conflicted := 0, 0
	for range 2 {
		switch err := <-results; {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrConflict):
			conflicted++
		default:
			t.Fatalf("unexpected concurrent CAS result: %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent CAS winners=%d conflicts=%d", succeeded, conflicted)
	}
	history, err := policy.History("platform-id")
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 {
		t.Fatalf("history events=%d, want create plus one replacement", len(history))
	}
}

func TestApplyConfigurationMarksUnexpectedPersistenceFailuresAndPreservesCause(t *testing.T) {
	base := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	policy, err := NewPolicyService(newMemoryPolicyStore(), nil, func() time.Time { return base })
	if err != nil {
		t.Fatal(err)
	}
	persistErr := errors.New("database is closed")
	_, err = policy.ApplyConfiguration(
		"platform-id",
		"platform",
		nil,
		0,
		AuditContext{},
		func(ConfigurationMutation) error { return persistErr },
		nil,
	)
	if !errors.Is(err, ErrPersistence) || !errors.Is(err, persistErr) {
		t.Fatalf("ApplyConfiguration error = %v, want ErrPersistence wrapping original cause", err)
	}
}
