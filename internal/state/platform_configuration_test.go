package state

import (
	"errors"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/tlspolicy"
	"github.com/google/uuid"
)

func TestApplyPlatformConfigurationIsAtomicAcrossPlatformPolicyAndHistory(t *testing.T) {
	engine, _, _ := newTestEngine(t)
	platformID := uuid.NewString()
	initial := tlsTestPlatform(platformID, "atomic-initial")
	if err := engine.UpsertPlatform(initial); err != nil {
		t.Fatal(err)
	}
	storedInitial, err := engine.GetPlatform(platformID)
	if err != nil {
		t.Fatal(err)
	}
	if storedInitial.ConfigVersion != 1 {
		t.Fatalf("initial config version = %d, want 1", storedInitial.ConfigVersion)
	}
	missingNow := time.Now().UTC()
	missingPolicy := tlspolicy.PolicyRecord{
		ID: uuid.NewString(), PlatformID: platformID, PlatformName: "missing-bundle-must-not-persist",
		Mode: tlspolicy.ModeTrustCustomCA, BundleID: uuid.NewString(), BundleFingerprint: "missing",
		Version: 1, CreatedAt: missingNow, UpdatedAt: missingNow,
	}
	missingEvent := tlspolicy.PolicyEvent{
		ID: uuid.NewString(), EventKind: "CREATE", PolicyID: missingPolicy.ID,
		PlatformID: platformID, PlatformName: missingPolicy.PlatformName,
		New: tlspolicy.SnapshotPolicy(missingPolicy), OccurredAt: missingNow,
	}
	missingPlatform := initial
	missingPlatform.Name = missingPolicy.PlatformName
	if _, err := engine.ApplyPlatformConfiguration(missingPlatform, 1, tlspolicy.ConfigurationMutation{
		ExpectedVersion: 0, Next: &missingPolicy, Event: &missingEvent,
	}); !errors.Is(err, tlspolicy.ErrNotFound) {
		t.Fatalf("missing bundle error = %v, want ErrNotFound", err)
	}
	missingRollback, err := engine.GetPlatformConfiguration(platformID)
	if err != nil {
		t.Fatal(err)
	}
	if missingRollback.Platform.Name != initial.Name || missingRollback.Platform.ConfigVersion != 1 || missingRollback.Policy != nil {
		t.Fatalf("missing bundle partially persisted state: %+v", missingRollback)
	}
	if history, err := engine.ListTLSPolicyHistory(platformID); err != nil || len(history) != 0 {
		t.Fatalf("missing bundle history = %+v err=%v", history, err)
	}

	registry := tlspolicy.NewCABundleRegistry(engine, time.Now)
	bundle, _, err := registry.Import(stateTestCAPEM(t), tlspolicy.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	policy := tlspolicy.PolicyRecord{
		ID: uuid.NewString(), PlatformID: platformID, PlatformName: "atomic-updated",
		Mode: tlspolicy.ModeTrustCustomCA, BundleID: bundle.ID, BundleFingerprint: bundle.Fingerprint,
		Version: 1, CreatedAt: now, UpdatedAt: now,
	}
	createEvent := tlspolicy.PolicyEvent{
		ID: uuid.NewString(), EventKind: "CREATE", PolicyID: policy.ID,
		PlatformID: platformID, PlatformName: policy.PlatformName,
		New: tlspolicy.SnapshotPolicy(policy), OccurredAt: now,
	}
	updated := initial
	updated.Name = policy.PlatformName
	updated.StickyTTLNs = int64(2 * time.Hour)
	updated.UpdatedAtNs = now.UnixNano()
	version, err := engine.ApplyPlatformConfiguration(updated, 1, tlspolicy.ConfigurationMutation{
		ExpectedVersion: 0, Next: &policy, Event: &createEvent,
	})
	if err != nil {
		t.Fatal(err)
	}
	if version != 2 {
		t.Fatalf("config version = %d, want 2", version)
	}
	assertPlatformConfigurationState(t, engine, platformID, "atomic-updated", 2, tlspolicy.ModeTrustCustomCA, 1, 1)

	staleAggregatePlatform := updated
	staleAggregatePlatform.Name = "stale-aggregate-must-not-persist"
	replacement := policy
	replacement.Mode = tlspolicy.ModeBypass
	replacement.BundleID = ""
	replacement.BundleFingerprint = ""
	replacement.Reason = "temporary exception"
	replacement.Version = 2
	replacement.UpdatedAt = now.Add(time.Minute)
	replaceEvent := tlspolicy.PolicyEvent{
		ID: uuid.NewString(), EventKind: "MODE_REPLACE", PolicyID: policy.ID,
		PlatformID: platformID, PlatformName: staleAggregatePlatform.Name,
		Old: tlspolicy.SnapshotPolicy(policy), New: tlspolicy.SnapshotPolicy(replacement),
		OccurredAt: replacement.UpdatedAt,
	}
	err = func() error {
		_, applyErr := engine.ApplyPlatformConfiguration(staleAggregatePlatform, 1, tlspolicy.ConfigurationMutation{
			ExpectedVersion: 1, Current: &policy, Next: &replacement, Event: &replaceEvent,
		})
		return applyErr
	}()
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("stale aggregate error = %v, want ErrConflict", err)
	}
	assertPlatformConfigurationState(t, engine, platformID, "atomic-updated", 2, tlspolicy.ModeTrustCustomCA, 1, 1)

	wrongCurrent := policy
	wrongCurrent.Version = 99
	stalePolicyPlatform := updated
	stalePolicyPlatform.Name = "stale-policy-must-not-persist"
	err = func() error {
		_, applyErr := engine.ApplyPlatformConfiguration(stalePolicyPlatform, 2, tlspolicy.ConfigurationMutation{
			ExpectedVersion: 99, Current: &wrongCurrent, Next: &replacement, Event: &replaceEvent,
		})
		return applyErr
	}()
	if !errors.Is(err, tlspolicy.ErrConflict) {
		t.Fatalf("stale policy error = %v, want TLS conflict", err)
	}
	assertPlatformConfigurationState(t, engine, platformID, "atomic-updated", 2, tlspolicy.ModeTrustCustomCA, 1, 1)

	duplicateHistoryEvent := replaceEvent
	duplicateHistoryEvent.ID = createEvent.ID
	rollbackPlatform := updated
	rollbackPlatform.Name = "history-failure-must-roll-back"
	if _, err := engine.ApplyPlatformConfiguration(rollbackPlatform, 2, tlspolicy.ConfigurationMutation{
		ExpectedVersion: 1, Current: &policy, Next: &replacement, Event: &duplicateHistoryEvent,
	}); err == nil {
		t.Fatal("expected duplicate history event to fail")
	}
	assertPlatformConfigurationState(t, engine, platformID, "atomic-updated", 2, tlspolicy.ModeTrustCustomCA, 1, 1)
}

func TestCreatePlatformConfigurationIsAtomicAcrossPlatformPolicyAndHistory(t *testing.T) {
	engine, _, _ := newTestEngine(t)
	verifyID := uuid.NewString()
	verifyPlatform := tlsTestPlatform(verifyID, "verify-create")
	if err := engine.CreatePlatformConfiguration(verifyPlatform, tlspolicy.ConfigurationMutation{ExpectedVersion: 0}); err != nil {
		t.Fatal(err)
	}
	verifyState, err := engine.GetPlatformConfiguration(verifyID)
	if err != nil {
		t.Fatal(err)
	}
	if verifyState.Platform.ConfigVersion != 1 || verifyState.Policy != nil {
		t.Fatalf("VERIFY create state = %+v", verifyState)
	}
	if history, err := engine.ListTLSPolicyHistory(verifyID); err != nil || len(history) != 0 {
		t.Fatalf("VERIFY create history = %+v err=%v", history, err)
	}

	registry := tlspolicy.NewCABundleRegistry(engine, time.Now)
	bundle, _, err := registry.Import(stateTestCAPEM(t), tlspolicy.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	platformID := uuid.NewString()
	platformRow := tlsTestPlatform(platformID, "atomic-create")
	policy := tlspolicy.PolicyRecord{
		ID: uuid.NewString(), PlatformID: platformID, PlatformName: platformRow.Name,
		Mode: tlspolicy.ModeTrustCustomCA, BundleID: bundle.ID, BundleFingerprint: bundle.Fingerprint,
		Version: 1, CreatedAt: now, UpdatedAt: now,
	}
	event := tlspolicy.PolicyEvent{
		ID: uuid.NewString(), EventKind: "CREATE", PolicyID: policy.ID,
		PlatformID: platformID, PlatformName: platformRow.Name,
		New: tlspolicy.SnapshotPolicy(policy), OccurredAt: now,
	}
	if err := engine.CreatePlatformConfiguration(platformRow, tlspolicy.ConfigurationMutation{
		ExpectedVersion: 0, Next: &policy, Event: &event,
	}); err != nil {
		t.Fatal(err)
	}
	assertPlatformConfigurationState(t, engine, platformID, platformRow.Name, 1, tlspolicy.ModeTrustCustomCA, 1, 1)

	missingID := uuid.NewString()
	missingPlatform := tlsTestPlatform(missingID, "missing-ca-create")
	missingPolicy := policy
	missingPolicy.ID = uuid.NewString()
	missingPolicy.PlatformID = missingID
	missingPolicy.PlatformName = missingPlatform.Name
	missingPolicy.BundleID = uuid.NewString()
	missingPolicy.BundleFingerprint = "missing"
	missingEvent := event
	missingEvent.ID = uuid.NewString()
	missingEvent.PolicyID = missingPolicy.ID
	missingEvent.PlatformID = missingID
	missingEvent.PlatformName = missingPlatform.Name
	missingEvent.New = tlspolicy.SnapshotPolicy(missingPolicy)
	if err := engine.CreatePlatformConfiguration(missingPlatform, tlspolicy.ConfigurationMutation{
		ExpectedVersion: 0, Next: &missingPolicy, Event: &missingEvent,
	}); !errors.Is(err, tlspolicy.ErrNotFound) {
		t.Fatalf("missing CA error = %v, want ErrNotFound", err)
	}
	if _, err := engine.GetPlatform(missingID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing CA left Platform behind: %v", err)
	}
	if history, err := engine.ListTLSPolicyHistory(missingID); err != nil || len(history) != 0 {
		t.Fatalf("missing CA history = %+v err=%v", history, err)
	}

	historyFailureID := uuid.NewString()
	historyFailurePlatform := tlsTestPlatform(historyFailureID, "history-failure-create")
	historyFailurePolicy := policy
	historyFailurePolicy.ID = uuid.NewString()
	historyFailurePolicy.PlatformID = historyFailureID
	historyFailurePolicy.PlatformName = historyFailurePlatform.Name
	historyFailureEvent := event
	historyFailureEvent.PolicyID = historyFailurePolicy.ID
	historyFailureEvent.PlatformID = historyFailureID
	historyFailureEvent.PlatformName = historyFailurePlatform.Name
	historyFailureEvent.New = tlspolicy.SnapshotPolicy(historyFailurePolicy)
	if err := engine.CreatePlatformConfiguration(historyFailurePlatform, tlspolicy.ConfigurationMutation{
		ExpectedVersion: 0, Next: &historyFailurePolicy, Event: &historyFailureEvent,
	}); err == nil {
		t.Fatal("expected duplicate history event to roll back create")
	}
	if _, err := engine.GetPlatform(historyFailureID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("history failure left Platform behind: %v", err)
	}
}

func TestSingularPlatformAndTLSPolicyMutationsIncrementAggregateVersion(t *testing.T) {
	engine, _, _ := newTestEngine(t)
	platformID := uuid.NewString()
	platformRow := tlsTestPlatform(platformID, "versioned-platform")
	if err := engine.UpsertPlatform(platformRow); err != nil {
		t.Fatal(err)
	}
	assertPlatformConfigVersion(t, engine, platformID, 1)

	policyService, err := tlspolicy.NewPolicyService(engine, nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	reason := "temporary exception"
	policy, err := policyService.Create(platformID, platformRow.Name, tlspolicy.Mutation{
		Mode: tlspolicy.ModeBypass, Reason: &reason, ExpirySet: true,
	}, tlspolicy.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	assertPlatformConfigVersion(t, engine, platformID, 2)

	replacementReason := "replacement exception"
	policy, err = policyService.Replace(platformID, policy.Version, tlspolicy.Mutation{
		Mode: tlspolicy.ModeBypass, Reason: &replacementReason,
	}, tlspolicy.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	assertPlatformConfigVersion(t, engine, platformID, 3)

	if err := policyService.Delete(platformID, policy.Version, tlspolicy.AuditContext{}); err != nil {
		t.Fatal(err)
	}
	assertPlatformConfigVersion(t, engine, platformID, 4)

	platformRow.Name = "versioned-platform-updated"
	platformRow.UpdatedAtNs++
	if err := engine.UpsertPlatform(platformRow); err != nil {
		t.Fatal(err)
	}
	assertPlatformConfigVersion(t, engine, platformID, 5)
}

func assertPlatformConfigurationState(
	t *testing.T,
	engine *StateEngine,
	platformID string,
	wantName string,
	wantConfigVersion int64,
	wantMode tlspolicy.Mode,
	wantPolicyVersion int64,
	wantHistoryLength int,
) {
	t.Helper()
	configuration, err := engine.GetPlatformConfiguration(platformID)
	if err != nil {
		t.Fatal(err)
	}
	if configuration.Platform.Name != wantName || configuration.Platform.ConfigVersion != wantConfigVersion {
		t.Fatalf("platform state = %+v, want name=%q config_version=%d", configuration.Platform, wantName, wantConfigVersion)
	}
	if configuration.Policy == nil || configuration.Policy.Mode != wantMode || configuration.Policy.Version != wantPolicyVersion {
		t.Fatalf("policy state = %+v, want mode=%s version=%d", configuration.Policy, wantMode, wantPolicyVersion)
	}
	history, err := engine.ListTLSPolicyHistory(platformID)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != wantHistoryLength {
		t.Fatalf("history length = %d, want %d: %+v", len(history), wantHistoryLength, history)
	}
}

func assertPlatformConfigVersion(t *testing.T, engine *StateEngine, platformID string, want int64) {
	t.Helper()
	platformRow, err := engine.GetPlatform(platformID)
	if err != nil {
		t.Fatal(err)
	}
	if platformRow.ConfigVersion != want {
		t.Fatalf("config version = %d, want %d", platformRow.ConfigVersion, want)
	}
}
