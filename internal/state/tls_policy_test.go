package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/model"
	"github.com/Resinat/Resin/internal/platform"
	"github.com/Resinat/Resin/internal/tlspolicy"
	"github.com/google/uuid"
)

func stateTestCAPEM(t *testing.T) []byte {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: "state test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func tlsTestPlatform(id, name string) model.Platform {
	return model.Platform{
		ID: id, Name: name, StickyTTLNs: int64(time.Hour),
		RegexFilters: []string{}, RegionFilters: []string{},
		ReverseProxyMissAction:           string(platform.ReverseProxyMissActionTreatAsEmpty),
		ReverseProxyEmptyAccountBehavior: string(platform.ReverseProxyEmptyAccountBehaviorRandom),
		AllocationPolicy:                 string(platform.AllocationPolicyBalanced),
		UpdatedAtNs:                      time.Now().UnixNano(),
	}
}

func TestTLSPolicyHistorySurvivesRenamePlatformDeletionAndBundleDeletion(t *testing.T) {
	engine, _, _ := newTestEngine(t)
	platformID := uuid.NewString()
	platformModel := tlsTestPlatform(platformID, "old-name")
	if err := engine.UpsertPlatform(platformModel); err != nil {
		t.Fatal(err)
	}
	registry := tlspolicy.NewCABundleRegistry(engine, time.Now)
	policy, err := tlspolicy.NewPolicyService(engine, registry, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := stateTestCAPEM(t)
	bundle, _, err := registry.Import(caPEM, tlspolicy.AuditContext{
		RequestID: "import-request", RemoteAddress: "192.0.2.8:1111", CredentialClass: "SHARED_ADMIN_TOKEN",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := registry.Import(caPEM, tlspolicy.AuditContext{
		RequestID: "reuse-request", RemoteAddress: "192.0.2.8:2222", CredentialClass: "SHARED_ADMIN_TOKEN",
	}); err != nil || created {
		t.Fatalf("dedup import created=%v err=%v", created, err)
	}
	rule, err := policy.Create(platformID, platformModel.Name, tlspolicy.Mutation{Mode: tlspolicy.ModeTrustCustomCA, BundleID: bundle.ID}, tlspolicy.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}

	platformModel.Name = "renamed-platform"
	platformModel.UpdatedAtNs++
	if err := engine.UpsertPlatform(platformModel); err != nil {
		t.Fatal(err)
	}
	storedPolicy, err := policy.Get(platformID)
	if err != nil {
		t.Fatal(err)
	}
	if storedPolicy.PlatformName != platformModel.Name {
		t.Fatalf("policy after rename = %+v", storedPolicy)
	}
	reason := "temporary vendor exception"
	rule, err = policy.Replace(platformID, rule.Version, tlspolicy.Mutation{Mode: tlspolicy.ModeBypass, Reason: &reason, ExpirySet: true}, tlspolicy.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}

	audit := tlspolicy.AuditContext{RequestID: "delete-request", RemoteAddress: "192.0.2.10:4444", CredentialClass: "SHARED_ADMIN_TOKEN"}
	if err := policy.DeletePlatform(platformID, audit); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.GetPlatform(platformID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted platform lookup error = %v", err)
	}
	if resolved, err := policy.Resolve(platformID, "private.example:443", time.Now()); err != nil || resolved.EffectiveMode != tlspolicy.ModeVerify {
		t.Fatalf("post-delete resolved = %+v err=%v", resolved, err)
	}
	history, err := policy.History(platformID)
	if err != nil {
		t.Fatal(err)
	}
	foundPolicyDelete, foundPlatformDelete := false, false
	for _, event := range history {
		if event.EventKind == "PLATFORM_DELETE_POLICY" {
			foundPolicyDelete = true
		}
		if event.EventKind == "PLATFORM_DELETE" {
			foundPlatformDelete = true
		}
		if strings.HasPrefix(event.EventKind, "PLATFORM_DELETE") {
			if event.PlatformName != platformModel.Name || event.RequestID != audit.RequestID || event.RemoteAddress != audit.RemoteAddress || event.CredentialClass != audit.CredentialClass {
				t.Fatalf("terminal history lost current name or audit context: %+v", event)
			}
		}
	}
	if !foundPolicyDelete || !foundPlatformDelete {
		t.Fatalf("terminal history missing: %+v", history)
	}

	if err := registry.DeleteIfUnused(bundle.ID, tlspolicy.AuditContext{
		RequestID: "bundle-delete", RemoteAddress: "192.0.2.8:3333", CredentialClass: "SHARED_ADMIN_TOKEN",
	}); err != nil {
		t.Fatal(err)
	}
	bundleHistory, err := registry.History(bundle.ID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(struct {
		Policies []tlspolicy.PolicyEvent   `json:"policies"`
		Bundles  []tlspolicy.CABundleEvent `json:"bundles"`
	}{history, bundleHistory})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "BEGIN CERTIFICATE") {
		t.Fatalf("history exposed PEM: %s", encoded)
	}
	if len(bundleHistory) != 3 || bundleHistory[0].EventKind != "CREATE" ||
		bundleHistory[1].EventKind != "REUSE" || bundleHistory[2].EventKind != "DELETE" {
		t.Fatalf("bundle history = %+v", bundleHistory)
	}
	for i, wantRequestID := range []string{"import-request", "reuse-request", "bundle-delete"} {
		eventJSON, err := json.Marshal(bundleHistory[i])
		if err != nil {
			t.Fatal(err)
		}
		var event map[string]any
		if err := json.Unmarshal(eventJSON, &event); err != nil {
			t.Fatal(err)
		}
		if event["request_id"] != wantRequestID || event["credential_class"] != "SHARED_ADMIN_TOKEN" {
			t.Fatalf("bundle history audit event %d = %s", i, eventJSON)
		}
		certificates, ok := event["certificates"].([]any)
		if !ok || len(certificates) != 1 {
			t.Fatalf("bundle history metadata event %d = %s", i, eventJSON)
		}
	}
}

func TestCABundleRegistryCertificateMetadataAndPolicySurviveRestart(t *testing.T) {
	stateDir := t.TempDir()
	cacheDir := t.TempDir()

	engine1, closer1, err := PersistenceBootstrap(stateDir, cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	platformID := uuid.NewString()
	platformModel := tlsTestPlatform(platformID, "restart-custom-ca")
	if err := engine1.UpsertPlatform(platformModel); err != nil {
		t.Fatal(err)
	}
	registry1 := tlspolicy.NewCABundleRegistry(engine1, time.Now)
	want, _, err := registry1.Import(stateTestCAPEM(t), tlspolicy.AuditContext{
		RequestID: "restart-import", RemoteAddress: "192.0.2.20:2000", CredentialClass: "SHARED_ADMIN_TOKEN",
	})
	if err != nil {
		t.Fatal(err)
	}
	policy1, err := tlspolicy.NewPolicyService(engine1, registry1, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy1.Create(platformID, platformModel.Name, tlspolicy.Mutation{
		Mode: tlspolicy.ModeTrustCustomCA, BundleID: want.ID,
	}, tlspolicy.AuditContext{}); err != nil {
		t.Fatal(err)
	}
	if err := closer1.Close(); err != nil {
		t.Fatal(err)
	}

	engine2, closer2, err := PersistenceBootstrap(stateDir, cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	defer closer2.Close()
	registry2 := tlspolicy.NewCABundleRegistry(engine2, time.Now)

	got, err := registry2.Get(want.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertCABundleCertificateMetadata(t, got, want)

	listed, err := registry2.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 {
		t.Fatalf("restarted CA bundle list length = %d, want 1", len(listed))
	}
	assertCABundleCertificateMetadata(t, listed[0], want)

	policy2, err := tlspolicy.NewPolicyService(engine2, registry2, time.Now)
	if err != nil {
		t.Fatalf("compile persisted custom CA policy after restart: %v", err)
	}
	resolved, err := policy2.Resolve(platformID, "private.example:443", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if resolved.EffectiveMode != tlspolicy.ModeTrustCustomCA ||
		resolved.BundleFingerprint != want.Fingerprint || len(resolved.CanonicalPEM) == 0 {
		t.Fatalf("custom CA policy after restart = %+v", resolved)
	}
	history, err := registry2.History(want.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || history[0].EventKind != "CREATE" ||
		history[0].RequestID != "restart-import" || len(history[0].Certificates) != 1 {
		t.Fatalf("CA history after restart = %+v", history)
	}
}

func TestCABundleHistoryMetadataSurvivesDeletionAndRestart(t *testing.T) {
	stateDir := t.TempDir()
	cacheDir := t.TempDir()
	engine1, closer1, err := PersistenceBootstrap(stateDir, cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	registry1 := tlspolicy.NewCABundleRegistry(engine1, time.Now)
	bundle, _, err := registry1.Import(stateTestCAPEM(t), tlspolicy.AuditContext{
		RequestID: "create", RemoteAddress: "192.0.2.30:3000", CredentialClass: "SHARED_ADMIN_TOKEN",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry1.DeleteIfUnused(bundle.ID, tlspolicy.AuditContext{
		RequestID: "delete", RemoteAddress: "192.0.2.31:3001", CredentialClass: "SHARED_ADMIN_TOKEN",
	}); err != nil {
		t.Fatal(err)
	}
	if err := closer1.Close(); err != nil {
		t.Fatal(err)
	}

	engine2, closer2, err := PersistenceBootstrap(stateDir, cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	defer closer2.Close()
	history, err := tlspolicy.NewCABundleRegistry(engine2, time.Now).History(bundle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 {
		t.Fatalf("deleted CA history after restart = %+v", history)
	}
	for i, want := range []struct {
		kind, requestID, remoteAddress string
	}{
		{kind: "CREATE", requestID: "create", remoteAddress: "192.0.2.30:3000"},
		{kind: "DELETE", requestID: "delete", remoteAddress: "192.0.2.31:3001"},
	} {
		event := history[i]
		if event.EventKind != want.kind || event.RequestID != want.requestID ||
			event.RemoteAddress != want.remoteAddress || event.CredentialClass != "SHARED_ADMIN_TOKEN" ||
			len(event.Certificates) != 1 {
			t.Fatalf("deleted CA history event %d after restart = %+v", i, event)
		}
		gotCertificate, wantCertificate := event.Certificates[0], bundle.Certificates[0]
		if gotCertificate.Subject != wantCertificate.Subject || gotCertificate.Issuer != wantCertificate.Issuer ||
			gotCertificate.Serial != wantCertificate.Serial ||
			!gotCertificate.NotBefore.Equal(wantCertificate.NotBefore) ||
			!gotCertificate.NotAfter.Equal(wantCertificate.NotAfter) {
			t.Fatalf("deleted CA certificate metadata event %d = %+v, want %+v", i, gotCertificate, wantCertificate)
		}
	}
	encoded, err := json.Marshal(history)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "BEGIN CERTIFICATE") || strings.Contains(string(encoded), "canonical_pem") {
		t.Fatalf("deleted CA history exposed PEM after restart: %s", encoded)
	}
}

func TestTLSPolicyStartupFailsClosedWhenPersistedCABundleIsMissingOrDamaged(t *testing.T) {
	tests := []string{"missing", "damaged canonical PEM", "mismatched certificate count"}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			stateDir := t.TempDir()
			cacheDir := t.TempDir()
			engine1, closer1, err := PersistenceBootstrap(stateDir, cacheDir)
			if err != nil {
				t.Fatal(err)
			}
			platformID := uuid.NewString()
			platformModel := tlsTestPlatform(platformID, "damaged-custom-ca")
			if err := engine1.UpsertPlatform(platformModel); err != nil {
				t.Fatal(err)
			}
			registry1 := tlspolicy.NewCABundleRegistry(engine1, time.Now)
			policy1, err := tlspolicy.NewPolicyService(engine1, registry1, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			bundle, _, err := registry1.Import(stateTestCAPEM(t), tlspolicy.AuditContext{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := policy1.Create(platformID, platformModel.Name, tlspolicy.Mutation{
				Mode: tlspolicy.ModeTrustCustomCA, BundleID: bundle.ID,
			}, tlspolicy.AuditContext{}); err != nil {
				t.Fatal(err)
			}
			if err := closer1.Close(); err != nil {
				t.Fatal(err)
			}

			db, err := OpenDB(filepath.Join(stateDir, "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "missing":
				if _, err := db.Exec(`PRAGMA foreign_keys = OFF`); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`DELETE FROM ca_bundles WHERE id = ?`, bundle.ID); err != nil {
					t.Fatal(err)
				}
			case "damaged canonical PEM":
				if _, err := db.Exec(`UPDATE ca_bundles SET canonical_pem = canonical_pem || 'damage' WHERE id = ?`, bundle.ID); err != nil {
					t.Fatal(err)
				}
			case "mismatched certificate count":
				if _, err := db.Exec(`UPDATE ca_bundles SET certificate_count = certificate_count + 1 WHERE id = ?`, bundle.ID); err != nil {
					t.Fatal(err)
				}
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}

			engine2, closer2, err := PersistenceBootstrap(stateDir, cacheDir)
			if err != nil {
				t.Fatal(err)
			}
			defer closer2.Close()
			registry2 := tlspolicy.NewCABundleRegistry(engine2, time.Now)
			if _, err := tlspolicy.NewPolicyService(engine2, registry2, time.Now); err == nil ||
				!errors.Is(err, tlspolicy.ErrIntegrity) {
				t.Fatalf("startup with %s CA bundle error = %v, want integrity failure", name, err)
			}
		})
	}
}

func TestCABundleHistoryCorruptionFailsClosed(t *testing.T) {
	engine, _, _ := newTestEngine(t)
	registry := tlspolicy.NewCABundleRegistry(engine, time.Now)
	bundle, _, err := registry.Import(stateTestCAPEM(t), tlspolicy.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.StateRepo.db.Exec(`UPDATE ca_bundle_history SET certificates_json = '{' WHERE bundle_id = ?`, bundle.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.History(bundle.ID); err == nil {
		t.Fatal("corrupt CA history metadata was silently accepted")
	}
}

func TestTLSPolicyStoreRechecksCustomCABundleInsideMutationTransaction(t *testing.T) {
	tests := []struct {
		name        string
		removeCA    bool
		fingerprint func(tlspolicy.CABundleRef) string
		wantError   error
	}{
		{
			name:        "missing bundle",
			removeCA:    true,
			fingerprint: func(bundle tlspolicy.CABundleRef) string { return bundle.Fingerprint },
			wantError:   tlspolicy.ErrNotFound,
		},
		{
			name:        "fingerprint mismatch",
			fingerprint: func(tlspolicy.CABundleRef) string { return "mismatched-fingerprint" },
			wantError:   tlspolicy.ErrIntegrity,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			engine, _, _ := newTestEngine(t)
			platformID := uuid.NewString()
			platformModel := tlsTestPlatform(platformID, "transactional-ca-check")
			if err := engine.UpsertPlatform(platformModel); err != nil {
				t.Fatal(err)
			}
			registry := tlspolicy.NewCABundleRegistry(engine, time.Now)
			bundle, _, err := registry.Import(stateTestCAPEM(t), tlspolicy.AuditContext{})
			if err != nil {
				t.Fatal(err)
			}
			if test.removeCA {
				if err := registry.DeleteIfUnused(bundle.ID, tlspolicy.AuditContext{}); err != nil {
					t.Fatal(err)
				}
			}
			now := time.Now().UTC()
			policy := tlspolicy.PolicyRecord{
				ID: uuid.NewString(), PlatformID: platformID, PlatformName: platformModel.Name,
				Mode: tlspolicy.ModeTrustCustomCA, BundleID: bundle.ID,
				BundleFingerprint: test.fingerprint(bundle), Version: 1,
				CreatedAt: now, UpdatedAt: now,
			}
			event := tlspolicy.PolicyEvent{
				ID: uuid.NewString(), EventKind: "CREATE", PolicyID: policy.ID,
				PlatformID: platformID, PlatformName: platformModel.Name,
				New: tlspolicy.SnapshotPolicy(policy), OccurredAt: now,
			}
			if err := engine.CreateTLSPolicy(policy, event); !errors.Is(err, test.wantError) {
				t.Fatalf("custom CA mutation error = %v, want %v", err, test.wantError)
			}
			if _, err := engine.GetTLSPolicy(platformID); !errors.Is(err, tlspolicy.ErrNotFound) {
				t.Fatalf("rejected custom CA policy was persisted: %v", err)
			}
			history, err := engine.ListTLSPolicyHistory(platformID)
			if err != nil {
				t.Fatal(err)
			}
			if len(history) != 0 {
				t.Fatalf("rejected custom CA mutation wrote history: %+v", history)
			}
		})
	}
}

func TestCABundleDeleteRacesPolicyBindWithoutDanglingReference(t *testing.T) {
	for iteration := 0; iteration < 20; iteration++ {
		engine, _, _ := newTestEngine(t)
		platformID := uuid.NewString()
		platformModel := tlsTestPlatform(platformID, "concurrent-ca-bind")
		if err := engine.UpsertPlatform(platformModel); err != nil {
			t.Fatal(err)
		}
		registry := tlspolicy.NewCABundleRegistry(engine, time.Now)
		policy, err := tlspolicy.NewPolicyService(engine, registry, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		bundle, _, err := registry.Import(stateTestCAPEM(t), tlspolicy.AuditContext{})
		if err != nil {
			t.Fatal(err)
		}

		start := make(chan struct{})
		var createErr, deleteErr error
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			_, createErr = policy.Create(platformID, platformModel.Name, tlspolicy.Mutation{
				Mode: tlspolicy.ModeTrustCustomCA, BundleID: bundle.ID,
			}, tlspolicy.AuditContext{})
		}()
		go func() {
			defer wait.Done()
			<-start
			deleteErr = registry.DeleteIfUnused(bundle.ID, tlspolicy.AuditContext{})
		}()
		close(start)
		wait.Wait()

		switch {
		case createErr == nil:
			if !errors.Is(deleteErr, tlspolicy.ErrBundleInUse) {
				t.Fatalf("iteration %d: bind succeeded but delete error = %v", iteration, deleteErr)
			}
			if _, err := engine.GetTLSPolicy(platformID); err != nil {
				t.Fatalf("iteration %d: successful bind was not persisted: %v", iteration, err)
			}
			if _, err := registry.Get(bundle.ID); err != nil {
				t.Fatalf("iteration %d: successful bind lost its CA bundle: %v", iteration, err)
			}
		case deleteErr == nil:
			if !errors.Is(createErr, tlspolicy.ErrNotFound) && !errors.Is(createErr, tlspolicy.ErrIntegrity) {
				t.Fatalf("iteration %d: delete succeeded but bind error = %v", iteration, createErr)
			}
			if _, err := engine.GetTLSPolicy(platformID); !errors.Is(err, tlspolicy.ErrNotFound) {
				t.Fatalf("iteration %d: deleted bundle left a policy: %v", iteration, err)
			}
			if _, err := registry.Get(bundle.ID); !errors.Is(err, tlspolicy.ErrNotFound) {
				t.Fatalf("iteration %d: deleted bundle still exists: %v", iteration, err)
			}
		default:
			t.Fatalf("iteration %d: neither bind nor delete succeeded: bind=%v delete=%v", iteration, createErr, deleteErr)
		}

		bundleHistory, err := registry.History(bundle.ID)
		if err != nil {
			t.Fatal(err)
		}
		if createErr == nil {
			if len(bundleHistory) != 1 || bundleHistory[0].EventKind != "CREATE" {
				t.Fatalf("iteration %d: rejected delete wrote partial history: %+v", iteration, bundleHistory)
			}
		} else if len(bundleHistory) != 2 || bundleHistory[0].EventKind != "CREATE" || bundleHistory[1].EventKind != "DELETE" {
			t.Fatalf("iteration %d: successful delete history = %+v", iteration, bundleHistory)
		}
	}
}

func assertCABundleCertificateMetadata(t *testing.T, got, want tlspolicy.CABundleRef) {
	t.Helper()
	if len(got.Certificates) != 1 || len(want.Certificates) != 1 {
		t.Fatalf("CA certificate metadata after restart = %+v, want %+v", got.Certificates, want.Certificates)
	}
	gotCertificate, wantCertificate := got.Certificates[0], want.Certificates[0]
	if gotCertificate.Subject != wantCertificate.Subject ||
		gotCertificate.Issuer != wantCertificate.Issuer ||
		gotCertificate.Serial != wantCertificate.Serial ||
		!gotCertificate.NotBefore.Equal(wantCertificate.NotBefore) ||
		!gotCertificate.NotAfter.Equal(wantCertificate.NotAfter) {
		t.Fatalf("CA certificate metadata after restart = %+v, want %+v", gotCertificate, wantCertificate)
	}
}

func TestPlatformTLSPolicySQLConstraintsRejectVerifyAndCrossModeState(t *testing.T) {
	engine, _, _ := newTestEngine(t)
	platformID := uuid.NewString()
	if err := engine.UpsertPlatform(tlsTestPlatform(platformID, "constraints")); err != nil {
		t.Fatal(err)
	}
	baseArgs := []any{uuid.NewString(), platformID, "constraints", time.Now().UnixNano(), time.Now().UnixNano()}
	queries := []struct {
		name        string
		mode        string
		bundle      any
		fingerprint string
		reason      string
	}{
		{"verify row", "VERIFY", nil, "", ""},
		{"custom with bypass reason", "TRUST_CUSTOM_CA", "missing-bundle", "fingerprint", "forbidden"},
		{"bypass with bundle", "BYPASS", "missing-bundle", "", "reason"},
		{"blank bypass reason", "BYPASS", nil, "", " "},
	}
	for _, tc := range queries {
		t.Run(tc.name, func(t *testing.T) {
			_, err := engine.StateRepo.db.Exec(`INSERT INTO platform_tls_policies (id, platform_id, platform_name, mode, bundle_id, bundle_fingerprint, bypass_reason, expires_at_ns, version, created_at_ns, updated_at_ns) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 1, ?, ?)`,
				baseArgs[0], baseArgs[1], baseArgs[2], tc.mode, tc.bundle, tc.fingerprint, tc.reason, baseArgs[3], baseArgs[4])
			if err == nil {
				t.Fatal("invalid persisted state was accepted")
			}
		})
	}
	if err := engine.UpsertPlatform(tlsTestPlatform(platform.DefaultPlatformID, platform.DefaultPlatformName)); err != nil {
		t.Fatal(err)
	}
	_, err := engine.StateRepo.db.Exec(`INSERT INTO platform_tls_policies (id, platform_id, platform_name, mode, bundle_id, bundle_fingerprint, bypass_reason, expires_at_ns, version, created_at_ns, updated_at_ns) VALUES (?, ?, ?, 'BYPASS', NULL, '', 'forbidden', NULL, 1, ?, ?)`,
		uuid.NewString(), platform.DefaultPlatformID, platform.DefaultPlatformName, time.Now().UnixNano(), time.Now().UnixNano())
	if err == nil {
		t.Fatal("Default platform policy was accepted by SQL constraint")
	}
}

func TestTLSPolicyCorruptBundleFingerprintFailsStartupCompilation(t *testing.T) {
	engine, _, _ := newTestEngine(t)
	platformID := uuid.NewString()
	platformModel := tlsTestPlatform(platformID, "corrupt-startup")
	if err := engine.UpsertPlatform(platformModel); err != nil {
		t.Fatal(err)
	}
	registry := tlspolicy.NewCABundleRegistry(engine, time.Now)
	policy, err := tlspolicy.NewPolicyService(engine, registry, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	bundle, _, err := registry.Import(stateTestCAPEM(t), tlspolicy.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	rule, err := policy.Create(platformID, platformModel.Name, tlspolicy.Mutation{
		Mode: tlspolicy.ModeTrustCustomCA, BundleID: bundle.ID,
	}, tlspolicy.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.StateRepo.db.Exec(`UPDATE platform_tls_policies SET bundle_fingerprint = 'damaged' WHERE id = ?`, rule.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := tlspolicy.NewPolicyService(engine, registry, time.Now); err == nil || !errors.Is(err, tlspolicy.ErrIntegrity) {
		t.Fatalf("corrupt startup compilation error = %v, want integrity failure", err)
	}
}
