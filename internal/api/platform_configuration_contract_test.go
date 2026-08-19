package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/model"
	"github.com/Resinat/Resin/internal/platform"
	"github.com/Resinat/Resin/internal/service"
	"github.com/Resinat/Resin/internal/tlspolicy"
	"github.com/google/uuid"
)

type failingConfigurationPolicyStore struct {
	err error
}

func (s failingConfigurationPolicyStore) ListTLSPolicies() ([]tlspolicy.PolicyRecord, error) {
	return nil, nil
}

func (s failingConfigurationPolicyStore) GetTLSPolicy(string) (tlspolicy.PolicyRecord, error) {
	return tlspolicy.PolicyRecord{}, s.err
}

func (s failingConfigurationPolicyStore) CreateTLSPolicy(tlspolicy.PolicyRecord, tlspolicy.PolicyEvent) error {
	return s.err
}

func (s failingConfigurationPolicyStore) ReplaceTLSPolicy(string, int64, tlspolicy.PolicyRecord, tlspolicy.PolicyEvent) error {
	return s.err
}

func (s failingConfigurationPolicyStore) DeleteTLSPolicy(string, int64, tlspolicy.PolicyEvent) error {
	return s.err
}

func (s failingConfigurationPolicyStore) DeletePlatformWithTLSHistory(string, tlspolicy.AuditContext) error {
	return s.err
}

func (s failingConfigurationPolicyStore) ListTLSPolicyHistory(string) ([]tlspolicy.PolicyEvent, error) {
	return nil, s.err
}

func TestCreatePlatformAcceptsAtomicTLSConfigurationAndPreservesLegacyResponse(t *testing.T) {
	srv, cp, _ := newControlPlaneTestServer(t)
	wireTestTLSPolicy(t, cp)

	legacy := doTLSAPIRequest(t, srv, http.MethodPost, "/api/v1/platforms", map[string]any{
		"name": "legacy-create-shape",
	}, nil)
	if legacy.Code != http.StatusCreated {
		t.Fatalf("legacy create status=%d body=%s", legacy.Code, legacy.Body.String())
	}
	legacyBody := decodeJSONMap(t, legacy)
	if _, nested := legacyBody["platform"]; nested {
		t.Fatalf("legacy response unexpectedly changed shape: %s", legacy.Body.String())
	}
	legacyID, _ := legacyBody["id"].(string)
	assertAggregateConfiguration(t, srv, "/api/v1/platforms/"+legacyID+"/configuration", "legacy-create-shape", 1, tlspolicy.ModeVerify, 0)

	explicitVerify := doTLSAPIRequest(t, srv, http.MethodPost, "/api/v1/platforms", map[string]any{
		"name":       "explicit-verify-create",
		"tls_policy": map[string]any{"mode": "VERIFY", "expected_version": 0},
	}, nil)
	if explicitVerify.Code != http.StatusCreated {
		t.Fatalf("explicit VERIFY create status=%d body=%s", explicitVerify.Code, explicitVerify.Body.String())
	}
	var explicitVerifyPlatform service.PlatformResponse
	if err := json.Unmarshal(explicitVerify.Body.Bytes(), &explicitVerifyPlatform); err != nil {
		t.Fatal(err)
	}
	assertAggregateConfiguration(t, srv, "/api/v1/platforms/"+explicitVerifyPlatform.ID+"/configuration", "explicit-verify-create", 1, tlspolicy.ModeVerify, 0)
	assertAggregateHistoryLength(t, cp, explicitVerifyPlatform.ID, 0)

	importRec := doTLSAPIRequest(t, srv, http.MethodPost, "/api/v1/ca-bundles", map[string]any{
		"pem": testCAPEM(t, "Create Platform CA"),
	}, nil)
	if importRec.Code != http.StatusCreated {
		t.Fatalf("import CA status=%d body=%s", importRec.Code, importRec.Body.String())
	}
	var bundle service.CABundleResponse
	if err := json.Unmarshal(importRec.Body.Bytes(), &bundle); err != nil {
		t.Fatal(err)
	}

	custom := doTLSAPIRequest(t, srv, http.MethodPost, "/api/v1/platforms", map[string]any{
		"name": "custom-ca-create",
		"tls_policy": map[string]any{
			"mode": "TRUST_CUSTOM_CA", "expected_version": 0, "bundle_id": bundle.ID,
		},
	}, map[string]string{"X-Request-ID": "create-platform-custom-ca"})
	if custom.Code != http.StatusCreated {
		t.Fatalf("custom CA create status=%d body=%s", custom.Code, custom.Body.String())
	}
	var customPlatform service.PlatformResponse
	if err := json.Unmarshal(custom.Body.Bytes(), &customPlatform); err != nil {
		t.Fatal(err)
	}
	assertAggregateConfiguration(t, srv, "/api/v1/platforms/"+customPlatform.ID+"/configuration", "custom-ca-create", 1, tlspolicy.ModeTrustCustomCA, 1)
	history, err := cp.TLSPolicyHistory(customPlatform.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || history[0].RequestID != "create-platform-custom-ca" || history[0].CredentialClass != "SHARED_ADMIN_TOKEN" {
		t.Fatalf("create history = %+v", history)
	}

	bypass := doTLSAPIRequest(t, srv, http.MethodPost, "/api/v1/platforms", map[string]any{
		"name": "bypass-create",
		"tls_policy": map[string]any{
			"mode": "BYPASS", "expected_version": 0,
			"reason": "approved create exception", "expires_at": nil,
		},
	}, nil)
	if bypass.Code != http.StatusCreated {
		t.Fatalf("BYPASS create status=%d body=%s", bypass.Code, bypass.Body.String())
	}
	var bypassPlatform service.PlatformResponse
	if err := json.Unmarshal(bypass.Body.Bytes(), &bypassPlatform); err != nil {
		t.Fatal(err)
	}
	configuration := getPlatformConfigurationAPI(t, srv, "/api/v1/platforms/"+bypassPlatform.ID+"/configuration")
	if configuration.TLSPolicy.Mode != tlspolicy.ModeBypass || configuration.TLSPolicy.Reason != "approved create exception" || configuration.ConfigVersion != 1 {
		t.Fatalf("BYPASS create configuration = %+v", configuration)
	}
}

func TestCreatePlatformTLSFailureLeavesNoPartialStateOrRuntime(t *testing.T) {
	srv, cp, _ := newControlPlaneTestServer(t)
	wireTestTLSPolicy(t, cp)

	for _, test := range []struct {
		name   string
		policy map[string]any
	}{
		{name: "missing-ca-create", policy: map[string]any{
			"mode": "TRUST_CUSTOM_CA", "expected_version": 0, "bundle_id": uuid.NewString(),
		}},
		{name: "invalid-bypass-create", policy: map[string]any{
			"mode": "BYPASS", "expected_version": 0, "expires_at": nil,
		}},
		{name: "invalid-version-create", policy: map[string]any{
			"mode": "BYPASS", "expected_version": 1, "reason": "invalid", "expires_at": nil,
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			rec := doTLSAPIRequest(t, srv, http.MethodPost, "/api/v1/platforms", map[string]any{
				"name": test.name, "tls_policy": test.policy,
			}, nil)
			if rec.Code < 400 {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			platforms, err := cp.ListPlatforms()
			if err != nil {
				t.Fatal(err)
			}
			for _, platform := range platforms {
				if platform.Name == test.name {
					t.Fatalf("failed create left persisted Platform: %+v", platform)
				}
			}
			if _, ok := cp.Pool.GetPlatformByName(test.name); ok {
				t.Fatal("failed create left runtime Platform")
			}
		})
	}
}

func TestCreatePlatformPersistenceFailureReturnsInternal(t *testing.T) {
	srv, cp, _ := newControlPlaneTestServer(t)
	storeErr := errors.New("database is closed")
	policy, err := tlspolicy.NewPolicyService(failingConfigurationPolicyStore{err: storeErr}, nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	cp.TLSPolicy = policy

	rec := doTLSAPIRequest(t, srv, http.MethodPost, "/api/v1/platforms", map[string]any{
		"name": "persistence-failure-create",
	}, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	assertErrorCode(t, rec, "INTERNAL")
	if _, ok := cp.Pool.GetPlatformByName("persistence-failure-create"); ok {
		t.Fatal("failed create left runtime Platform")
	}
}

func TestPlatformConfigurationAPIAtomicContractAndNoOpPolicy(t *testing.T) {
	srv, cp, _ := newControlPlaneTestServer(t)
	wireTestTLSPolicy(t, cp)
	platformID := mustCreatePlatform(t, srv, "aggregate-initial")
	configurationPath := "/api/v1/platforms/" + platformID + "/configuration"

	initial := getPlatformConfigurationAPI(t, srv, configurationPath)
	if initial.ConfigVersion != 1 || initial.TLSPolicy.Mode != tlspolicy.ModeVerify || initial.TLSPolicy.Version != 0 {
		t.Fatalf("initial configuration = %+v", initial)
	}

	importRec := doTLSAPIRequest(t, srv, http.MethodPost, "/api/v1/ca-bundles", map[string]any{
		"pem": testCAPEM(t, "Aggregate API CA"),
	}, nil)
	if importRec.Code != http.StatusCreated {
		t.Fatalf("import CA status=%d body=%s", importRec.Code, importRec.Body.String())
	}
	var bundle service.CABundleResponse
	if err := json.Unmarshal(importRec.Body.Bytes(), &bundle); err != nil {
		t.Fatal(err)
	}

	custom := putPlatformConfigurationAPI(t, srv, configurationPath, 1, map[string]any{
		"platform": aggregatePlatformFields("aggregate-updated"),
		"tls_policy": map[string]any{
			"mode": "TRUST_CUSTOM_CA", "expected_version": 0, "bundle_id": bundle.ID,
		},
	})
	if custom.Code != http.StatusOK || custom.Header().Get("ETag") != `"2"` {
		t.Fatalf("custom CA save status=%d etag=%q body=%s", custom.Code, custom.Header().Get("ETag"), custom.Body.String())
	}
	var customConfiguration service.PlatformConfigurationResponse
	if err := json.Unmarshal(custom.Body.Bytes(), &customConfiguration); err != nil {
		t.Fatal(err)
	}
	if customConfiguration.ConfigVersion != 2 || customConfiguration.Platform.Name != "aggregate-updated" ||
		customConfiguration.TLSPolicy.Mode != tlspolicy.ModeTrustCustomCA || customConfiguration.TLSPolicy.Version != 1 ||
		customConfiguration.TLSPolicy.BundleID != bundle.ID {
		t.Fatalf("authoritative custom CA response = %+v", customConfiguration)
	}
	assertAggregateHistoryLength(t, cp, platformID, 1)
	inUse := doTLSAPIRequest(t, srv, http.MethodDelete, "/api/v1/ca-bundles/"+bundle.ID, nil, nil)
	if inUse.Code != http.StatusConflict {
		t.Fatalf("referenced CA delete status=%d body=%s", inUse.Code, inUse.Body.String())
	}

	missingCA := putPlatformConfigurationAPI(t, srv, configurationPath, 2, map[string]any{
		"platform": aggregatePlatformFields("missing-ca-must-not-persist"),
		"tls_policy": map[string]any{
			"mode": "TRUST_CUSTOM_CA", "expected_version": 1, "bundle_id": uuid.NewString(),
		},
	})
	if missingCA.Code != http.StatusNotFound {
		t.Fatalf("missing CA status=%d body=%s", missingCA.Code, missingCA.Body.String())
	}
	assertAggregateConfiguration(t, srv, configurationPath, "aggregate-updated", 2, tlspolicy.ModeTrustCustomCA, 1)
	assertAggregateHistoryLength(t, cp, platformID, 1)

	stalePolicy := putPlatformConfigurationAPI(t, srv, configurationPath, 2, map[string]any{
		"platform": aggregatePlatformFields("stale-policy-must-not-persist"),
		"tls_policy": map[string]any{
			"mode": "BYPASS", "expected_version": 0, "reason": "stale", "expires_at": nil,
		},
	})
	if stalePolicy.Code != http.StatusConflict {
		t.Fatalf("stale policy status=%d body=%s", stalePolicy.Code, stalePolicy.Body.String())
	}
	assertAggregateConfiguration(t, srv, configurationPath, "aggregate-updated", 2, tlspolicy.ModeTrustCustomCA, 1)
	assertAggregateHistoryLength(t, cp, platformID, 1)

	staleAggregate := putPlatformConfigurationAPI(t, srv, configurationPath, 1, map[string]any{
		"platform": aggregatePlatformFields("stale-aggregate-must-not-persist"),
		"tls_policy": map[string]any{
			"mode": "VERIFY", "expected_version": 1,
		},
	})
	if staleAggregate.Code != http.StatusConflict {
		t.Fatalf("stale aggregate status=%d body=%s", staleAggregate.Code, staleAggregate.Body.String())
	}
	assertAggregateConfiguration(t, srv, configurationPath, "aggregate-updated", 2, tlspolicy.ModeTrustCustomCA, 1)
	assertAggregateHistoryLength(t, cp, platformID, 1)

	bypass := putPlatformConfigurationAPI(t, srv, configurationPath, 2, map[string]any{
		"platform": aggregatePlatformFields("aggregate-bypass"),
		"tls_policy": map[string]any{
			"mode": "BYPASS", "expected_version": 1, "reason": "approved exception", "expires_at": nil,
		},
	})
	if bypass.Code != http.StatusOK {
		t.Fatalf("BYPASS save status=%d body=%s", bypass.Code, bypass.Body.String())
	}
	var bypassConfiguration service.PlatformConfigurationResponse
	if err := json.Unmarshal(bypass.Body.Bytes(), &bypassConfiguration); err != nil {
		t.Fatal(err)
	}
	if bypassConfiguration.TLSPolicy.Reason != "approved exception" ||
		bypassConfiguration.TLSPolicy.EffectiveMode != tlspolicy.ModeBypass ||
		bypassConfiguration.TLSPolicy.Expired {
		t.Fatalf("BYPASS management projection = %+v", bypassConfiguration.TLSPolicy)
	}
	assertAggregateConfiguration(t, srv, configurationPath, "aggregate-bypass", 3, tlspolicy.ModeBypass, 2)
	assertAggregateHistoryLength(t, cp, platformID, 2)

	noOp := putPlatformConfigurationAPI(t, srv, configurationPath, 3, map[string]any{
		"platform": aggregatePlatformFields("aggregate-bypass"),
		"tls_policy": map[string]any{
			"mode": "BYPASS", "expected_version": 2, "expires_at": nil,
		},
	})
	if noOp.Code != http.StatusOK {
		t.Fatalf("unchanged BYPASS status=%d body=%s", noOp.Code, noOp.Body.String())
	}
	assertAggregateConfiguration(t, srv, configurationPath, "aggregate-bypass", 4, tlspolicy.ModeBypass, 2)
	assertAggregateHistoryLength(t, cp, platformID, 2)

	verify := putPlatformConfigurationAPI(t, srv, configurationPath, 4, map[string]any{
		"platform": aggregatePlatformFields("aggregate-verified"),
		"tls_policy": map[string]any{
			"mode": "VERIFY", "expected_version": 2,
		},
	})
	if verify.Code != http.StatusOK {
		t.Fatalf("VERIFY save status=%d body=%s", verify.Code, verify.Body.String())
	}
	assertAggregateConfiguration(t, srv, configurationPath, "aggregate-verified", 5, tlspolicy.ModeVerify, 0)
	assertAggregateHistoryLength(t, cp, platformID, 3)
	deleteBundle := doTLSAPIRequest(t, srv, http.MethodDelete, "/api/v1/ca-bundles/"+bundle.ID, nil, nil)
	if deleteBundle.Code != http.StatusNoContent {
		t.Fatalf("unreferenced CA delete status=%d body=%s", deleteBundle.Code, deleteBundle.Body.String())
	}
}

func TestPlatformConfigurationOmittedPolicyPreservesExpiredBypass(t *testing.T) {
	srv, cp, _ := newControlPlaneTestServer(t)
	wireTestTLSPolicy(t, cp)
	platformID := mustCreatePlatform(t, srv, "expired-bypass")
	reason := "expired exception retained for audit"
	now := time.Now().UTC()
	expiredAt := now.Add(-time.Hour)
	policy, err := cp.TLSPolicy.Create(platformID, "expired-bypass", tlspolicy.Mutation{
		Mode: tlspolicy.ModeBypass, Reason: &reason, ExpirySet: true, ExpiresAt: &expiredAt,
	}, tlspolicy.AuditContext{OccurredAt: now.Add(-2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if policy.Version != 1 {
		t.Fatalf("created policy = %+v", policy)
	}

	path := "/api/v1/platforms/" + platformID + "/configuration"
	before := getPlatformConfigurationAPI(t, srv, path)
	if before.ConfigVersion != 2 || before.TLSPolicy.Mode != tlspolicy.ModeBypass || before.TLSPolicy.Version != 1 ||
		before.TLSPolicy.Reason != reason || before.TLSPolicy.EffectiveMode != tlspolicy.ModeVerify || !before.TLSPolicy.Expired {
		t.Fatalf("before omitted save = %+v", before)
	}
	rec := putPlatformConfigurationAPI(t, srv, path, 2, map[string]any{
		"platform": aggregatePlatformFields("expired-bypass-renamed"),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("omitted policy save status=%d body=%s", rec.Code, rec.Body.String())
	}
	assertAggregateConfiguration(t, srv, path, "expired-bypass-renamed", 3, tlspolicy.ModeBypass, 1)
	assertAggregateHistoryLength(t, cp, platformID, 1)
}

func TestResetPlatformToDefaultResetsTLSConfigurationAtomically(t *testing.T) {
	srv, cp, _ := newControlPlaneTestServer(t)
	wireTestTLSPolicy(t, cp)
	platformID := mustCreatePlatform(t, srv, "reset-complete-configuration")
	configurationPath := "/api/v1/platforms/" + platformID + "/configuration"

	bypass := putPlatformConfigurationAPI(t, srv, configurationPath, 1, map[string]any{
		"platform": aggregatePlatformFields("reset-complete-configuration"),
		"tls_policy": map[string]any{
			"mode": "BYPASS", "expected_version": 0, "reason": "temporary upstream exception", "expires_at": nil,
		},
	})
	if bypass.Code != http.StatusOK {
		t.Fatalf("create BYPASS status=%d body=%s", bypass.Code, bypass.Body.String())
	}

	reset := doTLSAPIRequest(t, srv, http.MethodPost, "/api/v1/platforms/"+platformID+"/actions/reset-to-default", nil, nil)
	if reset.Code != http.StatusOK {
		t.Fatalf("reset status=%d body=%s", reset.Code, reset.Body.String())
	}
	var resetPlatform service.PlatformResponse
	if err := json.Unmarshal(reset.Body.Bytes(), &resetPlatform); err != nil {
		t.Fatal(err)
	}
	if resetPlatform.Name != "reset-complete-configuration" {
		t.Fatalf("reset platform = %+v", resetPlatform)
	}
	assertAggregateConfiguration(t, srv, configurationPath, "reset-complete-configuration", 3, tlspolicy.ModeVerify, 0)
	assertAggregateHistoryLength(t, cp, platformID, 2)
	resolved, err := cp.TLSPolicy.Resolve(platformID, "example.com:443", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if resolved.EffectiveMode != tlspolicy.ModeVerify {
		t.Fatalf("runtime mode after reset = %s, want VERIFY", resolved.EffectiveMode)
	}
}

func TestPlatformConfigurationBypassShorteningAndExtensionGovernance(t *testing.T) {
	srv, cp, _ := newControlPlaneTestServer(t)
	wireTestTLSPolicy(t, cp)
	platformID := mustCreatePlatform(t, srv, "bypass-governance")
	path := "/api/v1/platforms/" + platformID + "/configuration"
	longExpiry := time.Now().UTC().Add(3 * time.Hour).Truncate(time.Second)
	create := putPlatformConfigurationAPI(t, srv, path, 1, map[string]any{
		"platform": aggregatePlatformFields("bypass-governance"),
		"tls_policy": map[string]any{
			"mode": "BYPASS", "expected_version": 0, "reason": "bounded exception",
			"expires_at": longExpiry.Format(time.RFC3339),
		},
	})
	if create.Code != http.StatusOK {
		t.Fatalf("create BYPASS status=%d body=%s", create.Code, create.Body.String())
	}

	shortExpiry := longExpiry.Add(-time.Hour)
	shorten := putPlatformConfigurationAPI(t, srv, path, 2, map[string]any{
		"platform": aggregatePlatformFields("bypass-shortened"),
		"tls_policy": map[string]any{
			"mode": "BYPASS", "expected_version": 1, "expires_at": shortExpiry.Format(time.RFC3339),
		},
	})
	if shorten.Code != http.StatusOK {
		t.Fatalf("shorten BYPASS status=%d body=%s", shorten.Code, shorten.Body.String())
	}
	assertAggregateConfiguration(t, srv, path, "bypass-shortened", 3, tlspolicy.ModeBypass, 2)
	assertAggregateHistoryLength(t, cp, platformID, 2)

	for _, test := range []struct {
		name      string
		expiresAt any
	}{
		{name: "extend", expiresAt: longExpiry.Add(time.Hour).Format(time.RFC3339)},
		{name: "make permanent", expiresAt: nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			rec := putPlatformConfigurationAPI(t, srv, path, 3, map[string]any{
				"platform": aggregatePlatformFields("must-not-persist"),
				"tls_policy": map[string]any{
					"mode": "BYPASS", "expected_version": 2, "expires_at": test.expiresAt,
				},
			})
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			assertAggregateConfiguration(t, srv, path, "bypass-shortened", 3, tlspolicy.ModeBypass, 2)
			assertAggregateHistoryLength(t, cp, platformID, 2)
		})
	}
}

func TestLegacyMutationPathsAdvancePlatformConfigurationVersion(t *testing.T) {
	srv, cp, _ := newControlPlaneTestServer(t)
	wireTestTLSPolicy(t, cp)
	platformID := mustCreatePlatform(t, srv, "legacy-version-paths")
	configurationPath := "/api/v1/platforms/" + platformID + "/configuration"
	assertAggregateConfiguration(t, srv, configurationPath, "legacy-version-paths", 1, tlspolicy.ModeVerify, 0)

	patch := doTLSAPIRequest(t, srv, http.MethodPatch, "/api/v1/platforms/"+platformID, map[string]any{
		"sticky_ttl": "1h",
	}, nil)
	if patch.Code != http.StatusOK {
		t.Fatalf("PATCH status=%d body=%s", patch.Code, patch.Body.String())
	}
	assertPlatformConfigurationVersion(t, srv, configurationPath, 2)

	reset := doTLSAPIRequest(t, srv, http.MethodPost, "/api/v1/platforms/"+platformID+"/actions/reset-to-default", nil, nil)
	if reset.Code != http.StatusOK {
		t.Fatalf("reset status=%d body=%s", reset.Code, reset.Body.String())
	}
	assertPlatformConfigurationVersion(t, srv, configurationPath, 3)

	policyPath := "/api/v1/platforms/" + platformID + "/tls-policy"
	create := doTLSAPIRequest(t, srv, http.MethodPut, policyPath, map[string]any{
		"mode": "BYPASS", "reason": "legacy create", "expires_at": nil,
	}, map[string]string{"If-None-Match": "*"})
	if create.Code != http.StatusCreated {
		t.Fatalf("singular create status=%d body=%s", create.Code, create.Body.String())
	}
	assertPlatformConfigurationVersion(t, srv, configurationPath, 4)

	replace := doTLSAPIRequest(t, srv, http.MethodPut, policyPath, map[string]any{
		"mode": "BYPASS", "reason": "legacy replace",
	}, map[string]string{"If-Match": `"1"`})
	if replace.Code != http.StatusOK {
		t.Fatalf("singular replace status=%d body=%s", replace.Code, replace.Body.String())
	}
	assertPlatformConfigurationVersion(t, srv, configurationPath, 5)

	deleteRec := doTLSAPIRequest(t, srv, http.MethodDelete, policyPath, nil, map[string]string{"If-Match": `"2"`})
	if deleteRec.Code != http.StatusNoContent {
		t.Fatalf("singular delete status=%d body=%s", deleteRec.Code, deleteRec.Body.String())
	}
	assertPlatformConfigurationVersion(t, srv, configurationPath, 6)

	stale := putPlatformConfigurationAPI(t, srv, configurationPath, 5, map[string]any{
		"platform":   aggregatePlatformFields("stale-after-legacy"),
		"tls_policy": map[string]any{"mode": "VERIFY", "expected_version": 0},
	})
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale aggregate after legacy mutation status=%d body=%s", stale.Code, stale.Body.String())
	}
	assertPlatformConfigurationVersion(t, srv, configurationPath, 6)
}

func TestDefaultPlatformAggregateConfigurationRemainsStrict(t *testing.T) {
	srv, cp, _ := newControlPlaneTestServer(t)
	wireTestTLSPolicy(t, cp)
	defaultRow := model.Platform{
		ID: platform.DefaultPlatformID, Name: platform.DefaultPlatformName,
		StickyTTLNs: int64(30 * time.Minute), RegexFilters: []string{}, RegionFilters: []string{},
		ReverseProxyMissAction:           string(platform.ReverseProxyMissActionTreatAsEmpty),
		ReverseProxyEmptyAccountBehavior: string(platform.ReverseProxyEmptyAccountBehaviorRandom),
		AllocationPolicy:                 string(platform.AllocationPolicyBalanced),
		UpdatedAtNs:                      time.Now().UnixNano(),
	}
	if err := cp.Engine.UpsertPlatform(defaultRow); err != nil {
		t.Fatal(err)
	}
	cp.Pool.RegisterPlatform(platform.NewPlatform(defaultRow.ID, defaultRow.Name, nil, nil))
	path := "/api/v1/platforms/" + platform.DefaultPlatformID + "/configuration"

	forbidden := putPlatformConfigurationAPI(t, srv, path, 1, map[string]any{
		"platform": aggregatePlatformFields(platform.DefaultPlatformName),
		"tls_policy": map[string]any{
			"mode": "BYPASS", "expected_version": 0, "reason": "forbidden", "expires_at": nil,
		},
	})
	if forbidden.Code != http.StatusBadRequest {
		t.Fatalf("Default BYPASS status=%d body=%s", forbidden.Code, forbidden.Body.String())
	}
	assertAggregateConfiguration(t, srv, path, platform.DefaultPlatformName, 1, tlspolicy.ModeVerify, 0)
	assertAggregateHistoryLength(t, cp, platform.DefaultPlatformID, 0)

	strict := putPlatformConfigurationAPI(t, srv, path, 1, map[string]any{
		"platform":   aggregatePlatformFields(platform.DefaultPlatformName),
		"tls_policy": map[string]any{"mode": "VERIFY", "expected_version": 0},
	})
	if strict.Code != http.StatusOK {
		t.Fatalf("Default strict save status=%d body=%s", strict.Code, strict.Body.String())
	}
	assertAggregateConfiguration(t, srv, path, platform.DefaultPlatformName, 2, tlspolicy.ModeVerify, 0)
}

func aggregatePlatformFields(name string) map[string]any {
	return map[string]any{
		"name": name, "sticky_ttl": "45m", "regex_filters": []string{}, "region_filters": []string{},
		"reverse_proxy_miss_action": "TREAT_AS_EMPTY", "reverse_proxy_empty_account_behavior": "RANDOM",
		"reverse_proxy_fixed_account_header": "", "allocation_policy": "BALANCED",
		"passive_circuit_breaker_disabled": false,
	}
}

func putPlatformConfigurationAPI(t *testing.T, srv *Server, path string, version int64, body any) *httptest.ResponseRecorder {
	t.Helper()
	return doTLSAPIRequest(t, srv, http.MethodPut, path, body, map[string]string{
		"If-Match": `"` + strconv.FormatInt(version, 10) + `"`,
	})
}

func getPlatformConfigurationAPI(t *testing.T, srv *Server, path string) service.PlatformConfigurationResponse {
	t.Helper()
	rec := doTLSAPIRequest(t, srv, http.MethodGet, path, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET configuration status=%d body=%s", rec.Code, rec.Body.String())
	}
	var configuration service.PlatformConfigurationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &configuration); err != nil {
		t.Fatal(err)
	}
	return configuration
}

func assertAggregateConfiguration(t *testing.T, srv *Server, path, name string, configVersion int64, mode tlspolicy.Mode, policyVersion int64) {
	t.Helper()
	configuration := getPlatformConfigurationAPI(t, srv, path)
	if configuration.Platform.Name != name || configuration.ConfigVersion != configVersion ||
		configuration.TLSPolicy.Mode != mode || configuration.TLSPolicy.Version != policyVersion {
		t.Fatalf("configuration = %+v, want name=%q config=%d mode=%s policy=%d", configuration, name, configVersion, mode, policyVersion)
	}
}

func assertPlatformConfigurationVersion(t *testing.T, srv *Server, path string, version int64) {
	t.Helper()
	configuration := getPlatformConfigurationAPI(t, srv, path)
	if configuration.ConfigVersion != version {
		t.Fatalf("config version = %d, want %d", configuration.ConfigVersion, version)
	}
}

func assertAggregateHistoryLength(t *testing.T, cp *service.ControlPlaneService, platformID string, want int) {
	t.Helper()
	history, err := cp.TLSPolicyHistory(platformID)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != want {
		t.Fatalf("history length = %d, want %d: %+v", len(history), want, history)
	}
}
