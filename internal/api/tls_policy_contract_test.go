package api

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/model"
	"github.com/Resinat/Resin/internal/platform"
	"github.com/Resinat/Resin/internal/service"
	"github.com/Resinat/Resin/internal/tlspolicy"
	"github.com/google/uuid"
)

func testCAPEM(t *testing.T, commonName string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func doTLSAPIRequest(t *testing.T, srv *Server, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func wireTestTLSPolicy(t *testing.T, cp *service.ControlPlaneService) {
	t.Helper()
	registry := tlspolicy.NewCABundleRegistry(cp.Engine, time.Now)
	policy, err := tlspolicy.NewPolicyService(cp.Engine, registry, time.Now)
	if err != nil {
		t.Fatalf("NewPolicyService: %v", err)
	}
	cp.CABundles = registry
	cp.TLSPolicy = policy
}

func TestTLSRegistryAndPolicyAPIContract(t *testing.T) {
	srv, cp, _ := newControlPlaneTestServer(t)
	wireTestTLSPolicy(t, cp)
	platformName := "tls-contract"
	platformResp, err := cp.CreatePlatform(service.CreatePlatformRequest{Name: &platformName})
	if err != nil {
		t.Fatalf("CreatePlatform: %v", err)
	}

	caPEM := testCAPEM(t, "API Contract CA")
	importRec := doTLSAPIRequest(t, srv, http.MethodPost, "/api/v1/ca-bundles", map[string]any{"pem": caPEM}, map[string]string{"X-Request-ID": "create-ca"})
	if importRec.Code != http.StatusCreated {
		t.Fatalf("import status=%d body=%s", importRec.Code, importRec.Body.String())
	}
	if strings.Contains(importRec.Body.String(), "BEGIN CERTIFICATE") || strings.Contains(importRec.Body.String(), `"pem"`) {
		t.Fatalf("import response exposed PEM: %s", importRec.Body.String())
	}
	var bundle service.CABundleResponse
	if err := json.Unmarshal(importRec.Body.Bytes(), &bundle); err != nil {
		t.Fatal(err)
	}
	if len(bundle.Certificates) != 1 || !strings.Contains(bundle.Certificates[0].Subject, "Contract CA") ||
		bundle.Certificates[0].NotAfter.IsZero() {
		t.Fatalf("CA bundle display metadata = %+v", bundle.Certificates)
	}
	for _, path := range []string{"/api/v1/ca-bundles", "/api/v1/ca-bundles/" + bundle.ID} {
		rec := doTLSAPIRequest(t, srv, http.MethodGet, path, nil, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("bundle metadata %s status=%d body=%s", path, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "BEGIN CERTIFICATE") || strings.Contains(rec.Body.String(), `"pem"`) || strings.Contains(rec.Body.String(), "canonical_pem") {
			t.Fatalf("bundle metadata %s exposed PEM: %s", path, rec.Body.String())
		}
	}

	dedupRec := doTLSAPIRequest(t, srv, http.MethodPost, "/api/v1/ca-bundles", map[string]any{"pem": "\n" + caPEM}, map[string]string{"X-Request-ID": "reuse-ca"})
	if dedupRec.Code != http.StatusOK {
		t.Fatalf("dedup status=%d body=%s", dedupRec.Code, dedupRec.Body.String())
	}
	var dedup service.CABundleResponse
	if err := json.Unmarshal(dedupRec.Body.Bytes(), &dedup); err != nil {
		t.Fatal(err)
	}
	if dedup.ID != bundle.ID {
		t.Fatalf("dedup ID=%s want %s", dedup.ID, bundle.ID)
	}
	if len(dedup.Certificates) != 1 || dedup.Certificates[0].Subject != bundle.Certificates[0].Subject {
		t.Fatalf("dedup metadata=%+v want %+v", dedup.Certificates, bundle.Certificates)
	}

	policyPath := "/api/v1/platforms/" + platformResp.ID + "/tls-policy"
	verifyRec := doTLSAPIRequest(t, srv, http.MethodGet, policyPath, nil, nil)
	if verifyRec.Code != http.StatusOK || verifyRec.Header().Get("ETag") != `"0"` {
		t.Fatalf("initial VERIFY status=%d etag=%q body=%s", verifyRec.Code, verifyRec.Header().Get("ETag"), verifyRec.Body.String())
	}
	var initial tlspolicy.PolicyRecord
	if err := json.Unmarshal(verifyRec.Body.Bytes(), &initial); err != nil || initial.Mode != tlspolicy.ModeVerify || initial.Version != 0 {
		t.Fatalf("initial policy=%+v err=%v", initial, err)
	}
	customBody := map[string]any{"mode": "TRUST_CUSTOM_CA", "bundle_id": bundle.ID}
	missingCAS := doTLSAPIRequest(t, srv, http.MethodPut, policyPath, customBody, nil)
	if missingCAS.Code != http.StatusBadRequest {
		t.Fatalf("create without expected absence status=%d", missingCAS.Code)
	}
	createRec := doTLSAPIRequest(t, srv, http.MethodPut, policyPath, customBody, map[string]string{"If-None-Match": "*"})
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", createRec.Code, createRec.Body.String())
	}
	var policy tlspolicy.PolicyRecord
	if err := json.Unmarshal(createRec.Body.Bytes(), &policy); err != nil {
		t.Fatal(err)
	}
	if policy.Mode != tlspolicy.ModeTrustCustomCA || policy.Version != 1 {
		t.Fatalf("created policy=%+v", policy)
	}

	inUse := doTLSAPIRequest(t, srv, http.MethodDelete, "/api/v1/ca-bundles/"+bundle.ID, nil, nil)
	if inUse.Code != http.StatusConflict {
		t.Fatalf("delete referenced bundle status=%d body=%s", inUse.Code, inUse.Body.String())
	}

	bypassBody := []byte(`{"mode":"BYPASS","reason":"temporary vendor exception","expires_at":null}`)
	req := httptest.NewRequest(http.MethodPut, policyPath, bytes.NewReader(bypassBody))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", `"1"`)
	replaceRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(replaceRec, req)
	if replaceRec.Code != http.StatusOK {
		t.Fatalf("replace status=%d body=%s", replaceRec.Code, replaceRec.Body.String())
	}
	if strings.Contains(replaceRec.Body.String(), `"reason"`) || strings.Contains(replaceRec.Body.String(), "temporary vendor exception") {
		t.Fatalf("replace response exposed BYPASS reason: %s", replaceRec.Body.String())
	}
	policy = tlspolicy.PolicyRecord{}
	if err := json.Unmarshal(replaceRec.Body.Bytes(), &policy); err != nil {
		t.Fatal(err)
	}
	if policy.Mode != tlspolicy.ModeBypass || policy.ExpiresAt != nil || policy.Version != 2 || policy.BundleID != "" {
		t.Fatalf("replaced policy=%+v", policy)
	}

	futureTime := time.Now().UTC().Add(time.Hour)
	future := futureTime.Format(time.RFC3339)
	restrictWithoutReason := doTLSAPIRequest(t, srv, http.MethodPut, policyPath,
		map[string]any{"mode": "BYPASS", "expires_at": future}, map[string]string{"If-Match": `"2"`})
	if restrictWithoutReason.Code != http.StatusOK {
		t.Fatalf("permanent-to-temporary restriction status=%d body=%s", restrictWithoutReason.Code, restrictWithoutReason.Body.String())
	}
	policy = tlspolicy.PolicyRecord{}
	if err := json.Unmarshal(restrictWithoutReason.Body.Bytes(), &policy); err != nil {
		t.Fatal(err)
	}
	if policy.Version != 3 || policy.ExpiresAt == nil || !policy.ExpiresAt.Equal(futureTime.Truncate(time.Second)) {
		t.Fatalf("restricted policy=%+v", policy)
	}
	storedPolicy, err := cp.TLSPolicy.Get(platformResp.ID)
	if err != nil || storedPolicy.Reason != "temporary vendor exception" {
		t.Fatalf("stored BYPASS reason was not retained: policy=%+v err=%v", storedPolicy, err)
	}
	getPolicy := doTLSAPIRequest(t, srv, http.MethodGet, policyPath, nil, nil)
	if getPolicy.Code != http.StatusOK || strings.Contains(getPolicy.Body.String(), `"reason"`) || strings.Contains(getPolicy.Body.String(), "temporary vendor exception") {
		t.Fatalf("rule list exposed BYPASS reason: status=%d body=%s", getPolicy.Code, getPolicy.Body.String())
	}
	later := futureTime.Add(time.Hour).Format(time.RFC3339)
	extendNoReason := doTLSAPIRequest(t, srv, http.MethodPut, policyPath,
		map[string]any{"mode": "BYPASS", "expires_at": later}, map[string]string{"If-Match": `"3"`})
	if extendNoReason.Code != http.StatusBadRequest {
		t.Fatalf("temporary extension without new reason status=%d body=%s", extendNoReason.Code, extendNoReason.Body.String())
	}
	extendWithReason := doTLSAPIRequest(t, srv, http.MethodPut, policyPath,
		map[string]any{"mode": "BYPASS", "reason": "renewed exception", "expires_at": later}, map[string]string{"If-Match": `"3"`})
	if extendWithReason.Code != http.StatusOK {
		t.Fatalf("temporary extension status=%d body=%s", extendWithReason.Code, extendWithReason.Body.String())
	}

	staleDelete := doTLSAPIRequest(t, srv, http.MethodDelete, policyPath, nil, map[string]string{"If-Match": `"1"`})
	if staleDelete.Code != http.StatusConflict {
		t.Fatalf("stale delete status=%d body=%s", staleDelete.Code, staleDelete.Body.String())
	}
	deletePolicy := doTLSAPIRequest(t, srv, http.MethodDelete, policyPath, nil, map[string]string{"If-Match": `"4"`})
	if deletePolicy.Code != http.StatusNoContent {
		t.Fatalf("delete rule status=%d body=%s", deletePolicy.Code, deletePolicy.Body.String())
	}
	deleteBundle := doTLSAPIRequest(t, srv, http.MethodDelete, "/api/v1/ca-bundles/"+bundle.ID, nil, map[string]string{"X-Request-ID": "delete-ca"})
	if deleteBundle.Code != http.StatusNoContent {
		t.Fatalf("delete bundle status=%d body=%s", deleteBundle.Code, deleteBundle.Body.String())
	}

	policyHistory := doTLSAPIRequest(t, srv, http.MethodGet, policyPath+"/history", nil, nil)
	if policyHistory.Code != http.StatusOK || strings.Contains(policyHistory.Body.String(), "BEGIN CERTIFICATE") ||
		strings.Contains(policyHistory.Body.String(), `"reason"`) || strings.Contains(policyHistory.Body.String(), "temporary vendor exception") ||
		strings.Contains(policyHistory.Body.String(), "renewed exception") {
		t.Fatalf("rule history status=%d body=%s", policyHistory.Code, policyHistory.Body.String())
	}
	bundleHistory := doTLSAPIRequest(t, srv, http.MethodGet, "/api/v1/ca-bundles/"+bundle.ID+"/history", nil, nil)
	if bundleHistory.Code != http.StatusOK || strings.Contains(bundleHistory.Body.String(), "BEGIN CERTIFICATE") ||
		strings.Contains(bundleHistory.Body.String(), `"pem"`) || strings.Contains(bundleHistory.Body.String(), "canonical_pem") {
		t.Fatalf("bundle history status=%d body=%s", bundleHistory.Code, bundleHistory.Body.String())
	}
	var bundleEvents []map[string]any
	if err := json.Unmarshal(bundleHistory.Body.Bytes(), &bundleEvents); err != nil {
		t.Fatal(err)
	}
	if len(bundleEvents) != 3 {
		t.Fatalf("bundle history events = %v", bundleEvents)
	}
	for i, want := range []struct{ kind, requestID string }{
		{kind: "CREATE", requestID: "create-ca"},
		{kind: "REUSE", requestID: "reuse-ca"},
		{kind: "DELETE", requestID: "delete-ca"},
	} {
		if bundleEvents[i]["event_kind"] != want.kind || bundleEvents[i]["request_id"] != want.requestID ||
			bundleEvents[i]["credential_class"] != "SHARED_ADMIN_TOKEN" {
			t.Fatalf("bundle history event %d = %v", i, bundleEvents[i])
		}
		certificates, ok := bundleEvents[i]["certificates"].([]any)
		if !ok || len(certificates) != 1 {
			t.Fatalf("bundle history event %d certificates = %#v", i, bundleEvents[i]["certificates"])
		}
	}

	deletePlatform := doTLSAPIRequest(t, srv, http.MethodDelete, "/api/v1/platforms/"+platformResp.ID, nil, map[string]string{"X-Request-ID": "platform-delete-request"})
	if deletePlatform.Code != http.StatusNoContent {
		t.Fatalf("delete platform status=%d body=%s", deletePlatform.Code, deletePlatform.Body.String())
	}
	platformHistory := doTLSAPIRequest(t, srv, http.MethodGet, policyPath+"/history", nil, nil)
	if platformHistory.Code != http.StatusOK {
		t.Fatalf("platform history status=%d body=%s", platformHistory.Code, platformHistory.Body.String())
	}
	if !strings.Contains(platformHistory.Body.String(), `"event_kind":"PLATFORM_DELETE"`) ||
		!strings.Contains(platformHistory.Body.String(), `"request_id":"platform-delete-request"`) ||
		!strings.Contains(platformHistory.Body.String(), `"credential_class":"SHARED_ADMIN_TOKEN"`) {
		t.Fatalf("platform terminal history lost HTTP audit context: %s", platformHistory.Body.String())
	}
}

func TestTLSPolicyCreateDistinguishesOmittedAndNullExpiry(t *testing.T) {
	srv, cp, _ := newControlPlaneTestServer(t)
	wireTestTLSPolicy(t, cp)
	name := "expiry-contract"
	platformResp, err := cp.CreatePlatform(service.CreatePlatformRequest{Name: &name})
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/platforms/" + platformResp.ID + "/tls-policy"

	omitted := doTLSAPIRequest(t, srv, http.MethodPut, path,
		map[string]any{"mode": "BYPASS", "reason": "test"},
		map[string]string{"If-None-Match": "*"})
	if omitted.Code != http.StatusBadRequest {
		t.Fatalf("omitted expiry status=%d body=%s", omitted.Code, omitted.Body.String())
	}
	explicitNull := []byte(`{"mode":"BYPASS","reason":"test","expires_at":null}`)
	req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader(explicitNull))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-None-Match", "*")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("explicit null expiry status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestTLSResourcesRequireAdminAuthenticationAndRejectCrossModeFields(t *testing.T) {
	srv, cp, _ := newControlPlaneTestServer(t)
	wireTestTLSPolicy(t, cp)

	unauthorized := httptest.NewRecorder()
	srv.Handler().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/ca-bundles", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d body=%s", unauthorized.Code, unauthorized.Body.String())
	}

	name := "cross-mode-contract"
	platformResp, err := cp.CreatePlatform(service.CreatePlatformRequest{Name: &name})
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/platforms/" + platformResp.ID + "/tls-policy"
	invalid := []map[string]any{
		{"mode": "VERIFY"},
		{"mode": "TRUST_CUSTOM_CA", "bundle_id": "missing", "reason": "forbidden"},
		{"mode": "BYPASS", "bundle_id": uuid.NewString(), "reason": "reason", "expires_at": nil},
	}
	for i, body := range invalid {
		rec := doTLSAPIRequest(t, srv, http.MethodPut, path, body, map[string]string{"If-None-Match": "*"})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("invalid case %d status=%d body=%s", i, rec.Code, rec.Body.String())
		}
	}
}

func TestCAResourcesRejectUnauthorizedMutationsWithoutAudit(t *testing.T) {
	srv, cp, _ := newControlPlaneTestServer(t)
	wireTestTLSPolicy(t, cp)

	unauthorizedImport := httptest.NewRecorder()
	importBody, err := json.Marshal(map[string]any{"pem": testCAPEM(t, "Unauthorized CA")})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/ca-bundles", bytes.NewReader(importBody))
	request.Header.Set("Content-Type", "application/json")
	srv.Handler().ServeHTTP(unauthorizedImport, request)
	if unauthorizedImport.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized import status=%d body=%s", unauthorizedImport.Code, unauthorizedImport.Body.String())
	}
	if bundles, err := cp.ListCABundles(); err != nil || len(bundles) != 0 {
		t.Fatalf("unauthorized import changed CA state: bundles=%+v err=%v", bundles, err)
	}

	created := doTLSAPIRequest(t, srv, http.MethodPost, "/api/v1/ca-bundles",
		map[string]any{"pem": testCAPEM(t, "Authorized CA")}, map[string]string{"X-Request-ID": "authorized-create"})
	if created.Code != http.StatusCreated {
		t.Fatalf("authorized import status=%d body=%s", created.Code, created.Body.String())
	}
	var bundle service.CABundleResponse
	if err := json.Unmarshal(created.Body.Bytes(), &bundle); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		method string
		path   string
	}{
		{method: http.MethodDelete, path: "/api/v1/ca-bundles/" + bundle.ID},
		{method: http.MethodGet, path: "/api/v1/ca-bundles/" + bundle.ID + "/history"},
	} {
		recorder := httptest.NewRecorder()
		srv.Handler().ServeHTTP(recorder, httptest.NewRequest(test.method, test.path, nil))
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("unauthorized %s %s status=%d body=%s", test.method, test.path, recorder.Code, recorder.Body.String())
		}
	}
	if _, err := cp.GetCABundle(bundle.ID); err != nil {
		t.Fatalf("unauthorized delete removed CA bundle: %v", err)
	}
	history, err := cp.CABundleHistory(bundle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || history[0].EventKind != "CREATE" || history[0].RequestID != "authorized-create" {
		t.Fatalf("unauthorized requests changed CA history: %+v", history)
	}
}

func TestCAHistoryRecordsAuthenticationDisabledWithoutInventingTokenUse(t *testing.T) {
	_, cp, runtimeCfg := newControlPlaneTestServer(t)
	wireTestTLSPolicy(t, cp)
	srv := NewServer(0, "", service.SystemInfo{}, runtimeCfg, cp.EnvCfg, cp, 1<<20, nil, nil)

	importBody, err := json.Marshal(map[string]any{"pem": testCAPEM(t, "Auth Disabled CA")})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/ca-bundles", bytes.NewReader(importBody))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", "auth-disabled-create")
	recorder := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("auth-disabled import status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var bundle service.CABundleResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &bundle); err != nil {
		t.Fatal(err)
	}

	historyRecorder := httptest.NewRecorder()
	srv.Handler().ServeHTTP(historyRecorder, httptest.NewRequest(
		http.MethodGet, "/api/v1/ca-bundles/"+bundle.ID+"/history", nil,
	))
	if historyRecorder.Code != http.StatusOK {
		t.Fatalf("auth-disabled history status=%d body=%s", historyRecorder.Code, historyRecorder.Body.String())
	}
	var history []tlspolicy.CABundleEvent
	if err := json.Unmarshal(historyRecorder.Body.Bytes(), &history); err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || history[0].CredentialClass != credentialClassAuthDisabled ||
		history[0].RequestID != "auth-disabled-create" {
		t.Fatalf("auth-disabled CA history = %+v", history)
	}
}

func TestDefaultPlatformTLSPolicyIsReadOnlyVerify(t *testing.T) {
	srv, cp, _ := newControlPlaneTestServer(t)
	wireTestTLSPolicy(t, cp)
	if err := cp.Engine.UpsertPlatform(model.Platform{
		ID: platform.DefaultPlatformID, Name: platform.DefaultPlatformName,
		StickyTTLNs: int64(30 * time.Minute), RegexFilters: []string{}, RegionFilters: []string{},
		ReverseProxyMissAction: string(platform.ReverseProxyMissActionTreatAsEmpty),
		AllocationPolicy:       string(platform.AllocationPolicyBalanced),
		UpdatedAtNs:            time.Now().UnixNano(),
	}); err != nil {
		t.Fatalf("seed Default platform: %v", err)
	}
	path := "/api/v1/platforms/" + platform.DefaultPlatformID + "/tls-policy"

	get := doTLSAPIRequest(t, srv, http.MethodGet, path, nil, nil)
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), `"mode":"VERIFY"`) || !strings.Contains(get.Body.String(), `"version":0`) {
		t.Fatalf("Default GET status=%d body=%s", get.Code, get.Body.String())
	}
	put := doTLSAPIRequest(t, srv, http.MethodPut, path,
		map[string]any{"mode": "BYPASS", "reason": "forbidden", "expires_at": nil},
		map[string]string{"If-None-Match": "*"})
	if put.Code != http.StatusBadRequest {
		t.Fatalf("Default PUT status=%d body=%s", put.Code, put.Body.String())
	}
	deleteRec := doTLSAPIRequest(t, srv, http.MethodDelete, path, nil, map[string]string{"If-Match": `"1"`})
	if deleteRec.Code != http.StatusBadRequest {
		t.Fatalf("Default DELETE status=%d body=%s", deleteRec.Code, deleteRec.Body.String())
	}
}
