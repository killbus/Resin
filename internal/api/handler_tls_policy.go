package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Resinat/Resin/internal/service"
	"github.com/Resinat/Resin/internal/tlspolicy"
)

type importCABundleRequest struct {
	PEM string `json:"pem"`
}

type optionalString struct {
	Present bool
	Null    bool
	Value   string
}

func (v *optionalString) UnmarshalJSON(data []byte) error {
	v.Present = true
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		v.Null = true
		return nil
	}
	return json.Unmarshal(data, &v.Value)
}

type optionalExpiry struct {
	Present bool
	Null    bool
	Value   time.Time
}

func (v *optionalExpiry) UnmarshalJSON(data []byte) error {
	v.Present = true
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		v.Null = true
		return nil
	}
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("expires_at must be null or an RFC3339 string")
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return fmt.Errorf("expires_at must be null or an RFC3339 string")
	}
	v.Value = parsed.UTC()
	return nil
}

type putTLSPolicyRequest struct {
	Mode      tlspolicy.Mode `json:"mode"`
	BundleID  optionalString `json:"bundle_id"`
	Reason    optionalString `json:"reason"`
	ExpiresAt optionalExpiry `json:"expires_at"`
}

func mutationFromRequest(mode tlspolicy.Mode, bundleID, reason optionalString, expiry optionalExpiry) (tlspolicy.Mutation, error) {
	mutation := tlspolicy.Mutation{Mode: mode}
	if bundleID.Present {
		if bundleID.Null || strings.TrimSpace(bundleID.Value) == "" {
			return mutation, fmt.Errorf("bundle_id must be a non-empty string")
		}
		mutation.BundleID = strings.TrimSpace(bundleID.Value)
	}
	if reason.Present {
		if reason.Null {
			return mutation, fmt.Errorf("reason must be a string when present")
		}
		value := reason.Value
		mutation.Reason = &value
	}
	if expiry.Present {
		mutation.ExpirySet = true
		if !expiry.Null {
			value := expiry.Value.UTC()
			mutation.ExpiresAt = &value
		}
	}
	return mutation, nil
}

func tlsAuditContext(r *http.Request) tlspolicy.AuditContext {
	return tlspolicy.AuditContext{
		RequestID:       strings.TrimSpace(r.Header.Get("X-Request-ID")),
		RemoteAddress:   r.RemoteAddr,
		CredentialClass: requestCredentialClass(r),
	}
}

func parseIfMatchVersion(r *http.Request) (int64, error) {
	raw := strings.TrimSpace(r.Header.Get("If-Match"))
	if raw == "" {
		return 0, fmt.Errorf("If-Match with the current policy version is required")
	}
	raw = strings.Trim(raw, `"`)
	version, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || version <= 0 {
		return 0, fmt.Errorf("If-Match must contain a positive policy version")
	}
	return version, nil
}

func requireExpectedAbsence(r *http.Request) error {
	if strings.TrimSpace(r.Header.Get("If-None-Match")) != "*" {
		return fmt.Errorf("If-None-Match: * is required to create a TLS policy")
	}
	return nil
}

func HandleImportCABundle(cp *service.ControlPlaneService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req importCABundleRequest
		if err := DecodeBody(r, &req); err != nil {
			writeDecodeBodyError(w, err)
			return
		}
		bundle, created, err := cp.ImportCABundle([]byte(req.PEM), tlsAuditContext(r))
		if err != nil {
			writeServiceError(w, err)
			return
		}
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		WriteJSON(w, status, bundle)
	}
}

func HandleListCABundles(cp *service.ControlPlaneService) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		bundles, err := cp.ListCABundles()
		if err != nil {
			writeServiceError(w, err)
			return
		}
		WriteJSON(w, http.StatusOK, bundles)
	}
}

func HandleGetCABundle(cp *service.ControlPlaneService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := requireUUIDPathParam(w, r, "bundle_id", "bundle_id")
		if !ok {
			return
		}
		bundle, err := cp.GetCABundle(id)
		if err != nil {
			writeServiceError(w, err)
			return
		}
		WriteJSON(w, http.StatusOK, bundle)
	}
}

func HandleDeleteCABundle(cp *service.ControlPlaneService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := requireUUIDPathParam(w, r, "bundle_id", "bundle_id")
		if !ok {
			return
		}
		if err := cp.DeleteCABundle(id, tlsAuditContext(r)); err != nil {
			writeServiceError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func HandleCABundleHistory(cp *service.ControlPlaneService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := requireUUIDPathParam(w, r, "bundle_id", "bundle_id")
		if !ok {
			return
		}
		events, err := cp.CABundleHistory(id)
		if err != nil {
			writeServiceError(w, err)
			return
		}
		WriteJSON(w, http.StatusOK, events)
	}
}

func HandleGetTLSPolicy(cp *service.ControlPlaneService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		platformID, ok := requireUUIDPathParam(w, r, "id", "platform_id")
		if !ok {
			return
		}
		policy, err := cp.GetTLSPolicy(platformID)
		if err != nil {
			writeServiceError(w, err)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, policy.Version))
		WriteJSON(w, http.StatusOK, policy)
	}
}

func HandlePutTLSPolicy(cp *service.ControlPlaneService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		platformID, ok := requireUUIDPathParam(w, r, "id", "platform_id")
		if !ok {
			return
		}
		create := strings.TrimSpace(r.Header.Get("If-None-Match")) != ""
		replace := strings.TrimSpace(r.Header.Get("If-Match")) != ""
		if create == replace {
			writeInvalidArgument(w, "exactly one of If-None-Match: * or If-Match is required")
			return
		}
		var expected int64
		var err error
		if create {
			err = requireExpectedAbsence(r)
		} else {
			expected, err = parseIfMatchVersion(r)
		}
		if err != nil {
			writeInvalidArgument(w, err.Error())
			return
		}
		var req putTLSPolicyRequest
		if err := DecodeBody(r, &req); err != nil {
			writeDecodeBodyError(w, err)
			return
		}
		mutation, err := mutationFromRequest(req.Mode, req.BundleID, req.Reason, req.ExpiresAt)
		if err != nil {
			writeInvalidArgument(w, err.Error())
			return
		}
		var policy *tlspolicy.PolicyRecord
		status := http.StatusOK
		if create {
			policy, err = cp.CreateTLSPolicy(platformID, mutation, tlsAuditContext(r))
			status = http.StatusCreated
		} else {
			policy, err = cp.ReplaceTLSPolicy(platformID, expected, mutation, tlsAuditContext(r))
		}
		if err != nil {
			writeServiceError(w, err)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, policy.Version))
		WriteJSON(w, status, policy)
	}
}

func HandleDeleteTLSPolicy(cp *service.ControlPlaneService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		platformID, ok := requireUUIDPathParam(w, r, "id", "platform_id")
		if !ok {
			return
		}
		expected, err := parseIfMatchVersion(r)
		if err != nil {
			writeInvalidArgument(w, err.Error())
			return
		}
		if err := cp.DeleteTLSPolicy(platformID, expected, tlsAuditContext(r)); err != nil {
			writeServiceError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func HandleTLSPolicyHistory(cp *service.ControlPlaneService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		platformID, ok := requireUUIDPathParam(w, r, "id", "platform_id")
		if !ok {
			return
		}
		events, err := cp.TLSPolicyHistory(platformID)
		if err != nil {
			writeServiceError(w, err)
			return
		}
		WriteJSON(w, http.StatusOK, events)
	}
}
