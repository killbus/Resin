package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Resinat/Resin/internal/service"
	"github.com/Resinat/Resin/internal/tlspolicy"
)

type platformConfigurationPolicyRequest struct {
	Mode            tlspolicy.Mode `json:"mode"`
	ExpectedVersion int64          `json:"expected_version"`
	BundleID        optionalString `json:"bundle_id"`
	Reason          optionalString `json:"reason"`
	ExpiresAt       optionalExpiry `json:"expires_at"`
}

type putPlatformConfigurationRequest struct {
	Platform  service.PlatformConfigurationFields `json:"platform"`
	TLSPolicy *platformConfigurationPolicyRequest `json:"tls_policy,omitempty"`
}

func parseConfigurationIfMatch(r *http.Request) (int64, error) {
	raw := strings.TrimSpace(r.Header.Get("If-Match"))
	if raw == "" {
		return 0, fmt.Errorf("If-Match with the current configuration version is required")
	}
	raw = strings.Trim(raw, `"`)
	version, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || version <= 0 {
		return 0, fmt.Errorf("If-Match must contain a positive configuration version")
	}
	return version, nil
}

func HandleGetPlatformConfiguration(cp *service.ControlPlaneService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		platformID, ok := requireUUIDPathParam(w, r, "id", "platform_id")
		if !ok {
			return
		}
		configuration, err := cp.GetPlatformConfiguration(platformID)
		if err != nil {
			writeServiceError(w, err)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, configuration.ConfigVersion))
		WriteJSON(w, http.StatusOK, configuration)
	}
}

func HandlePutPlatformConfiguration(cp *service.ControlPlaneService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		platformID, ok := requireUUIDPathParam(w, r, "id", "platform_id")
		if !ok {
			return
		}
		expectedConfigVersion, err := parseConfigurationIfMatch(r)
		if err != nil {
			writeInvalidArgument(w, err.Error())
			return
		}
		var request putPlatformConfigurationRequest
		if err := DecodeBody(r, &request); err != nil {
			writeDecodeBodyError(w, err)
			return
		}
		serviceRequest := service.UpdatePlatformConfigurationRequest{Platform: request.Platform}
		if request.TLSPolicy != nil {
			mutation, err := mutationFromRequest(
				request.TLSPolicy.Mode,
				request.TLSPolicy.BundleID,
				request.TLSPolicy.Reason,
				request.TLSPolicy.ExpiresAt,
			)
			if err != nil {
				writeInvalidArgument(w, err.Error())
				return
			}
			if request.TLSPolicy.ExpectedVersion < 0 {
				writeInvalidArgument(w, "tls_policy.expected_version must be non-negative")
				return
			}
			serviceRequest.TLSPolicy = &service.PlatformConfigurationPolicyInput{
				ExpectedVersion: request.TLSPolicy.ExpectedVersion,
				Mutation:        mutation,
			}
		}
		configuration, err := cp.UpdatePlatformConfiguration(
			platformID,
			expectedConfigVersion,
			serviceRequest,
			tlsAuditContext(r),
		)
		if err != nil {
			writeServiceError(w, err)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, configuration.ConfigVersion))
		WriteJSON(w, http.StatusOK, configuration)
	}
}
