package service

import (
	"errors"
	"strings"
	"time"

	"github.com/Resinat/Resin/internal/platform"
	"github.com/Resinat/Resin/internal/state"
	"github.com/Resinat/Resin/internal/tlspolicy"
)

type PlatformConfigurationResponse struct {
	Platform      PlatformResponse          `json:"platform"`
	TLSPolicy     PlatformTLSPolicyResponse `json:"tls_policy"`
	ConfigVersion int64                     `json:"config_version"`
}

type PlatformTLSPolicyResponse struct {
	ID                string         `json:"id"`
	PlatformID        string         `json:"platform_id"`
	PlatformName      string         `json:"platform_name"`
	Mode              tlspolicy.Mode `json:"mode"`
	EffectiveMode     tlspolicy.Mode `json:"effective_mode"`
	Expired           bool           `json:"expired"`
	BundleID          string         `json:"bundle_id,omitempty"`
	BundleFingerprint string         `json:"bundle_fingerprint,omitempty"`
	Reason            string         `json:"reason,omitempty"`
	ExpiresAt         *time.Time     `json:"expires_at"`
	Version           int64          `json:"version"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
}

func projectManagementPolicy(policy tlspolicy.PolicyRecord, now time.Time) PlatformTLSPolicyResponse {
	effectiveMode, expired := tlspolicy.EvaluateConfiguredMode(policy, now)
	createdAt, updatedAt := policy.CreatedAt, policy.UpdatedAt
	if policy.Version == 0 {
		createdAt, updatedAt = time.Time{}, time.Time{}
	}
	return PlatformTLSPolicyResponse{
		ID: policy.ID, PlatformID: policy.PlatformID, PlatformName: policy.PlatformName,
		Mode: policy.Mode, EffectiveMode: effectiveMode, Expired: expired,
		BundleID: policy.BundleID, BundleFingerprint: policy.BundleFingerprint,
		Reason: policy.Reason, ExpiresAt: policy.ExpiresAt, Version: policy.Version,
		CreatedAt: createdAt, UpdatedAt: updatedAt,
	}
}

type PlatformConfigurationFields struct {
	Name                             string   `json:"name"`
	StickyTTL                        string   `json:"sticky_ttl"`
	RegexFilters                     []string `json:"regex_filters"`
	RegionFilters                    []string `json:"region_filters"`
	ReverseProxyMissAction           string   `json:"reverse_proxy_miss_action"`
	ReverseProxyEmptyAccountBehavior string   `json:"reverse_proxy_empty_account_behavior"`
	ReverseProxyFixedAccountHeader   string   `json:"reverse_proxy_fixed_account_header"`
	AllocationPolicy                 string   `json:"allocation_policy"`
	PassiveCircuitBreakerDisabled    bool     `json:"passive_circuit_breaker_disabled"`
}

type PlatformConfigurationPolicyInput struct {
	ExpectedVersion int64
	Mutation        tlspolicy.Mutation
}

type UpdatePlatformConfigurationRequest struct {
	Platform  PlatformConfigurationFields
	TLSPolicy *PlatformConfigurationPolicyInput
}

func (s *ControlPlaneService) GetPlatformConfiguration(platformID string) (*PlatformConfigurationResponse, error) {
	if s.Engine == nil {
		return nil, internal("state engine unavailable", nil)
	}
	view, err := s.Engine.GetPlatformConfiguration(platformID)
	if err != nil {
		if errors.Is(err, state.ErrNotFound) {
			return nil, notFound("platform not found")
		}
		return nil, internal("get platform configuration", err)
	}
	policy := tlspolicy.PolicyRecord{
		PlatformID: view.Platform.ID, PlatformName: view.Platform.Name, Mode: tlspolicy.ModeVerify,
	}
	if view.Policy != nil {
		policy = *view.Policy
	}
	platformResponse := s.withRoutableNodeCount(platformToResponse(view.Platform))
	return &PlatformConfigurationResponse{
		Platform: platformResponse, TLSPolicy: projectManagementPolicy(policy, time.Now().UTC()), ConfigVersion: view.Platform.ConfigVersion,
	}, nil
}

func platformConfigFromConfigurationFields(fields PlatformConfigurationFields) (platformConfig, *ServiceError) {
	name := platform.NormalizePlatformName(fields.Name)
	if name == "" {
		return platformConfig{}, invalidArg("platform.name is required")
	}
	if err := platform.ValidatePlatformName(name); err != nil {
		return platformConfig{}, invalidArg("platform.name: " + err.Error())
	}
	stickyTTL, err := time.ParseDuration(strings.TrimSpace(fields.StickyTTL))
	if err != nil {
		return platformConfig{}, invalidArg("platform.sticky_ttl: " + err.Error())
	}
	cfg := platformConfig{
		Name:                           name,
		RegexFilters:                   append([]string(nil), fields.RegexFilters...),
		RegionFilters:                  append([]string(nil), fields.RegionFilters...),
		ReverseProxyFixedAccountHeader: fields.ReverseProxyFixedAccountHeader,
		PassiveCircuitBreakerDisabled:  fields.PassiveCircuitBreakerDisabled,
	}
	if err := setPlatformStickyTTL(&cfg, stickyTTL); err != nil {
		return platformConfig{}, invalidArg("platform." + err.Message)
	}
	if err := setPlatformMissAction(&cfg, fields.ReverseProxyMissAction); err != nil {
		return platformConfig{}, invalidArg("platform." + err.Message)
	}
	if err := setPlatformEmptyAccountBehavior(&cfg, fields.ReverseProxyEmptyAccountBehavior); err != nil {
		return platformConfig{}, invalidArg("platform." + err.Message)
	}
	if err := setPlatformAllocationPolicy(&cfg, fields.AllocationPolicy); err != nil {
		return platformConfig{}, invalidArg("platform." + err.Message)
	}
	if err := validatePlatformConfig(&cfg, true); err != nil {
		return platformConfig{}, invalidArg("platform." + err.Message)
	}
	return cfg, nil
}

func (s *ControlPlaneService) UpdatePlatformConfiguration(
	platformID string,
	expectedConfigVersion int64,
	req UpdatePlatformConfigurationRequest,
	audit tlspolicy.AuditContext,
) (*PlatformConfigurationResponse, error) {
	if expectedConfigVersion <= 0 {
		return nil, invalidArg("If-Match must contain a positive configuration version")
	}
	if s.Engine == nil || s.Pool == nil || s.TLSPolicy == nil {
		return nil, internal("platform configuration service unavailable", nil)
	}

	s.platformMu.Lock()
	defer s.platformMu.Unlock()
	current, err := s.getPlatformModel(platformID)
	if err != nil {
		return nil, err
	}
	cfg, cfgErr := platformConfigFromConfigurationFields(req.Platform)
	if cfgErr != nil {
		return nil, cfgErr
	}
	if current.ID == platform.DefaultPlatformID && cfg.Name != platform.DefaultPlatformName {
		return nil, conflict("cannot rename Default platform")
	}
	if current.ID != platform.DefaultPlatformID && cfg.Name == platform.DefaultPlatformName {
		return nil, conflict("cannot use reserved name 'Default'")
	}
	runtimePlatform, compileErr := cfg.toRuntime(platformID)
	if compileErr != nil {
		return nil, invalidArg(compileErr.Error())
	}
	if err := s.Pool.PreparePlatformReplacement(runtimePlatform); err != nil {
		return nil, conflict("platform runtime cannot be replaced")
	}

	now := time.Now().UTC()
	platformRow := cfg.toModel(platformID, now.UnixNano())
	var desired *tlspolicy.Mutation
	var expectedPolicyVersion int64
	if req.TLSPolicy != nil {
		mutation := req.TLSPolicy.Mutation
		desired = &mutation
		expectedPolicyVersion = req.TLSPolicy.ExpectedVersion
	}
	var configVersion int64
	policy, applyErr := s.TLSPolicy.ApplyConfiguration(
		platformID,
		cfg.Name,
		desired,
		expectedPolicyVersion,
		audit,
		func(plan tlspolicy.ConfigurationMutation) error {
			var persistErr error
			configVersion, persistErr = s.Engine.ApplyPlatformConfiguration(platformRow, expectedConfigVersion, plan)
			return persistErr
		},
		func(publishTLS func()) {
			s.withPublicationWriteLock(func() {
				s.Pool.PublishPreparedPlatform(runtimePlatform)
				publishTLS()
			})
		},
	)
	if applyErr != nil {
		switch {
		case errors.Is(applyErr, state.ErrNotFound):
			return nil, notFound("platform or CA bundle not found")
		case errors.Is(applyErr, state.ErrConflict), errors.Is(applyErr, tlspolicy.ErrConflict):
			return nil, conflict("platform configuration version conflict")
		case errors.Is(applyErr, tlspolicy.ErrNotFound):
			return nil, notFound("CA bundle not found")
		case errors.Is(applyErr, tlspolicy.ErrDefaultPlatform):
			return nil, invalidArg(applyErr.Error())
		case errors.Is(applyErr, tlspolicy.ErrIntegrity):
			return nil, internal("apply platform TLS policy", applyErr)
		case errors.Is(applyErr, tlspolicy.ErrPersistence):
			return nil, internal("apply platform TLS policy", applyErr)
		default:
			return nil, invalidArg(applyErr.Error())
		}
	}

	platformRow.ConfigVersion = configVersion
	platformResponse := s.withRoutableNodeCount(platformToResponse(platformRow))
	policy.PlatformName = cfg.Name
	return &PlatformConfigurationResponse{
		Platform: platformResponse, TLSPolicy: projectManagementPolicy(policy, time.Now().UTC()), ConfigVersion: configVersion,
	}, nil
}

func (s *ControlPlaneService) withPublicationWriteLock(publish func()) {
	if s.PublicationGate == nil {
		publish()
		return
	}
	s.PublicationGate.Lock()
	defer s.PublicationGate.Unlock()
	publish()
}
