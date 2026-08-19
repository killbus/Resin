package proxy

import (
	"fmt"
	"sync"

	"github.com/Resinat/Resin/internal/platform"
	"github.com/Resinat/Resin/internal/tlspolicy"
)

type ReverseTLSPolicyEvaluator interface {
	Resolve(platformID, target string) (tlspolicy.ResolvedPolicy, error)
}

type ReverseRequestDecision struct {
	PlatformID            string
	PlatformName          string
	Platform              *platform.Platform
	NormalizedTarget      string
	Policy                tlspolicy.ResolvedPolicy
	TLSProfile            tlsProfile
	AuthorizationDecision string
}

const (
	reverseAuthorizationAllowed             = "ALLOW"
	reverseAuthorizationDeniedPlatform      = "DENY_PLATFORM_NOT_FOUND"
	reverseAuthorizationDeniedTarget        = "DENY_INVALID_TARGET"
	reverseAuthorizationDeniedIndeterminate = "DENY_POLICY_INDETERMINATE"
)

type ReverseRequestResolver struct {
	platforms       PlatformLookup
	policies        ReverseTLSPolicyEvaluator
	retireProfile   func(string)
	publicationGate *sync.RWMutex
}

func NewReverseRequestResolver(
	platforms PlatformLookup,
	policies ReverseTLSPolicyEvaluator,
	retireProfile func(string),
	publicationGates ...*sync.RWMutex,
) *ReverseRequestResolver {
	var publicationGate *sync.RWMutex
	if len(publicationGates) > 0 {
		publicationGate = publicationGates[0]
	}
	return &ReverseRequestResolver{
		platforms: platforms, policies: policies, retireProfile: retireProfile, publicationGate: publicationGate,
	}
}

func (r *ReverseRequestResolver) Resolve(platformName, protocol, target string) (ReverseRequestDecision, *ProxyError) {
	decision := ReverseRequestDecision{PlatformName: platformName}
	var err error
	if r == nil || r.platforms == nil {
		decision.AuthorizationDecision = reverseAuthorizationDeniedIndeterminate
		return decision, ErrInternalError
	}
	if protocol == "https" {
		normalized, err := tlspolicy.NormalizeTarget(target)
		if err != nil {
			decision.AuthorizationDecision = reverseAuthorizationDeniedTarget
			return decision, ErrInvalidHost
		}
		decision.NormalizedTarget = normalized
	}
	if r.publicationGate != nil {
		r.publicationGate.RLock()
		defer r.publicationGate.RUnlock()
	}
	var plat *platform.Platform
	var ok bool
	if platformName == "" {
		plat, ok = r.platforms.GetPlatform(platform.DefaultPlatformID)
	} else {
		plat, ok = r.platforms.GetPlatformByName(platformName)
	}
	if !ok || plat == nil {
		decision.AuthorizationDecision = reverseAuthorizationDeniedPlatform
		return decision, ErrPlatformNotFound
	}
	decision = ReverseRequestDecision{
		PlatformID:            plat.ID,
		PlatformName:          plat.Name,
		Platform:              plat,
		Policy:                tlspolicy.VerifyPolicy(plat.ID, ""),
		TLSProfile:            verifyTLSProfile(),
		AuthorizationDecision: reverseAuthorizationAllowed,
		NormalizedTarget:      decision.NormalizedTarget,
	}
	if protocol != "https" {
		return decision, nil
	}
	normalized := decision.NormalizedTarget
	decision.NormalizedTarget = normalized
	decision.Policy = tlspolicy.VerifyPolicy(plat.ID, normalized)
	if r.policies == nil {
		decision.AuthorizationDecision = reverseAuthorizationDeniedIndeterminate
		return decision, ErrInternalError
	}
	decision.Policy, err = r.policies.Resolve(plat.ID, normalized)
	if err != nil {
		decision.AuthorizationDecision = reverseAuthorizationDeniedIndeterminate
		return decision, ErrInternalError
	}
	decision.TLSProfile, err = compileTLSProfile(decision.Policy)
	if err != nil {
		decision.AuthorizationDecision = reverseAuthorizationDeniedIndeterminate
		return decision, ErrInternalError
	}
	if decision.Policy.Expired && r.retireProfile != nil {
		r.retireProfile(decision.Policy.ConfiguredProfileKey())
	}
	return decision, nil
}

func (d ReverseRequestDecision) String() string {
	return fmt.Sprintf("platform=%s target=%s policy=%s version=%d", d.PlatformID, d.NormalizedTarget, d.Policy.EffectiveMode, d.Policy.PolicyVersion)
}
