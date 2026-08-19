package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/Resinat/Resin/internal/tlspolicy"
)

type tlsProfile struct {
	key        string
	mode       tlspolicy.Mode
	generation uint64
	config     *tls.Config
}

func verifyTLSProfile() tlsProfile {
	return tlsProfile{key: "verify:v1", mode: tlspolicy.ModeVerify}
}

func compileTLSProfile(policy tlspolicy.ResolvedPolicy) (tlsProfile, error) {
	switch policy.EffectiveMode {
	case tlspolicy.ModeVerify:
		return verifyTLSProfile(), nil
	case tlspolicy.ModeTrustCustomCA:
		if len(policy.CanonicalPEM) == 0 || policy.BundleFingerprint == "" {
			return tlsProfile{}, fmt.Errorf("custom CA policy has no verified trust material")
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			return tlsProfile{}, fmt.Errorf("load system certificate pool: %w", err)
		}
		if roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(policy.CanonicalPEM) {
			return tlsProfile{}, fmt.Errorf("custom CA policy contains invalid trust material")
		}
		return tlsProfile{
			key:        policy.ProfileKey(),
			mode:       tlspolicy.ModeTrustCustomCA,
			generation: policy.SnapshotGeneration,
			config: &tls.Config{
				RootCAs: roots,
			},
		}, nil
	case tlspolicy.ModeBypass:
		return tlsProfile{
			key:        policy.ProfileKey(),
			mode:       tlspolicy.ModeBypass,
			generation: policy.SnapshotGeneration,
			config: &tls.Config{
				// This is reachable only after a platform BYPASS policy has been
				// resolved. Profile keys include that policy identity and version.
				InsecureSkipVerify: true, //nolint:gosec
			},
		}, nil
	default:
		return tlsProfile{}, fmt.Errorf("unknown effective TLS policy %q", policy.EffectiveMode)
	}
}

func (p tlsProfile) tlsConfig() *tls.Config {
	if p.config == nil {
		return nil
	}
	return p.config.Clone()
}
