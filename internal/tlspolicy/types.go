// Package tlspolicy owns platform-scoped reverse HTTPS verification policy.
package tlspolicy

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Resinat/Resin/internal/platform"
	"golang.org/x/net/idna"
)

const (
	FingerprintAlgorithmSHA256 = "SHA256"
	CanonicalizationVersion    = 1
)

var (
	ErrNotFound             = errors.New("tls policy object not found")
	ErrConflict             = errors.New("tls policy version conflict")
	ErrBundleInUse          = errors.New("CA bundle is in use")
	ErrFingerprintCollision = errors.New("CA bundle fingerprint collision")
	ErrIntegrity            = errors.New("TLS policy integrity failure")
	// ErrPersistence marks an unexpected storage/transaction failure. Domain
	// validation and optimistic-concurrency sentinels remain distinguishable so
	// API callers can map them to client errors while infrastructure failures
	// close as INTERNAL.
	ErrPersistence     = errors.New("TLS policy persistence failure")
	ErrDefaultPlatform = errors.New("Default platform TLS policy is fixed to VERIFY")
)

type Mode string

const (
	ModeVerify        Mode = "VERIFY"
	ModeTrustCustomCA Mode = "TRUST_CUSTOM_CA"
	ModeBypass        Mode = "BYPASS"
)

type CABundleRef struct {
	ID                      string                `json:"id"`
	FingerprintAlgorithm    string                `json:"fingerprint_algorithm"`
	Fingerprint             string                `json:"fingerprint"`
	CanonicalizationVersion int                   `json:"canonicalization_version"`
	CertificateCount        int                   `json:"certificate_count"`
	Certificates            []CertificateMetadata `json:"certificates"`
	CreatedAt               time.Time             `json:"created_at"`
}

// CertificateMetadata contains stable, non-secret X.509 fields used to
// identify an imported trust bundle without returning its canonical PEM.
type CertificateMetadata struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	Serial    string    `json:"serial"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

type VerifiedCABundle struct {
	Ref          CABundleRef
	CanonicalPEM []byte
}

type CABundleRecord struct {
	Ref          CABundleRef
	CanonicalPEM []byte
}

type AuditContext struct {
	RequestID       string
	RemoteAddress   string
	CredentialClass string
	OccurredAt      time.Time
}

type CABundleEvent struct {
	ID                      string                `json:"id"`
	BundleID                string                `json:"bundle_id"`
	EventKind               string                `json:"event_kind"`
	FingerprintAlgorithm    string                `json:"fingerprint_algorithm"`
	Fingerprint             string                `json:"fingerprint"`
	CanonicalizationVersion int                   `json:"canonicalization_version"`
	CertificateCount        int                   `json:"certificate_count"`
	Certificates            []CertificateMetadata `json:"certificates"`
	OccurredAt              time.Time             `json:"occurred_at"`
	RequestID               string                `json:"request_id,omitempty"`
	RemoteAddress           string                `json:"remote_address,omitempty"`
	CredentialClass         string                `json:"credential_class,omitempty"`
}

type PolicyRecord struct {
	ID                string     `json:"id"`
	PlatformID        string     `json:"platform_id"`
	PlatformName      string     `json:"platform_name"`
	Mode              Mode       `json:"mode"`
	BundleID          string     `json:"bundle_id,omitempty"`
	BundleFingerprint string     `json:"bundle_fingerprint,omitempty"`
	Reason            string     `json:"-"`
	ExpiresAt         *time.Time `json:"expires_at"`
	Version           int64      `json:"version"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// EvaluateConfiguredMode returns the request-time effect of one valid policy
// record without changing its persisted configuration state.
func EvaluateConfiguredMode(policy PolicyRecord, now time.Time) (Mode, bool) {
	if policy.Mode == ModeBypass && policy.ExpiresAt != nil && !now.Before(*policy.ExpiresAt) {
		return ModeVerify, true
	}
	return policy.Mode, false
}

type PolicySnapshot struct {
	Version           int64      `json:"version"`
	Mode              Mode       `json:"mode"`
	BundleID          string     `json:"bundle_id,omitempty"`
	BundleFingerprint string     `json:"bundle_fingerprint,omitempty"`
	Reason            string     `json:"-"`
	ExpiresAt         *time.Time `json:"expires_at"`
}

func SnapshotPolicy(policy PolicyRecord) *PolicySnapshot {
	return &PolicySnapshot{
		Version:           policy.Version,
		Mode:              policy.Mode,
		BundleID:          policy.BundleID,
		BundleFingerprint: policy.BundleFingerprint,
		Reason:            policy.Reason,
		ExpiresAt:         cloneTime(policy.ExpiresAt),
	}
}

type PolicyEvent struct {
	ID              string          `json:"id"`
	EventKind       string          `json:"event_kind"`
	PolicyID        string          `json:"policy_id,omitempty"`
	PlatformID      string          `json:"platform_id"`
	PlatformName    string          `json:"platform_name"`
	Old             *PolicySnapshot `json:"old,omitempty"`
	New             *PolicySnapshot `json:"new,omitempty"`
	OccurredAt      time.Time       `json:"occurred_at"`
	RequestID       string          `json:"request_id,omitempty"`
	RemoteAddress   string          `json:"remote_address,omitempty"`
	CredentialClass string          `json:"credential_class,omitempty"`
}

type CompiledPolicy struct {
	Record PolicyRecord
	Bundle *VerifiedCABundle
}

type ResolvedPolicy struct {
	SnapshotGeneration uint64
	ConfiguredMode     Mode
	EffectiveMode      Mode
	PolicyID           string
	PolicyVersion      int64
	PlatformID         string
	NormalizedTarget   string
	BundleFingerprint  string
	CanonicalPEM       []byte
	Reason             string
	ExpiresAt          *time.Time
	Expired            bool
}

func VerifyPolicy(platformID, target string) ResolvedPolicy {
	return ResolvedPolicy{
		ConfiguredMode:   ModeVerify,
		EffectiveMode:    ModeVerify,
		PlatformID:       platformID,
		NormalizedTarget: target,
	}
}

func (p ResolvedPolicy) ProfileKey() string {
	switch p.EffectiveMode {
	case ModeTrustCustomCA:
		return fmt.Sprintf("custom-ca:v1:%s:%s:%d:%s", p.PlatformID, p.PolicyID, p.PolicyVersion, p.BundleFingerprint)
	case ModeBypass:
		return fmt.Sprintf("bypass:v1:%s:%s:%d", p.PlatformID, p.PolicyID, p.PolicyVersion)
	default:
		return "verify:v1"
	}
}

func (p ResolvedPolicy) ConfiguredProfileKey() string {
	configured := p
	configured.EffectiveMode = p.ConfiguredMode
	return configured.ProfileKey()
}

func profileKeyForPolicy(policy PolicyRecord) string {
	return ResolvedPolicy{
		ConfiguredMode:    policy.Mode,
		EffectiveMode:     policy.Mode,
		PolicyID:          policy.ID,
		PolicyVersion:     policy.Version,
		PlatformID:        policy.PlatformID,
		BundleFingerprint: policy.BundleFingerprint,
	}.ProfileKey()
}

func ValidatePolicy(policy PolicyRecord) error {
	if policy.ID == "" || policy.PlatformID == "" || policy.PlatformName == "" {
		return fmt.Errorf("%w: policy identity is incomplete", ErrIntegrity)
	}
	if policy.PlatformID == platform.DefaultPlatformID {
		return ErrDefaultPlatform
	}
	if policy.Version <= 0 {
		return fmt.Errorf("%w: policy version must be positive", ErrIntegrity)
	}
	switch policy.Mode {
	case ModeTrustCustomCA:
		if policy.BundleID == "" || policy.BundleFingerprint == "" || policy.Reason != "" || policy.ExpiresAt != nil {
			return fmt.Errorf("%w: invalid TRUST_CUSTOM_CA fields", ErrIntegrity)
		}
	case ModeBypass:
		if policy.BundleID != "" || policy.BundleFingerprint != "" || strings.TrimSpace(policy.Reason) == "" {
			return fmt.Errorf("%w: invalid BYPASS fields", ErrIntegrity)
		}
	default:
		return fmt.Errorf("%w: persisted mode %q is invalid", ErrIntegrity, policy.Mode)
	}
	return nil
}

func NormalizeTarget(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "/?#@") {
		return "", fmt.Errorf("target must be an exact host:port")
	}
	u, err := url.Parse("https://" + raw)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("target must be an exact host:port")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" || strings.Contains(host, "%") {
		return "", fmt.Errorf("target host is invalid")
	}
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	} else {
		host, err = idna.Lookup.ToASCII(host)
		if err != nil || host == "" {
			return "", fmt.Errorf("target host is invalid")
		}
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", fmt.Errorf("target port is invalid")
	}
	return net.JoinHostPort(host, strconv.Itoa(portNumber)), nil
}

func cloneTime(in *time.Time) *time.Time {
	if in == nil {
		return nil
	}
	v := in.UTC()
	return &v
}
