package tlspolicy

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Resinat/Resin/internal/platform"
	"github.com/google/uuid"
)

// wrapConfigurationPersistenceError marks failures returned by the caller's
// transaction coordinator. The original error remains discoverable through
// errors.Is, so conflicts, missing records, and integrity failures retain
// their domain/API mapping while unexpected storage failures close as
// infrastructure errors.
func wrapConfigurationPersistenceError(err error) error {
	if err == nil {
		return nil
	}
	// A coordinator may return a domain sentinel directly. Keep it unchanged
	// for callers that rely on exact identity, while still marking all other
	// failures as persistence errors.
	switch {
	case errors.Is(err, ErrConflict), errors.Is(err, ErrNotFound),
		errors.Is(err, ErrIntegrity), errors.Is(err, ErrDefaultPlatform),
		errors.Is(err, ErrBundleInUse), errors.Is(err, ErrFingerprintCollision):
		return err
	default:
		return fmt.Errorf("%w: %w", ErrPersistence, err)
	}
}

type PolicyStore interface {
	ListTLSPolicies() ([]PolicyRecord, error)
	GetTLSPolicy(platformID string) (PolicyRecord, error)
	CreateTLSPolicy(policy PolicyRecord, event PolicyEvent) error
	ReplaceTLSPolicy(platformID string, expectedVersion int64, policy PolicyRecord, event PolicyEvent) error
	DeleteTLSPolicy(platformID string, expectedVersion int64, event PolicyEvent) error
	DeletePlatformWithTLSHistory(platformID string, audit AuditContext) error
	ListTLSPolicyHistory(platformID string) ([]PolicyEvent, error)
}

// ConfigurationMutation is a fully validated TLS change prepared while the
// policy service mutation lock is held. Persistence coordinators may commit it
// together with other platform state, but cannot construct domain records.
type ConfigurationMutation struct {
	ExpectedVersion int64
	Current         *PolicyRecord
	Next            *PolicyRecord
	Event           *PolicyEvent
}

func (m ConfigurationMutation) ChangesPolicy() bool { return m.Event != nil }

type Snapshot struct {
	Generation  uint64
	policies    map[string]CompiledPolicy
	profileKeys map[string]struct{}
}

func (s *Snapshot) clonePolicies() []PolicyRecord {
	if s == nil {
		return nil
	}
	rows := make([]PolicyRecord, 0, len(s.policies))
	for _, compiled := range s.policies {
		rows = append(rows, compiled.Record)
	}
	return rows
}

// ProfileKeys returns the non-VERIFY transport profiles referenced by a
// snapshot. Callers use the immutable keys to retire idle transports after a
// policy publication without reading policy fields in request handlers.
func (s *Snapshot) ProfileKeys() map[string]struct{} {
	out := make(map[string]struct{})
	if s == nil {
		return out
	}
	for key := range s.profileKeys {
		out[key] = struct{}{}
	}
	return out
}

type PolicyService struct {
	store    PolicyStore
	registry *CABundleRegistry
	now      func() time.Time

	mu          sync.Mutex
	snapshot    atomic.Pointer[Snapshot]
	generation  atomic.Uint64
	listeners   []func(old, next *Snapshot)
	expiryTimer policyTimer
	schedule    func(time.Duration, func()) policyTimer
}

type policyTimer interface {
	Stop() bool
}

func NewPolicyService(store PolicyStore, registry *CABundleRegistry, now func() time.Time) (*PolicyService, error) {
	return newPolicyService(store, registry, now, func(delay time.Duration, callback func()) policyTimer {
		return time.AfterFunc(delay, callback)
	})
}

func newPolicyService(store PolicyStore, registry *CABundleRegistry, now func() time.Time, schedule func(time.Duration, func()) policyTimer) (*PolicyService, error) {
	if now == nil {
		now = time.Now
	}
	p := &PolicyService{store: store, registry: registry, now: now, schedule: schedule}
	if err := p.Reload(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *PolicyService) AddSnapshotListener(listener func(old, next *Snapshot)) {
	if listener == nil {
		return
	}
	p.mu.Lock()
	p.listeners = append(p.listeners, listener)
	p.mu.Unlock()
}

func (p *PolicyService) Snapshot() *Snapshot {
	s := p.snapshot.Load()
	if s == nil {
		return &Snapshot{policies: map[string]CompiledPolicy{}, profileKeys: map[string]struct{}{}}
	}
	return s
}

func (p *PolicyService) Reload() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	rows, err := p.store.ListTLSPolicies()
	if err != nil {
		return err
	}
	next, err := p.compile(rows)
	if err != nil {
		return err
	}
	p.publish(next)
	return nil
}

func (p *PolicyService) compile(rows []PolicyRecord) (*Snapshot, error) {
	policies := make(map[string]CompiledPolicy, len(rows))
	for _, row := range rows {
		if err := ValidatePolicy(row); err != nil {
			return nil, err
		}
		if _, exists := policies[row.PlatformID]; exists {
			return nil, fmt.Errorf("%w: duplicate active policy for platform %s", ErrIntegrity, row.PlatformID)
		}
		compiled := CompiledPolicy{Record: row}
		if row.Mode == ModeTrustCustomCA {
			if p.registry == nil {
				return nil, fmt.Errorf("%w: custom CA registry unavailable", ErrIntegrity)
			}
			bundle, err := p.registry.Verified(row.BundleID)
			if err != nil {
				return nil, fmt.Errorf("%w: policy %s bundle: %v", ErrIntegrity, row.ID, err)
			}
			if row.BundleFingerprint != bundle.Ref.Fingerprint {
				return nil, fmt.Errorf("%w: policy %s bundle fingerprint mismatch", ErrIntegrity, row.ID)
			}
			compiled.Bundle = &bundle
		}
		policies[row.PlatformID] = compiled
	}
	return p.newSnapshot(policies, p.now()), nil
}

func (p *PolicyService) newSnapshot(policies map[string]CompiledPolicy, now time.Time) *Snapshot {
	profileKeys := make(map[string]struct{}, len(policies))
	for _, compiled := range policies {
		policy := compiled.Record
		if policy.Mode == ModeBypass && policy.ExpiresAt != nil && !now.Before(*policy.ExpiresAt) {
			continue
		}
		profileKeys[profileKeyForPolicy(policy)] = struct{}{}
	}
	return &Snapshot{Generation: p.generation.Add(1), policies: policies, profileKeys: profileKeys}
}

func (p *PolicyService) publish(next *Snapshot) {
	if next == nil {
		return
	}
	old := p.snapshot.Load()
	if old != nil {
		for _, listener := range p.listeners {
			listener(old, next)
		}
	}
	// Listeners publish the candidate generation to dependent caches before the
	// snapshot becomes visible. Requests that captured the old generation during
	// this interval therefore acquire non-cached transports, while requests that
	// observe next can never re-enter an obsolete cache index.
	p.snapshot.Store(next)
	p.scheduleNextExpiry(next)
}

func (p *PolicyService) scheduleNextExpiry(snapshot *Snapshot) {
	if p.expiryTimer != nil {
		p.expiryTimer.Stop()
		p.expiryTimer = nil
	}
	if snapshot == nil || p.schedule == nil {
		return
	}
	now := p.now()
	var earliest *time.Time
	for _, compiled := range snapshot.policies {
		expiresAt := compiled.Record.ExpiresAt
		if compiled.Record.Mode != ModeBypass || expiresAt == nil || !expiresAt.After(now) {
			continue
		}
		if earliest == nil || expiresAt.Before(*earliest) {
			value := *expiresAt
			earliest = &value
		}
	}
	if earliest == nil {
		return
	}
	expectedGeneration := snapshot.Generation
	p.expiryTimer = p.schedule(earliest.Sub(now), func() {
		p.publishExpiry(expectedGeneration)
	})
}

func (p *PolicyService) publishExpiry(expectedGeneration uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	current := p.Snapshot()
	if current.Generation != expectedGeneration {
		return
	}
	now := p.now()
	due := false
	for _, compiled := range current.policies {
		expiresAt := compiled.Record.ExpiresAt
		if compiled.Record.Mode == ModeBypass && expiresAt != nil && !now.Before(*expiresAt) {
			due = true
			break
		}
	}
	if !due {
		p.scheduleNextExpiry(current)
		return
	}
	// Expiry is a runtime publication, not a configuration mutation. Reusing
	// immutable compiled policies gives pre-publication requests their captured
	// policy while advancing the generation for every later acquisition.
	p.publish(p.newSnapshot(current.policies, now))
}

func (p *PolicyService) Resolve(platformID, rawTarget string, now time.Time) (ResolvedPolicy, error) {
	target, err := NormalizeTarget(rawTarget)
	if err != nil {
		return ResolvedPolicy{}, err
	}
	if now.IsZero() {
		now = p.now()
	}
	snap := p.Snapshot()
	compiled, ok := snap.policies[platformID]
	if !ok {
		resolved := VerifyPolicy(platformID, target)
		resolved.SnapshotGeneration = snap.Generation
		return resolved, nil
	}
	policy := compiled.Record
	resolved := ResolvedPolicy{
		SnapshotGeneration: snap.Generation,
		ConfiguredMode:     policy.Mode,
		EffectiveMode:      policy.Mode,
		PolicyID:           policy.ID,
		PolicyVersion:      policy.Version,
		PlatformID:         policy.PlatformID,
		NormalizedTarget:   target,
		BundleFingerprint:  policy.BundleFingerprint,
		Reason:             policy.Reason,
		ExpiresAt:          cloneTime(policy.ExpiresAt),
	}
	if policy.Mode == ModeTrustCustomCA && compiled.Bundle != nil {
		resolved.CanonicalPEM = bytes.Clone(compiled.Bundle.CanonicalPEM)
	}
	resolved.EffectiveMode, resolved.Expired = EvaluateConfiguredMode(policy, now)
	return resolved, nil
}

func (p *PolicyService) Create(platformID, platformName string, mutation Mutation, audit AuditContext) (PolicyRecord, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.findPolicy(platformID) != nil {
		return PolicyRecord{}, ErrConflict
	}
	now := p.mutationTime(audit)
	policy, err := p.buildPolicy(platformID, platformName, mutation, nil, now)
	if err != nil {
		return PolicyRecord{}, err
	}
	event := PolicyEvent{
		ID: uuid.NewString(), EventKind: eventKindForCreate(policy), PolicyID: policy.ID,
		PlatformID: platformID, PlatformName: platformName,
		New: SnapshotPolicy(policy), OccurredAt: now, RequestID: audit.RequestID,
		RemoteAddress: audit.RemoteAddress, CredentialClass: audit.CredentialClass,
	}
	next, err := p.snapshotWithPolicy(policy)
	if err != nil {
		return PolicyRecord{}, err
	}
	if err := p.store.CreateTLSPolicy(policy, event); err != nil {
		return PolicyRecord{}, err
	}
	p.publish(next)
	return policy, nil
}

func (p *PolicyService) Replace(platformID string, expectedVersion int64, mutation Mutation, audit AuditContext) (PolicyRecord, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if platformID == platform.DefaultPlatformID {
		return PolicyRecord{}, ErrDefaultPlatform
	}
	current, err := p.store.GetTLSPolicy(platformID)
	if err != nil {
		return PolicyRecord{}, err
	}
	if current.Version != expectedVersion || expectedVersion <= 0 {
		return PolicyRecord{}, ErrConflict
	}
	now := p.mutationTime(audit)
	policy, err := p.buildPolicy(current.PlatformID, current.PlatformName, mutation, &current, now)
	if err != nil {
		return PolicyRecord{}, err
	}
	event := PolicyEvent{
		ID: uuid.NewString(), EventKind: eventKindForReplacement(current, policy), PolicyID: policy.ID,
		PlatformID: policy.PlatformID, PlatformName: policy.PlatformName,
		Old: SnapshotPolicy(current), New: SnapshotPolicy(policy), OccurredAt: now,
		RequestID: audit.RequestID, RemoteAddress: audit.RemoteAddress, CredentialClass: audit.CredentialClass,
	}
	next, err := p.snapshotWithPolicy(policy)
	if err != nil {
		return PolicyRecord{}, err
	}
	if err := p.store.ReplaceTLSPolicy(platformID, expectedVersion, policy, event); err != nil {
		return PolicyRecord{}, err
	}
	p.publish(next)
	return policy, nil
}

func (p *PolicyService) Delete(platformID string, expectedVersion int64, audit AuditContext) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if platformID == platform.DefaultPlatformID {
		return ErrDefaultPlatform
	}
	current, err := p.store.GetTLSPolicy(platformID)
	if err != nil {
		return err
	}
	if current.Version != expectedVersion || expectedVersion <= 0 {
		return ErrConflict
	}
	now := p.mutationTime(audit)
	event := PolicyEvent{
		ID: uuid.NewString(), EventKind: "REVOKE", PolicyID: current.ID,
		PlatformID: current.PlatformID, PlatformName: current.PlatformName,
		Old: SnapshotPolicy(current), OccurredAt: now, RequestID: audit.RequestID,
		RemoteAddress: audit.RemoteAddress, CredentialClass: audit.CredentialClass,
	}
	next, err := p.snapshotWithoutPlatform(platformID)
	if err != nil {
		return err
	}
	if err := p.store.DeleteTLSPolicy(platformID, expectedVersion, event); err != nil {
		return err
	}
	p.publish(next)
	return nil
}

// DeletePlatform appends terminal TLS history and removes the active policy and
// platform in one transaction. The next executable snapshot is fully compiled
// before commit; publication after commit is an infallible pointer swap.
func (p *PolicyService) DeletePlatform(platformID string, audit AuditContext) error {
	return p.DeletePlatformWithPublication(platformID, audit, nil)
}

// DeletePlatformWithPublication lets the caller publish the runtime Platform
// removal and TLS snapshot under one shared publication boundary.
func (p *PolicyService) DeletePlatformWithPublication(
	platformID string,
	audit AuditContext,
	publish func(publishTLS func()),
) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	next, err := p.snapshotWithoutPlatform(platformID)
	if err != nil {
		return err
	}
	if err := p.store.DeletePlatformWithTLSHistory(platformID, audit); err != nil {
		return err
	}
	publishTLS := func() { p.publish(next) }
	if publish != nil {
		publish(publishTLS)
	} else {
		publishTLS()
	}
	return nil
}

// ApplyConfiguration prepares the desired platform policy, lets the caller
// persist it as part of a larger transaction, and publishes the precompiled
// snapshot only after that transaction succeeds. A nil desired mutation keeps
// the current policy. VERIFY removes an active policy.
func (p *PolicyService) ApplyConfiguration(
	platformID string,
	platformName string,
	desired *Mutation,
	expectedVersion int64,
	audit AuditContext,
	persist func(ConfigurationMutation) error,
	publish func(publishTLS func()),
) (PolicyRecord, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if persist == nil {
		return PolicyRecord{}, fmt.Errorf("configuration persistence callback is required")
	}

	var current *PolicyRecord
	stored, err := p.store.GetTLSPolicy(platformID)
	switch {
	case err == nil:
		current = &stored
	case err == ErrNotFound:
	case err != nil:
		return PolicyRecord{}, wrapConfigurationPersistenceError(err)
	}

	plan := ConfigurationMutation{ExpectedVersion: expectedVersion, Current: current}
	publishNoTLSChange := func() {
		if publish != nil {
			publish(func() {})
		}
	}
	response := PolicyRecord{PlatformID: platformID, PlatformName: platformName, Mode: ModeVerify}
	if current != nil {
		response = *current
		response.PlatformName = platformName
	}
	if desired == nil {
		if err := wrapConfigurationPersistenceError(persist(plan)); err != nil {
			return PolicyRecord{}, err
		}
		publishNoTLSChange()
		return response, nil
	}

	currentVersion := int64(0)
	if current != nil {
		currentVersion = current.Version
	}
	if expectedVersion != currentVersion || expectedVersion < 0 {
		return PolicyRecord{}, ErrConflict
	}
	if platformID == platform.DefaultPlatformID && desired.Mode != ModeVerify {
		return PolicyRecord{}, ErrDefaultPlatform
	}

	now := p.mutationTime(audit)
	var nextSnapshot *Snapshot
	switch desired.Mode {
	case ModeVerify:
		if desired.BundleID != "" || desired.Reason != nil || desired.ExpirySet {
			return PolicyRecord{}, fmt.Errorf("VERIFY prohibits bundle_id, reason, and expires_at")
		}
		if current == nil {
			if err := wrapConfigurationPersistenceError(persist(plan)); err != nil {
				return PolicyRecord{}, err
			}
			publishNoTLSChange()
			return response, nil
		}
		event := PolicyEvent{
			ID: uuid.NewString(), EventKind: "REVOKE", PolicyID: current.ID,
			PlatformID: current.PlatformID, PlatformName: platformName,
			Old: SnapshotPolicy(*current), OccurredAt: now, RequestID: audit.RequestID,
			RemoteAddress: audit.RemoteAddress, CredentialClass: audit.CredentialClass,
		}
		plan.Event = &event
		nextSnapshot, err = p.snapshotWithoutPlatform(platformID)
		response = PolicyRecord{PlatformID: platformID, PlatformName: platformName, Mode: ModeVerify}
	case ModeTrustCustomCA, ModeBypass:
		built, buildErr := p.buildPolicy(platformID, platformName, *desired, current, now)
		if buildErr != nil {
			return PolicyRecord{}, buildErr
		}
		if current != nil && samePolicyConfiguration(*current, built) {
			if err := wrapConfigurationPersistenceError(persist(plan)); err != nil {
				return PolicyRecord{}, err
			}
			publishNoTLSChange()
			return response, nil
		}
		event := PolicyEvent{
			ID: uuid.NewString(), PolicyID: built.ID, PlatformID: platformID, PlatformName: platformName,
			New: SnapshotPolicy(built), OccurredAt: now, RequestID: audit.RequestID,
			RemoteAddress: audit.RemoteAddress, CredentialClass: audit.CredentialClass,
		}
		if current == nil {
			event.EventKind = eventKindForCreate(built)
		} else {
			event.EventKind = eventKindForReplacement(*current, built)
			event.Old = SnapshotPolicy(*current)
		}
		plan.Next, plan.Event = &built, &event
		nextSnapshot, err = p.snapshotWithPolicy(built)
		response = built
	default:
		return PolicyRecord{}, fmt.Errorf("mode must be VERIFY, TRUST_CUSTOM_CA, or BYPASS")
	}
	if err != nil {
		return PolicyRecord{}, err
	}
	if err := wrapConfigurationPersistenceError(persist(plan)); err != nil {
		return PolicyRecord{}, err
	}
	publishTLS := func() {
		if plan.ChangesPolicy() {
			p.publish(nextSnapshot)
		}
	}
	if publish != nil {
		publish(publishTLS)
	} else {
		publishTLS()
	}
	return response, nil
}

func (p *PolicyService) Get(platformID string) (PolicyRecord, error) {
	return p.store.GetTLSPolicy(platformID)
}

func (p *PolicyService) History(platformID string) ([]PolicyEvent, error) {
	return p.store.ListTLSPolicyHistory(platformID)
}

type Mutation struct {
	Mode      Mode
	BundleID  string
	Reason    *string
	ExpirySet bool
	ExpiresAt *time.Time
}

func (p *PolicyService) buildPolicy(platformID, platformName string, mutation Mutation, current *PolicyRecord, now time.Time) (PolicyRecord, error) {
	if platformID == "" || platformName == "" {
		return PolicyRecord{}, fmt.Errorf("platform is required")
	}
	if platformID == platform.DefaultPlatformID {
		return PolicyRecord{}, ErrDefaultPlatform
	}
	policy := PolicyRecord{ID: uuid.NewString(), PlatformID: platformID, PlatformName: platformName, Version: 1, CreatedAt: now, UpdatedAt: now}
	if current != nil {
		policy = *current
		policy.Version = current.Version + 1
		policy.UpdatedAt = now
	}
	switch mutation.Mode {
	case ModeTrustCustomCA:
		if mutation.BundleID == "" || mutation.Reason != nil || mutation.ExpirySet {
			return PolicyRecord{}, fmt.Errorf("TRUST_CUSTOM_CA requires only bundle_id")
		}
		if p.registry == nil {
			return PolicyRecord{}, fmt.Errorf("%w: custom CA registry unavailable", ErrIntegrity)
		}
		bundle, err := p.registry.Get(mutation.BundleID)
		if err != nil {
			return PolicyRecord{}, err
		}
		policy.Mode, policy.BundleID, policy.BundleFingerprint = ModeTrustCustomCA, bundle.ID, bundle.Fingerprint
		policy.Reason, policy.ExpiresAt = "", nil
	case ModeBypass:
		if mutation.BundleID != "" {
			return PolicyRecord{}, fmt.Errorf("BYPASS prohibits bundle_id")
		}
		if (current == nil || current.Mode != ModeBypass) && !mutation.ExpirySet {
			return PolicyRecord{}, fmt.Errorf("BYPASS expiry must be explicitly present on create")
		}
		if current != nil && current.Mode == ModeBypass && !mutation.ExpirySet {
			mutation.ExpiresAt = cloneTime(current.ExpiresAt)
		}
		if mutation.ExpirySet && mutation.ExpiresAt != nil && !mutation.ExpiresAt.After(now) {
			return PolicyRecord{}, fmt.Errorf("BYPASS expiry must be in the future")
		}
		if mutation.ExpiresAt != nil {
			v := mutation.ExpiresAt.UTC()
			mutation.ExpiresAt = &v
		}
		reason := ""
		if mutation.Reason != nil {
			reason = stringsTrim(*mutation.Reason)
		} else if current != nil {
			reason = stringsTrim(current.Reason)
		}
		needsNewReason := current == nil || current.Mode != ModeBypass || (current.ExpiresAt != nil && mutation.ExpirySet && mutation.ExpiresAt == nil) || (current.ExpiresAt != nil && mutation.ExpirySet && mutation.ExpiresAt != nil && mutation.ExpiresAt.After(*current.ExpiresAt))
		if needsNewReason && mutation.Reason == nil {
			return PolicyRecord{}, fmt.Errorf("BYPASS reason is required for this change")
		}
		if reason == "" {
			return PolicyRecord{}, fmt.Errorf("BYPASS reason must be non-empty")
		}
		policy.Mode, policy.BundleID, policy.BundleFingerprint = ModeBypass, "", ""
		policy.Reason, policy.ExpiresAt = reason, cloneTime(mutation.ExpiresAt)
	default:
		return PolicyRecord{}, fmt.Errorf("mode must be TRUST_CUSTOM_CA or BYPASS")
	}
	if err := ValidatePolicy(policy); err != nil {
		return PolicyRecord{}, err
	}
	return policy, nil
}

func samePolicyConfiguration(a, b PolicyRecord) bool {
	if a.Mode != b.Mode || a.BundleID != b.BundleID || a.BundleFingerprint != b.BundleFingerprint || a.Reason != b.Reason {
		return false
	}
	if a.ExpiresAt == nil || b.ExpiresAt == nil {
		return a.ExpiresAt == nil && b.ExpiresAt == nil
	}
	return a.ExpiresAt.Equal(*b.ExpiresAt)
}

func (p *PolicyService) findPolicy(platformID string) *PolicyRecord {
	compiled, ok := p.Snapshot().policies[platformID]
	if !ok {
		return nil
	}
	policy := compiled.Record
	return &policy
}

func (p *PolicyService) snapshotWithPolicy(policy PolicyRecord) (*Snapshot, error) {
	rows := p.Snapshot().clonePolicies()
	replaced := false
	for i := range rows {
		if rows[i].PlatformID == policy.PlatformID {
			rows[i] = policy
			replaced = true
			break
		}
	}
	if !replaced {
		rows = append(rows, policy)
	}
	return p.compile(rows)
}

func (p *PolicyService) snapshotWithoutPlatform(platformID string) (*Snapshot, error) {
	rows := p.Snapshot().clonePolicies()
	filtered := rows[:0]
	for _, row := range rows {
		if row.PlatformID != platformID {
			filtered = append(filtered, row)
		}
	}
	return p.compile(filtered)
}

func (p *PolicyService) mutationTime(audit AuditContext) time.Time {
	if audit.OccurredAt.IsZero() {
		return p.now().UTC()
	}
	return audit.OccurredAt.UTC()
}

func eventKindForCreate(rule PolicyRecord) string {
	if rule.Mode == ModeBypass {
		return "BYPASS_CREATE"
	}
	return "CREATE"
}

func eventKindForReplacement(old, next PolicyRecord) string {
	if old.Mode != next.Mode {
		return "MODE_REPLACE"
	}
	if old.Mode == ModeTrustCustomCA && old.BundleID != next.BundleID {
		return "CA_ROTATION"
	}
	if old.Mode == ModeBypass && old.ExpiresAt != nil && next.ExpiresAt != nil && next.ExpiresAt.After(*old.ExpiresAt) {
		return "BYPASS_RENEWAL"
	}
	if old.Mode == ModeBypass && old.ExpiresAt != nil && next.ExpiresAt == nil {
		return "BYPASS_PERMANENT_CONVERSION"
	}
	return "REPLACE"
}

func stringsTrim(v string) string {
	return string(bytes.TrimSpace([]byte(v)))
}
