package state

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Resinat/Resin/internal/platform"
	"github.com/Resinat/Resin/internal/tlspolicy"
	"github.com/google/uuid"
)

func toNs(v time.Time) int64 {
	if v.IsZero() {
		return 0
	}
	return v.UTC().UnixNano()
}

func fromNs(ns sql.NullInt64) *time.Time {
	if !ns.Valid {
		return nil
	}
	v := time.Unix(0, ns.Int64).UTC()
	return &v
}

func encodeCABundleCertificates(certificates []tlspolicy.CertificateMetadata) (string, error) {
	if certificates == nil {
		certificates = []tlspolicy.CertificateMetadata{}
	}
	data, err := json.Marshal(certificates)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func decodeCABundleCertificates(raw string) ([]tlspolicy.CertificateMetadata, error) {
	if raw == "" {
		return []tlspolicy.CertificateMetadata{}, nil
	}
	var certificates []tlspolicy.CertificateMetadata
	if err := json.Unmarshal([]byte(raw), &certificates); err != nil {
		return nil, err
	}
	if certificates == nil {
		certificates = []tlspolicy.CertificateMetadata{}
	}
	return certificates, nil
}

func validateCustomCABundleReferenceTx(tx *sql.Tx, policy tlspolicy.PolicyRecord) error {
	if policy.Mode != tlspolicy.ModeTrustCustomCA {
		return nil
	}
	var fingerprint string
	if err := tx.QueryRow(`SELECT fingerprint FROM ca_bundles WHERE id = ?`, policy.BundleID).Scan(&fingerprint); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return tlspolicy.ErrNotFound
		}
		return err
	}
	if fingerprint != policy.BundleFingerprint {
		return fmt.Errorf("%w: CA bundle fingerprint mismatch", tlspolicy.ErrIntegrity)
	}
	return nil
}

func (r *StateRepo) CreateOrGetCABundle(record tlspolicy.CABundleRecord, event tlspolicy.CABundleEvent) (tlspolicy.CABundleRecord, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	tx, err := r.db.Begin()
	if err != nil {
		return tlspolicy.CABundleRecord{}, false, err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO ca_bundles (id, fingerprint_algorithm, canonicalization_version, fingerprint, canonical_pem, certificate_count, created_at_ns) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		record.Ref.ID, record.Ref.FingerprintAlgorithm, record.Ref.CanonicalizationVersion, record.Ref.Fingerprint, record.CanonicalPEM, record.Ref.CertificateCount, toNs(record.Ref.CreatedAt))
	if err == nil {
		event.BundleID = record.Ref.ID
		if err = insertCABundleEvent(tx, event); err != nil {
			return tlspolicy.CABundleRecord{}, false, err
		}
		if err = tx.Commit(); err != nil {
			return tlspolicy.CABundleRecord{}, false, err
		}
		return record, true, nil
	}
	var stored tlspolicy.CABundleRecord
	var createdNs int64
	err = tx.QueryRow(`SELECT id, fingerprint_algorithm, canonicalization_version, fingerprint, canonical_pem, certificate_count, created_at_ns FROM ca_bundles WHERE fingerprint = ?`, record.Ref.Fingerprint).Scan(
		&stored.Ref.ID, &stored.Ref.FingerprintAlgorithm, &stored.Ref.CanonicalizationVersion, &stored.Ref.Fingerprint, &stored.CanonicalPEM, &stored.Ref.CertificateCount, &createdNs)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return tlspolicy.CABundleRecord{}, false, fmt.Errorf("insert CA bundle: %w", err)
		}
		return tlspolicy.CABundleRecord{}, false, err
	}
	stored.Ref.CreatedAt = time.Unix(0, createdNs).UTC()
	if !bytes.Equal(stored.CanonicalPEM, record.CanonicalPEM) {
		return tlspolicy.CABundleRecord{}, false, tlspolicy.ErrFingerprintCollision
	}
	event.BundleID = stored.Ref.ID
	event.EventKind = "REUSE"
	event.FingerprintAlgorithm = stored.Ref.FingerprintAlgorithm
	event.Fingerprint = stored.Ref.Fingerprint
	event.CanonicalizationVersion = stored.Ref.CanonicalizationVersion
	event.CertificateCount = stored.Ref.CertificateCount
	if err := insertCABundleEvent(tx, event); err != nil {
		return tlspolicy.CABundleRecord{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return tlspolicy.CABundleRecord{}, false, err
	}
	return stored, false, nil
}

func (r *StateRepo) GetCABundle(id string) (tlspolicy.CABundleRecord, error) {
	row := r.db.QueryRow(`SELECT id, fingerprint_algorithm, canonicalization_version, fingerprint, canonical_pem, certificate_count, created_at_ns FROM ca_bundles WHERE id = ?`, id)
	var out tlspolicy.CABundleRecord
	var createdNs int64
	if err := row.Scan(&out.Ref.ID, &out.Ref.FingerprintAlgorithm, &out.Ref.CanonicalizationVersion, &out.Ref.Fingerprint, &out.CanonicalPEM, &out.Ref.CertificateCount, &createdNs); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return tlspolicy.CABundleRecord{}, tlspolicy.ErrNotFound
		}
		return tlspolicy.CABundleRecord{}, err
	}
	out.Ref.CreatedAt = time.Unix(0, createdNs).UTC()
	return out, nil
}

func (r *StateRepo) ListCABundles() ([]tlspolicy.CABundleRecord, error) {
	rows, err := r.db.Query(`SELECT id, fingerprint_algorithm, canonicalization_version, fingerprint, canonical_pem, certificate_count, created_at_ns FROM ca_bundles ORDER BY created_at_ns, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tlspolicy.CABundleRecord
	for rows.Next() {
		var record tlspolicy.CABundleRecord
		var createdNs int64
		if err := rows.Scan(&record.Ref.ID, &record.Ref.FingerprintAlgorithm, &record.Ref.CanonicalizationVersion, &record.Ref.Fingerprint, &record.CanonicalPEM, &record.Ref.CertificateCount, &createdNs); err != nil {
			return nil, err
		}
		record.Ref.CreatedAt = time.Unix(0, createdNs).UTC()
		out = append(out, record)
	}
	return out, rows.Err()
}

func (r *StateRepo) CountCABundleReferences(id string) (int, error) {
	var count int
	err := r.db.QueryRow(`SELECT COUNT(*) FROM platform_tls_policies WHERE bundle_id = ?`, id).Scan(&count)
	return count, err
}

func (r *StateRepo) DeleteCABundle(id string, event tlspolicy.CABundleEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var refs int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM platform_tls_policies WHERE bundle_id = ?`, id).Scan(&refs); err != nil {
		return err
	}
	if refs > 0 {
		return tlspolicy.ErrBundleInUse
	}
	result, err := tx.Exec(`DELETE FROM ca_bundles WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return tlspolicy.ErrNotFound
	}
	event.BundleID = id
	if err := insertCABundleEvent(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *StateRepo) ListCABundleHistory(bundleID string) ([]tlspolicy.CABundleEvent, error) {
	rows, err := r.db.Query(`SELECT id, bundle_id, event_kind, fingerprint_algorithm, fingerprint, canonicalization_version, certificate_count, certificates_json, occurred_at_ns, request_id, remote_address, credential_class FROM ca_bundle_history WHERE (? = '' OR bundle_id = ?) ORDER BY occurred_at_ns, id`, bundleID, bundleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tlspolicy.CABundleEvent
	for rows.Next() {
		var event tlspolicy.CABundleEvent
		var occurredNs int64
		var certificatesJSON string
		if err := rows.Scan(&event.ID, &event.BundleID, &event.EventKind, &event.FingerprintAlgorithm, &event.Fingerprint, &event.CanonicalizationVersion, &event.CertificateCount, &certificatesJSON, &occurredNs, &event.RequestID, &event.RemoteAddress, &event.CredentialClass); err != nil {
			return nil, err
		}
		certificates, err := decodeCABundleCertificates(certificatesJSON)
		if err != nil {
			return nil, fmt.Errorf("decode CA bundle history certificates: %w", err)
		}
		event.Certificates = certificates
		event.OccurredAt = time.Unix(0, occurredNs).UTC()
		out = append(out, event)
	}
	return out, rows.Err()
}

func insertCABundleEvent(tx *sql.Tx, event tlspolicy.CABundleEvent) error {
	if event.ID == "" {
		event.ID = uuid.NewString()
	}
	certificatesJSON, err := encodeCABundleCertificates(event.Certificates)
	if err != nil {
		return fmt.Errorf("encode CA bundle history certificates: %w", err)
	}
	_, err = tx.Exec(`INSERT INTO ca_bundle_history (id, bundle_id, event_kind, fingerprint_algorithm, fingerprint, canonicalization_version, certificate_count, certificates_json, occurred_at_ns, request_id, remote_address, credential_class) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.BundleID, event.EventKind, event.FingerprintAlgorithm, event.Fingerprint, event.CanonicalizationVersion, event.CertificateCount, certificatesJSON, toNs(event.OccurredAt), event.RequestID, event.RemoteAddress, event.CredentialClass)
	return err
}

func (r *StateRepo) ListTLSPolicies() ([]tlspolicy.PolicyRecord, error) {
	// The active row keeps the platform name captured when the policy was last
	// changed, but current API/runtime reads use the platform table as truth so a
	// platform rename cannot leak a stale name into a later history event.
	rows, err := r.db.Query(`SELECT r.id, r.platform_id, p.name, r.mode, COALESCE(r.bundle_id, ''), r.bundle_fingerprint, r.bypass_reason, r.expires_at_ns, r.version, r.created_at_ns, r.updated_at_ns FROM platform_tls_policies r JOIN platforms p ON p.id = r.platform_id ORDER BY r.platform_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tlspolicy.PolicyRecord
	for rows.Next() {
		var policy tlspolicy.PolicyRecord
		var expiresNs sql.NullInt64
		var createdNs, updatedNs int64
		if err := rows.Scan(&policy.ID, &policy.PlatformID, &policy.PlatformName, &policy.Mode, &policy.BundleID, &policy.BundleFingerprint, &policy.Reason, &expiresNs, &policy.Version, &createdNs, &updatedNs); err != nil {
			return nil, err
		}
		policy.ExpiresAt = fromNs(expiresNs)
		policy.CreatedAt = time.Unix(0, createdNs).UTC()
		policy.UpdatedAt = time.Unix(0, updatedNs).UTC()
		out = append(out, policy)
	}
	return out, rows.Err()
}

func (r *StateRepo) GetTLSPolicy(platformID string) (tlspolicy.PolicyRecord, error) {
	row := r.db.QueryRow(`SELECT r.id, r.platform_id, p.name, r.mode, COALESCE(r.bundle_id, ''), r.bundle_fingerprint, r.bypass_reason, r.expires_at_ns, r.version, r.created_at_ns, r.updated_at_ns FROM platform_tls_policies r JOIN platforms p ON p.id = r.platform_id WHERE r.platform_id = ?`, platformID)
	var policy tlspolicy.PolicyRecord
	var expiresNs sql.NullInt64
	var createdNs, updatedNs int64
	if err := row.Scan(&policy.ID, &policy.PlatformID, &policy.PlatformName, &policy.Mode, &policy.BundleID, &policy.BundleFingerprint, &policy.Reason, &expiresNs, &policy.Version, &createdNs, &updatedNs); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return tlspolicy.PolicyRecord{}, tlspolicy.ErrNotFound
		}
		return tlspolicy.PolicyRecord{}, err
	}
	policy.ExpiresAt = fromNs(expiresNs)
	policy.CreatedAt = time.Unix(0, createdNs).UTC()
	policy.UpdatedAt = time.Unix(0, updatedNs).UTC()
	return policy, nil
}

func (r *StateRepo) CreateTLSPolicy(policy tlspolicy.PolicyRecord, event tlspolicy.PolicyEvent) error {
	if err := tlspolicy.ValidatePolicy(policy); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := validateCustomCABundleReferenceTx(tx, policy); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO platform_tls_policies (id, platform_id, platform_name, mode, bundle_id, bundle_fingerprint, bypass_reason, expires_at_ns, version, created_at_ns, updated_at_ns) VALUES (?, ?, ?, ?, NULLIF(?, ''), ?, ?, ?, ?, ?, ?)`,
		policy.ID, policy.PlatformID, policy.PlatformName, policy.Mode, policy.BundleID, policy.BundleFingerprint, policy.Reason, nullableNs(policy.ExpiresAt), policy.Version, toNs(policy.CreatedAt), toNs(policy.UpdatedAt)); err != nil {
		if isSQLiteUniqueConstraint(err) {
			return tlspolicy.ErrConflict
		}
		return err
	}
	if err := insertPolicyEvent(tx, event); err != nil {
		return err
	}
	if err := bumpPlatformConfigVersionTx(tx, policy.PlatformID); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *StateRepo) ReplaceTLSPolicy(platformID string, expectedVersion int64, policy tlspolicy.PolicyRecord, event tlspolicy.PolicyEvent) error {
	if platformID == platform.DefaultPlatformID {
		return tlspolicy.ErrDefaultPlatform
	}
	if policy.PlatformID != platformID {
		return fmt.Errorf("%w: replacement platform identity mismatch", tlspolicy.ErrIntegrity)
	}
	if err := tlspolicy.ValidatePolicy(policy); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := validateCustomCABundleReferenceTx(tx, policy); err != nil {
		return err
	}
	result, err := tx.Exec(`UPDATE platform_tls_policies SET mode = ?, bundle_id = NULLIF(?, ''), bundle_fingerprint = ?, bypass_reason = ?, expires_at_ns = ?, version = ?, updated_at_ns = ? WHERE platform_id = ? AND version = ?`,
		policy.Mode, policy.BundleID, policy.BundleFingerprint, policy.Reason, nullableNs(policy.ExpiresAt), policy.Version, toNs(policy.UpdatedAt), platformID, expectedVersion)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return tlspolicy.ErrConflict
	}
	if err := insertPolicyEvent(tx, event); err != nil {
		return err
	}
	if err := bumpPlatformConfigVersionTx(tx, platformID); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *StateRepo) DeleteTLSPolicy(platformID string, expectedVersion int64, event tlspolicy.PolicyEvent) error {
	if platformID == platform.DefaultPlatformID {
		return tlspolicy.ErrDefaultPlatform
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`DELETE FROM platform_tls_policies WHERE platform_id = ? AND version = ?`, platformID, expectedVersion)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return tlspolicy.ErrConflict
	}
	if err := insertPolicyEvent(tx, event); err != nil {
		return err
	}
	if err := bumpPlatformConfigVersionTx(tx, platformID); err != nil {
		return err
	}
	return tx.Commit()
}

func bumpPlatformConfigVersionTx(tx *sql.Tx, platformID string) error {
	result, err := tx.Exec(`UPDATE platforms SET config_version = config_version + 1 WHERE id = ?`, platformID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return ErrNotFound
	}
	return nil
}

func (r *StateRepo) DeletePlatformWithTLSHistory(platformID string, audit tlspolicy.AuditContext) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var platformName string
	if err := tx.QueryRow(`SELECT name FROM platforms WHERE id = ?`, platformID).Scan(&platformName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	now := audit.OccurredAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rows, err := tx.Query(`SELECT id, platform_id, platform_name, mode, COALESCE(bundle_id, ''), bundle_fingerprint, bypass_reason, expires_at_ns, version, created_at_ns, updated_at_ns FROM platform_tls_policies WHERE platform_id = ?`, platformID)
	if err != nil {
		return err
	}
	var policies []tlspolicy.PolicyRecord
	for rows.Next() {
		var policy tlspolicy.PolicyRecord
		var expiresNs sql.NullInt64
		var createdNs, updatedNs int64
		if err := rows.Scan(&policy.ID, &policy.PlatformID, &policy.PlatformName, &policy.Mode, &policy.BundleID, &policy.BundleFingerprint, &policy.Reason, &expiresNs, &policy.Version, &createdNs, &updatedNs); err != nil {
			rows.Close()
			return err
		}
		policy.ExpiresAt = fromNs(expiresNs)
		policy.CreatedAt = time.Unix(0, createdNs).UTC()
		policy.UpdatedAt = time.Unix(0, updatedNs).UTC()
		policies = append(policies, policy)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, policy := range policies {
		if err := insertPolicyEvent(tx, tlspolicy.PolicyEvent{
			ID: uuid.NewString(), EventKind: "PLATFORM_DELETE_POLICY", PolicyID: policy.ID,
			PlatformID: platformID, PlatformName: platformName,
			Old: tlspolicy.SnapshotPolicy(policy), OccurredAt: now, RequestID: audit.RequestID,
			RemoteAddress: audit.RemoteAddress, CredentialClass: audit.CredentialClass,
		}); err != nil {
			return err
		}
	}
	if err := insertPolicyEvent(tx, tlspolicy.PolicyEvent{
		ID: uuid.NewString(), EventKind: "PLATFORM_DELETE", PlatformID: platformID,
		PlatformName: platformName, OccurredAt: now, RequestID: audit.RequestID,
		RemoteAddress: audit.RemoteAddress, CredentialClass: audit.CredentialClass,
	}); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM platform_tls_policies WHERE platform_id = ?`, platformID); err != nil {
		return err
	}
	result, err := tx.Exec(`DELETE FROM platforms WHERE id = ?`, platformID)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

func (r *StateRepo) ListTLSPolicyHistory(platformID string) ([]tlspolicy.PolicyEvent, error) {
	rows, err := r.db.Query(`SELECT id, event_kind, policy_id, platform_id, platform_name, old_version, new_version, old_mode, new_mode, old_bundle_id, new_bundle_id, old_bundle_fingerprint, new_bundle_fingerprint, old_bypass_reason, new_bypass_reason, old_expires_at_ns, new_expires_at_ns, occurred_at_ns, request_id, remote_address, credential_class FROM platform_tls_policy_history WHERE (? = '' OR platform_id = ?) ORDER BY occurred_at_ns, id`, platformID, platformID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []tlspolicy.PolicyEvent
	for rows.Next() {
		var event tlspolicy.PolicyEvent
		var oldVersion, newVersion sql.NullInt64
		var oldExpires, newExpires sql.NullInt64
		var occurredNs int64
		var oldMode, newMode, oldBundleID, newBundleID, oldFingerprint, newFingerprint, oldReason, newReason string
		if err := rows.Scan(&event.ID, &event.EventKind, &event.PolicyID, &event.PlatformID, &event.PlatformName, &oldVersion, &newVersion, &oldMode, &newMode, &oldBundleID, &newBundleID, &oldFingerprint, &newFingerprint, &oldReason, &newReason, &oldExpires, &newExpires, &occurredNs, &event.RequestID, &event.RemoteAddress, &event.CredentialClass); err != nil {
			return nil, err
		}
		if oldVersion.Valid {
			event.Old = &tlspolicy.PolicySnapshot{Version: oldVersion.Int64, Mode: tlspolicy.Mode(oldMode), BundleID: oldBundleID, BundleFingerprint: oldFingerprint, Reason: oldReason, ExpiresAt: fromNs(oldExpires)}
		}
		if newVersion.Valid {
			event.New = &tlspolicy.PolicySnapshot{Version: newVersion.Int64, Mode: tlspolicy.Mode(newMode), BundleID: newBundleID, BundleFingerprint: newFingerprint, Reason: newReason, ExpiresAt: fromNs(newExpires)}
		}
		event.OccurredAt = time.Unix(0, occurredNs).UTC()
		out = append(out, event)
	}
	return out, rows.Err()
}

func nullableNs(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().UnixNano()
}

func insertPolicyEvent(tx *sql.Tx, event tlspolicy.PolicyEvent) error {
	old := event.Old
	next := event.New
	var oldVersion, newVersion any
	if old != nil {
		oldVersion = old.Version
	}
	if next != nil {
		newVersion = next.Version
	}
	_, err := tx.Exec(`INSERT INTO platform_tls_policy_history (id, event_kind, policy_id, platform_id, platform_name, old_version, new_version, old_mode, new_mode, old_bundle_id, new_bundle_id, old_bundle_fingerprint, new_bundle_fingerprint, old_bypass_reason, new_bypass_reason, old_expires_at_ns, new_expires_at_ns, occurred_at_ns, request_id, remote_address, credential_class) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.EventKind, event.PolicyID, event.PlatformID, event.PlatformName,
		oldVersion, newVersion, modeValue(old), modeValue(next), bundleID(old), bundleID(next), fingerprint(old), fingerprint(next), reason(old), reason(next), expiry(old), expiry(next), toNs(event.OccurredAt), event.RequestID, event.RemoteAddress, event.CredentialClass)
	return err
}

func modeValue(s *tlspolicy.PolicySnapshot) string {
	if s == nil {
		return ""
	}
	return string(s.Mode)
}
func bundleID(s *tlspolicy.PolicySnapshot) string {
	if s == nil {
		return ""
	}
	return s.BundleID
}
func fingerprint(s *tlspolicy.PolicySnapshot) string {
	if s == nil {
		return ""
	}
	return s.BundleFingerprint
}
func reason(s *tlspolicy.PolicySnapshot) string {
	if s == nil {
		return ""
	}
	return s.Reason
}
func expiry(s *tlspolicy.PolicySnapshot) any {
	if s == nil || s.ExpiresAt == nil {
		return nil
	}
	return s.ExpiresAt.UTC().UnixNano()
}
