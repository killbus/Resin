package state

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Resinat/Resin/internal/model"
	"github.com/Resinat/Resin/internal/tlspolicy"
)

// PlatformConfigurationState is the strongly consistent persisted view used by
// the aggregate Platform configuration API.
type PlatformConfigurationState struct {
	Platform model.Platform
	Policy   *tlspolicy.PolicyRecord
}

func (r *StateRepo) GetPlatformConfiguration(platformID string) (PlatformConfigurationState, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	tx, err := r.db.Begin()
	if err != nil {
		return PlatformConfigurationState{}, err
	}
	defer tx.Rollback()

	platformRow, err := getPlatformTx(tx, platformID)
	if err != nil {
		return PlatformConfigurationState{}, err
	}
	policy, err := getTLSPolicyTx(tx, platformID)
	if err != nil && !errors.Is(err, tlspolicy.ErrNotFound) {
		return PlatformConfigurationState{}, err
	}
	state := PlatformConfigurationState{Platform: platformRow}
	if err == nil {
		state.Policy = &policy
	}
	if err := tx.Commit(); err != nil {
		return PlatformConfigurationState{}, err
	}
	return state, nil
}

// CreatePlatformConfiguration atomically inserts a new Platform and its
// optional initial TLS policy/history. The policy plan must be prepared by the
// TLS domain service for expected absence (version 0).
func (r *StateRepo) CreatePlatformConfiguration(
	platformRow model.Platform,
	policyMutation tlspolicy.ConfigurationMutation,
) error {
	platformRow, regexJSON, regionJSON, err := preparePlatformPersistence(platformRow)
	if err != nil {
		return err
	}
	if policyMutation.ExpectedVersion != 0 || policyMutation.Current != nil {
		return tlspolicy.ErrConflict
	}
	if policyMutation.Event == nil && policyMutation.Next != nil {
		return fmt.Errorf("%w: initial policy is missing history", tlspolicy.ErrIntegrity)
	}
	if policyMutation.Event != nil && policyMutation.Next == nil {
		return fmt.Errorf("%w: initial policy history is missing active state", tlspolicy.ErrIntegrity)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`INSERT INTO platforms (
		id, name, sticky_ttl_ns, regex_filters_json, region_filters_json,
		reverse_proxy_miss_action, reverse_proxy_empty_account_behavior,
		reverse_proxy_fixed_account_header, allocation_policy,
		passive_circuit_breaker_disabled, config_version, updated_at_ns
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`,
		platformRow.ID, platformRow.Name, platformRow.StickyTTLNs, regexJSON, regionJSON,
		platformRow.ReverseProxyMissAction, platformRow.ReverseProxyEmptyAccountBehavior,
		platformRow.ReverseProxyFixedAccountHeader, platformRow.AllocationPolicy,
		platformRow.PassiveCircuitBreakerDisabled, platformRow.UpdatedAtNs)
	if err != nil {
		if isSQLiteUniqueConstraint(err) {
			return fmt.Errorf("%w: platform name already exists", ErrConflict)
		}
		return err
	}

	if policyMutation.Event != nil {
		next := *policyMutation.Next
		if next.PlatformID != platformRow.ID || next.PlatformName != platformRow.Name || next.Version != 1 {
			return fmt.Errorf("%w: initial policy platform/version mismatch", tlspolicy.ErrIntegrity)
		}
		if err := tlspolicy.ValidatePolicy(next); err != nil {
			return err
		}
		if err := validateCustomCABundleReferenceTx(tx, next); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO platform_tls_policies (id, platform_id, platform_name, mode, bundle_id, bundle_fingerprint, bypass_reason, expires_at_ns, version, created_at_ns, updated_at_ns) VALUES (?, ?, ?, ?, NULLIF(?, ''), ?, ?, ?, ?, ?, ?)`,
			next.ID, next.PlatformID, next.PlatformName, next.Mode, next.BundleID, next.BundleFingerprint,
			next.Reason, nullableNs(next.ExpiresAt), next.Version, toNs(next.CreatedAt), toNs(next.UpdatedAt)); err != nil {
			if isSQLiteUniqueConstraint(err) {
				return tlspolicy.ErrConflict
			}
			return err
		}
		if err := insertPolicyEvent(tx, *policyMutation.Event); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// ApplyPlatformConfiguration atomically writes the complete Platform fields and
// an optional TLS policy change. The policy plan must have been prepared by the
// TLS domain service before this transaction begins.
func (r *StateRepo) ApplyPlatformConfiguration(
	platformRow model.Platform,
	expectedConfigVersion int64,
	policyMutation tlspolicy.ConfigurationMutation,
) (int64, error) {
	platformRow, regexJSON, regionJSON, err := preparePlatformPersistence(platformRow)
	if err != nil {
		return 0, err
	}
	if expectedConfigVersion <= 0 {
		return 0, ErrConflict
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	tx, err := r.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var currentConfigVersion int64
	if err := tx.QueryRow(`SELECT config_version FROM platforms WHERE id = ?`, platformRow.ID).Scan(&currentConfigVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	if currentConfigVersion != expectedConfigVersion {
		return 0, ErrConflict
	}

	var persistedPolicyVersion int64
	policyErr := tx.QueryRow(`SELECT version FROM platform_tls_policies WHERE platform_id = ?`, platformRow.ID).Scan(&persistedPolicyVersion)
	if policyErr != nil && !errors.Is(policyErr, sql.ErrNoRows) {
		return 0, policyErr
	}
	preparedCurrentVersion := int64(0)
	if policyMutation.Current != nil {
		if policyMutation.Current.PlatformID != platformRow.ID {
			return 0, fmt.Errorf("%w: prepared policy platform mismatch", tlspolicy.ErrIntegrity)
		}
		preparedCurrentVersion = policyMutation.Current.Version
	}
	if (errors.Is(policyErr, sql.ErrNoRows) && preparedCurrentVersion != 0) ||
		(policyErr == nil && persistedPolicyVersion != preparedCurrentVersion) {
		return 0, tlspolicy.ErrConflict
	}

	result, err := tx.Exec(`UPDATE platforms SET
		name = ?, sticky_ttl_ns = ?, regex_filters_json = ?, region_filters_json = ?,
		reverse_proxy_miss_action = ?, reverse_proxy_empty_account_behavior = ?,
		reverse_proxy_fixed_account_header = ?, allocation_policy = ?,
		passive_circuit_breaker_disabled = ?, config_version = config_version + 1,
		updated_at_ns = ?
		WHERE id = ? AND config_version = ?`,
		platformRow.Name, platformRow.StickyTTLNs, regexJSON, regionJSON,
		platformRow.ReverseProxyMissAction, platformRow.ReverseProxyEmptyAccountBehavior,
		platformRow.ReverseProxyFixedAccountHeader, platformRow.AllocationPolicy,
		platformRow.PassiveCircuitBreakerDisabled, platformRow.UpdatedAtNs,
		platformRow.ID, expectedConfigVersion)
	if err != nil {
		if isSQLiteUniqueConstraint(err) {
			return 0, fmt.Errorf("%w: platform name already exists", ErrConflict)
		}
		return 0, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return 0, ErrConflict
	}

	if policyMutation.Event != nil {
		if policyMutation.Next == nil {
			result, err = tx.Exec(`DELETE FROM platform_tls_policies WHERE platform_id = ? AND version = ?`, platformRow.ID, preparedCurrentVersion)
			if err != nil {
				return 0, err
			}
			if affected, _ := result.RowsAffected(); affected != 1 {
				return 0, tlspolicy.ErrConflict
			}
		} else {
			next := *policyMutation.Next
			if next.PlatformID != platformRow.ID {
				return 0, fmt.Errorf("%w: next policy platform mismatch", tlspolicy.ErrIntegrity)
			}
			if err := tlspolicy.ValidatePolicy(next); err != nil {
				return 0, err
			}
			if err := validateCustomCABundleReferenceTx(tx, next); err != nil {
				return 0, err
			}
			if policyMutation.Current == nil {
				_, err = tx.Exec(`INSERT INTO platform_tls_policies (id, platform_id, platform_name, mode, bundle_id, bundle_fingerprint, bypass_reason, expires_at_ns, version, created_at_ns, updated_at_ns) VALUES (?, ?, ?, ?, NULLIF(?, ''), ?, ?, ?, ?, ?, ?)`,
					next.ID, next.PlatformID, platformRow.Name, next.Mode, next.BundleID, next.BundleFingerprint,
					next.Reason, nullableNs(next.ExpiresAt), next.Version, toNs(next.CreatedAt), toNs(next.UpdatedAt))
			} else {
				result, err = tx.Exec(`UPDATE platform_tls_policies SET platform_name = ?, mode = ?, bundle_id = NULLIF(?, ''), bundle_fingerprint = ?, bypass_reason = ?, expires_at_ns = ?, version = ?, updated_at_ns = ? WHERE platform_id = ? AND version = ?`,
					platformRow.Name, next.Mode, next.BundleID, next.BundleFingerprint, next.Reason,
					nullableNs(next.ExpiresAt), next.Version, toNs(next.UpdatedAt), platformRow.ID, preparedCurrentVersion)
				if err == nil {
					if affected, _ := result.RowsAffected(); affected != 1 {
						return 0, tlspolicy.ErrConflict
					}
				}
			}
			if err != nil {
				if isSQLiteUniqueConstraint(err) {
					return 0, tlspolicy.ErrConflict
				}
				return 0, err
			}
		}
		if err := insertPolicyEvent(tx, *policyMutation.Event); err != nil {
			return 0, err
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return expectedConfigVersion + 1, nil
}

func getPlatformTx(tx *sql.Tx, platformID string) (model.Platform, error) {
	row := tx.QueryRow(`SELECT id, name, sticky_ttl_ns, regex_filters_json, region_filters_json,
		reverse_proxy_miss_action, reverse_proxy_empty_account_behavior,
		reverse_proxy_fixed_account_header, allocation_policy,
		passive_circuit_breaker_disabled, config_version, updated_at_ns
		FROM platforms WHERE id = ?`, platformID)
	var platformRow model.Platform
	var regexJSON, regionJSON string
	var passiveDisabled int
	if err := row.Scan(&platformRow.ID, &platformRow.Name, &platformRow.StickyTTLNs, &regexJSON, &regionJSON,
		&platformRow.ReverseProxyMissAction, &platformRow.ReverseProxyEmptyAccountBehavior,
		&platformRow.ReverseProxyFixedAccountHeader, &platformRow.AllocationPolicy,
		&passiveDisabled, &platformRow.ConfigVersion, &platformRow.UpdatedAtNs); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.Platform{}, ErrNotFound
		}
		return model.Platform{}, err
	}
	platformRow.PassiveCircuitBreakerDisabled = passiveDisabled != 0
	var err error
	platformRow.RegexFilters, err = decodeStringSliceJSON(regexJSON)
	if err != nil {
		return model.Platform{}, fmt.Errorf("decode platform %s regex_filters_json: %w", platformRow.ID, err)
	}
	platformRow.RegionFilters, err = decodeStringSliceJSON(regionJSON)
	if err != nil {
		return model.Platform{}, fmt.Errorf("decode platform %s region_filters_json: %w", platformRow.ID, err)
	}
	return platformRow, nil
}

func getTLSPolicyTx(tx *sql.Tx, platformID string) (tlspolicy.PolicyRecord, error) {
	row := tx.QueryRow(`SELECT r.id, r.platform_id, p.name, r.mode, COALESCE(r.bundle_id, ''), r.bundle_fingerprint, r.bypass_reason, r.expires_at_ns, r.version, r.created_at_ns, r.updated_at_ns FROM platform_tls_policies r JOIN platforms p ON p.id = r.platform_id WHERE r.platform_id = ?`, platformID)
	var policy tlspolicy.PolicyRecord
	var expiresNs sql.NullInt64
	var createdNs, updatedNs int64
	if err := row.Scan(&policy.ID, &policy.PlatformID, &policy.PlatformName, &policy.Mode, &policy.BundleID,
		&policy.BundleFingerprint, &policy.Reason, &expiresNs, &policy.Version, &createdNs, &updatedNs); err != nil {
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
