package service

import (
	"errors"
	"fmt"

	"github.com/Resinat/Resin/internal/platform"
	"github.com/Resinat/Resin/internal/state"
	"github.com/Resinat/Resin/internal/tlspolicy"
)

type CABundleResponse struct {
	tlspolicy.CABundleRef
	ReferenceCount int `json:"reference_count"`
}

func mapTLSPolicyError(action string, err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, tlspolicy.ErrNotFound), errors.Is(err, state.ErrNotFound):
		return notFound(action + ": not found")
	case errors.Is(err, tlspolicy.ErrConflict):
		return conflict(action + ": version conflict")
	case errors.Is(err, tlspolicy.ErrBundleInUse):
		return conflict(action + ": CA bundle is referenced by an active policy")
	case errors.Is(err, tlspolicy.ErrDefaultPlatform):
		return invalidArg(err.Error())
	case errors.Is(err, tlspolicy.ErrFingerprintCollision), errors.Is(err, tlspolicy.ErrIntegrity):
		return internal(action, err)
	default:
		return invalidArg(err.Error())
	}
}

func (s *ControlPlaneService) ImportCABundle(pem []byte, audit tlspolicy.AuditContext) (*CABundleResponse, bool, error) {
	if s.CABundles == nil {
		return nil, false, internal("CA bundle registry unavailable", nil)
	}
	ref, created, err := s.CABundles.Import(pem, audit)
	if err != nil {
		return nil, false, mapTLSPolicyError("import CA bundle", err)
	}
	return &CABundleResponse{CABundleRef: ref}, created, nil
}

func (s *ControlPlaneService) ListCABundles() ([]CABundleResponse, error) {
	if s.CABundles == nil {
		return nil, internal("CA bundle registry unavailable", nil)
	}
	refs, err := s.CABundles.List()
	if err != nil {
		return nil, mapTLSPolicyError("list CA bundles", err)
	}
	out := make([]CABundleResponse, 0, len(refs))
	for _, ref := range refs {
		count, err := s.CABundles.ReferenceCount(ref.ID)
		if err != nil {
			return nil, mapTLSPolicyError("read CA bundle references", err)
		}
		out = append(out, CABundleResponse{CABundleRef: ref, ReferenceCount: count})
	}
	return out, nil
}

func (s *ControlPlaneService) GetCABundle(id string) (*CABundleResponse, error) {
	if s.CABundles == nil {
		return nil, internal("CA bundle registry unavailable", nil)
	}
	ref, err := s.CABundles.Get(id)
	if err != nil {
		return nil, mapTLSPolicyError("get CA bundle", err)
	}
	count, err := s.CABundles.ReferenceCount(id)
	if err != nil {
		return nil, mapTLSPolicyError("read CA bundle references", err)
	}
	return &CABundleResponse{CABundleRef: ref, ReferenceCount: count}, nil
}

func (s *ControlPlaneService) DeleteCABundle(id string, audit tlspolicy.AuditContext) error {
	if s.CABundles == nil {
		return internal("CA bundle registry unavailable", nil)
	}
	return mapTLSPolicyError("delete CA bundle", s.CABundles.DeleteIfUnused(id, audit))
}

func (s *ControlPlaneService) CABundleHistory(id string) ([]tlspolicy.CABundleEvent, error) {
	if s.CABundles == nil {
		return nil, internal("CA bundle registry unavailable", nil)
	}
	events, err := s.CABundles.History(id)
	if err != nil {
		return nil, mapTLSPolicyError("list CA bundle history", err)
	}
	return events, nil
}

func (s *ControlPlaneService) GetTLSPolicy(platformID string) (*tlspolicy.PolicyRecord, error) {
	if s.TLSPolicy == nil {
		return nil, internal("TLS policy service unavailable", nil)
	}
	platformModel, err := s.getPlatformModel(platformID)
	if err != nil {
		return nil, err
	}
	policy, err := s.TLSPolicy.Get(platformID)
	if errors.Is(err, tlspolicy.ErrNotFound) {
		return &tlspolicy.PolicyRecord{
			PlatformID: platformModel.ID, PlatformName: platformModel.Name, Mode: tlspolicy.ModeVerify,
		}, nil
	}
	if err != nil {
		return nil, mapTLSPolicyError("get TLS policy", err)
	}
	return &policy, nil
}

func (s *ControlPlaneService) CreateTLSPolicy(platformID string, mutation tlspolicy.Mutation, audit tlspolicy.AuditContext) (*tlspolicy.PolicyRecord, error) {
	if s.TLSPolicy == nil {
		return nil, internal("TLS policy service unavailable", nil)
	}
	platformModel, err := s.getPlatformModel(platformID)
	if err != nil {
		return nil, err
	}
	if platformID == platform.DefaultPlatformID {
		return nil, invalidArg(tlspolicy.ErrDefaultPlatform.Error())
	}
	policy, createErr := s.TLSPolicy.Create(platformModel.ID, platformModel.Name, mutation, audit)
	if createErr != nil {
		return nil, mapTLSPolicyError("create TLS policy", createErr)
	}
	return &policy, nil
}

func (s *ControlPlaneService) ReplaceTLSPolicy(platformID string, expectedVersion int64, mutation tlspolicy.Mutation, audit tlspolicy.AuditContext) (*tlspolicy.PolicyRecord, error) {
	if s.TLSPolicy == nil {
		return nil, internal("TLS policy service unavailable", nil)
	}
	if _, err := s.getPlatformModel(platformID); err != nil {
		return nil, err
	}
	if platformID == platform.DefaultPlatformID {
		return nil, invalidArg(tlspolicy.ErrDefaultPlatform.Error())
	}
	policy, replaceErr := s.TLSPolicy.Replace(platformID, expectedVersion, mutation, audit)
	if replaceErr != nil {
		return nil, mapTLSPolicyError("replace TLS policy", replaceErr)
	}
	return &policy, nil
}

func (s *ControlPlaneService) DeleteTLSPolicy(platformID string, expectedVersion int64, audit tlspolicy.AuditContext) error {
	if s.TLSPolicy == nil {
		return internal("TLS policy service unavailable", nil)
	}
	if _, err := s.getPlatformModel(platformID); err != nil {
		return err
	}
	if platformID == platform.DefaultPlatformID {
		return invalidArg(tlspolicy.ErrDefaultPlatform.Error())
	}
	return mapTLSPolicyError("delete TLS policy", s.TLSPolicy.Delete(platformID, expectedVersion, audit))
}

func (s *ControlPlaneService) TLSPolicyHistory(platformID string) ([]tlspolicy.PolicyEvent, error) {
	if s.TLSPolicy == nil {
		return nil, internal("TLS policy service unavailable", nil)
	}
	events, err := s.TLSPolicy.History(platformID)
	if err != nil {
		return nil, mapTLSPolicyError("list TLS policy history", err)
	}
	return events, nil
}

func validateExpectedVersion(version int64) error {
	if version <= 0 {
		return invalidArg(fmt.Sprintf("expected version must be positive, got %d", version))
	}
	return nil
}
