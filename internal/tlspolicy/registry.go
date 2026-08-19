package tlspolicy

import (
	"bytes"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type CABundleStore interface {
	CreateOrGetCABundle(record CABundleRecord, event CABundleEvent) (CABundleRecord, bool, error)
	GetCABundle(id string) (CABundleRecord, error)
	ListCABundles() ([]CABundleRecord, error)
	CountCABundleReferences(id string) (int, error)
	DeleteCABundle(id string, event CABundleEvent) error
	ListCABundleHistory(bundleID string) ([]CABundleEvent, error)
}

type CABundleRegistry struct {
	store CABundleStore
	now   func() time.Time
}

func NewCABundleRegistry(store CABundleStore, now func() time.Time) *CABundleRegistry {
	if now == nil {
		now = time.Now
	}
	return &CABundleRegistry{store: store, now: now}
}

func (r *CABundleRegistry) Import(input []byte, audit AuditContext) (CABundleRef, bool, error) {
	canonical, err := CanonicalizeBundle(input)
	if err != nil {
		return CABundleRef{}, false, err
	}
	now := audit.OccurredAt.UTC()
	if now.IsZero() {
		now = r.now().UTC()
	}
	id := uuid.NewString()
	record := CABundleRecord{
		Ref: CABundleRef{
			ID:                      id,
			FingerprintAlgorithm:    FingerprintAlgorithmSHA256,
			Fingerprint:             canonical.Fingerprint,
			CanonicalizationVersion: CanonicalizationVersion,
			CertificateCount:        canonical.CertificateCount,
			Certificates:            cloneCertificateMetadata(canonical.Certificates),
			CreatedAt:               now,
		},
		CanonicalPEM: canonical.CanonicalPEM,
	}
	event := CABundleEvent{
		ID:                      uuid.NewString(),
		BundleID:                id,
		EventKind:               "CREATE",
		FingerprintAlgorithm:    FingerprintAlgorithmSHA256,
		Fingerprint:             canonical.Fingerprint,
		CanonicalizationVersion: CanonicalizationVersion,
		CertificateCount:        canonical.CertificateCount,
		Certificates:            cloneCertificateMetadata(canonical.Certificates),
		OccurredAt:              now,
		RequestID:               audit.RequestID,
		RemoteAddress:           audit.RemoteAddress,
		CredentialClass:         audit.CredentialClass,
	}
	stored, created, err := r.store.CreateOrGetCABundle(record, event)
	if err != nil {
		return CABundleRef{}, false, err
	}
	if !bytes.Equal(stored.CanonicalPEM, record.CanonicalPEM) {
		return CABundleRef{}, false, ErrFingerprintCollision
	}
	stored.Ref.Certificates = cloneCertificateMetadata(canonical.Certificates)
	return stored.Ref, created, nil
}

func (r *CABundleRegistry) Verified(id string) (VerifiedCABundle, error) {
	record, err := r.store.GetCABundle(id)
	if err != nil {
		return VerifiedCABundle{}, err
	}
	canonical, err := CanonicalizeBundle(record.CanonicalPEM)
	if err != nil {
		return VerifiedCABundle{}, fmt.Errorf("%w: bundle %s: %v", ErrIntegrity, id, err)
	}
	if record.Ref.FingerprintAlgorithm != FingerprintAlgorithmSHA256 ||
		record.Ref.CanonicalizationVersion != CanonicalizationVersion ||
		record.Ref.CertificateCount != canonical.CertificateCount ||
		record.Ref.Fingerprint != canonical.Fingerprint ||
		!bytes.Equal(record.CanonicalPEM, canonical.CanonicalPEM) {
		return VerifiedCABundle{}, fmt.Errorf("%w: bundle %s metadata or content mismatch", ErrIntegrity, id)
	}
	record.Ref.Certificates = cloneCertificateMetadata(canonical.Certificates)
	return VerifiedCABundle{Ref: record.Ref, CanonicalPEM: bytes.Clone(record.CanonicalPEM)}, nil
}

func cloneCertificateMetadata(in []CertificateMetadata) []CertificateMetadata {
	return append([]CertificateMetadata(nil), in...)
}

func (r *CABundleRegistry) Get(id string) (CABundleRef, error) {
	bundle, err := r.Verified(id)
	if err != nil {
		return CABundleRef{}, err
	}
	return bundle.Ref, nil
}

func (r *CABundleRegistry) List() ([]CABundleRef, error) {
	records, err := r.store.ListCABundles()
	if err != nil {
		return nil, err
	}
	refs := make([]CABundleRef, 0, len(records))
	for _, record := range records {
		bundle, err := r.Verified(record.Ref.ID)
		if err != nil {
			return nil, err
		}
		refs = append(refs, bundle.Ref)
	}
	return refs, nil
}

func (r *CABundleRegistry) ReferenceCount(id string) (int, error) {
	if _, err := r.Verified(id); err != nil {
		return 0, err
	}
	return r.store.CountCABundleReferences(id)
}

func (r *CABundleRegistry) DeleteIfUnused(id string, audit AuditContext) error {
	bundle, err := r.Verified(id)
	if err != nil {
		return err
	}
	now := audit.OccurredAt.UTC()
	if now.IsZero() {
		now = r.now().UTC()
	}
	event := CABundleEvent{
		ID:                      uuid.NewString(),
		BundleID:                bundle.Ref.ID,
		EventKind:               "DELETE",
		FingerprintAlgorithm:    bundle.Ref.FingerprintAlgorithm,
		Fingerprint:             bundle.Ref.Fingerprint,
		CanonicalizationVersion: bundle.Ref.CanonicalizationVersion,
		CertificateCount:        bundle.Ref.CertificateCount,
		Certificates:            cloneCertificateMetadata(bundle.Ref.Certificates),
		OccurredAt:              now,
		RequestID:               audit.RequestID,
		RemoteAddress:           audit.RemoteAddress,
		CredentialClass:         audit.CredentialClass,
	}
	return r.store.DeleteCABundle(id, event)
}

func (r *CABundleRegistry) History(id string) ([]CABundleEvent, error) {
	return r.store.ListCABundleHistory(id)
}
