package tlspolicy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"
)

func testCertificatePEM(t *testing.T, commonName string, isCA bool) ([]byte, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), privateKey
}

func TestCanonicalizeBundleIsFormattingOrderAndDuplicateInsensitive(t *testing.T) {
	first, _ := testCertificatePEM(t, "first", true)
	second, _ := testCertificatePEM(t, "second", true)

	one, err := CanonicalizeBundle(append(append(bytes.Clone(first), second...), first...))
	if err != nil {
		t.Fatal(err)
	}
	two, err := CanonicalizeBundle(append(append([]byte("\n\t"), second...), first...))
	if err != nil {
		t.Fatal(err)
	}
	if one.Fingerprint != two.Fingerprint || !bytes.Equal(one.CanonicalPEM, two.CanonicalPEM) {
		t.Fatal("semantically identical certificate sets did not canonicalize identically")
	}
	if one.CertificateCount != 2 {
		t.Fatalf("certificate count = %d, want 2", one.CertificateCount)
	}
	if len(one.Certificates) != 2 || len(two.Certificates) != 2 ||
		one.Certificates[0] != two.Certificates[0] || one.Certificates[1] != two.Certificates[1] {
		t.Fatalf("certificate metadata is not deterministic: one=%+v two=%+v", one.Certificates, two.Certificates)
	}
}

func TestCanonicalizeBundleRejectsNonCABlocksAndUnconsumedInput(t *testing.T) {
	caPEM, key := testCertificatePEM(t, "ca", true)
	leafPEM, _ := testCertificatePEM(t, "leaf", false)
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(caPEM)
	withHeaders := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes, Headers: map[string]string{"Name": "value"}})

	tests := map[string][]byte{
		"empty":       nil,
		"private key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
		"unknown":     pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not a certificate")}),
		"headers":     withHeaders,
		"trailing":    append(bytes.Clone(caPEM), []byte("not pem")...),
		"non ca":      leafPEM,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := CanonicalizeBundle(input); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

type memoryCABundleStore struct {
	mu            sync.Mutex
	byID          map[string]CABundleRecord
	byFingerprint map[string]string
	history       []CABundleEvent
}

func newMemoryCABundleStore() *memoryCABundleStore {
	return &memoryCABundleStore{byID: map[string]CABundleRecord{}, byFingerprint: map[string]string{}}
}

func cloneBundleRecord(in CABundleRecord) CABundleRecord {
	in.CanonicalPEM = bytes.Clone(in.CanonicalPEM)
	in.Ref.Certificates = cloneCertificateMetadata(in.Ref.Certificates)
	return in
}

func (s *memoryCABundleStore) CreateOrGetCABundle(record CABundleRecord, event CABundleEvent) (CABundleRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.byFingerprint[record.Ref.Fingerprint]; ok {
		stored := cloneBundleRecord(s.byID[id])
		if !bytes.Equal(stored.CanonicalPEM, record.CanonicalPEM) {
			return CABundleRecord{}, false, ErrFingerprintCollision
		}
		event.BundleID = stored.Ref.ID
		event.EventKind = "REUSE"
		event.FingerprintAlgorithm = stored.Ref.FingerprintAlgorithm
		event.Fingerprint = stored.Ref.Fingerprint
		event.CanonicalizationVersion = stored.Ref.CanonicalizationVersion
		event.CertificateCount = stored.Ref.CertificateCount
		s.history = append(s.history, event)
		return stored, false, nil
	}
	s.byID[record.Ref.ID] = cloneBundleRecord(record)
	s.byFingerprint[record.Ref.Fingerprint] = record.Ref.ID
	s.history = append(s.history, event)
	return cloneBundleRecord(record), true, nil
}

func (s *memoryCABundleStore) GetCABundle(id string) (CABundleRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.byID[id]
	if !ok {
		return CABundleRecord{}, ErrNotFound
	}
	return cloneBundleRecord(record), nil
}

func (s *memoryCABundleStore) ListCABundles() ([]CABundleRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]CABundleRecord, 0, len(s.byID))
	for _, record := range s.byID {
		out = append(out, cloneBundleRecord(record))
	}
	return out, nil
}

func (s *memoryCABundleStore) CountCABundleReferences(string) (int, error) { return 0, nil }

func (s *memoryCABundleStore) DeleteCABundle(id string, event CABundleEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	delete(s.byID, id)
	delete(s.byFingerprint, record.Ref.Fingerprint)
	s.history = append(s.history, event)
	return nil
}

func (s *memoryCABundleStore) ListCABundleHistory(bundleID string) ([]CABundleEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]CABundleEvent, 0, len(s.history))
	for _, event := range s.history {
		if bundleID == "" || event.BundleID == bundleID {
			out = append(out, event)
		}
	}
	return out, nil
}

func TestCABundleRegistryConcurrentDedupAndIntegrity(t *testing.T) {
	store := newMemoryCABundleStore()
	registry := NewCABundleRegistry(store, time.Now)
	caPEM, _ := testCertificatePEM(t, "dedup", true)

	const workers = 8
	ids := make(chan string, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ref, _, err := registry.Import(caPEM, AuditContext{})
			if err != nil {
				errs <- err
				return
			}
			ids <- ref.ID
		}()
	}
	wg.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var expected string
	for id := range ids {
		if expected == "" {
			expected = id
		}
		if id != expected {
			t.Fatalf("dedup returned id %q, want %q", id, expected)
		}
	}
	history, err := registry.History(expected)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != workers {
		t.Fatalf("history length = %d, want one event per import attempt", len(history))
	}
	createCount, reuseCount := 0, 0
	for _, event := range history {
		switch event.EventKind {
		case "CREATE":
			createCount++
		case "REUSE":
			reuseCount++
		default:
			t.Fatalf("unexpected bundle event kind %q", event.EventKind)
		}
	}
	if createCount != 1 || reuseCount != workers-1 {
		t.Fatalf("history events = %+v, want one CREATE and %d REUSE", history, workers-1)
	}

	store.mu.Lock()
	damaged := store.byID[expected]
	damaged.CanonicalPEM = append(bytes.Clone(damaged.CanonicalPEM), []byte("garbage")...)
	store.byID[expected] = damaged
	store.mu.Unlock()
	if _, err := registry.Verified(expected); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("damaged bundle error = %v, want ErrIntegrity", err)
	}
}

func TestCABundleRegistryHistoryRetainsAuditAndCertificateMetadata(t *testing.T) {
	store := newMemoryCABundleStore()
	registry := NewCABundleRegistry(store, time.Now)
	caPEM, _ := testCertificatePEM(t, "audited CA", true)
	createAudit := AuditContext{RequestID: "create", RemoteAddress: "192.0.2.1:1234", CredentialClass: "SHARED_ADMIN_TOKEN"}

	bundle, created, err := registry.Import(caPEM, createAudit)
	if err != nil || !created {
		t.Fatalf("initial import created=%v err=%v", created, err)
	}
	reuseAudit := AuditContext{RequestID: "reuse", RemoteAddress: "192.0.2.2:1234", CredentialClass: "SHARED_ADMIN_TOKEN"}
	if reused, created, err := registry.Import(caPEM, reuseAudit); err != nil || created || reused.ID != bundle.ID {
		t.Fatalf("dedup import bundle=%+v created=%v err=%v", reused, created, err)
	}
	deleteAudit := AuditContext{RequestID: "delete", RemoteAddress: "192.0.2.3:1234", CredentialClass: "SHARED_ADMIN_TOKEN"}
	if err := registry.DeleteIfUnused(bundle.ID, deleteAudit); err != nil {
		t.Fatal(err)
	}

	history, err := registry.History(bundle.ID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(history)
	if err != nil {
		t.Fatal(err)
	}
	var events []map[string]any
	if err := json.Unmarshal(encoded, &events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("history = %s, want CREATE, REUSE, DELETE", encoded)
	}
	for i, want := range []struct {
		kind      string
		requestID string
	}{
		{kind: "CREATE", requestID: "create"},
		{kind: "REUSE", requestID: "reuse"},
		{kind: "DELETE", requestID: "delete"},
	} {
		if events[i]["event_kind"] != want.kind || events[i]["request_id"] != want.requestID ||
			events[i]["credential_class"] != "SHARED_ADMIN_TOKEN" {
			t.Fatalf("history event %d = %v", i, events[i])
		}
		certificates, ok := events[i]["certificates"].([]any)
		if !ok || len(certificates) != 1 {
			t.Fatalf("history event %d certificates = %#v", i, events[i]["certificates"])
		}
		certificate := certificates[0].(map[string]any)
		if certificate["subject"] == "" || certificate["serial"] == "" || certificate["not_after"] == nil {
			t.Fatalf("history event %d certificate metadata = %v", i, certificate)
		}
	}
	if bytes.Contains(encoded, []byte("BEGIN CERTIFICATE")) || bytes.Contains(encoded, []byte(`"pem"`)) {
		t.Fatalf("history exposed PEM: %s", encoded)
	}
}

func TestCABundleRegistryCollisionDoesNotRecordRejectedReuse(t *testing.T) {
	store := newMemoryCABundleStore()
	registry := NewCABundleRegistry(store, time.Now)
	caPEM, _ := testCertificatePEM(t, "collision", true)
	bundle, _, err := registry.Import(caPEM, AuditContext{RequestID: "create"})
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	damaged := store.byID[bundle.ID]
	damaged.CanonicalPEM = append(bytes.Clone(damaged.CanonicalPEM), '\n')
	store.byID[bundle.ID] = damaged
	store.mu.Unlock()
	if _, _, err := registry.Import(caPEM, AuditContext{RequestID: "rejected-reuse"}); !errors.Is(err, ErrFingerprintCollision) {
		t.Fatalf("collision import error = %v, want ErrFingerprintCollision", err)
	}
	history, err := registry.History(bundle.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || history[0].EventKind != "CREATE" {
		t.Fatalf("collision history = %+v, want only CREATE", history)
	}
}
