package tlspolicy

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sort"
)

const (
	MaxBundlePEMBytes = 1 << 20
	MaxCertificates   = 64
	MaxCertificateDER = 256 << 10
)

var fingerprintDomain = []byte("resin.ca-bundle\x00v1\x00")

type CanonicalBundle struct {
	CanonicalPEM     []byte
	Fingerprint      string
	CertificateCount int
	Certificates     []CertificateMetadata
}

func CanonicalizeBundle(input []byte) (CanonicalBundle, error) {
	if len(input) == 0 {
		return CanonicalBundle{}, fmt.Errorf("CA bundle is empty")
	}
	if len(input) > MaxBundlePEMBytes {
		return CanonicalBundle{}, fmt.Errorf("CA bundle exceeds %d bytes", MaxBundlePEMBytes)
	}

	remaining := input
	unique := make(map[string][]byte)
	for {
		remaining = bytes.TrimSpace(remaining)
		if len(remaining) == 0 {
			break
		}
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return CanonicalBundle{}, fmt.Errorf("CA bundle contains non-certificate data")
		}
		block, rest := pem.Decode(remaining)
		if block == nil {
			return CanonicalBundle{}, fmt.Errorf("CA bundle contains malformed PEM")
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return CanonicalBundle{}, fmt.Errorf("CA bundle accepts only headerless CERTIFICATE blocks")
		}
		if len(block.Bytes) == 0 || len(block.Bytes) > MaxCertificateDER {
			return CanonicalBundle{}, fmt.Errorf("certificate size is invalid")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return CanonicalBundle{}, fmt.Errorf("parse CA certificate: %w", err)
		}
		if !cert.BasicConstraintsValid || !cert.IsCA || (cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0) {
			return CanonicalBundle{}, fmt.Errorf("certificate %q is not CA-capable", cert.Subject.String())
		}
		unique[string(block.Bytes)] = bytes.Clone(block.Bytes)
		if len(unique) > MaxCertificates {
			return CanonicalBundle{}, fmt.Errorf("CA bundle exceeds %d certificates", MaxCertificates)
		}
		remaining = rest
	}
	if len(unique) == 0 {
		return CanonicalBundle{}, fmt.Errorf("CA bundle is empty")
	}

	type item struct {
		digest [sha256.Size]byte
		der    []byte
		cert   *x509.Certificate
	}
	items := make([]item, 0, len(unique))
	for _, der := range unique {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return CanonicalBundle{}, fmt.Errorf("parse canonical CA certificate: %w", err)
		}
		items = append(items, item{digest: sha256.Sum256(der), der: der, cert: cert})
	}
	sort.Slice(items, func(i, j int) bool {
		if cmp := bytes.Compare(items[i].digest[:], items[j].digest[:]); cmp != 0 {
			return cmp < 0
		}
		return bytes.Compare(items[i].der, items[j].der) < 0
	})

	h := sha256.New()
	_, _ = h.Write(fingerprintDomain)
	canonicalPEM := make([]byte, 0, len(input))
	certificates := make([]CertificateMetadata, 0, len(items))
	var frame [8]byte
	for _, entry := range items {
		binary.BigEndian.PutUint64(frame[:], uint64(len(entry.der)))
		_, _ = h.Write(frame[:])
		_, _ = h.Write(entry.der)
		canonicalPEM = append(canonicalPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: entry.der})...)
		certificates = append(certificates, CertificateMetadata{
			Subject: entry.cert.Subject.String(), Issuer: entry.cert.Issuer.String(),
			Serial: entry.cert.SerialNumber.String(), NotBefore: entry.cert.NotBefore.UTC(), NotAfter: entry.cert.NotAfter.UTC(),
		})
	}

	return CanonicalBundle{
		CanonicalPEM:     canonicalPEM,
		Fingerprint:      hex.EncodeToString(h.Sum(nil)),
		CertificateCount: len(items),
		Certificates:     certificates,
	}, nil
}
