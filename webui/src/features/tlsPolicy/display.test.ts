import { describe, expect, it } from "vitest";
import { certificateSummary } from "./display";
import type { CABundle } from "./types";

function bundle(certificates: CABundle["certificates"]): CABundle {
  return {
    id: "bundle-id",
    fingerprint_algorithm: "SHA256",
    fingerprint: "fingerprint",
    canonicalization_version: 1,
    certificate_count: certificates.length,
    certificates,
    created_at: "2026-08-19T00:00:00Z",
    reference_count: 0,
  };
}

function certificate(subject: string, serial = "1"): CABundle["certificates"][number] {
  return {
    subject,
    issuer: subject,
    serial,
    not_before: "2026-01-01T00:00:00Z",
    not_after: "2036-01-01T00:00:00Z",
  };
}

describe("certificateSummary", () => {
  it("uses certificate identity before the opaque bundle ID", () => {
    expect(certificateSummary(bundle([{
      subject: "CN=Private Root CA",
      issuer: "CN=Private Root CA",
      serial: "1",
      not_before: "2026-01-01T00:00:00Z",
      not_after: "2036-01-01T00:00:00Z",
    }]))).toBe("CN=Private Root CA");
  });

  it("falls back to the bundle ID when certificate metadata is unavailable", () => {
    expect(certificateSummary(bundle([]))).toBe("bundle-id");
  });

  it("keeps a multi-certificate summary bounded", () => {
    expect(certificateSummary(bundle([
      certificate("CN=Private Root CA"),
      certificate("CN=Private Issuing CA"),
    ]))).toBe("CN=Private Root CA (+1)");
  });

  it("does not grow linearly for the maximum 64-certificate bundle", () => {
    const certificates = Array.from({ length: 64 }, (_, index) => certificate(`CN=Root ${index + 1}`));
    const summary = certificateSummary(bundle(certificates));

    expect(summary).toBe("CN=Root 1 (+63)");
    expect(summary.length).toBeLessThan(40);
    expect(summary).not.toContain("CN=Root 64");
  });

  it("uses the count rather than serial text when certificates share a subject", () => {
    expect(certificateSummary(bundle([
      certificate("CN=Shared Root", "100"),
      certificate("CN=Shared Root", "200"),
    ]))).toBe("CN=Shared Root (+1)");
  });
});
