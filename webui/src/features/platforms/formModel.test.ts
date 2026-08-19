import { describe, expect, it, vi } from "vitest";
import {
  describeBypassConfigurationChange,
  isTLSConfigurationChange,
  isTLSConfigurationSubmissionAllowed,
  newDefaultPlatformConfigurationFormValues,
  platformConfigurationToFormValues,
  requiresBypassReason,
  toPlatformCreateInput,
  toPlatformConfigurationInput,
} from "./formModel";
import type { PlatformConfiguration, PlatformTLSPolicy } from "./types";

const platform = {
  id: "platform-1",
  name: "example",
  sticky_ttl: "30m0s",
  regex_filters: [],
  region_filters: [],
  routable_node_count: 0,
  reverse_proxy_miss_action: "TREAT_AS_EMPTY" as const,
  reverse_proxy_empty_account_behavior: "RANDOM" as const,
  reverse_proxy_fixed_account_header: "",
  allocation_policy: "BALANCED" as const,
  passive_circuit_breaker_disabled: false,
  updated_at: "2026-08-19T00:00:00Z",
};

function bypassPolicy(expiresAt: string | null): PlatformTLSPolicy {
  return {
    platform_id: platform.id,
    mode: "BYPASS",
    effective_mode: "BYPASS",
    expired: false,
    reason: "current approved exception",
    expires_at: expiresAt,
    version: 2,
  };
}

function shiftLocalDateTime(value: string, minutes: number): string {
  const shifted = new Date(value);
  shifted.setMinutes(shifted.getMinutes() + minutes);
  const offset = shifted.getTimezoneOffset() * 60_000;
  return new Date(shifted.getTime() - offset).toISOString().slice(0, 16);
}

describe("Platform TLS configuration form", () => {
  it("builds create payloads with VERIFY omitted and explicit custom/BYPASS policies", () => {
    const verify = newDefaultPlatformConfigurationFormValues();
    verify.name = "new-platform";
    expect(toPlatformCreateInput(verify)).not.toHaveProperty("tls_policy");

    const custom = { ...verify, tls_mode: "TRUST_CUSTOM_CA" as const, tls_bundle_id: "bundle-1" };
    expect(toPlatformCreateInput(custom)).toMatchObject({
      tls_policy: { mode: "TRUST_CUSTOM_CA", expected_version: 0, bundle_id: "bundle-1" },
    });

    const bypass = {
      ...verify,
      tls_mode: "BYPASS" as const,
      tls_expiry_kind: "permanent" as const,
      tls_bypass_reason: "approved create exception",
    };
    expect(toPlatformCreateInput(bypass)).toMatchObject({
      tls_policy: { mode: "BYPASS", expected_version: 0, expires_at: null, reason: "approved create exception" },
    });
  });

  it("creates a fresh expiry baseline instead of reusing a stale module-level value", () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date("2026-08-19T12:00:00Z"));
      const first = newDefaultPlatformConfigurationFormValues();
      vi.setSystemTime(new Date("2026-08-19T15:00:00Z"));
      const second = newDefaultPlatformConfigurationFormValues();
      expect(second.tls_expires_at).not.toBe(first.tls_expires_at);
      expect(new Date(second.tls_expires_at).getTime()).toBeGreaterThan(new Date(first.tls_expires_at).getTime());
    } finally {
      vi.useRealTimers();
    }
  });

  it("keeps the current reason visible in the policy while starting a blank change-reason input", () => {
    const configuration: PlatformConfiguration = {
      platform,
      tls_policy: bypassPolicy(null),
      config_version: 3,
    };

    const values = platformConfigurationToFormValues(configuration);

    expect(configuration.tls_policy.reason).toBe("current approved exception");
    expect(values.tls_bypass_reason).toBe("");
    expect(isTLSConfigurationChange(values, configuration.tls_policy)).toBe(false);
    expect(toPlatformConfigurationInput(values, configuration.tls_policy)).toEqual({
      platform: expect.objectContaining({ name: "example" }),
    });
  });

  it("rebuilds the form from a complete reset snapshot without retaining BYPASS state", () => {
    const resetConfiguration: PlatformConfiguration = {
      platform,
      tls_policy: {
        platform_id: platform.id,
        mode: "VERIFY",
        effective_mode: "VERIFY",
        expired: false,
        expires_at: null,
        version: 0,
      },
      config_version: 4,
    };

    const values = platformConfigurationToFormValues(resetConfiguration);

    expect(values.tls_mode).toBe("VERIFY");
    expect(values.tls_bypass_reason).toBe("");
    expect(values.tls_policy_version).toBe(0);
    expect(toPlatformConfigurationInput(values, resetConfiguration.tls_policy)).toEqual({
      platform: expect.objectContaining({ name: "example" }),
    });
  });

  it("requires a new reason only when a BYPASS exception is enabled, extended, or made permanent", () => {
    const currentExpiry = "2026-08-20T12:00:00Z";
    const current = bypassPolicy(currentExpiry);
    const base = platformConfigurationToFormValues({ platform, tls_policy: current, config_version: 3 });

    const shortened = { ...base, tls_expires_at: shiftLocalDateTime(base.tls_expires_at, -60) };
    expect(isTLSConfigurationChange(shortened, current)).toBe(true);
    expect(requiresBypassReason(shortened, current)).toBe(false);

    const extended = { ...base, tls_expires_at: shiftLocalDateTime(base.tls_expires_at, 60) };
    expect(requiresBypassReason(extended, current)).toBe(true);

    const permanent = { ...base, tls_expiry_kind: "permanent" as const };
    expect(requiresBypassReason(permanent, current)).toBe(true);

    const verify: PlatformTLSPolicy = {
      platform_id: platform.id,
      mode: "VERIFY",
      effective_mode: "VERIFY",
      expired: false,
      expires_at: null,
      version: 0,
    };
    const enabled = { ...base, tls_mode: "BYPASS" as const };
    expect(requiresBypassReason(enabled, verify)).toBe(true);
  });

  it("does not submit a hidden reason after a BYPASS extension is withdrawn or shortened", () => {
    const current = bypassPolicy("2026-08-20T12:00:00Z");
    const base = platformConfigurationToFormValues({ platform, tls_policy: current, config_version: 3 });
    const shortened = {
      ...base,
      tls_bypass_reason: "reason left from an extension draft",
      tls_expires_at: shiftLocalDateTime(base.tls_expires_at, -60),
    };

    expect(requiresBypassReason(shortened, current)).toBe(false);
    expect(toPlatformConfigurationInput(shortened, current)).toEqual({
      platform: expect.objectContaining({ name: "example" }),
      tls_policy: {
        mode: "BYPASS",
        expected_version: 2,
        expires_at: expect.any(String),
      },
    });

    const withdrawn = { ...base, tls_bypass_reason: "hidden stale reason" };
    expect(toPlatformConfigurationInput(withdrawn, current)).toEqual({
      platform: expect.objectContaining({ name: "example" }),
    });
  });

  it("describes the concrete BYPASS change used by the save confirmation", () => {
    const verify: PlatformTLSPolicy = {
      platform_id: platform.id,
      mode: "VERIFY",
      effective_mode: "VERIFY",
      expired: false,
      expires_at: null,
      version: 0,
    };
    const enabled = {
      ...platformConfigurationToFormValues({ platform, tls_policy: verify, config_version: 3 }),
      tls_mode: "BYPASS" as const,
      tls_expiry_kind: "permanent" as const,
    };
    expect(describeBypassConfigurationChange(enabled, verify)).toEqual({
      kind: "enable",
      previousMode: "VERIFY",
      nextExpiresAt: null,
    });

    const current = bypassPolicy("2026-08-20T12:00:00Z");
    const base = platformConfigurationToFormValues({ platform, tls_policy: current, config_version: 3 });
    expect(describeBypassConfigurationChange({ ...base, tls_expiry_kind: "permanent" }, current)).toEqual({
      kind: "expiry",
      previousExpiresAt: "2026-08-20T12:00:00Z",
      nextExpiresAt: null,
    });
    expect(describeBypassConfigurationChange(base, current)).toBeNull();
  });

  it("allows Platform-only saves with an unchanged custom CA but blocks unverified CA changes", () => {
    const current: PlatformTLSPolicy = {
      platform_id: platform.id,
      mode: "TRUST_CUSTOM_CA",
      effective_mode: "TRUST_CUSTOM_CA",
      expired: false,
      bundle_id: "current-bundle",
      expires_at: null,
      version: 1,
    };
    const values = platformConfigurationToFormValues({
      platform,
      tls_policy: current,
      config_version: 3,
    });

    expect(isTLSConfigurationSubmissionAllowed(values, current, "unknown")).toBe(true);
    expect(toPlatformConfigurationInput(values, current)).toEqual({
      platform: expect.objectContaining({ name: "example" }),
    });
    expect(isTLSConfigurationSubmissionAllowed(values, current, "missing")).toBe(true);

    const replacement = { ...values, tls_bundle_id: "replacement-bundle" };
    expect(isTLSConfigurationSubmissionAllowed(replacement, current, "unknown")).toBe(false);
    expect(isTLSConfigurationSubmissionAllowed(replacement, current, "available")).toBe(true);
    expect(isTLSConfigurationSubmissionAllowed({ ...values, tls_bundle_id: "" }, current, "available")).toBe(false);

    const verify: PlatformTLSPolicy = {
      platform_id: platform.id,
      mode: "VERIFY",
      effective_mode: "VERIFY",
      expired: false,
      expires_at: null,
      version: 0,
    };
    expect(isTLSConfigurationSubmissionAllowed({ ...replacement, tls_mode: "TRUST_CUSTOM_CA" }, verify, "unknown")).toBe(false);
    expect(isTLSConfigurationSubmissionAllowed({ ...replacement, tls_mode: "TRUST_CUSTOM_CA" }, verify, "available")).toBe(true);
    expect(isTLSConfigurationSubmissionAllowed({ ...values, tls_mode: "VERIFY" }, current, "missing")).toBe(true);
  });
});
