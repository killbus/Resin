import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { useForm } from "react-hook-form";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { EN_TRANSLATIONS } from "../../i18n/translations";
import {
  defaultPlatformConfigurationFormValues,
  platformConfigurationToFormValues,
  type PlatformConfigurationFormValues,
} from "../platforms/formModel";
import type { Platform, PlatformTLSPolicy } from "../platforms/types";
import type { CABundle } from "./types";
import { PlatformTLSPolicyPanel, PlatformTLSPolicyStatus } from "./PlatformTLSPolicyPanel";

const platform: Platform = {
  id: "platform-1",
  name: "example",
  sticky_ttl: "30m0s",
  regex_filters: [],
  region_filters: [],
  routable_node_count: 0,
  reverse_proxy_miss_action: "TREAT_AS_EMPTY",
  reverse_proxy_empty_account_behavior: "RANDOM",
  reverse_proxy_fixed_account_header: "",
  allocation_policy: "BALANCED",
  passive_circuit_breaker_disabled: false,
  updated_at: "2026-08-19T00:00:00Z",
};

function PanelHarness({ policy, values }: { policy: PlatformTLSPolicy; values: PlatformConfigurationFormValues }) {
  const form = useForm<PlatformConfigurationFormValues>({
    defaultValues: { ...defaultPlatformConfigurationFormValues, ...values },
  });
  return <PlatformTLSPolicyPanel platformId={platform.id} policy={policy} form={form} />;
}

function renderPanelResult(
  policy: PlatformTLSPolicy,
  values: PlatformConfigurationFormValues,
  bundles?: CABundle[],
): { html: string; queryClient: QueryClient } {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  if (bundles) queryClient.setQueryData(["ca-bundles"], bundles);
  const html = renderToStaticMarkup(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <PanelHarness policy={policy} values={values} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { html, queryClient };
}

function renderPanel(
  policy: PlatformTLSPolicy,
  values: PlatformConfigurationFormValues,
  bundles?: CABundle[],
): string {
  return renderPanelResult(policy, values, bundles).html;
}

function caBundle(id: string, fingerprint: string, subject = "CN=Shared Root", serial = "1"): CABundle {
  return {
    id,
    fingerprint_algorithm: "SHA256",
    fingerprint,
    canonicalization_version: 1,
    certificate_count: 1,
    certificates: [{
      subject,
      issuer: subject,
      serial,
      not_before: "2026-01-01T00:00:00Z",
      not_after: "2036-01-01T00:00:00Z",
    }],
    created_at: "2026-08-19T00:00:00Z",
    reference_count: 0,
  };
}

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

describe("PlatformTLSPolicyStatus", () => {
  it("distinguishes an expired BYPASS configuration from its effective VERIFY behavior", () => {
    const html = renderToStaticMarkup(
      <PlatformTLSPolicyStatus
        policy={{
          platform_id: "platform-1",
          mode: "BYPASS",
          effective_mode: "VERIFY",
          expired: true,
          reason: "temporary upstream exception",
          expires_at: "2026-08-18T12:00:00Z",
          version: 1,
        }}
        translate={(text) => text}
      />,
    );

    expect(html).toContain("配置状态");
    expect(html).toContain("跳过证书校验");
    expect(html).toContain("已到期");
    expect(html).toContain("当前生效");
    expect(html).toContain("使用系统证书");
    expect(html).not.toContain("当前配置原因");
    expect(html).not.toContain("temporary upstream exception");
  });
});

describe("PlatformTLSPolicyPanel reason context", () => {
  it("keeps the English reason labels mutually distinct", () => {
    expect(EN_TRANSLATIONS["跳过证书校验的原因（必填）"]).toBe("Reason for Skipping Verification (Required)");
    expect(EN_TRANSLATIONS["当前原因"]).toBe("Current Reason");
    expect(EN_TRANSLATIONS["本次变更原因（必填）"]).toBe("Reason for This Change (Required)");
  });

  it("shows the current reason nearby without an editable field for an unchanged or shortened BYPASS", () => {
    const policy = bypassPolicy("2026-08-20T12:00:00Z");
    const baseline = platformConfigurationToFormValues({ platform, tls_policy: policy, config_version: 3 });

    const unchanged = renderPanel(policy, baseline);
    expect(unchanged).toContain("当前原因");
    expect(unchanged).toContain("current approved exception");
    expect(unchanged).not.toContain('id="tls-policy-reason"');

    const shortened = renderPanel(policy, {
      ...baseline,
      tls_expires_at: shiftLocalDateTime(baseline.tls_expires_at, -60),
    });
    expect(shortened).toContain("current approved exception");
    expect(shortened).not.toContain('id="tls-policy-reason"');
  });

  it("renders a blank required textarea only for enablement, extension, or permanent conversion", () => {
    const policy = bypassPolicy("2026-08-20T12:00:00Z");
    const baseline = platformConfigurationToFormValues({ platform, tls_policy: policy, config_version: 3 });

    const extended = renderPanel(policy, {
      ...baseline,
      tls_expires_at: shiftLocalDateTime(baseline.tls_expires_at, 60),
    });
    expect(extended).toContain('id="tls-policy-reason"');
    expect(extended).toContain("本次变更原因（必填）");
    expect(extended).toContain("required");
    expect(extended).not.toContain(">stale reason</textarea>");

    const permanent = renderPanel(policy, { ...baseline, tls_expiry_kind: "permanent" });
    expect(permanent).toContain('id="tls-policy-reason"');

    const verifyPolicy: PlatformTLSPolicy = {
      platform_id: platform.id,
      mode: "VERIFY",
      effective_mode: "VERIFY",
      expired: false,
      expires_at: null,
      version: 0,
    };
    const enabled = renderPanel(verifyPolicy, {
      ...platformConfigurationToFormValues({ platform, tls_policy: verifyPolicy, config_version: 3 }),
      tls_mode: "BYPASS",
    });
    expect(enabled).toContain('id="tls-policy-reason"');
    expect(enabled).toContain("跳过证书校验的原因（必填）");
    expect(enabled).not.toContain("当前原因");
    expect(enabled).not.toContain("本次变更原因（必填）");
  });

  it("uses the current-reason label only when a current BYPASS exists", () => {
    const policy = bypassPolicy("2026-08-20T12:00:00Z");
    const baseline = platformConfigurationToFormValues({ platform, tls_policy: policy, config_version: 3 });
    const html = renderPanel(policy, baseline);
    expect(html).toContain("当前原因");
    expect(html).not.toContain("跳过证书校验的原因");
    expect(html).not.toContain("本次变更原因（必填）");

    const extended = renderPanel(policy, {
      ...baseline,
      tls_expires_at: shiftLocalDateTime(baseline.tls_expires_at, 60),
    });
    expect(extended).toContain("当前原因");
    expect(extended).toContain("本次变更原因（必填）");
    expect(extended).not.toContain("跳过证书校验的原因");
  });
});

describe("PlatformTLSPolicyPanel CA selection", () => {
  const unavailableBundleID = "11111111-1111-1111-1111-111111111111";
  const policy: PlatformTLSPolicy = {
    platform_id: platform.id,
    mode: "TRUST_CUSTOM_CA",
    effective_mode: "TRUST_CUSTOM_CA",
    expired: false,
    bundle_id: unavailableBundleID,
    bundle_fingerprint: "missing-fingerprint",
    expires_at: null,
    version: 2,
  };

  it("marks an active bundle absent from the authoritative list as unavailable instead of offering its UUID", () => {
    const values = platformConfigurationToFormValues({ platform, tls_policy: policy, config_version: 3 });
    const html = renderPanel(policy, values, []);

    expect(html).toContain("当前 CA 证书不可用，请重新选择");
    expect(html).not.toContain(unavailableBundleID);
  });

  it("opens CA import in a new tab so the current platform draft remains mounted", () => {
    const values = platformConfigurationToFormValues({ platform, tls_policy: policy, config_version: 3 });
    const html = renderPanel(policy, { ...values, tls_bundle_id: "" }, []);

    expect(html).toContain('href="/ui/ca-bundles"');
    expect(html).toContain('target="_blank"');
  });

  it("keeps the new-tab import link visible when certificates already exist", () => {
    const values = platformConfigurationToFormValues({ platform, tls_policy: policy, config_version: 3 });
    const html = renderPanel(policy, values, [caBundle(unavailableBundleID, "aaaaaaaaaaaaaaaa")]);

    expect(html).toContain('href="/ui/ca-bundles"');
    expect(html).toContain('target="_blank"');
  });

  it("always refetches the bundle list when focus returns from CA import", () => {
    const values = platformConfigurationToFormValues({ platform, tls_policy: policy, config_version: 3 });
    const { queryClient } = renderPanelResult(policy, values, []);
    const options = queryClient.getQueryCache().find({ queryKey: ["ca-bundles"] })?.options as {
      refetchOnWindowFocus?: unknown;
    } | undefined;

    expect(options?.refetchOnWindowFocus).toBe("always");
  });

  it("keeps same-subject bundles distinguishable by fingerprint", () => {
    const values = platformConfigurationToFormValues({ platform, tls_policy: policy, config_version: 3 });
    const html = renderPanel(policy, values, [
      caBundle("bundle-a", "aaaaaaaaaaaa1111", "CN=Shared Root", "100"),
      caBundle("bundle-b", "bbbbbbbbbbbb2222", "CN=Shared Root", "200"),
    ]);

    expect(html).toContain("CN=Shared Root · aaaaaaaaaaaa...");
    expect(html).toContain("CN=Shared Root · bbbbbbbbbbbb...");
  });
});
