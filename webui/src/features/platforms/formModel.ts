import { z } from "zod";
import { allocationPolicies, emptyAccountBehaviors, missActions } from "./constants";
import { parseHeaderLines, parseLinesToList } from "./formParsers";
import type {
  Platform,
  PlatformConfiguration,
  PlatformConfigurationInput,
  PlatformCreateInput,
  PlatformTLSConfigurationInput,
  PlatformTLSPolicy,
  PlatformUpdateInput,
} from "./types";

const platformNameForbiddenChars = ".:|/\\@?#%~";
const platformNameForbiddenSpacing = " \t\r\n";
const platformNameReserved = "api";

function containsAny(source: string, chars: string): boolean {
  for (const ch of chars) {
    if (source.includes(ch)) {
      return true;
    }
  }
  return false;
}

export const platformNameRuleHint = "平台名不能包含 .:|/\\@?#%~、空格、Tab、换行、回车，也不能为保留字。";

export const platformFormSchema = z.object({
  name: z.string().trim()
    .min(1, "平台名称不能为空")
    .refine((value) => !containsAny(value, platformNameForbiddenChars), {
      message: "平台名称不能包含字符 .:|/\\@?#%~",
    })
    .refine((value) => !containsAny(value, platformNameForbiddenSpacing), {
      message: "平台名称不能包含空格、Tab、换行、回车",
    })
    .refine((value) => value.toLowerCase() !== platformNameReserved, {
      message: "平台名称不能为保留字",
    }),
  sticky_ttl: z.string().optional(),
  regex_filters_text: z.string().optional(),
  region_filters_text: z.string().optional(),
  reverse_proxy_miss_action: z.enum(missActions),
  reverse_proxy_empty_account_behavior: z.enum(emptyAccountBehaviors),
  reverse_proxy_fixed_account_header: z.string().optional(),
  allocation_policy: z.enum(allocationPolicies),
  passive_circuit_breaker_disabled: z.boolean(),
}).superRefine((value, ctx) => {
  if (
    value.reverse_proxy_empty_account_behavior === "FIXED_HEADER" &&
    parseHeaderLines(value.reverse_proxy_fixed_account_header).length === 0
  ) {
    ctx.addIssue({
      code: "custom",
      path: ["reverse_proxy_fixed_account_header"],
      message: "用于提取 Account 的 Headers 不能为空",
    });
  }
});

export type PlatformFormValues = z.infer<typeof platformFormSchema>;

export const platformConfigurationFormSchema = z.intersection(
  platformFormSchema,
  z.object({
    tls_mode: z.enum(["VERIFY", "TRUST_CUSTOM_CA", "BYPASS"]),
    tls_bundle_id: z.string(),
    tls_bypass_reason: z.string(),
    tls_expiry_kind: z.enum(["until", "permanent"]),
    tls_expires_at: z.string(),
    tls_policy_version: z.number().int().nonnegative(),
  }),
);

export type PlatformConfigurationFormValues = z.infer<typeof platformConfigurationFormSchema>;

export const defaultPlatformFormValues: PlatformFormValues = {
  name: "",
  sticky_ttl: "",
  regex_filters_text: "",
  region_filters_text: "",
  reverse_proxy_miss_action: "TREAT_AS_EMPTY",
  reverse_proxy_empty_account_behavior: "RANDOM",
  reverse_proxy_fixed_account_header: "Authorization",
  allocation_policy: "BALANCED",
  passive_circuit_breaker_disabled: false,
};

function defaultTLSExpiry(): string {
  const value = new Date(Date.now() + 60 * 60 * 1000);
  value.setSeconds(0, 0);
  const offset = value.getTimezoneOffset() * 60_000;
  return new Date(value.getTime() - offset).toISOString().slice(0, 16);
}

function toLocalDateTime(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return defaultTLSExpiry();
  const offset = parsed.getTimezoneOffset() * 60_000;
  return new Date(parsed.getTime() - offset).toISOString().slice(0, 16);
}

export function newDefaultPlatformConfigurationFormValues(): PlatformConfigurationFormValues {
  return {
    ...defaultPlatformFormValues,
    tls_mode: "VERIFY",
    tls_bundle_id: "",
    tls_bypass_reason: "",
    tls_expiry_kind: "until",
    tls_expires_at: defaultTLSExpiry(),
    tls_policy_version: 0,
  };
}

export const defaultPlatformConfigurationFormValues = newDefaultPlatformConfigurationFormValues();

export function platformToFormValues(platform: Platform): PlatformFormValues {
  const regexFilters = Array.isArray(platform.regex_filters) ? platform.regex_filters : [];
  const regionFilters = Array.isArray(platform.region_filters) ? platform.region_filters : [];

  return {
    name: platform.name,
    sticky_ttl: platform.sticky_ttl,
    regex_filters_text: regexFilters.join("\n"),
    region_filters_text: regionFilters.join("\n"),
    reverse_proxy_miss_action: platform.reverse_proxy_miss_action,
    reverse_proxy_empty_account_behavior: platform.reverse_proxy_empty_account_behavior,
    reverse_proxy_fixed_account_header: platform.reverse_proxy_fixed_account_header,
    allocation_policy: platform.allocation_policy,
    passive_circuit_breaker_disabled: platform.passive_circuit_breaker_disabled,
  };
}

export function platformConfigurationToFormValues(configuration: PlatformConfiguration): PlatformConfigurationFormValues {
  const policy = configuration.tls_policy;
  return {
    ...platformToFormValues(configuration.platform),
    tls_mode: policy.mode,
    tls_bundle_id: policy.bundle_id ?? "",
    tls_bypass_reason: "",
    tls_expiry_kind: policy.expires_at ? "until" : "permanent",
    tls_expires_at: policy.expires_at ? toLocalDateTime(policy.expires_at) : defaultTLSExpiry(),
    tls_policy_version: policy.version,
  };
}

function toPlatformPayloadBase(values: PlatformFormValues) {
  return {
    name: values.name.trim(),
    regex_filters: parseLinesToList(values.regex_filters_text),
    region_filters: parseLinesToList(values.region_filters_text, (value) => value.toLowerCase()),
    reverse_proxy_miss_action: values.reverse_proxy_miss_action,
    reverse_proxy_empty_account_behavior: values.reverse_proxy_empty_account_behavior,
    reverse_proxy_fixed_account_header: parseHeaderLines(values.reverse_proxy_fixed_account_header).join("\n"),
    allocation_policy: values.allocation_policy,
    passive_circuit_breaker_disabled: values.passive_circuit_breaker_disabled,
  };
}

export function toPlatformCreateInput(values: PlatformConfigurationFormValues): PlatformCreateInput {
  const input: PlatformCreateInput = {
    ...toPlatformPayloadBase(values),
    sticky_ttl: values.sticky_ttl?.trim() || undefined,
  };
  if (values.tls_mode !== "VERIFY") {
    input.tls_policy = toTLSConfigurationInput(values, 0, true);
  }
  return input;
}

export function toPlatformUpdateInput(values: PlatformFormValues): PlatformUpdateInput {
  return {
    ...toPlatformPayloadBase(values),
    sticky_ttl: values.sticky_ttl?.trim() || "",
  };
}

function parseTLSExpiryEpoch(value: string): number | undefined {
  const epoch = new Date(value).getTime();
  // The datetime-local control and its baseline both use minute precision.
  return Number.isFinite(epoch) ? Math.floor(epoch / 60_000) * 60_000 : undefined;
}

function bypassExpiryEpoch(values: PlatformConfigurationFormValues): number | null | undefined {
  if (values.tls_expiry_kind === "permanent") return null;
  return parseTLSExpiryEpoch(values.tls_expires_at);
}

function currentExpiryEpoch(current: PlatformTLSPolicy): number | null | undefined {
  if (current.expires_at === null) return null;
  return parseTLSExpiryEpoch(current.expires_at);
}

function bypassExpiry(values: PlatformConfigurationFormValues): string | null | undefined {
  const epoch = bypassExpiryEpoch(values);
  if (epoch === null || epoch === undefined) return epoch;
  return new Date(epoch).toISOString();
}

export function isFutureTLSExpiry(value: string): boolean {
  const epoch = parseTLSExpiryEpoch(value);
  return epoch !== undefined && epoch > Date.now();
}

export type TLSConfigurationValidationIssue = {
  field: "tls_bundle_id" | "tls_bypass_reason" | "tls_expires_at";
  message: string;
};

export function validateTLSConfigurationDraft(
  values: PlatformConfigurationFormValues,
  current: PlatformTLSPolicy,
  caBundleAvailability: CABundleAvailability,
): TLSConfigurationValidationIssue | null {
  if (values.tls_mode === "TRUST_CUSTOM_CA" && !values.tls_bundle_id) {
    return { field: "tls_bundle_id", message: "请选择一个 CA 证书" };
  }
  if (!isTLSConfigurationSubmissionAllowed(values, current, caBundleAvailability)) {
    return { field: "tls_bundle_id", message: "当前 CA 证书不可用，请重新选择" };
  }
  if (!isBypassConfigurationChange(values, current)) return null;
  if (requiresBypassReason(values, current) && !values.tls_bypass_reason.trim()) {
    return { field: "tls_bypass_reason", message: "跳过证书校验时必须填写原因" };
  }
  if (values.tls_expiry_kind === "until" && !isFutureTLSExpiry(values.tls_expires_at)) {
    return { field: "tls_expires_at", message: "到期时间必须在未来" };
  }
  return null;
}

export function tlsModeLabelKey(mode: PlatformTLSPolicy["mode"]): string {
  if (mode === "TRUST_CUSTOM_CA") return "使用自定义 CA 证书";
  if (mode === "BYPASS") return "跳过证书校验";
  return "使用系统证书";
}

export type CABundleAvailability = "unknown" | "available" | "missing";

export function isTLSConfigurationSubmissionAllowed(
  values: Pick<PlatformConfigurationFormValues, "tls_mode" | "tls_bundle_id">,
  current: PlatformTLSPolicy,
  caBundleAvailability: CABundleAvailability,
): boolean {
  if (values.tls_mode !== "TRUST_CUSTOM_CA") return true;
  if (!values.tls_bundle_id) return false;

  const unchanged = current.mode === "TRUST_CUSTOM_CA" &&
    values.tls_bundle_id === (current.bundle_id ?? "");
  if (unchanged) return true;
  return caBundleAvailability === "available";
}

export function isTLSConfigurationChange(
  values: PlatformConfigurationFormValues,
  current: PlatformTLSPolicy,
): boolean {
  if (values.tls_mode !== current.mode) return true;
  if (values.tls_mode === "VERIFY") return false;
  if (values.tls_mode === "TRUST_CUSTOM_CA") {
    return values.tls_bundle_id !== (current.bundle_id ?? "");
  }
  return bypassExpiryEpoch(values) !== currentExpiryEpoch(current);
}

export function isBypassConfigurationChange(
  values: PlatformConfigurationFormValues,
  current: PlatformTLSPolicy,
): boolean {
  return values.tls_mode === "BYPASS" && isTLSConfigurationChange(values, current);
}

export function requiresBypassReason(
  values: PlatformConfigurationFormValues,
  current: PlatformTLSPolicy,
): boolean {
  if (values.tls_mode !== "BYPASS") return false;
  if (current.mode !== "BYPASS") return true;

  const nextExpiry = bypassExpiryEpoch(values);
  const previousExpiry = currentExpiryEpoch(current);
  if (nextExpiry === undefined || previousExpiry === undefined || previousExpiry === null) return false;
  return nextExpiry === null || nextExpiry > previousExpiry;
}

export type BypassConfigurationChangeSummary =
  | {
    kind: "enable";
    previousMode: PlatformTLSPolicy["mode"];
    nextExpiresAt: string | null;
  }
  | {
    kind: "expiry";
    previousExpiresAt: string | null;
    nextExpiresAt: string | null;
  };

export function describeBypassConfigurationChange(
  values: PlatformConfigurationFormValues,
  current: PlatformTLSPolicy,
): BypassConfigurationChangeSummary | null {
  if (!isBypassConfigurationChange(values, current)) return null;

  const nextExpiresAt = bypassExpiry(values);
  if (nextExpiresAt === undefined) return null;
  if (current.mode !== "BYPASS") {
    return { kind: "enable", previousMode: current.mode, nextExpiresAt };
  }
  return {
    kind: "expiry",
    previousExpiresAt: current.expires_at,
    nextExpiresAt,
  };
}

export function toPlatformConfigurationInput(
  values: PlatformConfigurationFormValues,
  current: PlatformTLSPolicy,
): PlatformConfigurationInput {
  const platform = toPlatformUpdateInput(values);
  if (!isTLSConfigurationChange(values, current)) {
    return { platform };
  }

  return {
    platform,
    tls_policy: toTLSConfigurationInput(
      values,
      values.tls_policy_version,
      requiresBypassReason(values, current),
    ),
  };
}

function toTLSConfigurationInput(
  values: PlatformConfigurationFormValues,
  expected_version: number,
  includeBypassReason: boolean,
): PlatformTLSConfigurationInput {
  if (values.tls_mode === "VERIFY") {
    return { mode: "VERIFY", expected_version };
  }
  if (values.tls_mode === "TRUST_CUSTOM_CA") {
    return { mode: "TRUST_CUSTOM_CA", expected_version, bundle_id: values.tls_bundle_id };
  }
  const expires_at = bypassExpiry(values);
  if (expires_at === undefined) {
    throw new Error("BYPASS expiry is invalid");
  }
  const reason = includeBypassReason ? values.tls_bypass_reason.trim() : "";
  return {
    mode: "BYPASS",
    expected_version,
    expires_at,
    ...(reason ? { reason } : {}),
  };
}
