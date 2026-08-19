import { apiRequest } from "../../lib/api-client";
import type { CABundle, TLSPolicy, TLSPolicyMutation } from "./types";

const bundlePath = "/api/v1/ca-bundles";

type ApiCABundle = Omit<CABundle, "certificates"> & {
  certificates?: CABundle["certificates"] | null;
};

function normalizeCABundle(raw: ApiCABundle): CABundle {
  return {
    ...raw,
    certificates: Array.isArray(raw.certificates) ? raw.certificates : [],
  };
}

export function listCABundles(): Promise<CABundle[]> {
  return apiRequest<ApiCABundle[]>(bundlePath).then((bundles) => bundles.map(normalizeCABundle));
}

export function importCABundle(pem: string): Promise<CABundle> {
  return apiRequest<ApiCABundle>(bundlePath, { method: "POST", body: { pem } }).then(normalizeCABundle);
}

export function deleteCABundle(id: string): Promise<void> {
  return apiRequest<void>(`${bundlePath}/${id}`, { method: "DELETE" });
}

function policyPath(platformId: string): string {
  return `/api/v1/platforms/${platformId}/tls-policy`;
}

export function getTLSPolicy(platformId: string): Promise<TLSPolicy> {
  return apiRequest<TLSPolicy>(policyPath(platformId));
}

export function updateTLSPolicy(platformId: string, policy: TLSPolicyMutation, version: number): Promise<TLSPolicy> {
  return apiRequest<TLSPolicy>(policyPath(platformId), {
    method: "PUT",
    body: policy,
    headers: version > 0 ? { "If-Match": `"${version}"` } : { "If-None-Match": "*" },
  });
}

export function resetTLSPolicy(platformId: string, version: number): Promise<void> {
  return apiRequest<void>(policyPath(platformId), {
    method: "DELETE",
    headers: version > 0 ? { "If-Match": `"${version}"` } : undefined,
  });
}
