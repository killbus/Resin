export type TLSMode = "VERIFY" | "TRUST_CUSTOM_CA" | "BYPASS";

export type CABundle = {
  id: string;
  fingerprint_algorithm: string;
  fingerprint: string;
  canonicalization_version: number;
  certificate_count: number;
  certificates: Array<{
    subject: string;
    issuer: string;
    serial: string;
    not_before: string;
    not_after: string;
  }>;
  created_at: string;
  reference_count: number;
};

export type TLSPolicy = {
  platform_id: string;
  mode: TLSMode;
  effective_mode: TLSMode;
  expired: boolean;
  bundle_id?: string;
  bundle_fingerprint?: string;
  expires_at: string | null;
  version: number;
  updated_at?: string;
};

export type TLSPolicyMutation =
  | { mode: "TRUST_CUSTOM_CA"; bundle_id: string }
  | { mode: "BYPASS"; reason: string; expires_at: string | null };
