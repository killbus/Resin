import type { CABundle } from "./types";

export function certificateSummary(bundle: CABundle): string {
  const first = bundle.certificates[0];
  const identity = first?.subject || first?.issuer || bundle.id;
  const certificateCount = Math.max(bundle.certificate_count, bundle.certificates.length);
  return certificateCount > 1 ? `${identity} (+${certificateCount - 1})` : identity;
}
