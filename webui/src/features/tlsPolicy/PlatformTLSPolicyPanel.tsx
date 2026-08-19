import { useQuery } from "@tanstack/react-query";
import { ExternalLink, ShieldAlert } from "lucide-react";
import { useEffect } from "react";
import { useWatch, type UseFormReturn } from "react-hook-form";
import { Badge } from "../../components/ui/Badge";
import { Input } from "../../components/ui/Input";
import { Select } from "../../components/ui/Select";
import { Textarea } from "../../components/ui/Textarea";
import { useI18n } from "../../i18n";
import { formatApiErrorMessage } from "../../lib/error-message";
import { formatDateTime } from "../../lib/time";
import {
  requiresBypassReason,
  tlsModeLabelKey,
  type CABundleAvailability,
  type PlatformConfigurationFormValues,
} from "../platforms/formModel";
import type { PlatformTLSPolicy } from "../platforms/types";
import { listCABundles } from "./api";
import { certificateSummary } from "./display";

const ZERO_UUID = "00000000-0000-0000-0000-000000000000";

type Translate = (text: string, vars?: Record<string, unknown>) => string;

export function PlatformTLSPolicyStatus({
  policy,
  translate,
}: {
  policy: PlatformTLSPolicy;
  translate: Translate;
}) {
  const t = translate;
  return (
    <div className="tls-policy-status" aria-live="polite">
      <p>
        {t("配置状态")}: {" "}
        <Badge variant={policy.mode === "BYPASS" ? (policy.expired ? "warning" : "danger") : "success"}>
          {t(tlsModeLabelKey(policy.mode))}
        </Badge>
        {policy.expired ? <span> · {t("已到期")}</span> : null}
        {policy.expires_at ? <span> · {t("到期")}: {formatDateTime(policy.expires_at)}</span> : null}
      </p>
      {policy.effective_mode !== policy.mode ? (
        <p>
          {t("当前生效")}: <Badge variant="success">{t(tlsModeLabelKey(policy.effective_mode))}</Badge>
        </p>
      ) : null}
    </div>
  );
}

type PlatformTLSPolicyPanelProps = {
  platformId: string;
  policy: PlatformTLSPolicy;
  form: UseFormReturn<PlatformConfigurationFormValues>;
  disabled?: boolean;
  showStatus?: boolean;
  onCABundleAvailabilityChange?: (availability: CABundleAvailability) => void;
};

export function PlatformTLSPolicyPanel({
  platformId,
  policy,
  form,
  disabled = false,
  showStatus = true,
  onCABundleAvailabilityChange,
}: PlatformTLSPolicyPanelProps) {
  const { t } = useI18n();
  const isDefault = platformId === ZERO_UUID;
  const mode = useWatch({ control: form.control, name: "tls_mode" });
  const bundleId = useWatch({ control: form.control, name: "tls_bundle_id" });
  const expiryKind = useWatch({ control: form.control, name: "tls_expiry_kind" });
  useWatch({ control: form.control, name: "tls_expires_at" });
  const bundlesQuery = useQuery({
    queryKey: ["ca-bundles"],
    queryFn: listCABundles,
    enabled: mode === "TRUST_CUSTOM_CA" && !isDefault,
    refetchOnWindowFocus: "always",
  });
  const caBundleAvailability: CABundleAvailability = mode !== "TRUST_CUSTOM_CA" || !bundlesQuery.isSuccess
    ? "unknown"
    : bundleId && bundlesQuery.data.some((bundle) => bundle.id === bundleId)
      ? "available"
      : "missing";
  const selectedBundleMissing = Boolean(bundleId) && caBundleAvailability === "missing";
  const reasonRequired = mode === "BYPASS" && requiresBypassReason(form.getValues(), policy);
  const hasCurrentReason = policy.mode === "BYPASS" && Boolean(policy.reason);

  useEffect(() => {
    if (reasonRequired || !form.getValues("tls_bypass_reason")) return;
    form.setValue("tls_bypass_reason", "", { shouldDirty: true, shouldValidate: false });
    form.clearErrors("tls_bypass_reason");
  }, [form, reasonRequired]);

  useEffect(() => {
    onCABundleAvailabilityChange?.(caBundleAvailability);
  }, [caBundleAvailability, onCABundleAvailabilityChange]);

  return (
    <section className="tls-policy-panel tls-policy-wide">
      <div className="platform-drawer-section-head">
        <h4>{t("HTTPS 证书校验")}</h4>
        <p>{t("设置将应用于此平台的所有 HTTPS 反向代理请求。未配置时使用系统证书。")}</p>
      </div>

      {isDefault ? (
        <div className="callout callout-info">
          <ShieldAlert size={16} />
          <span>{t("Default 平台固定使用系统证书，不能修改证书校验方式。")}</span>
        </div>
      ) : null}

      {mode === "BYPASS" && !isDefault ? (
        <div className="callout callout-warning">
          <ShieldAlert size={16} />
          <span>{t("此设置会让此平台的所有 HTTPS 反向代理请求跳过证书颁发机构、有效期和目标域名校验，请谨慎使用。")}</span>
        </div>
      ) : null}

      <div className="form-grid tls-policy-fields">
        <div className="field-group tls-policy-wide">
          <label className="field-label" htmlFor="tls-policy-mode">{t("证书校验方式")}</label>
          <Select
            id="tls-policy-mode"
            disabled={isDefault || disabled}
            {...form.register("tls_mode")}
          >
            <option value="VERIFY">{t(tlsModeLabelKey("VERIFY"))}</option>
            <option value="TRUST_CUSTOM_CA">{t(tlsModeLabelKey("TRUST_CUSTOM_CA"))}</option>
            <option value="BYPASS">{t(tlsModeLabelKey("BYPASS"))}</option>
          </Select>
        </div>

        {mode === "TRUST_CUSTOM_CA" && !isDefault ? (
          <div className="field-group tls-policy-wide">
            <label className="field-label" htmlFor="tls-policy-bundle">{t("CA 证书")}</label>
            <Select id="tls-policy-bundle" disabled={disabled} {...form.register("tls_bundle_id")}>
              <option value="">{t("请选择 CA 证书")}</option>
              {bundlesQuery.data?.map((bundle) => (
                <option key={bundle.id} value={bundle.id} title={bundle.fingerprint}>
                  {certificateSummary(bundle)} · {bundle.fingerprint.slice(0, 12)}...
                </option>
              ))}
            </Select>
            {selectedBundleMissing ? (
              <p className="field-error" role="alert">{t("当前 CA 证书不可用，请重新选择")}</p>
            ) : null}
            {form.formState.errors.tls_bundle_id?.message ? (
              <p className="field-error">{t(form.formState.errors.tls_bundle_id.message)}</p>
            ) : null}
            {bundlesQuery.isLoading ? <p className="muted">{t("正在加载 CA 证书...")}</p> : null}
            {bundlesQuery.isError ? <p className="field-error">{formatApiErrorMessage(bundlesQuery.error, t)}</p> : null}
            {!bundlesQuery.isLoading && !bundlesQuery.isError && (bundlesQuery.data?.length ?? 0) === 0 ? (
              <p className="field-error">{t("还没有 CA 证书，请先导入")}</p>
            ) : null}
            <p className="muted">
              <a
                className="inline-link"
                href="/ui/ca-bundles"
                target="_blank"
                rel="noopener noreferrer"
                title={t("在新标签页中导入证书")}
              >
                <ExternalLink size={13} />
                {t("导入证书")}
              </a>
            </p>
          </div>
        ) : null}

        {mode === "BYPASS" && !isDefault ? (
          <>
            <div className="field-group">
              <label className="field-label" htmlFor="tls-policy-expiry-kind">{t("有效期")}</label>
              <Select id="tls-policy-expiry-kind" disabled={disabled} {...form.register("tls_expiry_kind")}>
                <option value="until">{t("到指定时间")}</option>
                <option value="permanent">{t("长期有效")}</option>
              </Select>
            </div>
            {expiryKind === "until" ? (
              <div className="field-group">
                <label className="field-label" htmlFor="tls-policy-expires-at">{t("到期时间")}</label>
                <Input id="tls-policy-expires-at" type="datetime-local" disabled={disabled} {...form.register("tls_expires_at")} />
                {form.formState.errors.tls_expires_at?.message ? (
                  <p className="field-error">{t(form.formState.errors.tls_expires_at.message)}</p>
                ) : null}
              </div>
            ) : null}
          </>
        ) : null}

        {hasCurrentReason || reasonRequired ? (
          <div className="field-group tls-policy-wide tls-policy-reason-field">
            {hasCurrentReason ? (
              <div className="tls-policy-current-reason">
                <span>{t("当前原因")}</span>
                <p>{policy.reason}</p>
              </div>
            ) : null}
            {reasonRequired ? (
              <>
                <label className="field-label" htmlFor="tls-policy-reason">
                  {t(hasCurrentReason ? "本次变更原因（必填）" : "跳过证书校验的原因（必填）")}
                </label>
                <Textarea
                  id="tls-policy-reason"
                  rows={3}
                  required
                  aria-required="true"
                  disabled={disabled}
                  placeholder={t("请说明原因")}
                  invalid={Boolean(form.formState.errors.tls_bypass_reason)}
                  {...form.register("tls_bypass_reason")}
                />
                <p className="muted tls-policy-reason-help">{t("启用、延长期限或改为长期有效时需要填写")}</p>
                {form.formState.errors.tls_bypass_reason?.message ? (
                  <p className="field-error">{t(form.formState.errors.tls_bypass_reason.message)}</p>
                ) : null}
              </>
            ) : null}
          </div>
        ) : null}
      </div>

      {showStatus ? <PlatformTLSPolicyStatus policy={policy} translate={t} /> : null}
    </section>
  );
}
