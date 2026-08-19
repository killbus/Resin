import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { AlertTriangle, RefreshCw, Sparkles, Trash2, Upload, X } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Badge } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { Card } from "../../components/ui/Card";
import { DataTable } from "../../components/ui/DataTable";
import { Textarea } from "../../components/ui/Textarea";
import { ToastContainer } from "../../components/ui/Toast";
import { useToast } from "../../hooks/useToast";
import { useI18n } from "../../i18n";
import { formatApiErrorMessage } from "../../lib/error-message";
import { formatDateTime } from "../../lib/time";
import { deleteCABundle, importCABundle, listCABundles } from "./api";
import { certificateSummary } from "./display";
import type { CABundle } from "./types";

function shortFingerprint(value: string): string {
  return value.length > 20 ? `${value.slice(0, 12)}...${value.slice(-8)}` : value;
}

export function CABundlesPage() {
  const { t } = useI18n();
  const queryClient = useQueryClient();
  const { toasts, showToast, dismissToast } = useToast();
  const [importOpen, setImportOpen] = useState(false);
  const [pem, setPEM] = useState("");
  const bundlesQuery = useQuery({ queryKey: ["ca-bundles"], queryFn: listCABundles });

  const importMutation = useMutation({
    mutationFn: importCABundle,
    onSuccess: async () => {
      setPEM("");
      setImportOpen(false);
      await queryClient.invalidateQueries({ queryKey: ["ca-bundles"] });
      showToast("success", t("CA 证书已导入"));
    },
    onError: (error) => showToast("error", formatApiErrorMessage(error, t)),
  });

  const deleteMutation = useMutation({
    mutationFn: deleteCABundle,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["ca-bundles"] });
      showToast("success", t("CA 证书已删除"));
    },
    onError: (error) => showToast("error", formatApiErrorMessage(error, t)),
  });

  const submitImport = (event: FormEvent) => {
    event.preventDefault();
    if (!pem.trim()) {
      showToast("error", t("请输入一个或多个 CA 证书 PEM"));
      return;
    }
    importMutation.mutate(pem);
  };

  const closeImport = () => {
    if (!importMutation.isPending) setImportOpen(false);
  };

  const columns: ColumnDef<CABundle>[] = [
    {
      id: "certificate",
      header: t("证书"),
      cell: ({ row }) => (
        <div className="ca-certificate-cell">
          <span title={certificateSummary(row.original)}>{certificateSummary(row.original)}</span>
          <span className="tls-mono" title={row.original.id}>{row.original.id}</span>
        </div>
      ),
    },
    {
      accessorKey: "fingerprint",
      header: t("SHA-256 指纹"),
      cell: ({ row }) => <span className="tls-mono" title={row.original.fingerprint}>{shortFingerprint(row.original.fingerprint)}</span>,
    },
    { accessorKey: "certificate_count", header: t("证书数量") },
    {
      id: "valid_until",
      header: t("最早到期"),
      cell: ({ row }) => {
        const earliest = (row.original.certificates ?? [])
          .map((certificate) => certificate.not_after)
          .filter(Boolean)
          .sort()[0];
        return earliest ? formatDateTime(earliest) : "-";
      },
    },
    {
      accessorKey: "reference_count",
      header: t("使用中的平台"),
      cell: ({ row }) => (
        <Badge variant={row.original.reference_count > 0 ? "success" : "muted"}>{row.original.reference_count}</Badge>
      ),
    },
    {
      accessorKey: "created_at",
      header: t("创建时间"),
      cell: ({ row }) => formatDateTime(row.original.created_at),
    },
    {
      id: "actions",
      header: t("操作"),
      cell: ({ row }) => {
        const bundle = row.original;
        const referenced = bundle.reference_count > 0;
        const label = referenced ? t("证书仍被平台使用，无法删除") : t("删除 CA 证书");
        return (
          <div className="ca-row-actions">
            <Button
              variant="ghost"
              size="sm"
              disabled={referenced || deleteMutation.isPending}
              title={label}
              aria-label={label}
              style={{ color: "var(--delete-btn-color, #c27070)" }}
              onClick={() => {
                if (window.confirm(t("确认删除此 CA 证书？"))) deleteMutation.mutate(bundle.id);
              }}
            >
              <Trash2 size={14} />
            </Button>
          </div>
        );
      },
    },
  ];

  const bundles = bundlesQuery.data ?? [];

  return (
    <section className="tls-policy-page">
      <header className="module-header">
        <div>
          <h2>{t("CA 证书")}</h2>
          <p className="module-description">{t("集中管理可供各平台使用的 CA 证书。导入证书不会自动改变任何平台的校验方式。")}</p>
        </div>
      </header>

      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      <Card className="ca-toolbar-card">
        <div className="list-card-header">
          <div>
            <h3>{t("已导入的证书")}</h3>
            <p>{t("共 {{count}} 个", { count: bundles.length })}</p>
          </div>
          <div className="ca-toolbar-actions">
            <Button size="sm" onClick={() => setImportOpen(true)}>
              <Upload size={16} />
              {t("导入证书")}
            </Button>
            <Button variant="secondary" size="sm" onClick={() => bundlesQuery.refetch()} disabled={bundlesQuery.isFetching}>
              <RefreshCw size={16} className={bundlesQuery.isFetching ? "spin" : undefined} />
              {t("刷新")}
            </Button>
          </div>
        </div>
      </Card>

      <Card className="ca-table-card">
        {bundlesQuery.isLoading ? <p className="muted">{t("正在加载 CA 证书...")}</p> : null}
        {bundlesQuery.isError ? (
          <div className="callout callout-error"><AlertTriangle size={15} />{formatApiErrorMessage(bundlesQuery.error, t)}</div>
        ) : null}
        {!bundlesQuery.isLoading && !bundlesQuery.isError && bundles.length === 0 ? (
          <div className="empty-box"><Sparkles size={16} /><p>{t("还没有导入 CA 证书")}</p></div>
        ) : null}
        {bundles.length > 0 ? (
          <DataTable data={bundles} columns={columns} getRowId={(bundle) => bundle.id} className="data-table-ca" />
        ) : null}
      </Card>

      {importOpen ? (
        <div className="modal-overlay" role="dialog" aria-modal="true" aria-label={t("导入证书")} onClick={closeImport}>
          <Card className="modal-card ca-import-modal" onClick={(event) => event.stopPropagation()}>
            <div className="modal-header">
              <div>
                <h3>{t("导入证书")}</h3>
                <p>{t("粘贴一个或多个 PEM 格式的 CA 证书。不要包含私钥或服务端证书。")}</p>
              </div>
              <Button variant="ghost" size="sm" onClick={closeImport} disabled={importMutation.isPending} aria-label={t("关闭")}>
                <X size={16} />
              </Button>
            </div>
            <form className="tls-import-form" onSubmit={submitImport}>
              <Textarea
                rows={10}
                value={pem}
                onChange={(event) => setPEM(event.target.value)}
                placeholder="-----BEGIN CERTIFICATE-----"
                aria-label={t("CA 证书 PEM")}
                autoFocus
              />
              <div className="tls-form-actions">
                <Button type="button" variant="secondary" onClick={closeImport} disabled={importMutation.isPending}>{t("取消")}</Button>
                <Button type="submit" disabled={importMutation.isPending}>
                  <Upload size={16} />
                  {importMutation.isPending ? t("导入中...") : t("导入证书")}
                </Button>
              </div>
            </form>
          </Card>
        </div>
      ) : null}
    </section>
  );
}
