# Platform reverse HTTPS TLS verification policy

Status: **completed and archived on 2026-08-19**.

## Goal

Allow a custom Resin platform to define how reverse HTTPS connections verify
upstream certificates while preserving the existing strict default, transport
isolation, node-health attribution, and audit behavior.

TLS verification is a platform setting. This follows Resin's existing platform
model: node filters, allocation, leases, reverse-proxy behavior, and passive
circuit-breaker behavior apply to every request using that platform. It is not
a target authorization or hostname-rule system.

## Corrected product facts

- A reverse proxy request selects a platform and supplies its target URL.
- Platforms are persisted configuration scopes whose settings apply to the
  platform as a whole; Resin has no existing per-target platform policy model.
- The earlier exact `host:port` model was an assistant-proposed risk-reduction
  baseline. It was not established by a real usage requirement and must not be
  treated as a product fact.
- The built-in `Default` platform is the fallback for requests without an
  explicit platform. Allowing it to relax TLS would create a global escape
  hatch, so its TLS mode is fixed to strict verification.
- `ProxyBypassRules` chooses direct versus routed egress. It does not affect TLS
  verification and does not authorize targets.
- Resin has one shared admin token and one shared proxy token, not per-user
  identities or RBAC. Audit records must not invent an operator identity.

## Required behavior

### Platform modes

Each custom platform has one effective reverse HTTPS TLS mode:

| Mode | User meaning | Persisted state |
|------|--------------|-----------------|
| `VERIFY` | Use normal system certificate verification | no active policy row |
| `TRUST_CUSTOM_CA` | Use system roots plus one imported immutable CA bundle | active policy |
| `BYPASS` | Skip certificate-chain and hostname verification | active policy |

The policy applies to every reverse HTTPS request using that platform, whether
egress is direct or routed. Forward proxy, CONNECT, SOCKS5, probes, HTTP targets,
and other platforms retain their existing behavior.

### Strict defaults and failure closure

- Missing policy means `VERIFY`; `VERIFY` is not persisted.
- The built-in `Default` platform rejects custom-CA and BYPASS mutations.
- Missing platform, corrupt policy, missing/damaged referenced CA, or unavailable
  policy evaluation fails before egress. It never silently becomes VERIFY or
  BYPASS.
- Direct and routed requests resolve the same platform policy before egress
  selection.

### Custom CA behavior

- Resin centrally imports public CA certificates, validates them, canonicalizes
  them, deduplicates immutable bundles by content fingerprint, and stores the
  canonical PEM in strong state.
- Importing a CA bundle changes no runtime behavior. A custom platform must
  explicitly select the bundle.
- Custom CA mode augments the normal system root pool with the selected bundle.
  Hostname/SNI, validity, and chain verification remain enabled.
- Resin does not generate keys, issue certificates, manage private keys, fetch
  certificates from arbitrary URLs, or operate a PKI/CRL/OCSP service.
- List responses, normal logs, history responses, and UI models never expose PEM.
- CA management history distinguishes new material, deduplicated reuse, and
  deletion, retaining verified certificate metadata and request/credential
  context after the active bundle is removed.

### BYPASS controls

- BYPASS is an explicit platform-wide exception, never an automatic fallback.
- A non-empty reason is required when enabling BYPASS and when extending a
  temporary exception or changing it to permanent.
- Expiry is explicit: `null` in the API means permanent; otherwise it is a
  future RFC3339 timestamp. At expiry the effective mode becomes VERIFY for new
  requests.
- The UI describes the scope and risk in user language. It must not expose JSON
  representation details such as "explicit null".

### Versioning, revocation, and history

- One active policy exists at most per custom platform.
- Create uses expected absence; replacement and deletion use the current
  positive version. The active mutation and append-only history event are one
  transaction.
- Snapshot publication is the linearization point for new requests. Obsolete
  idle transports are removed and closed; already-started requests, streams,
  and upgrades drain under their captured policy.
- Platform deletion removes active policy after appending terminal history.
  History is PEM-free and does not cascade with platform/policy deletion.

### Failure attribution and audit

- TLS identity/policy failures, target failures, local policy failures, client
  cancellation, and unknown composite dial failures do not reduce node health.
- Only explicit producer-side `NodeTransportFailure` evidence permits negative
  node-health feedback. Direct attempts never update node health; routed success
  keeps the existing positive feedback.
- Request audit correlates platform, actual target, configured/effective TLS
  mode, policy version, CA fingerprint when present, direct/routed egress,
  expiry fallback, outcome, and failure attribution. It records no PEM or
  BYPASS reason.

## WebUI requirements

- TLS verification appears within the existing platform **配置** tab, not as a
  new target-rule tab.
- Platform fields and TLS verification are one configuration task: one
  `保存配置` action submits them to one server-side atomic command. The UI must
  not expose an independent TLS save/reset context.
- A successful save returns the complete authoritative Platform configuration
  snapshot. Validation or version conflicts preserve the user's draft and
  cannot leave partial Platform, TLS policy, or policy-history writes.
- The management configuration snapshot exposes a BYPASS policy's current
  reason and distinguishes configured mode from effective mode after expiry.
  Request logs and compatibility policy/history endpoints continue to redact
  the reason, and CA PEM remains hidden everywhere.
- In the Platform form, the current BYPASS reason is shown read-only beside
  the TLS controls. A blank "reason for this change" input is shown only when
  the draft enables BYPASS, extends its expiry, or makes it permanent; a
  withdrawn reason draft is never submitted. The final confirmation names the
  concrete TLS mode/expiry change.
- The mode labels are user-facing Chinese: `使用系统证书`,
  `使用自定义 CA 证书`, and `跳过证书校验`.
- `Default` shows a read-only strict setting.
- The CA resource page follows existing resource-management layout and uses
  `CA 证书`, `导入证书`, and `已导入的证书`; it does not describe implementation
  concepts such as immutable registries, authorization boundaries, CAS, or
  normalized targets.
- CA rows and selectors identify bundles with verified certificate-derived
  metadata such as Subject and validity, rather than requiring users to infer
  purpose from an opaque UUID or truncated fingerprint.
- Multi-certificate bundles remain distinguishable in both the table and
  selector through a bounded identity summary plus fingerprint. An active
  bundle missing from a successfully loaded authoritative list is shown as
  unavailable and blocks a custom-CA mutation; a transient list error does not
  block an unrelated Platform-only save whose TLS state is unchanged. The
  Platform import affordance does not unload the current dirty draft and the
  selector refreshes when the operator returns.
- Buttons, tables, empty/loading/error states, tooltips, and responsive behavior
  follow existing Resin components and page conventions.
- `重置为默认配置` resets the complete Platform configuration atomically,
  including removal of any custom CA or BYPASS policy back to VERIFY.

## Acceptance criteria

- A custom platform can switch between VERIFY, custom CA, and BYPASS through
  API and WebUI; changes survive restart.
- The same platform policy governs multiple HTTPS targets and both direct and
  routed egress.
- Default cannot be relaxed through repository, service, API, or UI paths.
- Custom CA accepts both normal public certificates and certificates rooted in
  the selected bundle, while still rejecting wrong SAN, expiry, and wrong CA.
- BYPASS expiry, reason, version conflicts, revocation, cache retirement, and
  audit behavior are deterministic and tested.
- Forward/CONNECT/SOCKS5/probes remain strict and isolated.
- CA import/dedup/reference-aware deletion and PEM redaction remain tested.
- Existing failure-attribution and reverse-handler orchestration boundaries
  remain intact.
- Concurrent Platform/TLS edits are detected through an aggregate Platform
  configuration version; the atomic command never silently overwrites a newer
  configuration.
- WebUI build/type-check and focused lint pass, with no new design vocabulary or
  exact-target controls.
- Focused WebUI behavior tests cover reason/current-change separation, BYPASS
  governance, expired configured/effective display, unchanged TLS omission,
  full reset to VERIFY, and CA display identity.

## Out of scope

- A system-global TLS bypass or a configurable Default-platform exception.
- Per-host, wildcard, suffix, CIDR, path, account, or client-specific TLS rules.
- User/RBAC expansion, certificate issuance, private-key storage, automatic CA
  rotation/rebind, mutable aliases, or external secret providers.
- Hard termination of in-flight sessions when a policy changes.

## Create-form closure correction (2026-08-19)

Platform creation is part of the same complete configuration task as Platform
editing. The create form therefore exposes the existing HTTPS certificate
verification controls and submits them in the original `POST /platforms`
command; it must not create a Platform first and issue a second TLS request.

- The POST request keeps its legacy flat Platform fields and legacy flat
  `PlatformResponse` response for compatibility, with one optional
  `tls_policy` request member.
- Omitting `tls_policy`, or selecting `VERIFY`, creates a strict Platform with
  no active policy row. `TRUST_CUSTOM_CA` and `BYPASS` use expected policy
  version `0` and create their active row plus history event in the same SQL
  transaction as the Platform row.
- Runtime Platform registration and the initial TLS snapshot publish together
  under the existing publication gate. Any validation, CA integrity, name,
  history, or SQL failure leaves no Platform, policy, history, or runtime
  registration behind.
- The create form reuses the edit form's TLS fields and governance. Its
  default expiry is generated when the form is opened/reset, not once at
  module load.

The BYPASS reason labels are state-dependent: first enablement shows only
`跳过证书校验的原因（必填）`; an existing exception shows `当前原因`; an
extension or conversion to permanent shows `当前原因` plus
`本次变更原因（必填）`. The current reason remains read-only and is never
copied into the new-change input.

The correction is covered by red-to-green state, service, API, and WebUI
regressions for VERIFY/custom-CA/BYPASS creation, expected-version and
missing-CA failures, rollback/no-partial-state, publication ordering, fresh
expiry defaults, and the reason-label matrix.

## Closure audit corrections (2026-08-20)

- A Platform candidate may wait behind the shared publication gate while node
  state changes. Publication therefore performs one final non-failing routable
  view rebuild under the pool write lock before installing the runtime pointer;
  dirty notifications that race with that rebuild are replayed after install.
- Unexpected state-store or transaction failures are represented by a distinct
  persistence sentinel and map to `500 INTERNAL`. Mutation validation remains
  `400 INVALID_ARGUMENT`, missing CA remains `404`, and optimistic conflicts
  remain `409`; no storage failure is silently classified as user input.
