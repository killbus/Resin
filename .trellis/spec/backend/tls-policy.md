# Reverse HTTPS TLS Policy

> Executable contracts for platform-scoped reverse-proxy TLS verification.

## Scope

TLS verification is one optional setting per custom platform. It applies to all
reverse HTTPS requests using that platform, before direct/routed egress is
selected. It is not a target matcher or target authorization mechanism.

The built-in `Default` platform is always strict VERIFY. Forward proxy, CONNECT,
SOCKS5, HTTP targets, and probes do not consume platform TLS policy.

## Modes

| Mode | Stored | Required | Forbidden |
|------|--------|----------|-----------|
| `VERIFY` | no active row | none | policy row |
| `TRUST_CUSTOM_CA` | yes | immutable `bundle_id` | reason, expiry |
| `BYPASS` | yes | non-empty reason and explicit expiry presence | bundle |

Custom CA augments `x509.SystemCertPool()` and preserves hostname/SNI, validity,
and chain verification. BYPASS disables chain and hostname verification and is
never an automatic fallback.

For BYPASS, API `expires_at: null` means permanent; otherwise the timestamp must
be in the future. Extending a temporary exception or making it permanent
requires a newly supplied reason. At expiry, new requests use VERIFY.

## Ownership

- `CABundleRegistry`: bounded PEM validation, canonicalization, versioned
  fingerprint dedupe, immutable storage, integrity read, metadata/history, and
  reference-aware deletion. Every successful import outcome is auditable: a
  new bundle emits `CREATE`, while a fingerprint match emits `REUSE` against
  the existing immutable bundle ID. Rejected input and fingerprint collisions
  do not create lifecycle events. Canonical PEM is the active-record source of truth;
  verified reads revalidate it and derive certificate identity metadata after
  restart instead of persisting a second, drift-prone active metadata copy.
- `PlatformTLSPolicy`: one optional active policy per custom platform, CAS
  mutation, PEM-free history, runtime snapshots, expiry publication, and
  profile retirement. It accepts bundle IDs, never PEM.
- `ReverseRequestResolver`: platform lookup and TLS policy resolution before
  egress choice. Request target remains SNI/audit context, not a policy key.
- `OutboundTransportPool`: constructs/cache transports from complete immutable
  profiles. Forward always uses canonical VERIFY.
- Failure attribution and health feedback remain dedicated boundaries.

## API

```text
GET/POST /api/v1/ca-bundles
GET/DELETE /api/v1/ca-bundles/{bundle_id}
GET /api/v1/ca-bundles/{bundle_id}/history

GET    /api/v1/platforms/{platform_id}/tls-policy
PUT    /api/v1/platforms/{platform_id}/tls-policy
DELETE /api/v1/platforms/{platform_id}/tls-policy
GET    /api/v1/platforms/{platform_id}/tls-policy/history
```

GET returns effective VERIFY/version 0 when no active policy exists. PUT create
uses `If-None-Match: *`; replacement and DELETE use the positive current version
through `If-Match`. Default-platform relaxation is rejected at every mutation
entry point.

No response or log exposes canonical PEM. CA bundle history retains verified,
PEM-free certificate metadata (Subject, Issuer, serial, and validity) together
with request and credential context, including after the active bundle is
deleted. The history metadata is a deletion-surviving audit snapshot, not an
alternative active CA source of truth. Request logs and compatibility
singular-policy/history responses do not expose BYPASS reasons. The aggregate
Platform management configuration may return the current reason because that
screen owns the exception lifecycle. In the form, the current reason is a
read-only value in the same TLS reason context; a blank “reason for this
change” field is progressively disclosed only for BYPASS enablement, expiry
extension, or permanent conversion. If that change is withdrawn, the draft
reason is cleared and omitted from the payload.

The recorded credential class reflects the actual control-plane authentication
mode: `SHARED_ADMIN_TOKEN` for a request authenticated by the configured shared
token, or `AUTH_DISABLED` when an explicitly empty admin token leaves the API
unauthenticated. It never invents a per-user/operator identity.

Both singular and aggregate custom-CA writes recheck bundle existence and
fingerprint inside their persistence transaction, so a concurrent bundle
deletion cannot leave a dangling policy.

## Scenario: Atomic Platform Configuration

### 1. Scope / Trigger

This contract applies when a Platform form changes ordinary Platform fields and
HTTPS verification together, and when a Platform is deleted. It prevents a
saved Platform from exposing a new routing object with an old TLS snapshot (or
the reverse), prevents deletion from exposing a still-routable Platform with a
removed TLS policy, and prevents a stale form from overwriting a concurrent
singular Platform/TLS mutation.

### 2. Signatures

```text
GET /api/v1/platforms/{id}/configuration
PUT /api/v1/platforms/{id}/configuration
DELETE /api/v1/platforms/{id}
If-Match: "<config_version>"
```

The PUT body has a complete `platform` object and an optional `tls_policy`.
`StateRepo.ApplyPlatformConfiguration(platform, expectedConfigVersion,
ConfigurationMutation)` writes Platform, active policy, and policy history in
one SQL transaction. `ControlPlaneService.PublicationGate` and the reverse
resolver share one `*sync.RWMutex`.

Platform deletion uses
`PolicyService.DeletePlatformWithPublication(platformID, audit, publish)` so
the service can publish runtime removal and the prepared TLS snapshot inside
the same write-gate callback after the delete transaction commits.

### 3. Contracts

- GET/PUT response: `{ platform, tls_policy, config_version }` plus an ETag
  equal to `config_version`.
- Omitting `tls_policy` means “keep the current policy”, including an expired
  BYPASS record; it is not an implicit VERIFY request.
- Sending VERIFY removes the active policy row. A no-op BYPASS submission does
  not append history and does not require a new reason.
- Platform-only legacy PATCH and singular TLS mutations increment the same
  aggregate `config_version`. The legacy reset action resets the complete
  Platform configuration, atomically removes any active TLS policy, appends
  revocation history, and advances `config_version` once.
- Before commit, compile the Platform runtime and TLS profile. After commit,
  acquire the publication write gate, perform one non-failing final rebuild of
  the candidate routable view while the pool write lock blocks dirty
  notifications, then publish the prepared Platform and TLS snapshot and
  release the gate. Notifications racing with the rebuild are replayed against
  the newly registered Platform. A request resolver holds the read gate while
  capturing both objects; routed reverse execution uses that captured Platform
  and never resolves its name a second time.
- Platform deletion first commits Platform removal, active-policy removal, and
  terminal history. It then acquires the same write gate, unregisters the
  runtime Platform, and publishes the snapshot without that policy before
  releasing the gate. Readers observe either the complete old pair or a missing
  Platform, never a live Platform whose removed policy has fallen back to
  VERIFY.

### 4. Validation & Error Matrix

| Condition | Result |
|---|---|
| Missing/invalid `If-Match` | `400 INVALID_ARGUMENT` |
| Stale aggregate version | `409 CONFLICT`, no Platform/TLS/history write |
| Stale policy version | `409 CONFLICT`, no Platform/TLS/history write |
| Missing/damaged CA bundle | `404` or `500` integrity error, no partial write |
| Invalid Platform fields | `400 INVALID_ARGUMENT`, no partial write |
| Default + non-VERIFY policy | `400`, no policy/history write |
| History/SQL commit failure | transaction rollback, no runtime publication |
| Platform delete transaction failure | Platform and TLS runtime remain published |

### 5. Good/Base/Bad Cases

- Good: save a renamed Platform and custom CA together; response and next
  request observe the same `config_version` generation.
- Good: delete a Platform with BYPASS; an in-progress resolver keeps its old
  Platform/BYPASS capture, while every resolver after publication sees the
  Platform as missing.
- Base: save only a Platform field while omitting `tls_policy`; an expired
  BYPASS remains persisted for audit and still evaluates to VERIFY for new
  requests according to expiry semantics.
- Bad: resolve a Platform by name, publish TLS, then resolve the name again in
  the router; a rename can produce a mixed Platform/TLS decision.
- Bad: publish the policy-free TLS snapshot before unregistering the Platform;
  a concurrent request can route the deleted Platform under VERIFY.

### 6. Tests Required

- API: authoritative response/ETag, omitted policy, VERIFY deletion, Default
  rejection, stale aggregate/policy conflicts, management reason visibility,
  configured/effective expiry state, and compatibility endpoint redaction.
- State: transaction rollback at Platform, policy, CA-integrity, and history
  failure points; no partial history.
- Runtime: read/write gate blocks mixed generations; resolver captures the
  same Platform object used by `RoutePlatformRequest` after a rename. Holding a
  publication read lock across deletion keeps both the runtime Platform and old
  TLS policy visible until release, after which both are absent.
- WebUI: one Save Config request; unchanged TLS is omitted; BYPASS enable,
  extension, permanent conversion, and shortening enforce the reason matrix;
  current and per-change reasons stay distinct; expired configured/effective
  state is visible; CA identity comes from verified certificate metadata; CA
  table scrolls inside its card on mobile.

### 7. Wrong vs Correct

#### Wrong

```text
platform PATCH -> commit -> resolve TLS separately -> router.GetPlatformByName
```

This permits partial persistence and a second Platform generation during one
request.

#### Correct

```text
validate/prepare Platform + TLS
  -> one SQL transaction + aggregate CAS
  -> shared write-gate publication
  -> resolver read-gate capture
  -> RoutePlatformRequest(capturedPlatform)

delete Platform + terminal TLS history in one transaction
  -> shared write gate
  -> unregister runtime Platform + publish policy-free snapshot
  -> release readers
```

## Persistence

```text
ca_bundles
ca_bundle_history
platform_tls_policies       UNIQUE(platform_id)
platform_tls_policy_history no cascading FK to active objects
```

Active policy and history mutation are atomic. Platform deletion appends a
terminal policy event before deleting active state, then publishes runtime
Platform removal and TLS removal under one shared gate. History is evidence,
not a runtime replay source.

## Publication and revocation

1. Validate the complete candidate policy and referenced bundle.
2. Construct the candidate immutable snapshot/profile before commit.
3. Commit active state and history under CAS.
4. Publish the new generation and retire obsolete cached profiles.
5. Expose the new snapshot to request decisions.

Old idle connections close. Requests/streams/upgrades captured before
publication may drain. Temporary BYPASS expiry schedules the same publication
path at the exact boundary.

## Failure attribution

Target identity/service, local policy, client, and unknown failures never create
negative node health. The standard sing-box composite dial error remains
`OpaqueRoutedDialFailure` and Unknown. Only explicit producer-side
`NodeTransportFailure` evidence allows negative feedback. Direct requests emit
no node feedback; routed success retains positive feedback.

## UI contract

- Platform TLS controls live in the existing platform `配置` tab.
- User labels are `使用系统证书`, `使用自定义 CA 证书`, and `跳过证书校验`.
- Default is read-only strict verification.
- Central CA UI is named `CA 证书`; it uses ordinary resource language and does
  not expose registry, immutable payload, normalized target, CAS, or JSON-null
  terminology.
- BYPASS visibly states that CA, validity, and hostname checks are disabled, and
  offers `到指定时间` / `长期有效` rather than storage representation terms.

## Required tests

- Domain/state/API: discriminated modes, singular policy per platform, Default
  rejection, CAS, history, bundle references/integrity, redaction, migration,
  restart.
- TLS/runtime: multiple targets under one platform, direct/routed parity,
  system-root plus custom-root acceptance, SAN/expiry/wrong-CA rejection,
  BYPASS/expiry, generation publication, cache retirement, forward isolation.
- Attribution/audit: explicit node proof, opaque composite failures, direct no
  feedback, routed success, actual target plus policy metadata, no secrets.

## Forbidden patterns

- Per-target/wildcard/path/CIDR TLS rules inside this feature.
- Configurable TLS relaxation for `Default` or system-global policy.
- Treating `ProxyBypassRules` as trust or authorization.
- Retrying a failed custom-CA connection with weaker verification.
- Logging/returning PEM, or returning BYPASS reason outside the aggregate
  management configuration that owns it.
- Mutating a shared CA bundle in place or automatically rebinding platforms.

## Platform creation contract

Platform creation is another entry point to the same aggregate configuration,
not a two-request compensation workflow. `POST /api/v1/platforms` retains its
legacy flat Platform fields and flat response, and accepts one optional
`tls_policy` request member. Omission and `VERIFY` both mean no active policy;
custom CA and BYPASS require expected policy version `0`.

The service prepares the runtime Platform and TLS candidate before persistence.
The state layer inserts Platform (`config_version=1`), optional active policy,
and optional history in one SQL transaction, rechecking custom-CA existence
and fingerprint there. The shared publication gate then performs the final
non-failing routable-view rebuild and publishes the prepared Platform and TLS
snapshot together. Any validation, CA, name, history, or commit failure must
leave no persisted or runtime partial state.
Unexpected storage failures are wrapped as a persistence error and map to
`500 INTERNAL`, rather than being mistaken for mutation validation
(`400 INVALID_ARGUMENT`).

The WebUI create form uses the same TLS fields and governance as edit. VERIFY
is omitted from its payload. Temporary expiry defaults are generated per form
open/reset. BYPASS reason presentation is a state matrix: first enablement has
only `跳过证书校验的原因（必填）`; an existing exception displays read-only
`当前原因`; extension/permanent conversion displays that plus a blank
`本次变更原因（必填）`. Never reuse the visible current reason as the new
change input.
