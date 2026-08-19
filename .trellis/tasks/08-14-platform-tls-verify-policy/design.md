# Design - reverse HTTPS exact-target TLS verification policy

Status: **implemented; task-scoped build, tests, and WebUI build pass**.

## Design objective

Separate four decisions that the current reverse path and the previous draft
partly conflated:

1. Is the request authorized to use the selected platform and target?
2. What TLS identity policy applies to that target?
3. Should the request dial directly or through a Resin node?
4. If the attempt fails, which system component (if any) owns the failure?

The first two decisions must be identical for direct and routed traffic. Egress
selection cannot grant access or relax target identity verification.

## Pre-implementation flow problem

The earlier reverse handler parsed the path and account, built the target, and
then branches on `ProxyBypassRules` before `Router.RouteRequest`. A bypass match
therefore creates a direct transport without requiring a valid routed platform.
Platform/target trust logic added only to the routed branch would have created
two policy, audit, and failure-attribution chains.

`ProxyBypassRules` is also shared transport-routing configuration. It has no
subject, platform, trust material, TLS mode, or deny semantics, so it cannot be
used as the missing target authorization layer.

## Implemented module boundaries

### 1. CA bundle registry

`CABundleRegistry` is a central immutable trust-material store, not an
authorization or PKI service. It owns:

- complete PEM input decoding, size/count bounds, X.509 CA validation, and
  deterministic canonicalization;
- versioned content fingerprinting, canonical-byte collision confirmation, and
  idempotent create-or-return-existing import;
- immutable canonical PEM persistence, metadata/integrity reads, active-reference
  checks and explicit delete-if-unused.

It does not know platform targets, create or rebind TLS rules, publish runtime
policy, rotate rules automatically, or expose a mutable/latest alias. Importing
a bundle may produce a valid unused object and has zero effect on request
authorization. An import followed by a failed bind leaves that staged object for
explicit cleanup; it is not immediately deleted because a
concurrent rule may already reference the deduplicated bundle.

Bundle semantics are set-based. The decoder completely consumes bounded input
and accepts only headerless `CERTIFICATE` PEM blocks. It rejects empty input,
private keys, unknown block types, PEM headers, trailing non-whitespace data,
parse failures, and certificates that are not CA-capable. Each certificate's
complete DER is its identity. Exact duplicate DER entries are removed, remaining
entries are ordered by their individual SHA-256 digests, and the bundle digest
is SHA-256 over a domain-separated canonicalization version plus length-framed
DER values. The database stores the algorithm/canonicalization version and
canonical bytes. A unique-fingerprint conflict compares canonical bytes before
returning the existing bundle.

Conceptually:

```go
type CABundleRef struct {
	ID                      string
	Fingerprint             string
	CanonicalizationVersion uint16
	CertificateCount        int
}

type VerifiedCABundle struct {
	Ref          CABundleRef
	CanonicalPEM string
}
```

This read-only verified bundle view is the only runtime material handoff from
Registry to policy compilation. Policy persists and accepts only `bundle_id`;
it may consume canonical PEM from this view to construct a TLS profile but never
parses, normalizes, mutates, or persists that PEM itself.

The registry may be exposed through the same shared admin token as policy APIs,
because Resin has no RBAC. The module split represents different mutation and
lifecycle boundaries; it does not invent CA-manager and policy-manager actor
identities.

### 2. Platform TLS policy configuration and evaluator

Raw persisted/API fields do not flow into the reverse handler. A dedicated
`PlatformTLSPolicy` boundary validates rule structure on write and startup load:

- platform ownership, normalized exact HTTPS `host:port`, and
  `UNIQUE(platform_id, normalized_target)`;
- legal mode/material combinations;
- immutable bundle existence/integrity for TRUST_CUSTOM_CA, resolved through
  `CABundleRegistry` only after the exact-target rule is authorized;
- BYPASS `reason` presence and content constraints: creating or switching to
  BYPASS requires an explicit trimmed non-empty value; an unchanged expiry may
  retain it, while extending an expiry or making it permanent requires a new
  value;
- required three-state `expires_at` decoding: create omission is invalid,
  explicit JSON `null` is permanent, and a non-null value is a future RFC3339
  timestamp; replacement omission means unchanged and explicit `null` means
  permanent;
- stable policy ID/version and safely encoded audit metadata.

The domain policy is a discriminated union, not one freely constructible struct
with nullable fields:

```go
type ConfiguredTLSPolicy interface {
	isConfiguredTLSPolicy()
}

type CustomCAPolicy struct {
	BundleID string
}

type BypassPolicy struct {
	Reason    string
	ExpiresAt *time.Time // nil means permanent after presence-aware API decoding
}
```

The implementation uses a discriminated mutation/record model that enforces
this state matrix:

| Effective configured state | Bundle ID | Reason | Expires at |
| --- | --- | --- | --- |
| no row = VERIFY | prohibited | prohibited | prohibited |
| TRUST_CUSTOM_CA | required and resolvable | prohibited | prohibited |
| BYPASS | prohibited | required and non-empty | required on create; persisted `NULL` means permanent |

API DTOs preserve field presence and reject unknown or cross-mode fields. A
mode switch submits a complete new variant; it is not a generic merge that can
retain fields from the old mode. One policy compiler owns target normalization,
the state matrix, version CAS, bundle binding, and time-aware write validation.
It never accepts or parses raw PEM. The repository and startup loader invoke the
policy compiler instead of reimplementing mode checks. Runtime policy and proxy
types expose only compiled variants with a verified resolved bundle.

A first-version single table may use nullable storage columns only when SQL
`CHECK` constraints enforce `mode IN ('TRUST_CUSTOM_CA','BYPASS')`, positive
versions, and the required/prohibited column combinations above. An active
custom-CA rule has a restrictive foreign key to an immutable bundle. SQL does
not verify bundle contents or decide whether a timestamp is in the future;
these remain registry/policy responsibilities. Loading resolves every active
bundle and recomputes its content fingerprint. A corrupt/dangling reference
fails initial startup or rejects a replacement runtime snapshot; it is never
discarded and reinterpreted as the absence of a rule.

Active policy state and version history are separate persistence contracts.
The active-rule table is the only source for executable startup/runtime state.
An application-append-only history table records configuration transitions and
is never replayed as current policy. It has no cascade-delete foreign key to the
active rule or platform; instead it snapshots the rule ID, platform ID and name,
normalized target, event kind, old/new version and mode, old/new bundle ID and
CA fingerprint,
BYPASS reason/expiry when applicable, event time, request correlation ID, remote
address when available, and shared credential class. It stores neither PEM nor
token values and does not claim a natural-person actor. Application append-only
does not claim tamper resistance against an administrator with direct database
file access.

Registry lifecycle history is a separate application-append-only, PEM-free
stream owned by `CABundleRegistry`, with no cascading FK. It records first
creation and explicit delete-if-unused using bundle ID, fingerprint,
canonicalization version, certificate count, event kind/time, request correlation
ID, and remote address when present. An idempotent dedup hit does not create a
new configuration version; ordinary request/result audit may still observe it.

Configuration event kinds are finite and explicit: create, full mode
replacement, CA rotation, BYPASS renewal/permanent conversion, explicit rule
revocation, and platform/rule deletion. Natural BYPASS expiry is already fixed
by the version's `expires_at`; request audit records effective VERIFY fallback,
so expiry does not require a racing background history writer.

All active-rule mutations use one optimistic-concurrency contract. Create is a
CAS against absence (`If-None-Match: *` or expected version 0). Full replacement,
bundle rebind, BYPASS renewal/permanent conversion, revoke, and delete require
the current positive version (`If-Match` or `expected_rule_version`). The CAS,
history append, and active-row mutation occur in one SQL transaction. A unique
constraint conflict on concurrent create maps to the same version-conflict API
contract rather than producing ambiguous history.

Deleting a rule or platform uses one state-database transaction: snapshot the
affected active rules, append their terminal events plus the platform deletion
event, then remove active rows/platform state. Commit precedes publication of a
new immutable runtime snapshot and retirement of affected idle transports. A
crash after commit reloads the revoked state on restart; a failed transaction
leaves both active state and history unchanged. Rule and bundle lifecycle
history are retained indefinitely: there is no purge or archival path, and
deletion of active state never cascades into history.

A runtime evaluator consumes an immutable policy snapshot, normalized target,
and injectable clock. It performs exact matching and time-dependent expiry
evaluation, then returns either an immutable `ResolvedTLSPolicy` or a typed
denial. At `now >= expires_at`, a temporary BYPASS produces a resolved strict
VERIFY policy rather than a pre-dial denial. This ends the verification exception
without turning it into target-access authorization.
Permanent policies carry no deadline and therefore never enter the time-based
expiry branch. Zero time or a sentinel timestamp is not a permanent-policy
representation.

Neither `ReverseProxy.ServeHTTP` nor `ReverseRequestDecision` parses raw policy
fields, supplies defaults, calls `time.Now` for policy expiry, or interprets an
expired BYPASS rule.

### 3. Reverse request decision resolver

A shared resolver runs after path/target parsing and before egress selection.
It asks the TLS policy evaluator for an already validated result and returns one
immutable request decision:

```go
type ReverseRequestDecision struct {
	PlatformID      string
	PlatformName    string
	NormalizedTarget NormalizedTarget
	Authorization  TargetAuthorization
	Policy          ResolvedTLSPolicy
	TLSProfile      tlsProfile
	PolicyVersion   string
	AuditContext    ReversePolicyAuditContext
}
```

The concrete implementation is `ReverseRequestDecision`; its contract is:

- resolve one platform snapshot and reject a missing platform;
- normalize scheme, host, and port before matching;
- consume only the evaluator's validated exact-target policy result;
- derive an effective TLS profile from that result or fail closed;
- capture a stable policy identity/version for audit and revocation semantics;
- perform no node selection, lease creation, or network I/O.

### 4. Egress selector

After a valid request decision exists:

- `ProxyBypassRules` chooses direct versus routed transport only;
- direct chooses the local dialer and creates no node lease/health attribution;
- routed calls `Router.RouteRequest` and selects a node/outbound;
- both paths consume the decision's same TLS profile and audit context.

This intentionally changes the current behavior for a bypass-matched request
that names a missing platform: the request will fail before dialing. That is a
compatibility change requiring explicit documentation and tests.

### 5. TLS profile and transport pool

The previous review established that a cache key alone loses the information
needed to construct a custom TLS transport. Keep a complete immutable profile:

```go
type tlsProfile struct {
	key               string
	mode              platform.ReverseProxyTLSVerify
	rootComposition   RootComposition
	bundleFingerprint string
	caPEM             string
}
```

Profile constructors validate the selected mode/material and compute the key.
Fields are not mutated after construction. The pool uses `profile.key` for
lookup and `profile.mode`/`profile.caPEM` to build `TLSClientConfig`.
The key includes effective mode and root-composition semantics. Custom CA also
includes the immutable bundle fingerprint. BYPASS profiles are scoped by
platform and exact target so a verification-disabled connection cannot cross an
authorization boundary even when policy modes match.

The first version has one custom-root composition: target-exclusive. A matched
TRUST_CUSTOM_CA profile builds `RootCAs` only from its verified bundle and keeps
hostname/SNI, validity, and chain verification enabled. It does not append or
consult system roots, and any custom-chain failure is terminal for that attempt.
An unmatched target continues to use the canonical system-root VERIFY profile.

The shared pool is isolated by `(node.Hash, profile.key)` for routed traffic;
forward always passes the canonical VERIFY profile. Direct reverse traffic uses
an equivalent profile-aware cache/lifecycle. Transport creation errors
propagate; an invalid non-VERIFY profile never falls back to VERIFY.

Node eviction closes and removes all profiles for that node. Policy replacement,
revocation, and BYPASS expiry also remove obsolete profile indexes and close
their idle connections.

Every resolved non-VERIFY profile carries the immutable policy snapshot
generation that authorized it. The transport pool serializes snapshot
publication with direct/routed cache acquisition: publication installs the new
generation and active profile-key set before retiring obsolete indexes. A
request that captured an older generation may still drain using a newly built,
non-cached transport, but it cannot reinsert that profile into either cache.
Policy publication also schedules the earliest temporary BYPASS deadline; at
the exact `now >= expires_at` boundary it publishes a new generation and active
profile set without mutating configuration history or waiting for another
request.

### 6. Failure attribution

Keep symptom classification (`upstream_err_kind`) separate from causal
attribution and health action:

```go
type FailureAttribution string

const (
	FailureNode           FailureAttribution = "Node"
	FailureTargetIdentity FailureAttribution = "TargetIdentity"
	FailureTargetService  FailureAttribution = "TargetService"
	FailureClient         FailureAttribution = "Client"
	FailureLocalPolicy    FailureAttribution = "LocalPolicy"
	FailureUnknown        FailureAttribution = "Unknown"
)
```

The error boundary produces symptom detail, attribution, and whether negative
node health may be updated. `TargetIdentity`, `TargetService`, `LocalPolicy`,
`Client`, and `Unknown` never update negative node health.
X.509/hostname/CA/profile errors belong to target identity or local policy, not
directly to node health.

The evidence threshold for `FailureNode` is deliberately conservative. Only an
error explicitly wrapped as `NodeTransportFailure`, proving a failure on the
selected Resin node transport path, qualifies. Untyped DNS, timeout, refusal,
reset, target TLS anomalies, and generic round-trip errors remain `Unknown` or
another non-node category unless such explicit boundary proof exists.

The selected routed outbound adapter's `DialContext` is not a node-only proof
boundary. Standard sing-box SOCKS and HTTP outbounds combine the configured-node
dial with target SOCKS/CONNECT negotiation in that one call and expose no typed
phase result. Resin therefore wraps its untyped/composite errors only as
`OpaqueRoutedDialFailure`, which is attributed `Unknown` before X.509 symptom
classification and never permits negative node health. This deliberately accepts
false-negative passive health feedback rather than opening a node circuit for a
target refusal or proxy 502. Direct dial errors remain non-node-attributed.

An explicitly nested `NodeTransportFailure` is still accepted as proof if a
future lower-layer producer can identify the selected-node connection or
handshake phase. The standard sing-box adapters in the current wiring do not
produce that evidence. Routed success continues to provide positive/reset
feedback, and active probes remain independent of this conservative passive
failure contract.

Implement this as an independently testable boundary rather than another branch
inside `ReverseProxy.ServeHTTP`. Conceptually:

```go
type FailureAssessment struct {
	Detail            upstreamErrorDetail
	Attribution       FailureAttribution
	NegativeNodeHealth bool
}

type FailureAttributor interface {
	Assess(stage string, err error, decision ReverseRequestDecision) FailureAssessment
}

type HealthFeedback interface {
	Record(route *routing.RouteResult, assessment FailureAssessment)
}
```

The implemented `FailureAttributor` and `ReverseHealthFeedback` interfaces keep
symptom classification and causal attribution pure/testable logic;
health feedback consumes an assessment and refuses negative updates unless the
assessment explicitly permits them. The reverse handler never derives health
eligibility from an error string or X.509 type inline.

The health-feedback collaborator is the only reverse request-outcome component
allowed to call the existing `HealthRecorder`. Direct attempts produce no node
feedback, represented by a nil route at this conceptual boundary rather than a
fabricated node identity. Routed successes retain the current positive
feedback/reset semantics; whether that broader node-health model should change
is outside this TLS task unless Phase 0 explicitly brings it into scope.

### 7. Reverse handler orchestration

`ReverseProxy.ServeHTTP` remains the coordinator for HTTP lifecycle mechanics,
but the TLS feature must not expand it into the owner of policy semantics or
health causality. Its target flow is:

```text
parse request
  -> resolve ReverseRequestDecision
  -> select direct/routed egress
  -> execute through the selected transport
  -> delegate failure assessment
  -> delegate permitted health feedback
  -> emit correlated request/audit outcome
```

The handler may assemble inputs and dispatch collaborators. It does not parse CA
material, choose trust defaults, authorize targets, decide whether a symptom is
node-caused, inspect `reason`/`expires_at`, evaluate policy time, call
`HealthRecorder` directly for request outcomes, or format raw security audit
lines. Unit tests own configuration validation, policy evaluation, resolver,
attributor, and health-feedback behavior separately; handler tests verify only
the orchestration and end-to-end lifecycle contract.

## Stable security invariants

- Default behavior is strict system-root plus hostname verification.
- Missing/invalid/unknown authorization fails before network I/O.
- Custom CA never disables hostname/SNI verification.
- Custom CA is target-exclusive and never augments or falls back to system roots.
- BYPASS is reachable only from an explicit exact-target administrator rule; it is
  never selected by fallback or a broader matcher.
- Forward cannot receive a reverse non-VERIFY transport profile.
- Direct/routed selection cannot change authorization or TLS identity policy.
- Client-controlled audit values are safely encoded.
- A target identity/target service/local policy failure cannot directly punish
  node health.

## Resolved contract decisions

### Trust rule owner and target matcher

The matcher is fixed: one administrator-configured exact normalized HTTPS
`host:port`, applied within a valid platform and shared by clients under the
current proxy token. An active rule is an independently versioned row owned by
one platform, with `UNIQUE(platform_id, normalized_target)`. Platform deletion
uses the explicit history-first transaction above rather than cascade deletion.
This is a platform child-resource lifecycle, not platform-wide TLS policy.

### Custom CA semantics

The approved responsibility boundary is consumption of control-plane-provided
public CA trust anchors. `CABundleRegistry` validates and persists immutable,
content-addressed bundles; `PlatformTLSPolicy` binds a platform exact-target rule
to a bundle ID. Import and bind are separate. Import has no runtime effect, and
policy never accepts or parses PEM. Invalid input is rejected before bundle
persistence; a missing, malformed, or fingerprint-mismatched referenced bundle
fails closed at load/snapshot publication. Resin does not generate or retain CA
private keys, issue or renew certificates, operate PKI/CRL/OCSP services, or
modify the host's global root store.

Custom trust composition is fixed as target-exclusive. For a matched exact
platform/target rule, a new pool contains only the bound immutable bundle. This
is a target-scoped replacement, never a global/platform replacement. System-root
augmentation is excluded because OS/container root changes would silently alter
the effective trust set and make a bundle fingerprint insufficient to explain an
accepted chain. A chain that does not terminate at a bundle anchor fails without
fallback; services must send necessary intermediates. Public/private CA
transitions use an explicit transitional bundle containing the intended anchors,
followed by version-CAS rebind and later cleanup.

External secret references are excluded from the first version because Resin
has no secret-provider/version-pinning boundary and must retain deterministic
startup and rollback behavior. Full PEM is internal trust material: list
responses, ordinary logs, and audit event bodies expose only non-secret policy
metadata and fingerprints. The registry bounds input bytes, certificate count,
and individual certificate size. It exposes import/dedup, metadata/detail,
delete-if-unused, and explicit cleanup only; named version families, `latest`,
automatic discovery/rotation/rebind, and global default trust are excluded.

### BYPASS

`BYPASS` is part of the design target for an explicit
administrator-configured exact normalized HTTPS `host:port`. Its transport
profile disables certificate-chain and hostname verification for that target
only. It must not be inferred from a TLS failure, inherited from a platform
default, or matched through wildcard, suffix, CIDR, URL path, account, or
client-controlled policy input.

Direct and routed reverse requests consume the same resolved BYPASS profile.
The profile is isolated from VERIFY, custom CA, forward, other targets, and
other platforms. Every use is correlated with the policy version and final
outcome. `expires_at` representation is fixed: explicit `null` means permanent
and a future RFC3339 timestamp means temporary. An expired temporary rule yields
strict VERIFY. A trimmed non-empty `reason` is mandatory when creating or
switching to BYPASS. PATCH may retain the existing reason only when it does not
extend the exception: extending a temporary expiry or changing it to permanent
requires a new explicit reason, and an explicit blank value is rejected. The
reason is versioned audit context, not proof of identity, authorization,
approval, target safety, or necessity. No actor-identity field is required
because the shared admin token authenticates a capability, not an individual.

The resolved audit context preserves policy ID/version, configured mode BYPASS,
effective mode VERIFY, `expires_at`, and an expiry-fallback marker. Requests
after expiry use the VERIFY transport profile and cannot reuse an idle BYPASS
connection. Expiry retires the obsolete BYPASS profile's idle connections;
in-flight and upgraded streams retain their captured policy version and
naturally drain under the handshake-scoped revocation contract.

### Explicit exclusions

Broader target matchers, platform-wide TLS relaxation, client-specific
authorization, automatic downgrade to BYPASS, and CA/PKI lifecycle management
are outside this design.

### Update and revocation

Rebind, rule deletion, and temporary BYPASS expiry share one handshake-scoped
contract: snapshot publication changes behavior for new requests; old profile
idle connections are removed and closed; existing requests, streams, and
upgrades retain their captured decision until natural completion. Hard
termination of active sessions is explicitly outside this version and must not
be implied by `effective_at` or a successful policy write.

For bundle rebind, the fixed minimum completion contract is:

1. Validate the immutable bundle, expected rule version, complete replacement
   variant, candidate runtime snapshot, and TLS profile before committing.
2. In one SQL transaction, compare-and-swap the rule version, append old/new
   bundle ID/fingerprint history, and replace the restrictive bundle reference.
3. Publish the already constructed snapshot by an infallible atomic pointer
   exchange after commit and before returning API success.
4. Remove the old profile from cache indexes and close idle connections. A
   request beginning after publication cannot resolve the old bundle.

In-flight requests, streaming responses, and 101 upgraded streams that captured
the old decision before publication naturally drain under that policy version.
This handshake-scoped contract deliberately does not hard-terminate active
sessions; runtime audit records policy version, start/end, upgrade status, and
remaining old-session count where available. A control-plane success response
must not claim that active streams were already revoked.

## Persistence, API, and WebUI

The selected data model uses separate immutable CA bundle, platform-owned active
rule, append-only rule-history, and bundle-lifecycle-history tables. Migration,
repositories, services, API normalization, WebUI, and contract tests are wired
end to end.

Registry APIs provide idempotent import, metadata list/detail, reference count,
and delete-if-unused; there is no content PATCH. Platform rule APIs provide
create/full-mode replacement/rebind/delete and accept `bundle_id` only for
TRUST_CUSTOM_CA. Bind/rebind requires `expected_rule_version` or HTTP `If-Match`.
Create requires expected absence; replace, rebind, revoke, and delete require the
current positive version under the same conflict response contract.
The PUT replacement endpoint uses a presence-aware decoder so BYPASS expiry can
distinguish omitted, explicit JSON null, and a timestamp.

The WebUI separates a CA material catalog from per-platform exact-target trust
rules. The catalog must not label an imported unused bundle as trusted. Import
returns an existing or new immutable bundle; a failed subsequent bind leaves an
unused staged bundle. Rule screens show exact authorization scope and explicitly
select a bundle. List responses, ordinary logs, and audit events do not return
full PEM. No API or WebUI accepts CA private keys.

The BYPASS create API requires an explicit `expires_at` field. Replacement retains
the distinction between omitted (unchanged), explicit `null` (permanent), and a
timestamp (temporary); ordinary `omitempty` decoding is insufficient. The WebUI
must present an explicit Permanent/Until choice and visibly label permanent
BYPASS rules. Creating or switching to BYPASS also requires an explicit trimmed
non-empty `reason`. PATCH omission preserves the reason only when the exception
is not extended; a later expiry or a change to permanent requires a new reason.
The UI must collect that new reason in those flows rather than silently reusing
the previous value.

## Audit contract

A pre-round-trip WARN cannot satisfy a requirement that includes the final
failure kind. The final mechanism must correlate at least:

- platform and policy version;
- normalized target;
- effective mode and non-secret trust-material fingerprint when applicable;
- authorization decision;
- direct/routed mode and node when present;
- final result, symptom classification, and failure attribution.

Resin has no user/RBAC or per-administrator identity model. Configuration and
request audit may record rule ID/version, timestamps, remote address, platform,
account/request context, and result, but must not label a shared-token request
as a specific person or synthesize `created_by`/`updated_by` fields.

Configuration changes use the durable append-only version-history contract
defined above. Request execution evidence is projected into the retained request
log record with normalized target, authorization decision, direct/routed egress
mode, rule ID/version, configured/effective mode, non-secret bundle fingerprint,
expired state, attribution, and final request result. BYPASS reason remains only
in protected configuration history and is not copied into per-request logs.

## Rollout and rollback

The state migration adds separate active and history tables and upgrades retained
request-log shards with the non-secret TLS outcome columns. Rollout preserves
strict behavior when no rule exists and fails closed for missing or corrupt
policy material. Bypass-matched requests with an invalid platform are rejected
before egress; contract tests cover this compatibility change.
