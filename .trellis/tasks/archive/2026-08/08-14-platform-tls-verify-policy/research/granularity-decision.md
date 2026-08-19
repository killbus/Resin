# Research - trust-policy granularity decision

> **Superseded decision record (2026-08-19):** The exact-target model below was
> an intermediate assistant recommendation and is not the implemented product
> contract. Repository evidence subsequently established Platform as Resin's
> existing whole-request configuration boundary, with one optional TLS policy
> per custom Platform. See [`assumption-correction.md`](./assumption-correction.md),
> [`../prd.md`](../prd.md), and [`../design.md`](../design.md). The remainder is
> retained only as design-history context.

Status: **target matcher and persistence owner resolved**.

## Question

The target scope is one exact normalized HTTPS `host:port` within a platform.
The selected persistence model uses independently versioned platform child rules,
a central immutable content-addressed CA bundle registry, and lifecycle-independent
PEM-free history.

## Previous decision (2026-08-14)

The initial review selected **per-platform** because platform is the existing
persisted policy entity, account is runtime routing data, host is client input,
and a global setting would poison the shared forward/reverse transport pool.

The following parts remain valid:

- Account is not a suitable trust-policy owner. It is runtime-extracted,
  client-influenced routing identity, not persisted configuration.
- A global TLS relaxation is unacceptable because forward and reverse share an
  outbound HTTP transport pool.
- Any reusable transport must be isolated by TLS profile, and forward must use
  the strict VERIFY profile.
- The built-in Default path must remain strict and fail closed.

## Why the decision was reopened

The prior argument conflated target selection with target authorization:

> The host is client input, therefore a per-host policy lets the client choose
> its trust mode.

That implication is invalid. A client can select a target while an
operator-controlled matcher independently decides whether that target is
authorized for additional trust. Platform is also selected by the client under
the current shared-token model, so client influence alone does not distinguish
platform from host.

The initial decision also optimized for the existing persistence pipeline
before establishing the authorization boundary. A platform may still be the
storage owner, but current evidence does not justify a platform-wide rule that
applies to every target selected under that platform.

## Grounded implications

1. `ProxyBypassRules` cannot serve as the missing target authorization layer.
   It selects direct versus routed dialing and has no deny semantics, subject,
   platform, TLS mode, or trust material.
2. Platform-wide BYPASS would authorize certificate-verification bypass for
   every reverse HTTPS host reachable under a named platform. Default lock does
   not constrain that named-platform authorization surface.
3. The operator-controlled matcher is exact normalized HTTPS `host:port`.
   Hostname suffix, wildcard, CIDR, URL path/prefix, and platform-wide matching
   are rejected because they broaden custom trust or BYPASS beyond the named
   target.
4. Direct and routed transport must consume the same resolved trust decision.
   Egress choice must not determine authorization or TLS identity semantics.

## Resolved product boundary

- Only a request authorized by the shared admin token configures a rule; Resin
  cannot identify a distinct administrator.
- One rule matches one exact HTTPS `host:port` within a valid platform.
- Requests presenting the current shared proxy token observe the same rule set;
  this task does not add client-specific identity or permissions.
- No rule means VERIFY. An explicit rule selects TRUST_CUSTOM_CA or BYPASS.
- Direct and routed reverse paths consume the same decision.

## Persistence candidates

- Platform-owned target trust rules: platform remains the persistence owner,
  with exact-target rules stored as children rather than platform-wide columns.
- Independent target trust rules: rules are stored separately and may be
  referenced by one or more platforms.

## Resolution

An active rule is stored as its own row but owned by exactly one platform. This
preserves exact-target CRUD/versioning without creating reusable cross-platform
authorization. CA material reuse is a separate concern: `CABundleRegistry`
deduplicates immutable canonical certificate sets, while `PlatformTLSPolicy`
binds one exact-target rule to a specific `bundle_id`. Import never grants trust,
and rotation requires an explicit version-CAS rebind.

Configuration history has no cascading foreign key to platform, active rule, or
bundle. It snapshots IDs/fingerprints and survives deletion without becoming a
runtime policy source.

## Evidence needed for the persistence decision

- Whether rules need reuse across platforms.
- Required CRUD/list/detail API and WebUI workflows.
- Atomic platform/rule update and deletion behavior.
- Restart, rollback, rotation, and audit-history requirements.

These requirements are now selected in the PRD/design. Remaining work concerns
history retention, revocation completion, and failure attribution rather than
ownership or root composition.
