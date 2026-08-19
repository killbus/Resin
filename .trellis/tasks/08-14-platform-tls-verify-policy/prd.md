# Reverse HTTPS exact-target TLS verification policy

Status: **implemented - task-scoped build, tests, and WebUI build pass; untouched
repository lint/vet baseline findings are recorded in `implement.md`**.

## Goal

Allow a control-plane-configured reverse HTTPS request to establish the intended
target identity when the system root store is insufficient, without weakening
unapproved targets, forward proxy traffic, CONNECT, SOCKS5, or unrelated
platforms/nodes.

The user value is reliable access to legitimate private or enterprise HTTPS
targets while retaining an explainable, revocable trust boundary. The feature
is an administrator-configured TLS verification policy for an exact reverse target:
strict verification by default, a control-plane-provided custom CA, or an explicit
verification bypass. It is not a general CA-management system.

## Confirmed current behavior

- Reverse HTTPS uses Go's default system roots and hostname verification because
  the current transport has no `TLSClientConfig`.
- Unknown/private CAs and other certificate validation failures return HTTP 502
  `UPSTREAM_REQUEST_FAILED`; X.509 families are captured in
  `upstream_err_kind`.
- The client request selects both platform and target host. The current shared
  proxy token does not independently authorize clients to platforms/targets.
- The control plane uses one shared `RESIN_ADMIN_TOKEN`; the proxy uses one
  shared `RESIN_PROXY_TOKEN`. Resin has no user/RBAC model or authenticated
  `created_by`/`updated_by` actor identity.
- Forward and reverse HTTP share a transport pool keyed by `node.Hash`.
- `ProxyBypassRules` selects direct versus routed transport. It is not a target
  authorization policy.
- Direct reverse requests currently bypass platform existence/routing checks.
- Reverse round-trip failures other than cancellation currently feed negative
  node health, including target certificate/identity failures.

See `research/first-principles-audit.md` for code evidence and the convergence
record.

## Required outcomes and invariants

1. **Strict default and failure closure**
   - Requests without an explicit, valid control-plane policy use current
     system-root and hostname verification.
   - VERIFY is represented only by the absence of an exact-target rule; no
     persisted VERIFY row or nullable all-modes payload is valid.
   - Missing platform, invalid policy, or indeterminate authorization does not
     silently select direct transport, relax verification, or initiate a
     connection.

2. **One policy decision before egress selection**
   - Direct and routed reverse requests use the same normalized target,
     platform snapshot, authorization decision, TLS policy, and audit context.
   - A trust rule matches one exact normalized HTTPS `host:port` within its
     platform. It does not authorize a hostname suffix, CIDR, URL path, or every
     target reachable through that platform.
   - Under the current shared-token model, the feature adds no client-specific
     identity or permission layer; requests presenting the shared proxy token
     observe the same administrator-configured rule set.
   - `ProxyBypassRules` controls only direct versus routed dialing.
   - Route/node selection occurs only after the request policy is resolved.

3. **Transport isolation**
   - Forward proxy always uses the canonical VERIFY transport profile.
   - Reverse transports with different effective TLS trust do not share
     keep-alive connections.
   - Node eviction clears every cached profile for that node.

4. **Identity preservation**
   - Any custom-CA mechanism continues to verify hostname/SNI.
   - `TRUST_CUSTOM_CA` is target-exclusive: after an exact platform/target rule
     matches, only its immutable bundle supplies trust anchors. System roots are
     not augmented or consulted, and chain failure never falls back to VERIFY.
     No matching rule continues to use normal system roots.
   - BYPASS is an explicit exception that disables certificate-chain and
     hostname verification only for its exact matched target; it is never a
     fallback for an invalid or missing policy.
   - Explicit rules form a discriminated union. `TRUST_CUSTOM_CA` requires only
     an immutable `bundle_id` and prohibits BYPASS fields. Bundle resolution
     supplies the already validated normalized PEM and fingerprint only after
     the exact-target rule is authorized.
     `BYPASS` requires only its non-empty reason and required-presence nullable
     expiry and prohibits CA fields. A mode switch replaces the complete variant
     atomically rather than merging fields across variants.

5. **Failure attribution**
   - `TargetIdentity`, `TargetService`, `LocalPolicy`, `Client`, and `Unknown`
     failures do not directly create negative node-health feedback.
   - Only a failure explicitly attributed to the node transport path may update
     negative node health.
   - Direct requests never create node-health feedback. Routed success retains
     the existing positive-health/reset behavior unless a later approved design
     explicitly replaces it.
   - Existing `upstream_err_kind` remains a symptom classification; it is not by
     itself causal attribution.

6. **Revocation and observability**
   - Policy update/revocation is handshake-scoped. Publishing a new immutable
     snapshot is the linearization point: later requests use the new bundle, no
     rule, or strict VERIFY as applicable. Old profiles leave cache indexes and
     their idle connections close immediately.
   - Requests, streaming responses, and 101 upgrades that captured the old
     decision before publication may naturally drain under that policy version;
     this version does not hard-terminate active sessions. Audit records the old
     policy version, connection/request start and end, upgrade status, and active
     old-session count where available.
   - Audit evidence correlates platform, normalized target, effective policy,
     trust-material fingerprint, authorization result, and final request result.
   - Client-controlled audit fields are encoded safely.
   - Current executable rules and configuration history have independent
     lifecycles. Every create, mode replacement, CA rotation, BYPASS renewal or
     permanent conversion, explicit revocation, and deletion appends a durable
     version event before the active state changes.
   - Deleting a rule or platform removes its executable authorization and
     retires the corresponding runtime profile, but does not cascade-delete
     configuration history. History stores snapshot identifiers and metadata,
     CA fingerprints, reason, and expiry; it never stores CA PEM, tokens, or a
     fabricated natural-person actor.
   - Bundle lifecycle history is separate and PEM-free. First creation and
     explicit delete-if-unused appends an immutable event with bundle identity,
     fingerprint/canonicalization version, certificate count, action, timestamp,
     and request context. A dedup hit creates no lifecycle version because it is
     an idempotent request result rather than a state transition.

7. **Compatibility boundary**
   - Forward proxy, CONNECT, SOCKS5, health probes, and unrelated platform
     traffic retain their existing behavior.
   - Any change that rejects a previously accepted direct request with an
     unknown platform is documented and tested as a compatibility change.

8. **CA responsibility boundary**
   - Resin accepts public CA trust anchors through a central immutable
     `CABundleRegistry`. It validates and canonicalizes the complete certificate
     set, computes a versioned content fingerprint, deduplicates it, and persists
     one bundle in strong state. Importing a bundle does not authorize any target
     or change runtime behavior.
   - `CABundleRegistry` owns only import, canonicalization, deduplication,
     metadata/read, integrity verification, and reference-aware delete.
     `PlatformTLSPolicy` separately owns platform exact-target
     rules, modes, `bundle_id` bind/rebind, reason/expiry, rule version, history,
     runtime publication, and revocation. Neither service performs the other's
     mutation. Policy mutations carry only immutable `bundle_id`; runtime
     compilation obtains a read-only verified bundle view containing canonical
     PEM plus integrity metadata from the Registry.
   - Import and bind are two API operations. Import is idempotent
     create-or-return-existing and may leave a valid unused bundle. Binding or
     rebinding requires an existing immutable bundle and an atomic
     rule-version/history update. Every active-rule mutation uses CAS: create
     requires expected absence; replace/rebind/delete/revoke requires the current
     positive version. No `latest`, mutable alias,
     automatic binding, automatic rebind, or in-place bundle content update is
     permitted.
   - Canonicalization treats a bundle as a set of complete X.509 certificate DER
     values: duplicate DER entries and input order have no semantic effect.
     Inputs accept only headerless `CERTIFICATE` PEM blocks, completely consume
     the bounded input, reject private keys/unknown blocks/trailing garbage/empty
     bundles, and require CA-capable certificates. Unique DER values are ordered
     by their SHA-256 digest and hashed with a domain-separated, versioned,
     length-framed bundle algorithm. The canonicalization/fingerprint version is
     persisted, and a digest uniqueness hit is confirmed by canonical-byte
     comparison.
   - Resin does not generate a CA, hold CA private keys, issue or renew service
     certificates, process CSRs, distribute certificates, operate enterprise
     PKI/CRL/OCSP services, or modify the host's global root store.
   - Active rules reference bundles with delete restriction. Missing, damaged,
     or fingerprint-mismatched bundle references fail startup/snapshot
     publication and never become absent-rule VERIFY. Full PEM is absent from
     list endpoints, ordinary logs, and audit event bodies. External secret
     references are not part of this version.

9. **BYPASS control boundary**
   - Only an administrator-configured exact normalized HTTPS `host:port` may
     select BYPASS. Wildcards, suffixes, CIDRs, platform defaults,
     account-derived rules, and automatic downgrade from VERIFY/custom CA are
     prohibited.
   - Direct and routed reverse requests consume the same BYPASS decision and an
     isolated transport profile; forward, CONNECT, SOCKS5, and other targets
     remain strictly verified or retain their existing behavior.
   - Every BYPASS use records only real available context: timestamp, rule
     ID/version, target, request source/account when present, direct/routed mode,
     and final result. It does not claim a natural-person actor identity.
   - A BYPASS rule requires a `reason` whose trimmed value is non-empty. Creating
     or switching a rule to BYPASS requires an explicit reason. A PATCH that
     leaves the BYPASS expiry unchanged may retain the existing reason, while
     extending a temporary expiry or changing it to permanent requires a new
     explicit reason. An explicit empty reason is invalid.
   - The reason is administrator-supplied audit context, not proof of a person's
     identity, approval, authorization, target safety, or business necessity. It
     is validated and safely encoded, and each policy version retains the reason
     applicable to that version.
   - `expires_at` is required to be explicitly present on create: JSON `null`
     means permanent and a future RFC3339 timestamp means temporary. On PATCH,
     omission preserves the current value while explicit `null` changes it to
     permanent. Zero time and sentinel dates do not encode permanence.
   - At `now >= expires_at`, a temporary BYPASS stops providing an exception and
     the effective mode becomes strict VERIFY. Expiry does not create a target
     access denial. Audit context distinguishes configured BYPASS from effective
     VERIFY caused by expiry.

## Design target

An administrator using the shared control-plane credential configures one exact
normalized HTTPS `host:port` rule within a platform. The rule selects
`TRUST_CUSTOM_CA` with configured and persisted public CA trust anchors, or explicit
`BYPASS`; no matching rule means strict `VERIFY`.
VERIFY and custom CA preserve hostname/SNI verification. The resolved rule
applies identically before either direct or routed egress is selected. All
requests presenting the current shared proxy token observe the same configured
rules.

Custom CA is trust-anchor consumption, not CA lifecycle management. BYPASS is a
deliberate exact-target verification exception. Central bundle storage is only
an immutable trust-material registry; platform-owned exact-target rules remain
the authorization boundary. Configuration history is retained indefinitely
without a purge path. Revocation is handshake-scoped, and negative node health
requires an explicit `NodeTransportFailure` proof.

The earlier proposal selected per-platform `VERIFY | TRUST_CUSTOM_CA | BYPASS`
and persisted CA PEM on the platform row. That proposal is retained as decision
history but is no longer implementation-approved.

## Out of scope

- A global TLS verification escape hatch.
- Platform-wide, hostname-suffix, CIDR, or URL-path trust rules.
- Account-derived trust policy.
- A new client identity or per-client authorization system beyond the current
  shared proxy token.
- Changing TLS behavior for forward proxy, CONNECT, SOCKS5, or probes.
- Treating `ProxyBypassRules` as target authorization.
- Generating CA keys, holding CA private keys, signing/renewing/distributing
  certificates, or operating a general-purpose PKI.
- Mutable CA objects, named version families, `latest`, automatic certificate
  discovery/rotation/rebind, global default trust, or bundle-based target
  matching.
- Augmenting a matched custom-CA rule with system roots or falling back to
  system roots after exclusive-bundle chain failure.

## Resolved implementation contracts

- Negative node-health feedback is conservative: only an error explicitly
  wrapped as `NodeTransportFailure` is attributed to the selected Resin node.
  DNS, timeout, refusal, reset, target TLS, local policy, client cancellation,
  and unknown errors do not qualify without that proof.
- PEM-free bundle lifecycle and TLS rule history are retained indefinitely.
  The implementation exposes no purge or archival path, and platform, rule, or
  bundle deletion never cascades into history.
- Update and revocation are handshake-scoped: snapshot publication governs new
  requests, idle obsolete profiles close, and already-started work drains.

## Acceptance framework

The implementation demonstrates:

- Current strict verification remains unchanged for an unapproved target.
- An approved private target succeeds only under its authorized trust rule;
  wrong CA, wrong hostname, expired certificate, malformed policy, and an
  out-of-scope host or port fail closed as specified.
- Re-importing semantically identical certificate sets in different PEM order or
  formatting returns the same immutable bundle. Import alone changes no rule or
  runtime snapshot; concurrent import/dedup verifies canonical bytes on a digest
  uniqueness hit.
- Registry and policy APIs are separate. A rule accepts only `bundle_id`, binds
  with version CAS, and cannot select a missing/damaged bundle. Create uses
  expected-absence CAS; every later mutation uses the current positive version.
  Active references restrict bundle deletion; unused staged bundles remain
  non-authorizing.
- Validated canonical CA PEM, fingerprint algorithm/version, fingerprint, and
  bundle identity survive restart. Full PEM is absent from list responses,
  ordinary logs, and audit event bodies.
- A system-trusted target succeeds without a rule. The same chain fails under a
  matched target-exclusive custom rule unless its terminating trust anchor is in
  the bound bundle. A private chain succeeds only under the matching bundle;
  wrong SAN, incomplete chain, wrong bundle, and bundle failure never fall back
  to system roots.
- Rebind, delete, and BYPASS expiry switch new requests at snapshot publication,
  close old idle connections, and leave already-started in-flight/upgrade
  sessions to natural drain without claiming hard revocation.
- API, domain, and database contract tests reject every cross-mode field
  combination, a persisted VERIFY row, stale fields after a mode switch, invalid
  versions, and fingerprint/PEM mismatch. Corrupt persisted rules fail startup
  or snapshot publication rather than being treated as absent VERIFY rules.
- An exact-target BYPASS rule permits that target's otherwise-invalid
  certificate while the same certificate still fails under VERIFY/custom CA
  and for every unmatched host or port.
- BYPASS create/mode-switch rejects a missing or blank reason. Extending a
  temporary BYPASS or changing it to permanent requires a new reason, retains
  versioned audit history, and never invents a natural-person actor identity.
- Platform/rule deletion atomically records terminal history before removing
  active rows. The history survives platform deletion without a cascading
  foreign key, while new requests no longer observe the removed authorization
  and idle transports for it are retired.
- First bundle creation and explicit unused-bundle deletion append PEM-free
  registry lifecycle events; dedup hits do not create false configuration
  versions.
- Rebinding a rule transactionally replaces its immutable `bundle_id`, advances
  the rule version, and appends old/new fingerprints under expected-version CAS.
  The new resolved snapshot/profile is constructible before commit, is published
  before API success, and prevents later requests or idle connections from using
  the old bundle.
- Paired direct/routed requests have identical authorization and TLS outcomes;
  only node/egress fields differ.
- Same-node forward HTTPS remains strict while reverse custom trust is active.
- Repeated target-identity/target-service/local-policy failures leave node
  failure count, circuit state, and unrelated platform routability unchanged.
- A failure explicitly attributed to node transport still drives the existing
  passive-health threshold.
- Policy update/revocation meets the approved new/idle/in-flight semantics and
  does not reuse an incompatible transport profile.
- Audit records are correlated, safely encoded, and contain the approved policy
  identity and final result.
- Migration, API contract, WebUI validation, restart, and rollback behavior use
  the final separate bundle/rule/history persistence model.
- Task-scoped Go build/tests and WebUI build/lint pass. Repository-wide lint and
  vet retain unrelated baseline findings recorded in `implement.md`.
