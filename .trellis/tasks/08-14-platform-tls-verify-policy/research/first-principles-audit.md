# First-principles audit - reverse HTTPS target trust

Status: grounded review completed on 2026-08-18; target scope and modes are now
resolved, with implementation contracts still open.

## Purpose

Re-evaluate the task before implementation without assuming that a per-platform
three-state TLS switch is the right problem or solution. The review first
derived expected outcomes from current code and system behavior, then compared
the existing PRD/design against those outcomes.

## Verified code facts

1. Reverse requests obtain both platform name and target host from the client
   request path (`internal/proxy/reverse.go`, path parsing around lines 158-213).
   Resin currently has one shared proxy token and no independent mapping from a
   client to allowed platforms or targets.
2. `ProxyBypassRules` selects local direct dialing rather than a Resin node. In
   the reverse path, the direct branch occurs before `Router.RouteRequest`
   (`internal/proxy/reverse.go`, around lines 298-321), so it does not require a
   valid platform or produce a routed platform/node result.
3. `ProxyBypassRules` is a transport-routing mechanism, not an authorization
   policy. A non-match routes through a Resin node; it does not reject access.
4. Forward and reverse HTTP share `OutboundTransportPool`, currently keyed only
   by `node.Hash` (`internal/proxy/transport.go`, around lines 40-72). CONNECT
   and SOCKS5 use byte-stream paths rather than this HTTP TLS verification path.
5. Reverse `RoundTrip` errors other than cancellation are passed to
   `recordPassiveResultAsync(..., false)` (`internal/proxy/reverse.go`, around
   lines 342-357). X.509 error families are classified for request logs, but
   that classification does not gate node-health feedback.
6. A platform is an existing persisted policy/routing entity with copy-on-write
   runtime replacement. There is no persisted target-trust-rule entity today.
7. The repository and task artifacts contain no production failure samples or
   deployment facts proving whether the motivating failures are unknown CA,
   hostname mismatch, expiry, or incomplete chains.

## Conclusions supported by those facts

- The problem is an operator-authorized exact-target TLS verification policy for
  reverse HTTPS requests. BYPASS is required as an explicit mode, but it is not
  a global or platform-wide switch.
- A client choosing a host does not prevent the operator from defining which
  hosts may receive an exception. Target selection and target authorization are
  separate decisions.
- Platform is a convenient persistence/routing boundary, but current evidence
  does not establish it as the complete target-trust authorization boundary.
  Platform itself is also client-selected under the shared-token model.
- Direct and routed requests need one policy decision before egress selection.
  Direct/routed may differ in how they dial, but not in target authorization,
  TLS identity policy, audit meaning, or failure attribution.
- `ProxyBypassRules` must remain a transport selector unless a separate,
  explicitly approved compatibility change makes it an authorization policy.
- TLS identity/local-policy failures must not directly become negative node
  health feedback. Symptom classification (`upstream_err_kind`) is not enough
  to establish causal attribution to a node.
- `internal/proxy/reverse.go` is already an orchestration hotspot: request
  parsing, direct/routed selection, transport execution, lifecycle recording,
  error handling, and health feedback meet in `ServeHTTP`. The TLS task must not
  add mode-specific policy or health-eligibility logic there. Attribution and
  health feedback need an independently testable boundary consumed by the
  handler.

## Invalidated or reopened assumptions

1. **Per-platform is decided** - reopened. Existing persistence infrastructure
   is implementation evidence, not proof of the required authorization scope.
2. **Per-host is spoofable because host is client input** - invalid. An
   operator-controlled target rule can constrain a client-selected target.
3. **BYPASS scope is undecided** - resolved. BYPASS is required only as an
   administrator-configured exact normalized HTTPS `host:port` mode, with no broader
   matcher or automatic fallback.
4. **Direct can remain VERIFY and outside policy** - rejected. Direct and routed
   consume the same resolved VERIFY/custom-CA/BYPASS decision.
5. **TLS failures can preserve existing node-health behavior** - invalid as a
   default. The current coupling can turn a target certificate/policy problem
   into global node routing punishment.
6. **A pre-round-trip WARN satisfies audit requirements** - invalid when the
   contract requires final failure classification and durable correlation.

## Retainable design work

- Strict, fail-closed default behavior.
- Hostname verification for any custom-CA mode.
- An immutable TLS profile carrying cache key, mode, and CA material.
- Transport isolation by `(node.Hash, TLS profile)` with forward fixed to the
  canonical VERIFY profile.
- CA-content hashing for profile identity.
- Existing X.509 symptom classification for logs.
- Layered repo/service/runtime validation once the final data model is chosen.

## Required architecture boundaries

### Request decision

One shared resolver must normalize the target, resolve one platform snapshot,
apply operator-controlled authorization, derive the effective TLS profile, and
produce audit context before direct/routed selection. `ProxyBypassRules` then
selects the dial path only.

### Failure attribution

Round-trip symptoms must be mapped to an explicit attribution such as `Node`,
`TargetIdentity`, `TargetService`, `Client`, `LocalPolicy`, or `Unknown`.
`Unknown` and non-node attributions do not produce negative node-health
feedback. A separate design is still needed for the evidence threshold that
can safely label a failure as `Node`.

The reverse handler coordinates this boundary but does not implement it inline:
it passes stage/error/request-decision context to an attributor, then delegates
any permitted health action to a health-feedback collaborator.

## Convergence assessment

There is enough evidence to reject the old per-platform implementation design
and fix the replacement product target: exact `host:port`, shared-admin-token
configuration, shared-proxy-token requests, direct/routed parity, and
VERIFY/custom-CA/BYPASS modes.
Implementation remains blocked on the contracts below.

Remaining decisions are history retention, update/revocation completion points,
and the evidence threshold for node-health attribution. Root composition is
fixed as target-exclusive with no system-root augmentation/fallback.
Material/authorization ownership is fixed: a central immutable
content-addressed registry persists validated canonical CA bundles, while
platform-owned exact-target rules bind only by immutable bundle ID. Import does
not grant trust, and no external secret reference is introduced.
BYPASS governance is also fixed: a trimmed non-empty reason is required
on create/mode-switch, with a new versioned reason for expiry extension or a
change to permanent; it is audit context rather than actor identity or proof of
approval.
