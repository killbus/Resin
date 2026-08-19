# Round-two convergence review

Status: **design target and architecture boundaries converged; two
implementation contracts remain open**.

## Review question

Do the current facts and design produce an actionable next step without hiding
unresolved implementation contracts or expanding `ReverseProxy.ServeHTTP` into
a policy and health-causality owner?

## Confirmed convergence

The grounded review and independent systems reviews agree on these boundaries:

1. Resolve one immutable, administrator-configured `ReverseRequestDecision` before
   selecting direct or routed egress.
   Raw policy fields are first validated by a configuration boundary and
   time-dependent expiry is evaluated by an independent runtime evaluator;
   `RequestDecision` consumes only the validated result.
2. Keep `ProxyBypassRules` limited to transport selection.
3. Pass a complete immutable TLS profile (key, mode, and CA material) to the
   cache owner so it can both find and construct transports.
4. Keep symptom classification, causal attribution, and health action separate.
5. Permit negative node health only for explicitly node-attributed failures.
   Target identity, target service, local policy, client, and unknown failures
   are ineligible; direct requests have no node-health feedback.
6. Keep `ReverseProxy.ServeHTTP` as orchestration only. Dedicated resolver,
   attributor, health-feedback, and audit components own their semantics and are
   tested independently before handler integration.

These are actionable architecture constraints and should be preserved in the
final design. The product target is now also fixed: operator-owned exact HTTPS
`host:port` rules configured through the shared admin token, shared-proxy-token
requests, direct/routed parity, and strict VERIFY with explicit TRUST_CUSTOM_CA
or BYPASS modes.

## Ordered action plan

1. Decide the evidence threshold for node attribution, or extract the broader
   health change as a prerequisite.
2. Decide PEM-free configuration-history retention/purge behavior.
3. Rewrite the final PRD/design/implementation plan and present the required
   planning summary for explicit approval.
4. During implementation, establish and test resolver/attribution/health gates
   before integrating them into the reverse handler.

## Implementation audit focus

The follow-up structural review found no new design defect but identified the
main implementation risk: new abstractions could be added while the original
policy and health responsibilities remain in `ReverseProxy.ServeHTTP`.

Design convergence does not imply code convergence. In the current planning
baseline, `internal/proxy/reverse.go` around lines 303-342 still owns egress
selection, transport execution, error handling, and node-health updates. That
known coupling is the implementation target, not evidence that C1-C3 have
already been completed.

The implementation review must therefore prove:

- raw TLS policy validation and BYPASS expiry evaluation occur outside the
  handler, using an immutable snapshot and injectable clock;
- a rejected decision causes no bypass evaluation, route/lease selection, dial,
  or health update;
- each direct/routed failure traverses attribution and health gating exactly
  once;
- `ServeHTTP` contains no CA parsing, `reason`/`expires_at` inspection, policy
  clock evaluation, authorization matching, TLS/error-causality branches, or
  direct request-outcome calls to the existing health recorder;
- negative node feedback has one owner and cannot be reached for non-node
  attribution categories.

Merely introducing the proposed interfaces does not satisfy the architecture.
The old responsibilities must be removed from the handler and verified through
focused integration tests and static/manual review.

## Remaining gaps

- No evidence threshold safely identifies a node-caused failure.
- History retention/purge behavior and the evidence threshold for node health
  attribution remain open implementation contracts.

The trust-material source is closed: the first version persists validated,
canonical CA PEM, fingerprint algorithm/version, and fingerprint in a central
immutable content-addressed bundle registry. `CABundleRegistry` owns only
import/dedup/integrity/delete-if-unused; `PlatformTLSPolicy` owns platform child
rules and fixed bundle-ID bind/rebind. Import has no authorization effect, and no
external secret reference is introduced. Full PEM stays out of list responses,
ordinary logs, and audit event bodies.

The user explicitly confirmed this Registry/Policy split after the conditional
review and its follow-up findings were incorporated.

The user also confirmed target-exclusive custom roots. A matched custom rule
uses only its verified bundle while preserving hostname/SNI, validity, and chain
verification; it neither augments nor falls back to system roots. The reviewer
confirmed this is policy semantics within `PlatformTLSPolicy`, not another
module, and that material continues to arrive through the Registry's read-only
verified bundle view.

The BYPASS governance contract is closed: each rule has a trimmed non-empty
reason; create/mode-switch requires it, and extending an expiry or changing to
permanent requires a new versioned reason. This text is audit context and does
not establish a natural-person actor or prove approval.

The policy shape is also closed against invalid representable states: absence
means VERIFY; persisted rules are an exhaustive TRUST_CUSTOM_CA/BYPASS union.
API presence types, one domain compiler, and database `CHECK` constraints share
the same required/prohibited field matrix. Mode switches replace a whole variant,
and corrupt stored rows fail startup or snapshot publication rather than
silently becoming VERIFY.

Active-rule and history lifecycles are separate. Configuration history is a
durable, application-append-only, PEM-free event stream with snapshot identifiers
and no cascading platform/rule foreign key. Platform/rule deletion records a
terminal event in the same database transaction before removing active state;
runtime authorization and idle profiles are then revoked without erasing the
history needed to explain permanent BYPASS, renewal, or CA rotation.

Every active-rule mutation shares one CAS contract: expected absence on create,
current positive version on replace/rebind/revoke/delete, with history and active
mutation in the same transaction. Registry lifecycle history is independently
PEM-free and append-only for first creation and deletion; dedup hits are
idempotent request results rather than new state versions. Runtime bundle handoff
is a read-only verified bundle view because it contains canonical PEM as well as
metadata, while policy mutation APIs still accept only `bundle_id`.

Revocation semantics are now closed as handshake-scoped: snapshot publication is
the new-request cutover, old idle profiles close, and pre-existing in-flight,
streaming, and upgraded sessions naturally drain. The design does not claim hard
active-session termination; audit must expose old policy version and session
lifetimes where available.

The CA responsibility boundary is closed: Resin consumes administrator-provided
public trust anchors and manages only its own trust configuration lifecycle. CA
private keys, certificate issuance/renewal/distribution, and general PKI
operation are out of scope.

Further feature or abstract architecture debate is not the next useful round.
The next round should resolve the first implementation contract in `prd.md`.
