# Reverse proxy upstream redirect handling policy

## Goal and delivery boundary

Let an operator opt a Platform into keeping supported same-origin HTTP redirects
inside Resin. A following client re-enters the reverse proxy with the original
URL identity representation and reaches the intended upstream path.

This is the implementation contract for TEAM B. It defines a bounded first
release: default PASS_THROUGH, optional same-origin REWRITE, no server-side
FOLLOW. The task remains planning; this package does not claim implementation
or runtime acceptance. Technical boundaries are in [design.md](design.md),
execution and verification in [implement.md](implement.md).

Each subsequent request authenticates, resolves Account, and routes normally.
Keeping the URL identity does not freeze the initially resolved Account, TLS
policy, lease, node, or egress IP for a whole redirect chain.

## Confirmed background

Evidence is from workspace HEAD 79b8ee97200e703e2a3a8d433589fcf7e5f5000a,
2026-10-01; see [implementation map](research/implementation-map.md).

- ReverseProxy performs one upstream round trip and leaves Location untouched
  (internal/proxy/reverse.go:330-414, especially :367-414). A root-relative
  Location such as /x removes the Resin prefix. The reverse parser then normally
  rejects it with 403 or 400, not 401/404 (reverse.go:168; errors.go:27).
  Path-relative and query-only references can preserve the prefix; an absolute
  upstream URL takes a following client outside Resin.
- Resin's V1 identity prefix is /PROXY_TOKEN/Platform.Account/protocol/host/path
  (DESIGN.md:71). Account precedence includes an explicit X-Resin-Account
  override (DESIGN.md:72, :126; reverse.go:465-509). Header extraction can return
  an entire credential (account_matcher.go:170; DESIGN.md:132).
- Leases are keyed by PlatformID and Account (internal/routing/lease.go:14-27).
  Domain independence does not guarantee the same IP after lease expiry,
  empty-account random allocation, or routing failure (router.go:91-102).
- Forward HTTP also uses a single round trip (internal/proxy/forward.go:261-294).
  Its redirect behavior is outside this change. Probes/downloads already use
  http.Client following behavior (internal/netutil/outbound_http.go:67;
  internal/netutil/downloader.go:59), also outside scope.
- Platform policy has established model/service/UI paths. The reverse resolver
  captures Platform and TLS before selecting egress
  (internal/proxy/reverse_decision.go:54-117). ModifyResponse is the response
  interception point; generic ErrorHandler currently treats errors as transport
  failures (internal/proxy/reverse.go:348-365).

[audit.md](audit.md) records the earlier, incomplete task draft and absent source
delivery. Its PRD line numbers and planning findings describe that historical
snapshot, not this replacement package.

## Requirements

### R1 — Platform configuration and compatibility

Add ordinary Platform field `reverse_proxy_redirect_policy` with exactly two
case-sensitive values: PASS_THROUGH and REWRITE. In the API, explicit empty,
null, wrong-type, whitespace-padded, and unknown values are invalid arguments.
Omission is distinct from an explicit value.

| Operation | Required behavior |
| --- | --- |
| Migrate an existing Platform, including Default | Store PASS_THROUGH regardless of environment |
| Fresh built-in Default / create with field omitted | Use the configured creation default |
| Create with explicit valid value | Use that value |
| Legacy PATCH or aggregate configuration PUT omits field | Preserve the current persisted value |
| Update with explicit valid value | Replace the value through the existing save flow |
| Reset-to-default action | Use the configured creation default |
| Restart | Load the persisted value; do not overwrite it from environment |

The creation default is configured with
RESIN_DEFAULT_PLATFORM_REVERSE_PROXY_REDIRECT_POLICY and is PASS_THROUGH when
unset. A set value must be one of the two exact enum values; invalid or empty
values fail startup validation. As with existing ordinary Platform defaults,
this setting affects new custom Platforms and reset as well as initial Default
creation. It is not a global live override.

Expose the field through existing Platform create/list/get/patch/reset,
configuration GET/PUT, system environment projection, and Platform forms. It
applies to reverse HTTP and HTTPS, direct and routed egress, and the built-in
Default as well as custom Platforms. Default's TLS restrictions do not apply
to this ordinary field. Do not create a separate policy resource or save flow.

Persistence, aggregate config_version/ETag CAS, and runtime publication must
include the field. A stale write or failed persistence must not partially
publish redirect/routing/TLS configuration. The request uses the Platform
snapshot captured at resolution; later requests observe later published values.

### R2 — Response eligibility and single-hop behavior

PASS_THROUGH preserves existing response handling. It adds no Location parsing,
validation, rewriting, or following, including for cross-origin locations.

REWRITE processes only 301, 302, 303, 307, and 308 with a Location field.
A missing Location passes through. A present but empty/whitespace-only Location,
or multiple Location field values, is invalid. One Location containing a comma
is one reference, not a comma-separated list. Noneligible statuses, including
201, 300, 304, and 101, retain existing handling.

For accepted rewrites, preserve status and body. Resin does not follow, replay,
buffer a request body for replay, or change the method. The client applies its
own redirect/method rules. There is no internal hop loop or chain state.

### R3 — Reference resolution and same-origin boundary

Resolve a Location against the actual upstream request URL, never the Resin
entry URL. Support root-relative, path-relative, dot-segment, query-only,
fragment-only, protocol-relative, and absolute HTTP(S) references.

Origin is (scheme, normalized hostname, effective port). Scheme/hostname case
and omitted versus explicit default ports compare equal; different DNS names
are not equated by resolution. A scheme change, including HTTP to HTTPS, a host
change, or a different effective port is cross-origin and must be rejected in
REWRITE. There is no pass-through fallback on rejection.

Reject unsupported schemes, userinfo, malformed percent escapes/authority,
embedded raw control characters, raw backslash ambiguity, and references that
cannot be represented safely under R4. Validate before origin comparison so an
invalid reference is reported as invalid, not cross-origin. Surrounding HTTP
optional whitespace may be removed before validation; an empty result is invalid.
Do not perform destination DNS lookup, connection, or fetching to make this
response decision. Rejection behavior is R6.

### R4 — Safe prefix construction and Account boundary

The rewritten Location stays on the client-facing Resin origin and contains
the original URL Platform/Account representation, the valid proxy-token
representation when authentication is enabled, and the resolved upstream URL.
Never derive this prefix from upstream headers. With authentication disabled,
even an input with an empty token segment must produce a safe same-origin
reference, never a leading // network-path reference.

Resolve upstream dot segments before assembling the prefix. Preserve escaped
slashes, encoded identity delimiters, Unicode path content, query order and
repetitions, meaningful empty queries, and fragments. Do not unescape or clean
the entire assembled proxy path. Reject encoded-dot path segments that a browser
could normalize through the prefix, including %2e, .%2e, %2e., and %2e%2e
(case-insensitive). An unsafe dot-only identity/token segment must not be silently
changed into a different authenticated identity. Round-trip the generated URL
through the real V1 parser in tests.

Do not put resolved Account, X-Resin-Account, Authorization, Cookie, or other
header values into Location. Preserve the original URL identity even when it
was overridden for this request. Existing Account precedence and extraction
rules run on every next request; a path-dependent rule or missing header can
produce a different Account. Callers needing an explicit Account should send
X-Resin-Account on each request under the existing precedence rules. This still
does not promise a fixed node/IP.

### R5 — Credential and header handling

Cross-origin rewriting is excluded because Resin paths share one client-visible
origin: a following client could otherwise send A's Authorization or cookies to
B. Preserve ordinary same-upstream Authorization/Cookie behavior and existing
identity-header stripping; do not strip all application credentials to simulate
safe cross-origin support.

For requests whose captured mode is REWRITE, remove outbound Referer before
sending upstream; it can contain a Resin token-bearing URL from an earlier
navigation. Successful rewritten responses set Referrer-Policy: no-referrer
and Cache-Control: no-store. Local redirect errors also use no-store. These
changes are specific to REWRITE; PASS_THROUGH retains its baseline behavior.

Detailed response capture and new diagnostics must not acquire a generated
token-bearing Location or a header-derived Account from this transformation.
Capture the original upstream headers before rewriting, or redact the generated
Location. Do not reflect a rejected reference or credential in an error body.
Apart from these explicit adjustments, retain existing response header/body
handling. General cookie, HTML, JavaScript, and Refresh rewriting is out of scope.

### R6 — Errors, logs, and node health

| Condition in REWRITE | Client response | Failure attribution |
| --- | --- | --- |
| Valid HTTP(S) destination has a different origin | 502, X-Resin-Error: REDIRECT_CROSS_ORIGIN | LocalPolicy |
| Invalid/unsupported/ambiguous Location or unsafe prefix | 502, X-Resin-Error: REDIRECT_LOCATION_INVALID | TargetService |

Use a short static error body with no upstream body or URL reflection. Do not
forward upstream Location or Set-Cookie on these local errors. Close the upstream
body, without unbounded draining. Use one normal request completion/log with the
current request's Platform, resolved Account, original target, downstream status,
and proxy error code. Do not allocate a log for an unmade next-hop request.

Receiving an upstream response is network success even when its redirect is
rejected: NetOK remains true and node health/circuit state receives no negative
feedback. Routed requests retain exactly one positive feedback event under the
existing response-arrival convention; direct requests have no node feedback.
Do not send redirect errors through generic transport-error classification.
Accepted rewrites log the upstream 3xx normally; a client's next request produces
its own normal lifecycle. No chain ID or request-log schema expansion is required.

### R7 — Operator experience and documentation

Place the policy in existing create/configuration forms and aggregate saving,
with Chinese and English labels/help. Explain that PASS_THROUGH preserves the
upstream response and REWRITE keeps same-origin redirects through Resin and
rejects other origins. Same-origin includes scheme and port. Explain per-request
Account behavior and that fixed IP and arbitrary browser-site compatibility are
not guaranteed. Reset/read-back must reflect the server's configured default.

Update API/operator/environment documentation with the enum, omission/default
semantics, a /next example, a cross-origin failure example, error codes, explicit
Account guidance, and rollback by selecting PASS_THROUGH.

## Acceptance criteria

TEAM B must attach reproducible evidence for these checks. Unchecked means
pending implementation, not a known failing test. URL examples use upstream
https://a.example/dir/start?old=1 and Resin path
/token/Shop.alice/https/a.example/dir/start?old=1; use local fixtures in tests.

- [ ] AC01 (R1): With no env override, fresh Default, omitted-field create, and
  migrated rows use PASS_THROUGH. With env REWRITE, new/default creation and
  reset use REWRITE, while existing rows migrate to PASS_THROUGH. Restart retains
  explicit persisted values despite a changed env default.
- [ ] AC02 (R1): API rejects null, empty, wrong-type, padded, and unknown values;
  startup rejects a set invalid/empty env value. Both valid values round-trip
  through every configuration response and the environment projection.
- [ ] AC03 (R1): An older PATCH/aggregate PUT omitting the field preserves a
  stored REWRITE value. Explicit changes save; stale CAS, preparation failure,
  and persistence failure leave stored/runtime Platform and TLS consistent.
- [ ] AC04 (R1): Default/custom Platforms and HTTP/HTTPS direct/routed paths use
  their captured policy. A configuration change while a response is pending
  affects later resolutions, not the already captured request.
- [ ] AC05 (R2): PASS_THROUGH returns original unusual/cross-origin Location
  values under existing handling and never performs another upstream request.
- [ ] AC06 (R2): All five eligible statuses rewrite; absent Location and
  noneligible statuses pass through. Empty/multiple fields fail; a single URL
  containing a comma is preserved as one reference.
- [ ] AC07 (R3, R4): /next?x=1&x=2#part becomes
  /token/Shop.alice/https/a.example/next?x=1&x=2#part. next, ../next, ?new=2,
  and #part use upstream base semantics; following reaches the intended path.
- [ ] AC08 (R3): Same-origin absolute/protocol-relative URLs, host case, and
  explicit default ports are accepted. Host, effective port, and either scheme
  change are rejected with REDIRECT_CROSS_ORIGIN.
- [ ] AC09 (R3, R6): Malformed escapes/authority, userinfo, non-HTTP(S), controls,
  raw backslashes, and multiple fields yield REDIRECT_LOCATION_INVALID without
  reflecting the reference. Use synthetic responses when HTTP transport rejects
  malformed headers before ModifyResponse.
- [ ] AC10 (R4): Escaped slashes, encoded identity delimiters, Unicode paths,
  ordered/repeated queries, an empty query delimiter, and fragments survive.
  Encoded-dot traversal segments fail safely, including mixed case variants.
- [ ] AC11 (R4): Auth-disabled empty token produces a Location inside Resin.
  Auth-enabled token/identity encoding round-trips; unsafe dot-only prefixes
  fail safely. Include WHATWG/browser URL resolution as well as Go parsing.
- [ ] AC12 (R4): X-Resin-Account overrides a different URL Account normally;
  header-derived credentials never appear in generated Location. A path-rule
  change can change Account on the next request, as documented.
- [ ] AC13 (R2, R5): POST+303 and replayable POST+307/308 follow the client's
  method/body behavior. Resin makes one round trip and does not buffer/replay a
  streamed request body or follow internally.
- [ ] AC14 (R3, R5): With automatic client following and Authorization/Cookie on
  a request to A, a cross-origin redirect cannot reach test server B in REWRITE.
  Same-origin authenticated redirects continue to work.
- [ ] AC15 (R5): REWRITE strips outbound Referer; PASS_THROUGH does not gain that
  behavior. Rewritten responses contain no-referrer/no-store. Detailed capture
  contains no newly generated token-bearing Location.
- [ ] AC16 (R6): Both errors release upstream bodies, omit Location/Set-Cookie,
  use no-store, and emit exactly one 502 log with the stated code/attribution and
  NetOK=true. Direct/routed health assertions match R6, without transport errors.
- [ ] AC17 (R1, R6): A follow-up request re-enters normal identity/TLS/bypass/
  routing resolution and logging. A redirect loop causes no internal following;
  client limits control repeated requests. No frozen chain state is introduced.
- [ ] AC18 (R7): UI create/edit/reset/read-back and combined Platform/TLS saving
  retain the policy correctly; both locales explain the supported boundary.
- [ ] AC19 (R2, R5): Existing reverse streaming/upgrades, forward HTTP, CONNECT,
  and SOCKS5 retain their behavior; redirect support adds no body replay path.

## Out of scope

- FOLLOW; cross-origin continuation/allowlists, credential jars, origin-isolated
  hosting, continuation tokens, and frozen Account/lease/IP across a chain.
- Forward proxy, CONNECT, SOCKS5, probes, and subscription-download changes.
- Per-path redirect rules; general URL middleware; cookie, HTML, JS, or Refresh
  rewriting; a browser compatibility/security boundary for arbitrary websites.
- Global logging cleanup, pre-authentication error logging, and new chain metrics.

There are no blocking product questions for this bounded first release. Expansion
beyond these boundaries requires a separately reviewed contract.
