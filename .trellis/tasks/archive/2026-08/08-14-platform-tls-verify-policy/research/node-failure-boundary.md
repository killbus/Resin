# Research: Conservative node-transport failure boundary

- Query: What is the narrowest reliable production boundary for classifying a routed outbound failure as `NodeTransportFailure`, given that sing-box `Outbound.DialContext` may include both the selected-node connection/handshake and the target CONNECT operation?
- Scope: mixed (repository wiring plus pinned dependency source)
- Date: 2026-08-18

## Findings

### Conclusion

There is no true node-socket-only failure hook in the public API used by Resin for
the pinned sing-box version. The current boundary in
`internal/proxy/transport.go:230-236` is too broad: it turns every failure from a
composite `adapter.Outbound.DialContext` call into node-health proof. For SOCKS
and HTTP nodes, that call first connects/handshakes to the configured proxy and
then asks that proxy to connect to the requested target. A target refusal,
unreachable response, or target-facing proxy error therefore returns through the
same method.

The narrowest reliable boundary is producer-side explicit evidence from code
that directly owns the configured node-server dial/handshake. Resin does not
currently have such a production producer. Consequently, the safest minimal
behavior is:

1. Never construct `NodeTransportFailure` merely because the selected
   `adapter.Outbound.DialContext` returned an error.
2. Treat an untyped/composite outbound-dial error as `Unknown` (and therefore
   ineligible for negative node health), while preserving cancellation as
   `Client`.
3. Continue accepting an already typed `NodeTransportFailure` as proof, so a
   future evidence-aware producer can opt in without weakening the consumer.
4. Accept the deliberate false-negative: standard sing-box outbounds produce no
   passive negative-health event from this opaque dial result until a genuine
   lower-level hook exists. Routed successes may keep the current positive/reset
   behavior, and active probes remain independent.

If audit attribution must distinguish an X.509 error inside the opaque outbound
dial from target TLS, introduce a non-health-bearing wrapper such as
`OpaqueRoutedDialFailure`. The attributor should check, in order: explicit
`NodeTransportFailure`, client cancellation, opaque routed-dial failure
(`Unknown`), then target-identity errors. This is slightly safer than returning
the error bare because node-proxy TLS errors occur inside the outbound dial,
whereas reverse-target TLS occurs after that dial returns a connection. The
opaque wrapper is boundary metadata, not node proof.

### Why the current adapter boundary is not node-only

- The pinned `adapter.Outbound` interface embeds only `N.Dialer`; it offers no
  node-server dial callback, handshake callback, error phase, or typed result
  (`.../sing-box@v1.12.21/adapter/outbound.go:11-19`). Its own comment says proxy
  outbounds create early connections by default, further warning that the
  abstraction is not a simple physical-socket boundary
  (`adapter/outbound.go:11`).
- Resin creates the protocol implementation through the sing-box registry and
  stores only the resulting `adapter.Outbound`
  (`internal/outbound/builder.go:131-161`,
  `internal/outbound/manager.go:72-96`, `internal/node/entry.go:59-60`). Routing
  later recovers only that interface (`internal/proxy/route_outbound.go:26-38`).
  `RawOptions` remains on the entry, but it does not expose the private protocol
  client or its underlying server dialer.
- The SOCKS outbound delegates the whole operation to its private
  `*socks.Client` (`.../sing-box@v1.12.21/protocol/socks/outbound.go:29-35,70-94`).
  That client dials the configured node server and then performs SOCKS4/5 target
  negotiation in one method (`.../sing@v0.7.18/protocol/socks/client.go:102-150`).
- The HTTP outbound likewise delegates to a private `*http.Client`
  (`.../sing-box@v1.12.21/protocol/http/outbound.go:26-30,55-60`). The client
  dials the configured HTTP proxy, writes a target `CONNECT`, and reads its
  response in the same method
  (`.../sing@v0.7.18/protocol/http/client.go:61-140`).
- Resin cannot inject a dialer through the registry construction path: each
  pinned outbound constructor calls `dialer.New` itself, and the resulting
  protocol client/dialer fields are private
  (`sing-box .../protocol/socks/outbound.go:38-58` and
  `.../protocol/http/outbound.go:32-51`). The generic network `Dialer` interface
  only has `DialContext`/`ListenPacket`; it has no observer facility
  (`.../sing@v0.7.18/common/network/dialer.go:11-14`).
- `N.HandshakeFailure`/`N.HandshakeSuccess` and `N.EarlyConn` are not a
  node-socket failure hook. They are connection capabilities used to report
  later stream handshake results (`.../sing@v0.7.18/common/network/handshake.go:11-33,63-88`;
  `common/network/early.go:3-5`). They do not reveal which internal phase caused
  `Outbound.DialContext` to return an error.

Therefore a genuine hook requires one of: an upstream API addition, a maintained
fork, or repo-owned protocol adapters that reproduce each relevant sing-box
constructor while injecting an observed lower-level server dialer. The last
option avoids a dependency fork but is still invasive, protocol-specific, and
easy to drift from upstream. Reflection/unsafe access to private fields is not a
production boundary.

### Exact error evidence exposed by SOCKS

The SOCKS client preserves phase internally but discards it at the public error
boundary:

- A failure from the underlying dialer while connecting to the configured SOCKS
  server is returned unchanged (`sing .../protocol/socks/client.go:116-119`).
  This is physically node-side, but the outer API does not label it as such.
- SOCKS4/5 handshake read/write errors are also returned unchanged
  (`protocol/socks/handshake.go:32-48,51-121`). An EOF/reset can mean the node
  connection failed, but it can also be the proxy closing while handling a
  target request; the public error carries no phase.
- SOCKS5 target reply codes are semantically rich on the wire: 3 is network
  unreachable, 4 host unreachable, 5 connection refused, and 6 TTL expired
  (`protocol/socks/socks5/protocol.go:31-39`). However, the client converts every
  non-success reply into `E.New("socks5: request rejected, code=", code)`
  (`protocol/socks/handshake.go:114-121`). `E.New` is just `errors.New`, so the
  dynamic result is an ordinary `*errors.errorString` with no exported code or
  phase (`common/exceptions/error.go:25-27`). For example, target refusal is only
  the text `socks5: request rejected, code=5`.
- SOCKS4 rejection is similarly flattened to an ordinary string containing code
  91/92/93 (`protocol/socks/handshake.go:41-48`;
  `protocol/socks/socks4/protocol.go:23-26`).
- SOCKS5 authentication failures and unsupported methods are also ordinary
  strings (`protocol/socks/handshake.go:65-86`). They are plausibly node/config
  failures, but string matching them would couple health decisions to
  non-contractual dependency text.
- SOCKS4 target-domain resolution can occur before proxy negotiation and returns
  an untyped lookup error (`sing-box .../protocol/socks/outbound.go:86-92`). Thus
  even a whitelist based on `net.Error`/`*net.DNSError` would misattribute some
  target failures.

It is safe to recognize the SOCKS numeric rejection strings as evidence that an
error is *not proven node-local*, but unsafe to infer that every other error is
node-local. A blacklist followed by catch-all node attribution will fail closed
in the wrong direction when dependency behavior or protocols change.

### Exact error evidence exposed by HTTP

- The configured HTTP/HTTPS proxy-server dial (including its optional TLS
  detour) is returned unchanged if it fails
  (`sing .../protocol/http/client.go:70-74`; sing-box constructs the TLS detour at
  `.../protocol/http/outbound.go:32-50`). No exported wrapper says that the error
  came from that sub-step.
- `request.Write` and `http.ReadResponse` I/O failures are returned raw
  (`sing .../protocol/http/client.go:108-117`). At that point the proxy may be
  failing independently or closing because its target attempt failed, so an
  EOF/reset is not causal node proof.
- A successful target CONNECT is represented only by HTTP 200
  (`protocol/http/client.go:119-129`). Non-200 responses are flattened with
  `E.New` into ordinary error strings: 407 becomes `authentication required`,
  405 becomes `method not allowed`, and everything else becomes
  `unexpected status: <status>` (`protocol/http/client.go:130-139`). A proxy 502,
  503, or 504 commonly represents target-side failure but has no typed status or
  causal field at the outbound boundary.

There is consequently no stable `errors.As`/`errors.Is` discriminator for HTTP
CONNECT target rejection versus node failure. Parsing messages/status text is
not reliable production evidence.

### Repository contract and minimal implementation shape

The existing health consumer is correctly conservative in isolation:
`defaultFailureAttributor` enables negative health only when `errors.As` finds
`*NodeTransportFailure` (`internal/proxy/failure_attribution.go:56-63`), and the
feedback layer checks both the attribution and boolean before recording failure
(`failure_attribution.go:90-95`). The defect is solely that the producer at
`internal/proxy/transport.go:230-236` manufactures that proof at an opaque
boundary.

Minimal repair contract:

```go
// OpaqueRoutedDialFailure proves only that the composite routed outbound call
// returned before yielding a stream. It does not prove which hop caused it.
type OpaqueRoutedDialFailure struct { Err error }

// In the http.Transport DialContext adapter:
conn, err := ob.DialContext(ctx, network, destination)
if err != nil {
    return nil, &OpaqueRoutedDialFailure{Err: err} // never NodeTransportFailure
}
```

`defaultFailureAttributor.Assess` should still detect an explicit nested
`NodeTransportFailure` first, then cancellation, then map
`OpaqueRoutedDialFailure` to `Unknown`. If the extra wrapper is considered too
large for this repair, returning `err` unchanged is health-safe, but an outbound
node-TLS X.509 error may be mislabeled `TargetIdentity` by the current later
check (`failure_attribution.go:68-74`).

There is also a package-ownership caveat for future real evidence. The marker is
currently declared in `internal/proxy` (`failure_attribution.go:23-42`), while
the production outbound builder lives in `internal/outbound` and `proxy`
already imports `outbound`. An evidence-aware producer in the builder cannot
import the current marker without an import cycle. Before implementing a real
lower-level producer, move the marker contract to a lower neutral package (for
example `internal/outbound/failure`) and have `proxy` consume it, or define a
neutral marker interface there. This relocation is unnecessary for the minimal
false-positive repair because there is no current producer.

Do not implement any of these tempting alternatives:

- wrapping every adapter error except known SOCKS/HTTP target strings;
- parsing dependency error messages as health proof;
- classifying `net.Error`, syscall refusal/unreachable, EOF/reset, timeout, or
  X.509 alone as node failure at the composite boundary;
- assuming `Outbound.Type()` reveals the internal phase; or
- using reflection/unsafe to reach the private client dialer.

All permit future or already-known target failures to open the selected node's
circuit, contradicting the task's conservative-attribution invariant.

### Deterministic tests

1. **Opaque generic adapter failure stays non-node.** Replace the existing
   `TestRoutedDialBoundaryProducesNodeTransportEvidence` expectation in
   `internal/proxy/transport_test.go:241-265`. A fake outbound returning each of
   `errors.New`, `syscall.ECONNREFUSED`, a `*net.OpError`, EOF, timeout, and an
   X.509 error must not yield `errors.As(..., *NodeTransportFailure)` and must
   assess as `Unknown` (except explicit caller cancellation, which is `Client`).
   If `OpaqueRoutedDialFailure` is added, assert it is present and unwraps the
   original symptom.
2. **Explicit proof remains eligible.** A package-local fake outbound may return
   `&NodeTransportFailure{Err: sentinel}`. Assert the transport preserves it
   through wrapping, `Assess` returns `FailureNode` with
   `NegativeNodeHealth=true`, and the feedback spy gets exactly one negative
   record. This tests the opt-in producer contract without claiming sing-box
   currently supplies it.
3. **Real pinned SOCKS5 target refusal is not node proof.** Start a loopback
   scripted SOCKS5 server, complete method negotiation, read CONNECT, and reply
   with bytes/code 5 (`connection refused`) without dialing the requested
   target. Build a real `{"type":"socks","server":"127.0.0.1",...}` outbound
   with `SingboxBuilder`; call the pooled transport's `DialContext`. Assert the
   error contains the dependency's rejection symptom if desired, but more
   importantly it is opaque/Unknown, is not `NodeTransportFailure`, and records
   no negative health. This uses only loopback and an ephemeral listener.
4. **Real pinned HTTP proxy target failure is not node proof.** Start a loopback
   HTTP server that verifies a CONNECT request and deterministically returns
   `502 Bad Gateway` without target egress. Build a real
   `{"type":"http","server":"127.0.0.1",...}` outbound and make the same
   assertions. This directly guards the current regression.
5. **Repeated failures do not mutate node health.** Feed each of the two real
   protocol failures through the reverse health path at least the configured
   circuit threshold and assert failure count/circuit state and feedback-call
   count remain unchanged. Then run the explicit-proof fake at the threshold to
   show the existing passive circuit behavior still works.
6. **Target TLS remains correctly classified.** Have the fake outbound return a
   successful `net.Conn` to a loopback TLS server with an untrusted/mismatched
   certificate. Because this failure occurs after outbound dial success, it must
   remain `TargetIdentity`, not opaque and not node proof. This protects the
   distinction introduced by an opaque routed-dial wrapper.

The real-protocol tests should assert semantic health/attribution, not concrete
unexported `*errors.errorString` types or the full dependency message, so a
dependency patch cannot silently restore false-positive node health.

## Files Found

- `go.mod` - pins `github.com/sagernet/sing-box v1.12.21` and
  `github.com/sagernet/sing v0.7.18`.
- `internal/proxy/transport.go` - currently wraps every composite routed
  outbound dial error as `NodeTransportFailure`.
- `internal/proxy/failure_attribution.go` - owns the marker, attribution order,
  and negative-health gate.
- `internal/proxy/transport_test.go` - currently codifies the over-broad adapter
  boundary and is the first regression test to change.
- `internal/outbound/builder.go` - constructs official sing-box outbounds via
  the registry; it has no injected server-dial observer.
- `internal/outbound/manager.go` - stores the built outbound interface on the
  node entry.
- `internal/node/entry.go` - stores raw options plus only an
  `adapter.Outbound` pointer, not protocol phase hooks.
- `internal/proxy/route_outbound.go` - route resolution exposes only the stored
  outbound interface to the proxy transport.
- `/home/agent/go/pkg/mod/github.com/sagernet/sing-box@v1.12.21/adapter/outbound.go`
  - public outbound contract is only a generic dialer.
- `/home/agent/go/pkg/mod/github.com/sagernet/sing-box@v1.12.21/protocol/socks/outbound.go`
  - private SOCKS client wiring and composite delegation.
- `/home/agent/go/pkg/mod/github.com/sagernet/sing-box@v1.12.21/protocol/http/outbound.go`
  - private HTTP client/TLS-detour wiring and composite delegation.
- `/home/agent/go/pkg/mod/github.com/sagernet/sing@v0.7.18/protocol/socks/client.go`
  and `handshake.go` - configured-server dial plus target negotiation and error
  flattening.
- `/home/agent/go/pkg/mod/github.com/sagernet/sing@v0.7.18/protocol/http/client.go`
  - configured-server dial plus target CONNECT and status flattening.
- `/home/agent/go/pkg/mod/github.com/sagernet/sing@v0.7.18/common/exceptions/error.go`
  - proves `E.New` produces only ordinary `errors.New` values.

## External References

- Dependency source inspected from the local Go module cache for the exact
  versions pinned by `go.mod`: sing-box `v1.12.21` and sing `v0.7.18`.
- No external documentation promises a stronger error contract than the source
  above; dependency error strings should therefore be treated as implementation
  details, not a production API.

## Related Specs

- `.trellis/tasks/08-14-platform-tls-verify-policy/prd.md:87-95,240-245,302-308`
  - only explicitly node-attributed failures may create negative health;
  unknown/target failures must not.
- `.trellis/tasks/08-14-platform-tls-verify-policy/design.md:300-337` - intended
  attribution model; lines 330-335 need correction because the sing-box adapter
  dial is not actually a node-only boundary.
- `.trellis/tasks/08-14-platform-tls-verify-policy/research/first-principles-audit.md:101-107`
  - previously left the concrete evidence threshold for separate design.
- `.trellis/spec/guides/cross-layer-thinking-guide.md` - requires explicit error
  contracts at layer boundaries; here the important boundary is physical node
  dial versus proxy target CONNECT, not merely the Go interface call.

## Caveats / Not Found

- No public node-server dial/error callback, phase-tagged error, exported SOCKS
  reply error, exported HTTP CONNECT status error, or injectable dialer factory
  was found in the pinned APIs used by Resin.
- No standard sing-box outbound in the current Resin wiring can construct the
  Resin-local `internal/proxy.NodeTransportFailure`; only package-local tests can
  do so without moving the contract.
- The environment did not expose a `go` executable on `PATH`, so this research
  could inspect the complete cached source but did not execute proposed tests.
- Other supported proxy protocols can also combine node and target work or use
  lazy/early connections. The absence of a generic phase hook means findings
  for SOCKS/HTTP justify the conservative generic rule; they do not establish
  safe positive classifiers for VMess, VLESS, Trojan, SSH, Shadowsocks, or other
  outbounds.
