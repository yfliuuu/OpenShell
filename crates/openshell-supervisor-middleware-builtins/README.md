# Built-in supervisor middleware

The gateway installs validation-only services. Supervisors install execution
services through `services_for_sandbox`, using the immutable sandbox ID and a
clone of the live `ProviderCredentialState` handle. Registry reconstruction must
reuse that handle, not a startup credential snapshot.

## Mandatory static authentication

The gateway and supervisor enable the `mandatory-static-auth` Cargo feature by
default:

```shell
cargo build -p openshell-gateway -p openshell-supervisor
```

Deploy matching gateway and supervisor runtime artifacts. They register
`acme/myservice-auth` in-process; do not add an external gRPC middleware
registration. Compilation makes the handler available, but only a sandbox
policy attachment activates enforcement. It requires gateway-managed sandbox
configuration, not standalone proxy or local policy-file mode.

Builds using `--no-default-features` must select `mandatory-static-auth` when
they need the handler. The `defaults-without-telemetry` aliases and the
supervisor's `system-ca-roots` alias retain it.

Attach providers declaring distinct static credential environment keys and
endpoint bindings, then configure one mandatory attachment independently of the
providers' generated policies:

```yaml
network_middlewares:
  mandatory_myservice_auth:
    middleware: acme/myservice-auth
    order: 2147483647
    on_error: fail_closed
    endpoints:
      include: [api.service-1.com, api.service-2.com]
    config:
      rules:
        - host: api.service-1.com
          port: 443
          path: "/**"
          credential_env: SERVICE_1_TOKEN
          header_name: X-MyService-ID
        - host: api.service-2.com
          port: 443
          path: "/**"
          credential_env: SERVICE_2_TOKEN
          header_name: X-MyService2-ID
```

Each selected request must match exactly one host/port/path rule. The handler
replaces all existing values of that rule's header, including literal
credentials supplied by the workload. It resolves only the selected key, which
must be a current declared static credential authorized for the admitted host,
port, and path. Missing, expired, unsafe, or unauthorized credentials fail
closed without falling back to another rule or provider.

Rules support ordinary custom header names. Protected headers such as
`Authorization`, `Cookie`, framing/hop-by-hop headers, `x-amz-*`, and
`x-openshell-credential*` remain forbidden. The service must treat its selected
header as authoritative; it must not authenticate another identity through an
alternative channel or expose the credential in responses.

Use 1-64 rules with all five fields shown above. Hosts use the policy's
DNS-label-aware patterns. Paths use provider endpoint semantics (`/v1/**`
includes `/v1`), are case-sensitive, and match the credential-redacted request
path without its query. Selected traffic with no rule is denied, including
unmatched ports or paths on selected hosts. Traffic outside the attachment's
host selector is unaffected.

Admission rejects potentially overlapping rules; it never uses list order as
precedence. Exact paths and subtrees can prove disjointness. General path globs
on overlapping host/port scopes are conservatively rejected when disjointness
cannot be established. The outer selector must cover every rule host. Wildcard
rules require a verbatim or universal `**` include and no overlapping exclusion;
literal hosts may use broader includes.

The legacy `config: {credential_env: MYSERVICE_TOKEN, header_name: X-MyService-ID}`
form remains supported as an attachment-wide rule. Do not mix it with `rules`.

The maximum signed 32-bit order reserves the last request middleware position.
Other policy attachments must have distinct, lower orders. Gateway admission
checks the attachment configuration without credential access. Supervisor
activation also rejects dynamic token grants targeting the same header on
potentially overlapping host/port/path rule scopes. Grants for other headers or
disjoint scopes can coexist. The legacy form retains host-wide conflict checks.

The handler uses the existing buffered `HTTP_REQUEST/PRE_CREDENTIALS` operation
with a 256 KiB body limit and the platform's default evaluation timeout. It does
not add a streaming-request fast path. Uninspected routes and `tls: skip` cannot
satisfy mandatory enforcement. The normal inspected HTTP protocol limitations
still apply.

## Credential lifecycle and dispatch

The atomic accessor captures the value with its provider revision, local
installation ID, expiry, and binding identity. A local-only evaluation result
carries provenance through the middleware chain and request preparation. The
final write guard validates the original installation and expiry. Later
credential preparation cannot reauthorize an old literal token by capturing a
newer installation.

Existing middleware callbacks use a default adapter with no credential
provenance. Mandatory authentication requires provenance on successful results.
The remote middleware protobuf contract is unchanged. New result wrappers omit
request bodies and credential-bearing mutations from debug output.

An initialized but unavailable credential is a valid runtime state. Detachment
and revocation can activate without the selected credential while the attachment
remains present, including with last-known-good policy retention enabled.
Protected requests then fail closed; an explicitly authorized replacement
restores service without restarting the workload. Registry rebuilding preserves
access to the same live state.

Only activation changes the authorization boundary. A separately invalid
configuration can still be rejected; do not report its revocation as activated.
Requests already dispatched are not recalled or automatically replayed.

## Verification

Run the focused tests:

```shell
cargo test -p openshell-core --lib atomic_static_capture
cargo test -p openshell-core --lib endpoint_path
cargo test -p openshell-core --lib host_pattern
cargo test -p openshell-supervisor-middleware --lib credential_provenance
cargo test -p openshell-supervisor-middleware --lib headers::tests
cargo test -p openshell-supervisor-middleware-builtins --lib --features mandatory-static-auth mandatory_auth
cargo test -p openshell-supervisor-network --lib mandatory_auth
cargo test -p openshell-supervisor-network --lib middleware_provenance
cargo test -p openshell-supervisor --lib mandatory_auth
cargo test -p openshell-server --lib --features mandatory-static-auth middleware::tests
```

The network tests exercise inspected and passthrough HTTP relays, repeated
headers, placeholder inputs, concurrent credential states, and rotation and
revocation on existing keep-alive connections. They include one sandbox state
with two providers and different custom headers, verifying that selective
revocation leaves the other endpoint usable. Dispatch tests cover expiry and
installation changes before upstream writes.

Against a dedicated E2E gateway and supervisor with the handler available, use:

```shell
cargo test --manifest-path e2e/rust/Cargo.toml --features e2e-docker,e2e-mandatory-static-auth --test proxy_egress_pipeline mandatory_static_auth_overwrites_workload_credentials
```

Use the repository's existing E2E setup to prepare that dedicated gateway and
workload image first. The E2E feature selects the test; it does not rebuild or
replace running gateway and supervisor artifacts.
