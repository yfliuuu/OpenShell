# Built-in supervisor middleware

The gateway installs validation-only services. Supervisors install execution
services through `services_for_sandbox`, using the immutable sandbox ID and a
clone of the live `ProviderCredentialState` handle. Registry reconstruction must
reuse that handle, not a startup credential snapshot.

## Opt-in mandatory static authentication

Build both binaries with the `mandatory-static-auth` feature:

```shell
cargo build -p openshell-gateway -p openshell-supervisor --features mandatory-static-auth
```

Deploy these binaries in your custom gateway and supervisor runtime artifacts.
The feature is off by default. It registers `acme/myservice-auth` in-process;
do not add an external gRPC middleware registration. It requires gateway-managed
sandbox configuration, not standalone proxy or local policy-file mode.

Attach a provider declaring a static credential environment key and endpoint
binding, then configure the mandatory attachment independently of the provider's
generated policy:

```yaml
network_middlewares:
  mandatory_myservice_auth:
    middleware: acme/myservice-auth
    order: 2147483647
    on_error: fail_closed
    endpoints:
      include: [api.myservice.example]
    config:
      credential_env: MYSERVICE_TOKEN
      header_name: X-MyService-ID
```

This implementation supports only the `X-MyService-ID` custom header. It replaces
all existing values, including literal credentials supplied by the workload.
The configured key must resolve to a current declared static credential
authorized for the admitted host, port, and path. Missing, expired, or unsafe
credentials fail closed. The service must not authenticate another identity
through a different header, cookie, query parameter, or body.

The maximum signed 32-bit order reserves the last request middleware position.
Other policy attachments must have distinct, lower orders. Gateway admission
checks the attachment configuration without credential access. Supervisor
activation also rejects dynamic token grants targeting the same header on
overlapping hosts. Grants for other headers or non-overlapping hosts can coexist.

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
cargo test -p openshell-supervisor-middleware --lib credential_provenance
cargo test -p openshell-supervisor-network --lib mandatory_auth
cargo test -p openshell-supervisor-network --lib middleware_provenance
cargo test -p openshell-supervisor --lib --features mandatory-static-auth mandatory_auth
cargo test -p openshell-server --lib --features mandatory-static-auth middleware::tests
```

The network tests exercise inspected and passthrough HTTP relays, repeated
headers, placeholder inputs, concurrent credential states, and rotation and
revocation on existing keep-alive connections. Dispatch tests cover expiry and
installation changes before upstream writes.

Against a dedicated E2E gateway and supervisor built with the feature, use:

```shell
cargo test --manifest-path e2e/rust/Cargo.toml --features e2e-docker,e2e-mandatory-static-auth --test proxy_egress_pipeline mandatory_static_auth_overwrites_workload_credentials
```

Use the repository's existing E2E setup to prepare that dedicated gateway and
workload image first. The E2E feature selects the test; it does not rebuild or
replace running gateway and supervisor artifacts.
