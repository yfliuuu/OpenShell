# Network supervisor

This crate forbids unsafe code, including its local tests. Typed socket APIs
provide original-destination lookup for transparent proxying.

Socket attribution tests pass a duplicate connected socket as a spawned child's
stdin. Re-executing the test binary checks multiple holders with the same binary
identity; executing a different binary checks ambiguous shared-socket identity.
The fixture kills and reaps the child when the parent test ends.

The manual proxy performance baseline still counts allocations. Its test-only
global allocator uses `openshell-driver-vm::allocation_tracking`; the unsafe
allocator implementation belongs to the VM crate. The VM dependency disables
default features, so this instrumentation does not
require the compute runtime or Unix-only sandbox library. It is a development
dependency only.

## Local credential provenance

Local authentication middleware can return typed credential provenance alongside
HTTP mutations. Carry it through request rebuilding into each request's
`L7EvalContext`, independently of the connection's credential state. Inspected,
passthrough, and forward-proxy dispatch guards validate the originating
installation and expiry before writes. Do not overwrite that pin when later
credential preparation reads the live state.

The opt-in handler and its verification commands are documented in
[built-in middleware](../openshell-supervisor-middleware-builtins/README.md).
