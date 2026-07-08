# Hook Ownership Refactor

Design proposal — enforced ownership for kernel hooks and observers, replacing
today's honor-system-by-string mechanism with a Linux-LSM-style ownership
model where every non-kernel hook is tied to a lifecycle-managed entity that
enforces cleanup on drop.

**Status:** design proposal — awaiting review before implementation.

**Scope:** kernel `NativeHookRegistry` + `ObserverRegistry` registration
APIs, plus `ServiceRegistry`.  Consumer migration: `services::audit` (the
only true hook-only service today).  Kernel-adjacent trusted code
(`PermissionHook`, `BoundaryHook`, `transport::transport_observer`) stays
on the unscoped surface per an explicit whitelist.  Driver-owned hooks
(`DriverLifecycleCoordinator` extension) is scoped in but tracked as
follow-up.

---

## 1. Current state

Kernel exposes six registration methods on `Kernel`:

| Method | Owner tag | Enforced? |
|--------|-----------|-----------|
| `register_native_hook(hook)` | `hook.name()` | No — no owner |
| `register_observer(observer, name, mask)` | `name` | No — no owner |
| `register_service_hook(service_name, hook)` | `service_name` (string) | No — string not validated |
| `register_service_observer(service_name, observer, name, mask)` | `service_name` (string) | No — string not validated |
| `unregister_native_hook(name)` | — | — |
| `unregister_observer(name)` | — | — |

Service-scoped registrations record a `service_name → [hook_or_observer_name]`
mapping in `Kernel::service_hook_names` / `service_observer_names`. On
`unregister_service(name)`, `unhook_service(name)` batch-removes every hook
and observer the service installed.

**No cross-check** against `ServiceRegistry`. Any string is accepted as
`service_name`. Nothing prevents a caller from passing a name that has no
corresponding registry entry — the mapping is populated on push, orphaned on
drift.

**Production callers today:**

- `services::audit::install_root` — `register_native_hook` (unscoped) + `register_observer` (unscoped, tag `"zone_audit_auto_wire"`).
- `services::managed_agent::install` — two `register_native_hook` calls (unscoped).
- `services::matrix_adapter::rooms::install` + `sync::install` — `register_native_hook` (unscoped).
- `transport::transport_observer::install` (nexus-vfs #126) — `register_observer` (unscoped, tag `"transport-observer"`).  Kernel-adjacent trusted transport-tier code; not a `ServiceRegistry` entry.

No production caller of `register_service_hook` / `register_service_observer`
exists.  The service-scoped API is defined and unit-tested but no service
today uses it — all service-tier hooks reach directly for the unscoped
surface and rely on convention to remember what they installed.  The
transport-tier `transport_observer` also uses the unscoped surface, but for
a different reason: it's kernel-adjacent code and would be whitelisted with
`PermissionHook` / `BoundaryHook` under the enforced surface below.

**`ServiceRegistry` shape today** (`core/service_registry.rs:80`):

```rust
enum ServiceInstance {
    Managed(Box<dyn ServiceLifecycle>),  // gRPC sidecar / dylib
    Rust(Arc<dyn RustService>),          // in-tree Rust service
}
```

Every entry must implement one of the two lifecycle traits — no "hook-only,
no RPC" variant. Audit conceptually IS a service (identity, boot-installed,
owns per-zone state) but doesn't expose a `Call()` RPC, so it doesn't fit
either variant and is absent from `ServiceRegistry`.  (Transport_observer
does NOT need a `ServiceRegistry` entry — it's a transport-tier primitive,
owned by the transport crate itself, with the same lifecycle as
`transport::peer_blob`; see §5.2.)

**`DriverLifecycleCoordinator`** (`core/dlc.rs:28`) is an empty unit struct
today, holding mount lifecycle (routing + metastore) only. No hook API,
no unregister-on-drop path.

## 2. Design goals

1. Every non-kernel hook has a formal owning entity — a service (in
   `ServiceRegistry`) or a driver (in `DriverLifecycleCoordinator`).
2. Ownership is enforced at registration time — the owner must exist in its
   registry before its hooks/observers can register.
3. Automatic cleanup on owner drop — service unregister or driver unmount
   removes every hook and observer the entity installed.
4. Extends to driver-owned hooks — future capability (Linux drivers install
   netfilter / LSM hooks tied to their module lifetime).
5. Existing service-tier consumers migrate cleanly — `services::audit` becomes
   a proper `ServiceRegistry` entry with legitimate identity.
   `transport::transport_observer` (nexus-vfs) does NOT migrate — it's a
   transport-tier primitive whose owner is the crate itself, whitelisted
   alongside `PermissionHook` / `BoundaryHook`.

## 3. Design

### 3.1 `ServiceInstance::HookOnly` variant

Extend `ServiceRegistry::ServiceInstance` with a third variant for services
whose only kernel surface is hook/observer registration:

```rust
enum ServiceInstance {
    Managed(Box<dyn ServiceLifecycle>),
    Rust(Arc<dyn RustService>),
    HookOnly(HookOnlyService),          // NEW
}

struct HookOnlyService {
    // Handles registered under this service; kernel drains on unregister.
    // Populated by `register_service_hook` / `register_service_observer`
    // when they resolve to this entry.  Kernel-internal detail — services
    // never construct this directly.
}
```

`HookOnlyService` has no `RustService` / `ServiceLifecycle` trait implementation.
It exists purely as a lifecycle anchor — enlist creates it, unregister drains
it. `ServiceRegistry::enlist_hook_only(name)` is the new entry point.

### 3.2 Handle-based registration

Change the four `register_service_*` methods to require an `ServiceHandle`
issued by `ServiceRegistry` at enlist time:

```rust
// Before (honor-system):
kernel.register_service_observer("transport-observer", obs, name, mask);

// After (enforced):
let handle = kernel.enlist_hook_only_service("transport-observer")?;
kernel.register_service_observer(&handle, obs, name, mask);
```

`ServiceHandle` is an opaque token that internally references its
`ServiceRegistry` entry. `register_service_*` reads the handle to reach the
entry directly — no string lookup, no drift possible. Constructing a handle
without going through the registry is impossible (private ctor).

The unscoped `register_native_hook` / `register_observer` remain, restricted
to **kernel built-ins** — a compile-time-tagged whitelist (`PermissionHook`,
`BoundaryHook`, kernel-owned `FileWatcher` waiters). Services must go through
the handle path.

### 3.3 Cleanup on drop

`ServiceRegistry::unregister(name)` already invokes `unhook_service(name)`.
Under the handle model, `HookOnly` entries drain the same way — the
handle-tagged registrations attached to the entry are batch-removed. Dropping
the last `Arc<ServiceHandle>` triggers no cleanup by itself; cleanup is
lifecycle-driven at unregister time. Handles are cheap to clone.

### 3.4 Driver extension (follow-up)

`DriverLifecycleCoordinator` gains a symmetric API:

```rust
let driver_handle = dlc.enlist(driver_name)?;
kernel.register_driver_hook(&driver_handle, hook);
```

Unmounting the driver drains its hooks. `DriverHandle` is a distinct type from
`ServiceHandle` — registrations are keyed by handle type + entry, so a service
and a driver cannot alias.

## 4. Alternative considered — parallel `HookOwnerRegistry`

A second `HookOwnerRegistry` was considered — one that holds hook-only owners
separately from `ServiceRegistry`. This was rejected:

- Two registries must be kept in sync (services that migrate between RPC and
  hook-only surfaces would move between registries).
- `unhook_service` already knows how to batch-clean by tag; splitting into two
  registries doubles the batch-clean paths.
- Conceptually, audit IS a service — it has identity, boot lifecycle,
  register/unregister semantics — it just doesn't expose a `Call()` RPC.
  Modeling it as a `ServiceInstance` variant matches reality.

`ServiceInstance::HookOnly` is a smaller change with a single registry as the
lifecycle SSOT.

## 5. Migration

### 5.1 `services::audit`

- `install(kernel, zone_id, stream_path)` becomes handle-driven: enlist a
  hook-only service `"audit"`, register `AuditHook` via the handle. Called
  per-zone by `ZoneAuditAutoWire`.
- `install_root(kernel, root_zone_id, stream_path)` enlists `"audit"` once,
  installs the root-zone `AuditHook`, then registers the
  `ZoneAuditAutoWire` observer under the same handle.

### 5.2 `transport::transport_observer` — no migration

`transport::transport_observer` (nexus-vfs #126) is a transport-tier
primitive owned by the transport crate, not a service in `ServiceRegistry`.
It's the dual of `transport::peer_blob` (peer_blob fetches, transport_observer
classifies), installed at the same boot step by cluster main, and shares
peer_blob's lifecycle.  Uses the unscoped `register_observer` — legitimate
for kernel-adjacent trusted code, whitelisted alongside `PermissionHook`
and `BoundaryHook` under the enforced surface below.

### 5.3 Other current unscoped callers

- `services::managed_agent`, `services::matrix_adapter`, dylib plugins — each
  gets a `ServiceHandle` from their existing `ServiceRegistry` entry (they
  already have `RustService` impls) and migrates their `register_native_hook`
  calls to the handle path.

Legacy unscoped `register_native_hook` / `register_observer` calls without a
kernel-built-in tag become compile errors after the migration completes.

## 6. Non-goals

- No runtime feature-flag gate on federation — feature flags remain the sole
  build gate for optional services (consistent with today's
  `services::audit::install_root`).
- No change to `MutationObserver` trait shape or `FileEvent` payload.
- No move of audit or transport_observer to a different crate.
- No change to the syscall ABI.

## 7. Rollout

Three PRs, sequential (this design doc already merged as nexus-vfs #125):

1. **nexus-vfs** — `ServiceInstance::HookOnly` variant + `ServiceHandle` type
   + handle-based `register_service_*` APIs.  Existing string-based APIs stay
   temporarily as deprecated aliases forwarding to the new path so nexus can
   migrate incrementally.  Kernel-adjacent trusted code (`PermissionHook`,
   `BoundaryHook`, `transport::transport_observer`) keeps calling the
   unscoped `register_native_hook` / `register_observer` per an explicit
   compile-time whitelist.
2. **nexus** — migrate `services::audit` from unscoped registration to
   handle-based enrollment.  Bumps nexus-vfs dep pin.
3. **nexus** — migrate remaining service-tier callers
   (`services::managed_agent`, `services::matrix_adapter`, dylib plugins)
   to handles.  Then delete the deprecated string-based `register_service_*`
   APIs in nexus-vfs; every service-tier caller now uses handles, transport
   tier stays on the whitelisted unscoped surface.

## 8. Open questions

- Handle lifetime: should `ServiceHandle` be `Clone` (multiple hook install
  sites share one)? Preference is yes — simplifies zone-mount auto-wire loops
  that hold a single handle across many `install_for_zone` calls.
- Deprecation window: does the CI kernel-architecture lint gate on the
  handle path once step 4 lands, or is a follow-up lint PR expected?
- Driver hook extension: land in step 2 or as a fifth PR after audit +
  transport-observer migrate? Preference is fifth PR — keeps step 2 focused
  on the service side.
