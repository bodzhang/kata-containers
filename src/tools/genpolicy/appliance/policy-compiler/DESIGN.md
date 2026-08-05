# GenPolicy Appliance Policy Compiler

This document is the source of truth for the appliance's final stage, the
standalone policy compiler. It owns the regex and value-generalization contract
for turning captured `CreateContainerRequest` artifacts into deployable Kata
Agent policy. The dry-run capture flow that produces the compiler's inputs is
described in [../DESIGN.md](../DESIGN.md).

## Role

The compiler is an appliance-local Rust binary. Its runtime inputs are paired
raw and tagged `CreateContainerRequest` files plus `dynamic-tags.json`. The raw
request preserves exact request-level storages, devices, and flags; the tagged
request carries the nested final OCI with deployment-variable markers. There is
no direct OCI-config, storage-predictor, or partial-capture fallback. In the
current implementation, “flags” means `sandbox_pidns`; other captured
request-level fields are listed explicitly under
[Request authority and coverage](#request-authority-and-coverage).
The compiler also reads exact exec commands from workload probe and lifecycle
actions because those future Agent `ExecProcessRequest` operations are not part
of the OCI `CreateContainer` specification.

The production appliance must not build, install, or invoke the legacy
`genpolicy` binary. It must not call `AgentPolicy::from_files()`,
`get_container_policy()`, or the Pod/controller-specific YAML-to-policy
generators. A separate test-only Docker target may build and invoke the legacy
binary solely to compare outputs during validation.

The compiler owns small serializable `PolicyData` and `ContainerPolicy`
wrappers because the corresponding legacy container fields are private.

## Fidelity model: capture structure, generalize deployment-specific values

The compiler exists because the dry-run and the production cluster resolve the
same workload YAML differently, and the policy must accept the production
result while remaining tightly bounded.

Legacy GenPolicy hardcodes templates that predict which environment variables,
storages, and mounts the API server, kubelet, containerd, and Kata shim inject,
and with which shapes. Those templates encode one point-in-time understanding of
component behavior and drift as the components evolve.

The appliance instead runs the pinned real components in a clean room, so the
**set and structure** of injected environment variables, storages, mounts, and
OCI fields is captured at high fidelity with no template guessing. The trade is
that the concrete **values** produced by that run belong to the dry-run cluster,
not the deployment target. When the same YAML is applied to a production
cluster it is normalized by that cluster's configuration: its service CIDR and
resulting ClusterIPs, its assigned service ports, its containerd-assigned
sandbox and container IDs, its API-server-assigned Pod UID, its node name, its
CNI-assigned network-namespace UUID, and host paths that embed those
identifiers.

Every captured Agent-interface string therefore belongs to one of two classes,
and the compiler treats them differently.

### Value classification

- **Deployment-invariant** values come from the trusted workload declaration or
  the pinned image and profile. They are compiled **exact**: process argv,
  working directory, image identity/digest, YAML-declared environment entries,
  `volumeMount` destinations, `securityContext` UID/GID, capabilities, no-new-
  privileges, root read-only state, masked and read-only paths, mount
  destinations/types/options, and probe/lifecycle exec argv.
- **Deployment-variable** values are assigned by the target cluster at deploy
  time. They are compiled as **typed, anchored, bounded regexes or structured
  correlations**, rather than open wildcards. The legacy compatibility mode has
  explicit exceptions documented below.

  | Value | Grammar / correlation |
  | --- | --- |
  | Service `_HOST` / `_ADDR` | bounded IPv4/IPv6 address grammar |
  | Service `_PORT` numeric and `_SERVICE_PORT` | bounded numeric `[0-9]{1,5}` |
  | Service `_PROTO` | protocol enum `(tcp\|udp\|sctp)` |
  | Composite service `_PORT` (`proto://ip:port`) | proto enum + address grammar + port grammar, fully anchored |
  | Sandbox ID | bounded annotation pattern; its runtime value is then reused when matching sandbox-scoped storage and mount paths |
  | Container / bundle ID | extracted from the runtime root path and reused when matching bundle-scoped storage and mount paths |
  | Pod UID | UUID grammar; the only dynamic component admitted in the sandbox log-directory pattern |
  | Node name | `$(node-name)` request correlation |
  | Pod / sandbox name | `$(sandbox-name)` correlation derived from workload `metadata`, not the synthetic clean-room name |
  | CNI network namespace | bounded `/var/run/netns/cni-<uuid>` grammar |
  | External-untrusted mount source | regex anchored wholly inside an allowlisted runtime-managed shared-filesystem domain (see the source-domain contract below) |

The dry-run raises fidelity on **which** fields exist; the compiler restores
portability on the values the production cluster reassigns, using the tightest
grammar that admits every legitimate production value and nothing else.

### Regex security invariants

- Anchor every marker-generated expression with `^` and `$`, escape all static text,
  and use a field-specific grammar rather than `.+` or `.*`.
- Security-relevant identities and destinations use exact values or structured
  correlation, never an open regex.
- Identifiers that recur across fields (sandbox/container ID, Pod UID) are
  correlated by binding the value once and reusing it, preserving relational
  integrity instead of independent wildcards.
- External-untrusted sources use a regex only when it is emitted from a trusted
  profile after trust-domain classification and is confined to an allowlisted
  external domain; UVM-local sources must never satisfy an external rule.
- Unknown or unclassified dynamic-marker contexts fail closed; they are never
  reduced to `.*`, prefix matching, or a user-provided raw regex.
- Treat inherited legacy expressions separately from marker-generated
  expressions. Legacy mode deliberately retains broad service-variable-name
  patterns and `^/.*$` termination-message compatibility; balanced mode removes
  those two broad surfaces.

## Dynamic OCI field treatment

Regexes apply to complete policy field values, not to unchecked fragments. For
environment entries, the matched value is the complete `NAME=value` string and
every input entry must match an exact policy environment entry or an approved
anchored regex.

| OCI-derived value | Legacy mode | Balanced mode |
| --- | --- | --- |
| Explicit image/YAML environment values | Exact `NAME=value` | Exact `NAME=value` |
| Kubernetes service-link environment values | Omitted from exact `Env` when covered by an inherited, anchored service-variable regex; generation fails if any captured variable lacks coverage | Per-variable anchored regex keyed to the exact captured variable name, with a typed value grammar (bounded IPv4/IPv6 for `_HOST`/`_ADDR`, numeric port, protocol enum). Portable across ClusterIP and port reassignment; tighter than legacy because the accepted variable-name set is exactly the captured services rather than any service-shaped name |
| Pod name, Pod UID, and node-derived environment values | Structured substitutions such as `$(sandbox-name)`, `$(pod-uid)`, and `$(node-name)` | Same structured substitutions; these are correlations to request/runtime state rather than arbitrary wildcard regexes |
| Sandbox and bundle/container IDs | Sandbox annotation values use bounded patterns; Rego reuses the runtime sandbox ID and extracts the bundle/container ID from the runtime root path for path correlation | Same structured correlation where deployment-time generation prevents an exact value |
| Kata `nerdctl/network-namespace` | Synthesized from the sandbox OCI network namespace and matched with the bounded `/var/run/netns/cni-<UUID>` grammar | Same bounded CNI grammar; an exact captured UUID is not deployable because CNI generates a new value |
| Sandbox log directory | Namespace and sandbox name are correlated to the request; only the Pod UID component uses a typed UUID grammar | Same relational pattern |
| Termination-message request path | Legacy-compatible `^/.*$` | Exact `/dev/termination-log`, accepted only when capture proves the dedicated external kubelet bind mount |
| Guest-visible source of an externally backed mount | Trusted-profile regex anchored within the Kata shared-filesystem domain | Same trust-domain-confined regex; exact matching would not make mutable host content trustworthy |
| Process argv, working directory, UID/GID, capabilities, root read-only state, mount destinations/types/options, masked paths, and read-only paths | Exact captured values, with documented Kata normalization where required | Exact captured values, with the same documented Kata normalization |
| Unknown dynamic strings or unsupported marker contexts | Left exact or generation fails; never converted to `.*` | Left exact or generation fails; never converted to `.*` |

`dynamic-tags.json` records marker provenance and grammars with request-rooted
JSON pointers. `createcontainer-requests/` remains the exact request reference,
while `policy-oci-diff.json` records whether each compiled field came from the
captured request, trusted workload YAML, or explicit policy normalization.

## Legacy and balanced policy modes

The appliance supports two deployable policy modes from the same request captures:

- **legacy** is the default compatibility mode. It preserves inherited
  `allow_env_regex` entries and the legacy service-variable grammars, permits
  any termination-message path, and generalizes generated CNI and kubelet path
  components. A generation-time coverage gate verifies that every captured
  service variable omitted from exact `Env` entries is covered by an inherited
  regex. The inherited service grammar accepts any service-shaped variable name,
  so this mode carries the broadest authorization surface;
- **balanced** is enabled with `GENPOLICY_BALANCED=1`. It clears the inherited
  environment regexes and replaces each captured service endpoint with a
  per-variable anchored, typed regex keyed to the exact captured variable name
  (bounded IPv4/IPv6 for `_HOST`/`_ADDR`, numeric port, protocol enum) rather
  than an exact IP or port, because both the ClusterIP and the cluster-assigned
  ports differ between the dry-run and production clusters. It restricts
  termination messages to the dedicated externally backed `/dev/termination-log`
  mount unless those strings already contain an existing generated name/UID
  marker. It emulates the Kata shim by copying the sandbox OCI network namespace
  path into `nerdctl/network-namespace`, then generalizes that generated CNI
  path with a bounded regex. Existing regex-backed relation markers remain
  explicit residual risks.

`policy.rego` contains legacy mode and `policy-balanced.rego` contains balanced
mode. `policy-mode-report.json` records their differences. Neither mode requires
regeneration when a service ClusterIP or port is reassigned; both admit any
value inside the bounded grammar. Regeneration is required when the service
**topology** changes — a service added, removed, or renamed, or its protocol
changed — because balanced pins the captured variable-name set. Both modes
retain bounded generated-identity relationships required for deployable
controller workloads. Raw requests under `createcontainer-requests/` remain the exact reference
for generated values that cannot be predicted safely at deployment time.

A future external-domain mode may wildcard endpoints or storage sources only
inside a structured external-untrusted trust domain. It requires runtime
knowledge to exclude UVM-local, loopback, link-local, agent/control endpoints,
and TCB-internal filesystem paths; the current generic IP/path regexes cannot
provide that guarantee. Balanced mode also does not yet distinguish image/YAML
environment provenance from unknown runtime injection or enforce
required-exactly-once environment keys.

Balanced mode must reject a termination-message path that is not the dedicated
external kubelet bind mount. Exact capture is insufficient: pinning a malicious
path under image code or UVM-internal state would preserve an overwrite
primitive. Detection of the external kubelet mount uses its normalized
`pods/<pod-id>/containers/<container>/<log-id>` role and does not pin the host's
kubelet root directory.

## Effective regex rules

The Rego evaluator uses regex matching for several policy fields, but that does
not mean every such field is intentionally variable. The compiler must
distinguish literal values, structured substitutions, and intentional regexes.

### Environment

- Exact captured `NAME=value` entries remain exact.
- `$(node-name)`, `$(pod-uid)`, and `$(sandbox-name)` preserve the captured
  environment variable name and correlate only the value.
- In balanced mode, each captured service variable gets one fully anchored
  expression. The variable name and `=` are regex-escaped literals; only the
  value uses its typed IP, port, protocol, or composite grammar.
- In legacy mode, inherited expressions use
  `$(svc_name_downward_env)`, currently
  `[A-Z](?:[A-Z0-9_]{0,61}[A-Z0-9])?`. Consequently any service-shaped variable
  name may match. The generation-time coverage check proves that captured
  service variables are accepted, but it does not narrow the accepted name set.
- Rego checks every runtime environment entry, but the policy does not yet
  enforce image/YAML provenance, duplicate-key rejection, or required-exactly-
  once semantics.

### OCI mounts and Agent storages

- Mount destination, type, and options are exact except for documented
  settings normalizations.
- External shared-filesystem bind sources use compiler-generated, fully
  anchored patterns confined to `$(cpath)` or `$(sfprefix)`. Bundle/sandbox IDs
  are substituted from the same runtime request, random path components have a
  bounded hexadecimal grammar, and volume or destination names are escaped and
  pinned.
- `/dev/shm` is UVM-local and must have the exact source
  `/run/kata-containers/sandbox/shm`.
- Guest-local `tmpfs`, `local`, and `hugetlbfs` storage sources are literal
  constants (`tmpfs`, `local`, and `nodev`). Their mount points are passed to
  `regex.match`, but the compiler emits escaped, fully anchored paths; this is
  regex syntax implementing exact or ID-correlated path matching, not an open
  source wildcard.
- Block storage addresses vary by runtime device assignment. The policy pins
  the storage shape and correlates its mount point to the base64url encoding of
  the runtime device source rather than accepting an arbitrary path.
- Guest-pull image references and dm-verity root hashes are exact per-container
  identities carried by policy-only marker storages.

There is one current representation hazard: `rules.rego` has generic fallback
branches that call `regex.match` on `p_mount.source` and `p_storage.source` even
when the compiler intended the value as a literal. Standard guest-local sources
such as `tmpfs`, `local`, and `nodev` contain no regex metacharacters and are not
broadened in practice, while external patterns need these branches. The policy
schema should nevertheless distinguish literal sources from regex sources, or
the compiler must escape all literal sources before they reach a regex branch.
Until then, newly supported source forms containing regex metacharacters require
an explicit negative test proving that near-matches are denied.

### Annotations

Selected deployment-variable annotation values use anchored patterns, including
the sandbox ID, sandbox log directory, sandbox name, and CNI namespace. The
sandbox ID is reused by sandbox-scoped path substitutions. However, the shared
Rego currently allows any `io.kubernetes.cri.*` annotation key without checking
its value in `allow_anno_key_value`. Specialized rules constrain the subset used
for container selection and path correlation, but the general annotation rule
is a residual authorization gap and must not be described as full annotation
value pinning.

## Compiler implementation contract

### Code reused directly

The compiler should depend on the repository GenPolicy library and reuse these
public components without modifying `src/tools/genpolicy/src`:

- `settings::Settings::new()` and the existing settings/drop-in format;
- policy OCI types including `KataSpec`, `KataProcess`, `KataMount`,
  `KataLinux`, and their child types;
- `policy::get_kata_namespaces()` for guest namespace normalization;
- `yaml::{new_k8s_resource, K8sResource::get_containers}` for common Pod and
  controller traversal;
- `yaml::K8sResource::get_sandbox_name()` for controller-specific Pod-name
  patterns derived from workload metadata;
- `pod::Container::get_exec_commands()` for exact probe and lifecycle commands;
- `yaml::add_policy_annotation()` for annotation placement;
- `kata_types::initdata::{InitData, encode_initdata}` for initdata encoding;
- the existing `rules.rego`, base settings, and appliance settings drop-ins.

The compiler owns small serializable `PolicyData` and `ContainerPolicy`
wrappers because the corresponding legacy container fields are private.

### Appliance-local implementation

The compiler must implement:

- loading paired raw/tagged requests and matching their nested OCI by CRI
  container type/name;
- taking storages, devices, `sandbox_pidns`, and rootfs identity directly from
  the captured request rather than a predictor or workload-derived fallback;
- deterministic ordering and deduplication of equivalent kubelet retries;
- conversion of captured process, user, arguments, environment, working
  directory, capabilities, no-new-privileges, root read-only state, mounts,
  masked paths, and read-only paths into the policy OCI model;
- replacement of dynamic markers with constrained environment, annotation, or
  mount regexes from `dynamic-tags.json`;
- reuse of inherited GenPolicy service-link regexes in legacy mode rather than
  generating redundant service-specific regexes from captured values;
- fail-fast validation that every captured service-link environment variable
  removed from the explicit policy environment is covered by an inherited
  legacy regex, with coverage counts recorded in `policy-oci-diff.json`;
- explicit Kata normalization for guest root paths, shared-filesystem mount
  sources, guest namespaces, bundle annotations, and container-type
  annotations;
- extraction of exact liveness, readiness, startup, post-start, and pre-stop
  exec command arrays from the trusted workload YAML;
- controller-specific sandbox-name patterns from the workload kind and
  `metadata.name` or `metadata.generateName`, rather than the synthetic Pod name
  used only to exercise the clean-room runtime;
- sandbox log-directory patterns bound to the request sandbox namespace and
  name through Rego substitutions, with only the API-assigned Pod UID admitted
  through a typed UUID regex;
- policy assembly with existing Rego rules, deterministic JSON serialization,
  initdata encoding, workload annotation, and field-level provenance.

The captured request is authoritative. A settings template can normalize a
captured field for policy matching, but it cannot introduce a workload mount,
storage, device, process property, or request flag absent from the request.

Rootfs identity is always scoped to one `ContainerPolicy`. The compiler stores
dm-verity root hashes in that container's synthetic `dmverity-roothashes`
storage and guest-pull digest references in its `guest-pull-images` storage.
These policy-only markers are excluded from the Agent storage-count balance.
The legacy pod-level root-hash and image fields remain empty and are not
authorization inputs; a runtime rootfs without a matching container marker is
denied.

### Request authority and coverage

| Captured field | Compiler treatment |
| --- | --- |
| `oci` | Tagged request is compiled; raw OCI is retained for legacy environment coverage checks. |
| `storages` | Raw request is authoritative. Supported volume classes are converted to bounded policy forms; rootfs identities become per-container marker storages. Unsupported classes are omitted to fail closed, or fail generation under strict coverage. |
| `devices` | Raw request devices are copied into the container policy. Workload YAML is consulted only for additional policy checks already defined by the shared GenPolicy model, such as declared `volumeDevices` paths and NVIDIA pGPU count. |
| `sandbox_pidns` | Copied exactly from the raw request. |
| `container_id` | Used to pair captures and report errors; runtime bundle/container identity is correlated through OCI annotations and root paths rather than pinned to the dry-run ID. |
| `exec_id` | Captured but not represented by the compiler. |
| `shared_mounts` | Captured but not represented by the compiler. |
| `stdin_port`, `stdout_port`, `stderr_port` | Captured but not represented by the compiler. |

These unsupported fields are a fail-closed requirement, not merely a
documentation concern: generation must reject non-default values until policy
data and Rego rules represent them. The current deserializer ignores those
fields, so this rejection is an outstanding implementation gap.

Raw and tagged files are paired by basename. Current validation checks
`container_id` and the CRI container type/name annotations. The stronger
contract is to prove that request-level fields are byte-for-byte equivalent and
that every nested OCI difference corresponds to an occurrence recorded in
`dynamic-tags.json`. Until that validation exists, the tagger and its output
directory are part of the trusted compiler input path.

### Non-OCI policy fields

The captured request supplies fields outside OCI as well as its final nested
OCI. For the initial compatibility profile:

- sandbox storages come from the versioned settings profile;
- workload storages, devices, and `sandbox_pidns` come from the raw captured
  request;
- exec command allowlists contain exact commands from workload probe and
  lifecycle actions;
- standard optional runtime annotation patterns are added locally;
- unsupported storage or volume classes are omitted so runtime evaluation fails
  closed, or fail generation when strict storage coverage is enabled; they are
  never reconstructed from Kubernetes YAML.

Probe and lifecycle exec commands are the narrow exception: they describe
future `ExecProcessRequest` operations and therefore do not exist in the
initial `CreateContainerRequest`. The workload declaration is authoritative
for those operations, and the policy admits their argument arrays exactly.

### External storage and device trust boundary

Exact string matching is not a security benefit for the guest-visible source
of host-provided storage. Code inside the Kata UVM must treat the content as
untrusted and mutable even when the source string is stable. The policy's
security obligation is instead to prove that a source classified as external
cannot be redirected to code, data, sockets, devices, or other trusted state
inside the Kata UVM.

The source trust domain is a property of the resolved backing object, not just
its path spelling. A path inside the guest may be an externally backed shared
filesystem mount, while a syntactically similar path may resolve to UVM-local
state through a symlink, bind mount, mount-namespace alias, `..` traversal, or
runtime reconfiguration. Request capture establishes the final Agent-visible
shape but cannot by itself prove the production backing object's identity.

Storage and device policy generation must follow these rules:

- treat source, mount point, driver, filesystem type, options, device type,
  device ID, and container-visible destination as security-sensitive fields;
- accept external sources only from explicitly allowlisted runtime-managed
  roots or identifiers whose backing object is proven to originate outside the
  UVM;
- canonicalize and resolve the source in the relevant mount namespace before
  classification; reject `..`, symlink escapes, bind aliases, and ambiguous or
  nonexistent sources;
- permit a compiler-generated guest-source regex when it is anchored wholly
  inside an allowlisted runtime-managed external domain, such as Kata's shared
  filesystem root; exact matching within that domain does not protect against
  mutable untrusted content;
- reject any source that resolves to the guest root filesystem, container
  rootfs, agent sockets, policy/initdata, runtime control state, or another
  UVM-internal trusted path or device;
- correlate sandbox/container IDs in source paths structurally rather than
  replacing them with an unconstrained path regex;
- never accept a user-provided raw regex for a storage or device source; source
  regexes must be emitted from a trusted profile after trust-domain
  classification;
- require exact device identity and trusted runtime/device-manager provenance;
  a container-visible device path alone does not prove which device is exposed;
- fail generation when source provenance or the external-versus-UVM-local
  classification cannot be established.

The current appliance admits only storage classes with explicit compiler and
Rego handling and rejects or omits unsupported classes so they fail closed.
Captured final storages and devices are authoritative for request shape, while
their backing-object trust remains bounded by the class-specific checks above.

`tests/fixtures/storage-boundary-workload.yaml` exercises `emptyDir`,
ConfigMap, host-directory, and host-character-device volume transformations.
The final request captures are the policy reference artifacts. Policy
generation is expected to fail at the unsupported workload bind mount. This
fixture verifies that capture can observe the transformation without silently
authorizing an unclassified source.

### Proposal: end-to-end storage and device source enforcement

This section describes proposed hardening and is not implemented end to end.
Request-level policy evaluation is active, and the appliance generates bounded
rules for supported storage and device shapes. The remaining design separates
what the clean-room appliance can establish from what must be enforced inside
the Kata UVM. Policy generation alone does not prove the backing object used by
a production Agent.

#### Implementation status

| Capability | Current status |
| --- | --- |
| Evaluate the incoming `CreateContainerRequest` before container creation | Implemented. The Agent calls `is_allowed()` before `do_create_container()`, and policy evaluation errors fail the request. |
| Generate bounded policy for supported OCI mounts, Agent storages, devices, and per-container rootfs identities | Implemented for the explicit compiler and Rego classes documented above. |
| Versioned semantic source classes and trusted external-root registry | Not implemented. Policy data does not carry the proposed `external-shared`, `guest-local`, `block-hotplug`, `device-hotplug`, `cdh-trusted`, or `forbidden-uvm` classes. |
| Race-resistant source and destination confinement | Not implemented. Existing bind handling uses path canonicalization; it does not resolve and mount through a shared fd-relative `openat2()` confinement layer. |
| Authorize the effective request after CDI, CDH, storage, namespace, hook, and sealed-secret transformations | Not implemented. Authorization currently precedes those transformations. |
| Policy-bound cross-container `shared_mounts` | Not implemented. The compiler does not represent captured `shared_mounts`, and Agent cloning is not tied to a policy-declared sharable-mount identity. |
| Trusted hotplug/device-registry correlation | Partial. Existing request policy constrains supported device fields, but the proposed end-to-end transport and resolved guest-device identity contract is not implemented. |

#### Source-domain contract

Every policy mount, storage, and device should carry an explicit semantic
class:

- `external-shared`: mutable, untrusted host content exposed through a
  runtime-managed shared-filesystem root;
- `guest-local`: storage intentionally created inside the UVM, including local
  or memory-backed `emptyDir`;
- `block-hotplug`: a host-provided block device resolved through the Kata
  device manager and guest transport;
- `device-hotplug`: a non-block device whose guest identity is established by
  runtime hotplug or an equivalent trusted device registry;
- `cdh-trusted`: trusted storage or sealed-secret content established through
  the Confidential Data Hub;
- `forbidden-uvm`: Agent sockets, policy/initdata, guest rootfs, container
  rootfs, runtime control state, and arbitrary pre-existing guest devices.

The policy contract should version these classes, their allowed fields, and the
Agent capabilities needed to enforce them. An Agent must reject an unsupported
contract version rather than ignore a class or silently weaken its checks.

#### Clean-room appliance responsibilities

The appliance can validate declared intent and generate bounded policy:

1. Capture the final `CreateContainerRequest` by driving the pinned runtime-rs
   container-create path. Upstream runc OCI and predictor reports are not
   compiler authorities.
2. Require one raw/tagged request pair for every expected sandbox or workload
   container and validate that tagging changed only approved nested OCI
   occurrences. A storage predictor may remain as an audit comparison, but it
   cannot supply missing policy fields.
3. Generate source regexes only from trusted profile rules. An
   `external-shared` regex must be fully anchored within an allowlisted Kata
   shared-filesystem root. Exact matching is unnecessary because the content
   remains mutable and untrusted.
4. Validate settings by class. An external mount must not use a guest-local
   source pattern, and a guest-local mount must not be accepted by an external
   rule.
5. Escape all dynamic path components before inserting them into a regex and
   validate bundle, sandbox, and container IDs with field-specific grammars.
6. Reject `/dev` and `/sys` hostPath inputs unless an authoritative runtime
   device identity is available. A guest-visible device path is not proof of
   the device's origin.
7. Record the source class, generated pattern, trusted rule, required Agent
   capability, and rejection reason in policy provenance.
8. Continue failing closed for CSI, direct volumes, CDI, VFIO, or other classes
  whose live runtime state or enforcement contract cannot be reproduced
  authoritatively. Supported block-emptyDir and rootfs block classes remain
  limited to their explicit compiler and Rego clauses.

The clean-room process cannot resolve production-UVM symlinks, mount aliases,
mount IDs, device identities, or races. Those checks belong to the Agent.

#### Required Agent-side enforcement

The Agent currently evaluates the incoming request before
`do_create_container()`: `is_allowed()` calls `AgentPolicy::allow_request()`, a
denial returns `PERMISSION_DENIED`, and an evaluation error returns `INTERNAL`.
`do_set_policy()` also evaluates `SetPolicyRequest` before installing a policy.
This request gate is necessary but does not implement the source-domain
enforcement below because later Agent operations can resolve backing objects
and mutate the effective OCI and storage plan.

The Agent should maintain a registry of external roots and mount identities
created during sandbox setup, including the virtiofs/9p shared root and
Agent-created watchable mounts. For an `external-shared` source, it should:

1. Resolve the source relative to a registered root using an fd-based API such
   as `openat2()` with `RESOLVE_BENEATH` and `RESOLVE_NO_MAGICLINKS`.
2. Verify that resolution does not cross into an unregistered mount or a
   `forbidden-uvm` object.
3. Bind-mount the resolved fd/object instead of resolving the original path a
   second time. A `canonicalize()` followed by a path-based mount is
   insufficient because it retains a time-of-check/time-of-use race.
4. Enforce class-specific mount-point roots so an untrusted request cannot
   mount storage over Agent or runtime control state.

Guest-local paths must be checked under separate class-specific roots and must
never satisfy an external-source policy rule.

Source-domain enforcement is required at every privileged path consumer, not
only at the initial `CreateContainerRequest` policy check:

| Agent surface | Required enforcement |
| --- | --- |
| Rustjail OCI bind mounts | Resolve `OCI.Mounts[*].source` through the matched source-domain resolver before `mount_from()` mounts it. Canonicalizing an arbitrary guest path without checking its domain still permits exposure of UVM-internal state. |
| Agent `Storage` handling | Validate `source`, `mount_point`, `driver`, filesystem type, options, propagation flags, sharing mode, and ownership settings as one class-specific contract before handler dispatch. A driver name must not authorize arbitrary `mount(2)` parameters. |
| Storage destinations | Resolve or create mount points beneath dedicated class-specific roots with fd-relative, no-escape operations. Validate destinations before adding them to sandbox storage state or invoking a handler. |
| Cross-container `shared_mounts` | Keep denied unless policy explicitly identifies the source container and a registered sharable mount identity. Merely confirming that `src_path` appears in the source namespace's mount table is not authorization to clone that subtree with `open_tree()`. |
| ConfigMap/Secret watchable-copy path | Confine both source and target to registered roots. Recursive scanning, copying, deletion, ownership changes, and fallback bind mounts must use no-escape, symlink-safe traversal rather than lexical prefix operations. |
| Recursive ownership updates | Do not follow symlinks out of the mounted volume while applying `fsGroup`, `chown`, or permission changes. |

The same trusted path-resolution helper should be reused by storage mounting,
OCI bind mounting, shared-mount cloning, watchable-copy handling, and recursive
ownership operations. Parallel path validators with different semantics would
leave gaps between these surfaces.

Block and other devices require identity checks against the Agent's trusted
hotplug/device registry. The Agent must correlate the requested transport,
device identifier, and resolved guest device; it must not authorize a device
from its container-visible `/dev` path alone.

#### Authorize the effective request

The current request gate runs before Agent-side device resolution, CDI edits,
CDH handling, storage mounting, and sealed-secret handling. The creation path
should be split into three stages:

1. **Prepare:** resolve device mappings and compute CDI, CDH, storage, and OCI
   edits without creating mounts or starting the container.
2. **Authorize:** evaluate policy against the effective post-transformation
   OCI, storage, and device plan.
3. **Commit:** perform storage mounts and container creation only after the
   effective plan is authorized.

If an operation cannot be prepared without side effects, it needs a dedicated
policy check before the operation and a final effective-OCI validation before
container creation.

CDI policy must account for every injected mount, environment entry, hook, and
device node and correlate the CDI device kind with a trusted resolved device.
CDH trusted storage and sealed secrets need dedicated resource constraints and
must not be treated as ordinary shared mounts.

The prepare stage must also validate driver semantics. Each supported storage
class needs an allowlist for driver, filesystem type, mount flags, propagation
mode, driver options, and expected source and destination domains. For example,
selecting a virtio-fs handler must not permit the caller to request an
unrelated filesystem type or arbitrary bind/move/shared mount flags.

#### Incremental delivery

Support should be enabled by class:

1. Add the versioned source-domain policy contract and reject unknown contract
   versions or classes.
2. Add effective-plan authorization around Agent transformations, with
   dedicated pre-operation checks where preparation cannot be side-effect free.
3. Add external-domain resolution and mount-time enforcement for standard
   runtime files and shared ConfigMap, Secret, projected, and downwardAPI
   mounts.
4. Add separate shared, memory, local, and encrypted `emptyDir` classes.
5. Add block, CSI, and direct-volume support only with authoritative
   device-manager provenance.
6. Add CDI, VFIO, and CDH support after post-transformation authorization is
   available.

Unsupported classes remain denied. An audit-only mode may be used to measure
compatibility during rollout, but confidential production mode must enforce.

#### Draft acceptance criteria

- external source strings may vary only within their class's bounded external
  domain;
- an external-classified source cannot resolve to guest rootfs, container
  rootfs, Agent sockets, policy/initdata, runtime control state, or an
  arbitrary existing guest device;
- `..`, symlink, bind-alias, nested-mount, and rename-race attempts cannot
  escape a registered external root;
- an allowed source cannot be mounted onto an arbitrary UVM destination, and a
  driver cannot be used to request a filesystem type or propagation mode
  outside its class contract;
- cross-container shared mounts cannot clone `/`, `/proc`, secret volumes, or
  any mount that was not registered as sharable;
- watchable ConfigMap/Secret synchronization cannot scan, copy, delete, or
  change ownership outside its registered source and target roots;
- CDI, CDH, storage, or device edits performed after receipt of the original
  request cannot bypass policy;
- a volume or device class is not declared supported until both appliance-side
  generation tests and Agent-side runtime-domain tests pass.

Open questions for follow-up analysis include the exact fd-based mount API,
kernel compatibility requirements, the representation of source classes in
policy data, how to prepare CDH operations without side effects, and whether
the Agent should return structured policy-match metadata or enforce source
domains in a separate trusted validator. A further Agent-hardening question is
whether the same fd-relative confinement framework should protect privileged
rootfs setup operations that currently run before `pivot_root` or `chroot`;
that issue is broader than generated mount policy but relies on the same
no-escape filesystem invariant.

### Deliberately excluded legacy code

The compiler does not reuse:

- `AgentPolicy` and YAML resource/controller parsing;
- image registry or containerd image-pull helpers;
- image entrypoint, environment, user, or group derivation;
- YAML-driven mount, storage, device, or container-process derivation.

Those values are already resolved in the captured request. Probe and lifecycle
exec requests are read exactly from workload YAML as described above because
they are future operations absent from container creation.

### Validation contract

Automated validation must prove that:

- the appliance image contains and invokes the standalone compiler, not the
  legacy `genpolicy` executable;
- changing a captured request OCI field such as `oci.process.cwd` changes the final policy
  without changing workload YAML;
- dynamic markers do not appear in final Rego and become constrained policy
  expressions;
- no uncaptured settings mount is introduced;
- workload exec probes and lifecycle hooks appear as exact command arrays;
- the encoded annotation decodes to the exact emitted `policy.rego`;
- duplicate equivalent captures are deterministic and conflicting duplicates
  fail;
- unsupported non-OCI policy requirements fail with an actionable error.

`policy-oci-diff.json` records the selected capture and the source or
normalization reason for every compiled field.

### Open hardening requirements

Before this appliance is used to generate production policy, classify every
dynamic field by security impact. The appliance must generate a restrictive
policy without relying on broad matching behavior.

The generator must follow this rule:

> Generate a regex only for bounded configuration whose accepted values remain
> in the same validated trust domain. Security-relevant identities and
> destinations must use exact values or structured correlation. Guest-visible
> sources for untrusted external storage may use compiler-generated regexes
> confined to an allowlisted external domain.

Until every field is classified, the compiler must remain fail-closed:

- never generate `ExecProcessRequest.regex`; authorize exec only with exact
  argv arrays, or deny it;
- keep executable paths, arguments, UID/GID, capabilities, image identity,
  devices, mount destinations, and mount types/options exact;
- allow mount or storage source regexes only when generated from trusted
  runtime metadata and anchored entirely within a validated external-untrusted
  domain. UVM-local sources must be separately classified and must not match
  those patterns. Runtime IDs must still be validated by structured
  relationships to the sandbox/container ID;
- reject unknown dynamic-marker contexts instead of falling back to `.*`,
  prefix matching, or user-provided raw regex;
- admit workload storages and devices only from the captured request and only
  through explicitly supported, fail-closed class conversions.

Candidate regex fields are limited to explicitly reviewed non-secret
configuration values, for example Kubernetes-generated service IP/port
environment variables, DNS-format host names, and similarly bounded metadata.
Even for these fields, the compiler must:

- use a field-specific grammar rather than `.+`;
- escape all static text and anchor the complete expression with `^` and `$`;
- record the tag, authoritative source, field context, grammar, and security
  classification in provenance;
- reject secret-derived environment variables and user-controlled values unless
  they are represented exactly.

Acceptance tests must prove that exact security fields reject executable
prefixes/suffixes, extra or merged argv elements, shell metacharacters, sibling
mount paths, `..` traversal, altered storage definitions, alternate images,
and secret-value substitutions. Regex-approved configuration fields must reject
near-matches outside their bounded grammar.
