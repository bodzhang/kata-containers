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
| Kata `nerdctl/network-namespace` | Generalized with the configured dynamic-value grammar when present in the captured Agent request; otherwise omitted | The policy and request must either both omit the annotation or both contain a matching value |
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
  identities carried by policy-only marker storages. Dedicated rootfs clauses
  also bind the storage mount point to
  `/run/kata-containers/<bundle-id>/rootfs`; guest-pull additionally requires
  the runtime's single `image_guest_pull=...` driver-option envelope.

The policy schema does not encode a distinct literal-versus-regex source type.
To prevent literals containing regex metacharacters from being broadened,
`rules.rego` permits the generic source-regex fallback only when the expanded
policy source is explicitly anchored with `^` and `$`. Exact literal equality
is handled by a separate rule. New source patterns therefore require both
anchors and a negative near-match test.

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
| `devices` | Raw non-VFIO request devices are copied into policy and matched with exact cardinality, unique paths, and any non-empty captured stable fields. Empty legacy placeholder fields remain path-only. Workload YAML supplies additional OCI checks for declared `volumeDevices` paths. For each declared NVIDIA pGPU, the compiler preserves an unsuffixed VFIO requirement instead of pinning runtime-assigned device numbers or PCI paths. This is request-shape enforcement, not physical-device identity. |
| `sandbox_pidns` | Copied exactly from the raw request. |
| `container_id` | Used to pair captures and report errors; runtime bundle/container identity is correlated through OCI annotations and root paths rather than pinned to the dry-run ID. |
| `exec_id` | Captured and required to be empty; non-empty values fail generation because the field is not represented in policy. |
| `shared_mounts` | Captured and required to be empty; non-empty values fail generation because policy-bound sharing is not implemented. |
| `stdin_port`, `stdout_port`, `stderr_port` | Captured and required to be absent; configured ports fail generation because they are not represented in policy. |

These unsupported fields are a fail-closed requirement, not merely a
documentation concern: generation must reject non-default values until policy
data and Rego rules represent them. The top-level request deserializer also
rejects unknown fields so a newly added request field cannot be silently
discarded.

Raw and tagged directories must contain exactly the same basename set. Pair
validation requires equal `container_id`, request-level storages, devices,
flags, unsupported fields, and CRI container type/name annotations. The
remaining stronger contract is to prove that every nested OCI difference
corresponds to the exact occurrence and original-value digest recorded in
`dynamic-tags.json`. Until that validation exists, the tagger and its output
directory remain part of the trusted compiler input path.

#### Legacy request-rule inheritance audit

The compiler does not maintain a forked endpoint-default table. It loads the
legacy `Settings` implementation, serializes the complete
`settings.request_defaults` value into `policy_data.request_defaults`, and
concatenates the configured shared `rules.rego` before that data. The
production appliance image copies the repository's base
`genpolicy-settings.json` and applies a drop-in that changes only
`cluster_config.pause_container_image`. Consequently, the following legacy
policy classes are inherited rather than reconstructed:

| Legacy policy class | Source | Appliance result |
|---|---|---|
| Hardcoded allow defaults | Shared Rego defaults for sandbox teardown, OOM and guest details, CPU/memory online, container removal, stale virtiofs cleanup, signaling, starting, stats, terminal resize, and process waiting. | Inherited from the same `rules.rego`. |
| Hardcoded deny defaults | Every other named Agent endpoint defaults to false, including create, exec, copy, networking updates, tracing, policy replacement, resource updates, stream RPCs, and unsupported memory-agent operations. | Inherited from the same `rules.rego`; endpoint-specific clauses can admit only their constrained cases. |
| Structured request defaults | `CreateContainerRequest`, `CopyFileRequest`, `ExecProcessRequest`, `UpdateRoutesRequest`, `UpdateInterfaceRequest`, and `AddARPNeighborsRequest`. | The complete deserialized settings objects are copied into policy data; compiler mode changes are limited to documented environment regex handling. Workload-derived exec commands are stored per container. |
| Boolean request defaults | `CloseStdinRequest`, `ReadStreamRequest`, `WriteStreamRequest`, `UpdateEphemeralMountsRequest`, and `GetDiagnosticDataRequest`. | Copied unchanged. All five are false in the base settings. |
| Failure behavior | `AllowRequestsFailingPolicy` defaults to false in shared Rego. | Inherited; policy evaluation failure remains fail-closed. |

This audit found no omitted legacy default rule. The compatibility exception is
not missing policy text but a field-model gap: legacy stream booleans govern
the old read/write/close RPCs, while legacy create and exec rules did not model
passfd port fields. An output policy can therefore contain all legacy defaults
and still fail to constrain passfd attachments unless those request fields are
checked separately.

#### Cross-cutting future improvement: versioned Agent endpoint profiles

The inherited defaults do not completely match the current Agent and runtime.
They cover normal sandbox/container creation and teardown, basic container
stats, OOM notification, guest capability discovery, CPU/memory online, stale
virtiofs cleanup, and constrained network setup. Several newer or
feature-specific automatic runtime calls still default to denied, however.
That can preserve confidentiality while silently disabling legitimate
Kubernetes behavior.

This is primarily an Agent and shared GenPolicy compatibility problem, not an
appliance feature. The endpoint definitions and policy-check call sites belong
to the Agent, while the defaults and common admission rules belong to shared
`rules.rego` and `genpolicy-settings.json`. Legacy GenPolicy and the appliance
both consume that contract. The appliance may derive tighter request data from
capture, but it must not own the endpoint inventory or establish a divergent
baseline. This section is retained here to record how the shared contract
affects appliance output and where capture can improve it.

The policy should classify an endpoint by trusted runtime purpose instead of
assuming that every read is harmless or every default-denied operation is
interactive. The intended profiles are:

| Profile | Intended caller and behavior | Default posture |
|---|---|---|
| Core lifecycle | Automatic shim operations required to create, start, stop, wait for, and remove a declared workload. | Enabled with container/sandbox state and request-shape checks. |
| Observability | Automatic status, resource statistics, OOM events, pod stdout/stderr collection, termination messages, and explicitly selected metrics. Workload output is assumed to follow the deployment's data-handling policy. | Enabled for declared containers and bounded outputs; the data remains host-visible and is not trusted evidence. |
| Feature automation | Automatic calls required only when a selected runtime or workload feature is active, such as dynamic resource updates, memory hotplug, swap, direct-volume statistics, or guest clock synchronization. | Enabled only when compiler inputs prove that the feature is selected, with endpoint-specific fields constrained. |
| Interactive/debug | `ExecProcessRequest` outside declared probes/lifecycle hooks, stdin, terminal resize, pause/resume used as operator controls, network inspection, and ad hoc diagnostics. | Denied unless an explicit deployment profile opts in. |
| Administrative | Policy replacement, iptables mutation, memory-agent tuning, tracing, and unrestricted guest mutation. | Denied by the workload policy; use a separately authenticated administrative channel if required. |

##### Current compatibility findings

| Endpoint or family | Current inherited behavior | Compatibility assessment and future rule |
|---|---|---|
| `CreateSandboxRequest`, `CreateContainerRequest`, and `CopyFileRequest` | Default deny with structured allow rules. | Retain. These are automatic operations, but admission must continue to depend on the compiled sandbox, container, storage, device, and copy-path contracts. |
| `StartContainerRequest`, `WaitProcessRequest`, `RemoveContainerRequest`, `DestroySandboxRequest`, and `RemoveStaleVirtiofsShareMountsRequest` | Default allow. | Required automatically. Replace unconditional allows where practical with known sandbox/container state and idempotent lifecycle transitions. |
| `SignalProcessRequest` | Default allow. | Needed for automatic stop/kill, but too broad for the desired non-interactive profile. Constrain the target to a policy-known process and allow only lifecycle-required signals and state transitions. |
| `GuestDetailsRequest` and `OnlineCPUMemRequest` | Default allow. | Retain for runtime capability discovery and automatic CPU/memory online. Bound resource values to the selected runtime resource envelope. |
| `StatsContainerRequest` and `GetOOMEventRequest` | Default allow. | Retain in the observability profile. Bind stats to a policy-known container; keep OOM output metadata-only and bounded. |
| `UpdateInterfaceRequest`, `UpdateRoutesRequest`, and `AddARPNeighborsRequest` | Default deny with settings-backed structured rules. | Retain as core automatic network reconciliation. Add complete-set/duplicate checks and bind the request to the sandbox network plan rather than relying only on forbidden-value filters. |
| `UpdateContainerRequest` | Unconditionally denied. | Compatibility gap for CRI/containerd resource updates, including Kubernetes in-place resource changes. Add a policy container id check and a compiler-produced resource envelope; reject devices and controllers not declared by that envelope. |
| `GetDiagnosticDataRequest` | Denied by the default settings boolean. | Compatibility gap for automatic Kubernetes termination messages when `shared_fs = "none"`. Admit only `log_type == "termination_log"`, a policy-known container, the declared termination-message contract, and a bounded response size. Do not enable a generic diagnostic-data read. |
| `ReadStreamRequest` | Denied by the default settings boolean; both stdout and stderr share the same Rego entrypoint. | Compatibility gap for the legacy stream transport used to collect pod logs. Future Agent policy input must distinguish `ReadStdout` from `ReadStderr`, bind the stream to a known process, and cap each read. Enable output in the observability profile while keeping `WriteStreamRequest` and `CloseStdinRequest` denied. Passfd output requires the separate one-shot binding design below. |
| `GetMetricsRequest` | Unconditionally denied. | Compatibility gap for the shim metrics endpoint, which currently drops unavailable Agent metrics and returns the remaining metrics. Add an observability option for bounded, reviewed Agent metric families; do not treat this payload as workload-only telemetry. |
| `VolumeStatsRequest` | Unconditionally denied. | Compatibility gap for CSI/direct-volume `NodeGetVolumeStats` handling. Admit only normalized guest paths bound to a policy-known mounted volume; do not authorize arbitrary guest path probing. |
| `ResizeVolumeRequest` | Denied, and the current Agent returns `UNIMPLEMENTED` after policy admission. | Keep denied until the Agent implements it. Future support must bind the path and requested size to a declared resizable volume and an operator-defined maximum. |
| `UpdateEphemeralMountsRequest` | Denied by the default settings boolean. | Compatibility gap after automatic sandbox memory growth, when the runtime recalculates tmpfs limits. Replace the boolean with exact Agent-managed tmpfs identities and limits derived from the admitted memory envelope. |
| `MemHotplugByProbeRequest` | Unconditionally denied. | Feature compatibility gap when the selected hypervisor uses guest memory probing. Admit only addresses and sizes returned by a trusted hotplug registry and correlated with the resource update. |
| `ReseedRandomDevRequest` | Unconditionally denied. | Feature compatibility gap for VM factory reuse, which automatically reseeds the guest RNG. Prefer an in-guest trusted entropy source; otherwise authorize exactly one bounded reseed during trusted VM assignment, not arbitrary runtime writes. |
| `AddSwapRequest` and `AddSwapPathRequest` | Unconditionally denied. | Feature compatibility gap when runtime swap is configured. Admit only a device/path registered by the trusted device manager and selected by the runtime profile; remain denied when swap is disabled. |
| `SetGuestDateTimeRequest` | Unconditionally denied. | Optional VM clock-sync compatibility gap. If enabled, constrain the requested time to a small skew window around a trusted time source. Host-supplied wall time alone is not a confidential-computing trust anchor. |
| `PauseContainerRequest` and `ResumeContainerRequest` | Unconditionally denied. | Acceptable for the non-interactive Kubernetes profile; ordinary pod lifecycle does not require them. Add only as a paired feature with known container state if a platform workflow proves a requirement. |
| `TtyWinResizeRequest` | Default allow. | Inconsistent with disabling interactive operation. Change the hardened profile to deny it unless a declared terminal process and interactive profile are both active. |
| `ExecProcessRequest` | Default deny with exact global/probe/lifecycle command paths. | Continue to deny arbitrary human exec. Preserve exact probe and lifecycle process contracts, while recognizing that command equality alone does not prove control-plane purpose. |
| `ListInterfacesRequest`, `ListRoutesRequest`, `GetIPTablesRequest`, and `SetIPTablesRequest` | Unconditionally denied. | Keep out of the baseline. Current runtime paths expose these as management operations, not required periodic Kubernetes status calls. A network integration that needs them requires a separate structured profile; iptables writes must never be enabled as a bare boolean. |
| `MemAgentMemcgConfig`, `MemAgentCompactConfig`, and `SetPolicyRequest` | Unconditionally denied. | Retain as administrative-only. Workload policy must not authorize its own replacement or unrestricted memory-agent tuning. |
| `StartTracingRequest` and `StopTracingRequest` | Still present as shared Rego defaults, but absent from the current `AgentService` protocol. | Treat as stale compatibility entries. Endpoint-manifest validation should report policy rules with no current RPC as well as RPCs with no rule. |

##### Delivery plan

1. **Inventory endpoints at the Agent/shared-policy boundary.** Derive the
  service method, request type, policy entrypoint, and pre-side-effect
  policy-check status from the current Agent protocol and implementation.
  Shared CI must require every method to be explicitly classified as
  constrained, allowed, denied, or intentionally outside policy scope. It must
  also report stale Rego entrypoints. Unknown endpoints remain fail-closed.
2. **Add shared policy conformance tests.** Exercise the automatic shim paths
  for pod creation, network setup, start, stats, OOM watcher setup, stop, and
  removal against shared `rules.rego`. Add feature cases for resource updates,
  `shared_fs = "none"` termination messages, memory growth/tmpfs refresh,
  swap, and direct volumes. These tests protect legacy GenPolicy and every
  other consumer of the shared policy, not only the appliance.
3. **Correct the shared GenPolicy contract.** Add bounded common rules and
  extend `RequestDefaults` only where configuration is necessary. Cover exact
  container binding for stats and termination logs, normalized policy-volume
  paths for volume stats, and an explicit reviewed Agent metrics profile.
  Avoid blanket boolean enables.
4. **Add legacy generator support.** Populate new structured policy data from
  trusted workload and runtime settings where legacy GenPolicy can do so
  safely. Features without sufficient trusted input remain denied rather than
  receiving guessed policy entries.
5. **Implement required Agent enforcement.** Centralize pre-side-effect policy
  checks for every non-health RPC, distinguish stdout from stderr, cap outputs,
  and add trusted bindings for resource envelopes, tmpfs identities, hotplug,
  swap, lifecycle signals, and passfd streams. CI must explicitly list any
  endpoint outside policy scope.
6. **Integrate the shared contract into the appliance.** Reuse the shared
  endpoint classifications, settings schema, and Rego rules. Use authoritative
  captured requests only to produce tighter endpoint-specific data that legacy
  generation cannot know. Appliance tests should supplement, not duplicate or
  replace, the shared compatibility suite.

The first implementation target belongs in Agent/shared-policy CI: prove that
the current endpoint set is completely classified and that core automatic shim
operations remain usable. Bounded observability and other automatic operations
reachable from CRI and shim-management APIs follow in the shared contract. The
solution must not be an appliance settings drop-in that flips all denied
requests to true; that would restore compatibility only for one consumer while
discarding the request-shape and workload-purpose boundaries that policy is
intended to enforce.

#### Process identity and passfd I/O

The currently unsupported request fields do not have one common security
model. They require separate treatment.

**Create-time `exec_id` remains empty by invariant.** Runtime-rs constructs a
container's `CreateContainerRequest` with an empty exec ID, and the Agent does
not consume that field while creating the init process. A non-empty value does
not enable a legitimate create-container feature and must remain denied. Future
process creation uses `ExecProcessRequest`, where `exec_id` is an opaque
runtime process handle rather than a policy identity. The Agent must continue
to validate its syntax, require uniqueness within the container, and reject
collision with the init process. Policy authorization for an exec is based on
the target container's policy state and exact process contract, not on trusting
the handle's spelling.

**Legacy stream RPC denial does not deny passfd streams.** The base settings
set `CloseStdinRequest`, `ReadStreamRequest`, and `WriteStreamRequest` to false,
which disables the Agent's older stream RPC path. These booleans are global
controls and do not express stdin, stdout, or stderr presence for an individual
process. Legacy generation records OCI terminal mode, but does not translate
the parsed Kubernetes `stdin` field into stream policy. Passfd handles bypass
the older RPC path after attachment, so their authorization requires the
separate presence and ownership design below.

#### Potential future improvement: policy-bound shared mounts

This subsection is a potential future improvement, not a commitment or a
description of current support. Legacy GenPolicy does not represent
`shared_mounts`, and its Rego requires the request list to be empty. The
appliance captures the field but currently rejects any non-empty value during
generation. That fail-closed behavior must remain until both policy and Agent
enforcement described below are implemented.

`shared_mounts` can be supported only as an explicit cross-container trust
grant. A policy entry must identify the exact tuple `(name, source container,
source path, destination container, destination path)` and the destination
container's `CreateContainerRequest` must match the complete declared set with
no extras or duplicates. Container names must resolve uniquely to policy
container identities; a request cannot choose a different source or
destination by name alone.

Exact tuple matching is necessary but not sufficient. The Agent currently
waits for `src_path` to appear in the source container's mount table and clones
that subtree with `open_tree()`. Secure support also requires the Agent to:

1. Treat the policy declaration as an intentional grant for the source
  container to provide content to the destination container. Do not infer
  sharing from an untrusted request alone.
2. Resolve the source and destination beneath the corresponding container
  roots or mount namespaces with fd-relative, no-escape operations. Reject
  symlinks, `..`, namespace aliases, and destinations that cover protected
  runtime paths.
3. Verify that the source is a mount point with a stable mount identity, open
  that object once, and move the opened tree rather than resolving the path a
  second time. Register the identity as sharable before cloning when the
  source originates from an Agent-managed storage; for an application-created
  mount, the policy grant explicitly delegates the approved source path to
  that source container.
4. Fail container creation if the source container, source mount, clone, or
  destination move is unavailable. A timeout, unresolved source, or failed
  `move_mount()` must not be silently skipped.
5. Consume each declaration once and record the resulting destination mount
  identity, preventing replay or a later request from substituting another
  subtree at the same path.

Until those Agent checks and policy fields exist, rejecting every non-empty
`shared_mounts` request is the correct fail-closed behavior. Merely copying the
captured tuples into policy would authorize path strings, not the mounted
objects they name.

#### Potential future improvement: policy-bound passfd I/O

**Passfd stdio ports are transport handles, not workload identities.** Their
numeric values are allocated at runtime and must not be pinned to clean-room
values. Policy should instead carry, per container process, whether stdin,
stdout, and stderr streams are expected. Rego can require zero for a disabled
stream and a non-zero, pairwise-distinct handle for each enabled stream; it
must also correlate terminal mode with stderr absence. The expected presence
bits come from the captured final request and a trusted profile that enables
passfd I/O, not from arbitrary production values.

The Agent must atomically claim each non-zero handle from its passfd stream
registry before any other request can use it, verify that every required stream
exists and has the expected direction, and fail creation rather than replacing
a missing stream with `None`. Registry entries must be one-shot and bound to
the target sandbox, container/process, and stream role. If the transport cannot
provide that binding, accepting a non-zero port proves only that some stream
used that number and is not sufficient for cross-container isolation.

With those registry checks, supporting variable non-zero ports is preferable
to generation-time rejection. Until then, the compiler's rejection of any
configured passfd port is a temporary fail-closed gate. The same presence and
one-shot binding contract applies to passfd ports on `ExecProcessRequest`.

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

#### Device and GPU requirements

The final request remains authoritative for the device shape presented to the
Agent, but a policy device must not be a verbatim copy of runtime-assigned
identity. In particular, VFIO device numbers, guest PCI paths, and CDI
annotation suffixes vary between the clean room and production.

The compiler/Rego-only first phase is implemented:

- raw non-VFIO devices retain exact cardinality, unique container paths, and
  non-empty captured `id`, type, `vm_path`, and options;
- empty fields in legacy volume-device placeholders remain path-only for
  compatibility;
- declared pGPUs produce unsuffixed VFIO requirements, while captured suffixed
  runtime devices are used only to reject undeclared or count-mismatched
  capture;
- Rego correlates runtime VFIO number suffixes with unique CDI annotation
  suffixes and checks the configured type, guest path shape, and PCI option
  grammar.

The remaining Agent-dependent phase should represent each device as a typed
requirement with two groups of fields:

- invariant intent: device class, expected count, container-visible path or
  path family, access mode, vendor/class kind when declared, and whether the
  device is represented through CDI;
- runtime correlation: device number, transport identifier, guest PCI path,
  CDI annotation suffix, and the Agent device-registry object that resolved
  them.

For GPUs and other VFIO devices, workload resource limits may establish count
and requested CDI kind, but they cannot establish the physical device selected
on the production node. A clean room without that hardware must not synthesize
or claim a production identity. Secure support requires an Agent registry,
rooted in trusted hotplug and guest-device resolution, to bind the policy
requirement to the resolved host device, transport operation, guest device, and
final CDI edits. Claims supplied by the untrusted host runtime and CDI
annotations are correlation data, not trust anchors.

Physical-identity support stays fail-closed until an Agent integration test
proves registry and post-CDI effective-plan binding.

#### Implementation complexity and boundary

| Improvement | Complexity | Status / ownership |
| --- | --- | --- |
| Preserve normalized VFIO requirements and reject undeclared captured VFIO devices | Medium | Implemented in the compiler; no Agent change. |
| Exact non-VFIO cardinality and captured stable fields | Low | Implemented in shared Rego with legacy path-only compatibility; no Agent change. |
| Reject exec passfd handles in the current unsupported profile | Low | Implemented in shared Rego; no Agent change. |
| Reject negative CopyFile sizes and offsets outside the declared size | Low | Implemented in shared Rego; no Agent change. |
| Record a data-free CopyFile manifest and compare it with mount shape | Medium | Future appliance capture/compiler work; useful before, but not sufficient without, session enforcement. |
| Bind a device requirement to hotplug transport, resolved guest device, and post-CDI effective plan | High | Design only; requires Agent/device-registry and creation-flow changes. |
| Distinguish probe/lifecycle purpose from an identical interactive exec | Very high | Design only; requires protocol changes and a trusted intent issuer outside the host path. |
| Enforce one-shot passfd stream ownership and role | High | Design only; requires Agent passfd registry and protocol changes. |
| Enforce bundle-bound, one-shot CopyFile sessions and sealing | High | Design only; requires Agent state and protocol changes. |

#### Potential future improvement: purpose-bound runtime exec

An exact process contract is necessary but does not prove why an exec was
requested. Today, a user-issued exec that reproduces an allowed probe or
lifecycle process is indistinguishable from that action at the Agent boundary.
The policy must not claim caller or purpose authorization unless the runtime
adds authenticated request metadata that the host cannot freely substitute.

If purpose separation is required, the request needs an exec authorization
context bound to the sandbox, container, operation class (`probe`, `lifecycle`,
or `interactive`), and one process request. That context must be issued by a
trusted authority outside the untrusted host path, such as a signed
control-plane workload intent verified in the guest or an in-guest trusted
scheduler. A token issued merely because the host runtime requested one does
not establish purpose. The Agent must validate the context before matching the
corresponding policy entry. Probe contexts may be reusable within bounded
command and concurrency rules; lifecycle contexts need phase-specific
issuance; interactive contexts remain denied unless explicitly declared.
Without a trusted issuer, policy can authorize only the process shape, not its
origin.

Each exec policy entry should match the complete process contract: exact argv,
user and groups, environment semantics, cwd, no-new-privileges, capabilities,
terminal mode, and expected stdio presence. `exec_id` remains an opaque,
unique, runtime handle and is never an authorization identity. Regex command
authorization remains disabled. Compiler-to-Rego tests must cover near-match
argv, changed process fields, use before container creation, wrong-container
reuse, duplicate/replayed handles, terminal changes, and passfd stream-role
mismatches.

#### Potential future improvement: bounded CopyFile sessions

The current static `$(sfprefix)` rule is a permanent domain-wide write grant.
It confines destination paths but does not prove that a copy belongs to a
captured workload operation, and the recording Agent does not retain individual
`CopyFileRequest` calls. Secure support should model a copy session rather than
an unrestricted path prefix.

Runtime-rs should register a copy plan before issuing file RPCs. The plan must
be bound to the sandbox and destination bundle, identify the target mount role,
and constrain the permitted relative paths and file types. Where metadata is
deployment-invariant, it should also constrain mode, ownership, and final size;
where ConfigMap or Secret content is intentionally deployment-variable, policy
must classify it as mutable external input instead of pretending that capture
attests it. Content digests are appropriate only for explicitly immutable
inputs whose digest is available from a trusted declaration.

The Agent should issue a one-shot session handle, require every chunk to claim
that session and a declared file, enforce monotonic non-overlapping offsets and
size limits, and atomically seal the destination when the plan completes.
Unknown files, duplicate completion, writes after sealing, cross-bundle reuse,
and incomplete sessions must fail. Existing `pathrs` confinement remains a
required defense but is not a substitute for operation authorization.

The appliance capture Agent should record a data-free copy manifest containing
path, type, metadata, total size, and sequence boundaries while omitting Secret
payload bytes. The compiler can then compare that manifest with the final mount
shape and emit bounded copy-session policy. `kubectl cp` remains outside this
contract because it is an exec-based `tar` workflow, not an Agent
`CopyFileRequest` operation.

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
| Policy-bound cross-container `shared_mounts` | Not implemented. The compiler rejects non-empty captured `shared_mounts`, and Agent cloning is not tied to a policy-declared sharable-mount identity. |
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
- generated GPU/VFIO policy preserves normalized count and class requirements,
  accepts correlated runtime-assigned device numbers, and rejects missing,
  extra, duplicate, wrong-kind, or registry-unbound devices;
- no exec request is described as probe- or lifecycle-authorized without a
  context from a trusted issuer; process-only mode rejects every near-match and
  wrong-container request while acknowledging that an identical caller cannot
  be distinguished;
- CopyFile writes require an active bundle-bound plan, cannot add undeclared
  files or metadata, cannot overlap or exceed declared ranges, and cannot be
  replayed after the destination is sealed;
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
- raw and tagged capture basename sets and request-level fields match exactly;
- unknown request fields and unsupported non-default `exec_id`, `shared_mounts`,
  or stdio ports fail generation;
- per-container guest-pull and dm-verity rootfs storages reject another bundle's
  rootfs mount point;
- literal mount and storage sources reject regex near-matches;
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
