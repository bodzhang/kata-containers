# GenPolicy Rego Fragments

## Status

This document proposes a design for separating workload-static and UVM-static
policy from versioned platform mutations. It does not describe functionality
currently implemented by Kata Agent or GenPolicy.

## Motivation

GenPolicy currently predicts the complete `CreateContainerRequest` that Kata
Agent will receive. That request is not produced directly from workload YAML.
It is the result of a pipeline:

```mermaid
flowchart LR
    YAML[Workload YAML] --> API[Kubernetes API and controllers]
    IMG[Image configuration] --> KUBE[Kubelet CRI resolution]
    API --> KUBE
    KUBE --> CTR[containerd OCI generation]
    CTR --> KATA[runtime-rs transformation]
    KATA --> AGENT[Kata Agent request]
```

The prediction embeds behavior from specific Kubernetes, containerd, and Kata
versions in GenPolicy. Component upgrades can therefore cause policy drift even
when workload intent has not changed.

The proposed design makes GenPolicy responsible for static workload, image,
and measured UVM constraints. Versioned **Rego fragments** validate mutations
introduced by the platform profile. The name and composition model follow the hcsshim
security-policy fragment design, including fragment identity by issuer, feed,
namespace, and security version number (SVN). The main adaptation is that Kata
fragments validate platform mutations rather than contribute additional
containers.

The hcsshim design provides useful precedents:

- a base policy explicitly authorizes a fragment issuer, feed, minimum SVN, and
  exported content;
- each fragment is isolated in a Rego package namespace;
- fragment framework compatibility is explicit;
- fragment loading fails closed on identity, namespace, or SVN mismatch;
- `platform_rules` can contribute platform-owned environment and mount rules.

See the hcsshim
[`framework.rego`](https://github.com/microsoft/hcsshim/blob/main/pkg/securitypolicy/framework.rego),
[`securitypolicyenforcer_rego.go`](https://github.com/microsoft/hcsshim/blob/main/pkg/securitypolicy/securitypolicyenforcer_rego.go),
and
[`platform_rules.rego`](https://github.com/microsoft/hcsshim/blob/main/pkg/securitypolicy/fragment_test_policies/platform_rules.rego).

## Goals

- Generate exact policy constraints from workload YAML and digest-bound image
  configuration without predicting platform implementation details.
- Assign every platform mutation to one category and one owning fragment.
- Reuse reviewed fragments across workloads with the same measured profile.
- Correlate generated values with static workload intent and with other values
  in the same request.
- Reject unknown fields, unclaimed mutations, fragment overlap, and profile
  mismatch.
- Derive candidate fragments from capture evidence, then require review and
  negative tests before publication.

## Non-goals

- Trusting containerd or runtime-rs merely because a captured request contains
  self-consistent values.
- Automatically proving a safe rule from a finite set of captures.
- Allowing fragments to add arbitrary workload identities, commands, devices,
  storages, environment variables, or mount destinations.
- Treating component version strings as a complete profile identity.
- Supporting arbitrary admission webhooks, CSI drivers, or device plugins
  without including their configuration and evidence in the profile.

## Terminology

Static policy
:   Constraints derived from trusted workload YAML, referenced ConfigMaps and
  Secrets, image configuration bound to a manifest digest, or a measured UVM
  artifact such as the built-in pause container.

UVM-static policy
:   Constraints derived from the measured UVM image and independent of the
  Kubernetes, containerd, and runtime-rs profile. The built-in pause
  executable and its image-derived process identity are UVM-static.

Static policy IR
:   A compiler intermediate representation containing only static policy plus
  stable workload subject identifiers. It deliberately omits every
  profile-owned final-policy field.

Mutation
:   A field addition, default, resolution, rewrite, removal, normalization, or
    generated value between static input and the Agent-visible request.

Fragment
:   A reviewed mutation module that materializes profile-owned final-policy
  constraints at build time and validates the same claims at runtime.

Profile
:   The complete set of component versions, configurations, binaries, and
    operating modes that determine request mutation behavior.

Claim
:   A JSON-pointer path or typed collection role that a fragment exclusively
    owns and must validate.

## Additive Composition Model

The composition operation is purely additive. GenPolicy first emits a static
policy IR with stable subjects derived from workload intent, for example
`container/sidecar`, `container/workload`, or
`sandbox/default/balanced-mode`. A fragment can add an absent constraint below
one of those subjects. It cannot replace or delete static data.

```mermaid
flowchart LR
    YAML[Workload YAML and image data] --> IR[Static policy IR]
  UVM[Measured UVM image] --> IR
    PROFILE[Selected profile fragments] --> COMPOSE[Additive compositor]
    IR --> COMPOSE
    COMPOSE --> POLICY[Final policy data]
    POLICY --> REGO[Runtime Rego validators]
```

The final policy produced by composition is:

$$
P = S \oplus M_1 \oplus M_2 \oplus \dots \oplus M_n
$$

where $S$ is the static IR and each $M_i$ is a set of additions at previously
absent paths. The operator $\oplus$ is defined only when all target subjects
exist, all target paths are absent, and no two fragments claim the same target.
Composition fails otherwise.

This is simpler than applying general JSON Patch or allowing arbitrary Rego to
construct policy data. In particular:

- stable workload subject IDs select containers; array indexes and
  profile-generated CRI annotations do not;
- fragment order cannot affect the result when claims are disjoint;
- an addition cannot overwrite a static constraint;
- duplicate, missing, or ambiguous subjects fail composition;
- the final policy contains ordinary policy data and can use the existing
  Agent policy interface.

A platform transformation described as a rewrite is still additive at this
boundary. For example, the static IR omits the host root path and the
runtime-rs fragment adds the final `$(root_path)` constraint. A platform
removal is represented by an absence assertion checked by the fragment; it is
not permission to delete a static constraint. If a purported fragment needs
to overwrite trusted YAML or image data, the mutation classification or trust
boundary is wrong.

## Runtime Authorization Model

Let $P$ be the composed final policy, $Q$ the Agent-visible request, and $F_i$
a fragment validator. Authorization requires the final static constraints and
every selected fragment to agree:

$$
allow(P,Q) = static(P,Q) \land \bigwedge_{i=1}^{n} F_i(P,Q,C)
$$

$C$ contains values bound from the same request, such as sandbox ID, bundle ID,
Pod UID, sandbox name, and namespace. Fragments compose by intersection, not by
union. A fragment cannot make a request valid after static policy rejects it.

Each final request field must be one of:

1. validated directly by static policy;
2. claimed and validated by exactly one fragment;
3. explicitly shared by fragments through a documented dependency; or
4. rejected as unclaimed.

Collections require role-based ownership rather than index ownership. Mounts
are keyed by destination and purpose, environment entries by variable name,
storages by driver and correlated mount point, and namespaces by type. Array
ordering is not a mutation unless the protocol gives ordering semantic meaning.

!!! warning "Fragments are validators, not authorities"
    API server, kubelet, containerd, and runtime-rs are outside the Kata-CC
    trust boundary. A fragment describes the request shape that trusted Agent
    policy permits; it does not make the producing component trusted.

## Mutation Operations

Every claim records one operation. This makes fragment review about a bounded
transformation rather than a complete request template.

| Operation | Meaning | Example |
| --- | --- | --- |
| `default` | Add a fixed value when workload input omits it | OCI version |
| `generate` | Create a deployment-specific value with a bounded grammar | Pod UID |
| `resolve` | Resolve a declared reference against profile state | `fieldRef`, ConfigMap environment |
| `derive` | Compute a value from static input or another bound value | hostname from Pod name |
| `normalize` | Convert representation without changing intent | capabilities compared as a set |
| `rewrite` | Add only the final guest-oriented constraint; the host form is absent from static IR | Kata rootfs path |
| `remove` | Assert that a profile-owned final field is absent; never delete static data | guest Seccomp disabled |
| `envelope` | Add transport metadata around a statically authorized identity | guest-pull driver options |

The fragment manifest records the operation, owned path or role, static anchor,
correlations, evidence, and whether absence is also meaningful.

## Mutation Categories

### Static workload, image, and UVM pause

This category is not a fragment. GenPolicy owns it.

| Data | Treatment |
| --- | --- |
| Manifest digest | Exact |
| Command and arguments | Exact, using Kubernetes image/YAML precedence |
| Working directory | Exact |
| Image and YAML environment | Exact after static precedence resolution |
| UID, GID, and supplementary groups | Exact |
| Capabilities and no-new-privileges | Exact set/value |
| Root read-only state | Exact |
| Volume role and destination | Exact |
| Probe and lifecycle commands | Exact |
| Built-in pause command and process identity | Exact from the measured UVM image |

Static data must not contain containerd-generated root paths, CRI annotations,
host mount paths, or runtime-rs storage objects. It does contain stable subject
IDs and static anchors needed by fragment additions, such as container name,
volume role, destination, image digest, command, and environment-variable name.

The pause container is a special static subject. Kata uses the pause executable
from the UVM image rather than treating the Kubernetes CRI sandbox image as a
workload image pulled into the guest. Its command, executable identity, and
UVM-root relationship are pinned by the measured UVM artifact and do not vary
with Kubernetes, containerd, or runtime-rs versions. The CRI pause image
reference can still appear as sandbox envelope metadata, but it is not
authority for guest code or rootfs content.

Profile fragments may add the sandbox OCI version, generated identity,
annotations, namespaces, mounts, sysctls, cgroup data, and Agent transport
fields. They cannot redefine the pause executable, command, or UVM-root
identity. A UVM image update creates a new UVM-static baseline; it is not a new
containerd or runtime-rs mutation fragment.

The existing containerd 1.7.29 and 2.3.3 captures corroborate this boundary.
Both sandbox requests have command `/pause`, UID and GID `65535`, supplementary
GID `65535`, working directory `/`, no-new-privileges enabled, and a read-only
root. Capture equality is supporting evidence; the measured UVM artifact
remains the authority.

The first static IR prototype derives the following constraints without reading
either generated policy:

- command and arguments using Kubernetes image/YAML precedence;
- image environment plus literal YAML, ConfigMap, and Secret precedence;
- explicit or image working directory;
- explicit no-new-privileges and read-only-rootfs intent;
- probe and lifecycle exec commands; and
- unresolved `valueFrom` declarations as typed `resolve` anchors, not captured
  values.

It rejects image references that are not manifest-digest bound. It does not yet
classify user and group resolution, capability deltas other than explicit final
sets, volume intent, or emit the UVM-static pause subject.

### Kubernetes API and controller fragment

This fragment owns object mutations visible after API admission and controller
reconciliation:

- generated Pod name and UID;
- namespace defaulting;
- Deployment, Job, and other controller-generated Pod identity;
- restart, DNS, scheduler, probe, and termination-message defaults;
- service ClusterIP and assigned service-port values.

Only defaults that influence an Agent request need runtime Rego rules. Other
defaults remain provenance evidence. Generated names and UIDs use bounded
grammars and are bound once for reuse by later fragments.

Admission webhooks are separate fragments because Kubernetes version alone does
not identify their behavior.

### Kubelet resolution fragment

This fragment owns translation from the bound Pod to CRI input:

- `fieldRef`, `resourceFieldRef`, ConfigMap, and Secret environment resolution;
- service-link environment variables;
- Pod hostname;
- termination-message and Kubernetes-managed file mounts;
- resource-to-cgroup calculations;
- Pod security-context projection into OCI user and group fields;
- kubelet-prepared volume sources.

Resolution must remain anchored to static declarations. For example, the
fragment can permit `POD_UID=<bound Pod UID>` but cannot permit an arbitrary
environment variable with a UUID value. Service rules pin the statically
declared Service and port names while allowing only typed endpoint values.

Capturing the CRI boundary between kubelet and containerd is required before
this category can be separated completely from containerd OCI generation.

### containerd OCI fragment

This fragment owns conversion from CRI input to the raw OCI specification:

- OCI specification version;
- CRI annotations;
- sandbox OCI defaults;
- default sysctls, masked paths, read-only paths, capabilities, and resources;
- host-oriented standard mounts;
- cgroup path generation;
- ordering-insensitive normalization of set-like fields.

The fragment must validate absence as well as presence. A version that does not
emit an annotation or sysctl requires that field to remain absent.

The current containerd 1.7.29 and 2.3.3 capture comparison found three stable
differences across five workloads and eleven paired create requests:

| Claim | containerd 1.7.29 | containerd 2.3.3 | Request scope |
| --- | --- | --- | --- |
| OCI version | `1.1.0` | `1.3.0` | Sandbox and containers |
| `io.kubernetes.cri.podsandbox.image-name` | Absent | Exact configured CRI sandbox reference; metadata only | Sandbox |
| Sandbox sysctls | Absent | `ip_unprivileged_port_start=0` and `ping_group_range=0 2147483647` | Sandbox |

Capability, environment, and mount ordering differed but their semantic sets
did not. Generated IDs, ClusterIPs, CNI paths, and Kata path hashes are not
containerd-version claims.

### runtime-rs fragment

This fragment owns the raw-OCI to Agent-request transformation:

- root path rewrite to `/run/kata-containers/<bundle-id>/rootfs`;
- PID, network, IPC, UTS, mount, and cgroup namespace normalization;
- host mount source rewrite into Kata guest-visible domains;
- `/dev/shm` rewrite to `/run/kata-containers/sandbox/shm`;
- Kata bundle and container-type annotations;
- Agent `Storage` and `Device` construction;
- `shared_mounts` and `sandbox_pidns` request fields;
- Seccomp removal when enabled by trusted Kata configuration, paired with an
  explicit final-request absence rule.

Root paths, storage mount points, and bundle annotations must bind the same
bundle ID. Sandbox-scoped mount and storage paths must bind the same sandbox ID.
The fragment rejects internally consistent but statically unanchored identities.
The current upstream Rego does not enforce sandbox Seccomp absence in the
captured profile, so that observed removal remains an uncovered candidate, not
an implemented fragment claim.

### Rootfs and storage-mode fragment

Storage behavior merits a separate fragment because it depends on trusted Kata
configuration and snapshotter artifacts, not only runtime-rs version:

- guest pull: exact workload manifest digest; the built-in pause root remains
  UVM-static and is not authorized by a CRI image reference;
- EROFS/dm-verity: exact root hash, layer identity, driver, and options;
- shared filesystem: source constrained to the configured shared domain;
- `shared_fs = "none"`: Agent-local disk `emptyDir` fallback;
- encrypted block `emptyDir`: encryption options and device correlation;
- plain block `emptyDir`: explicit opt-in and exact unencrypted shape;
- memory `emptyDir`: exact tmpfs storage shape;
- ConfigMap, Secret, downward API, and projected-volume copy-to-guest rewrites.

This category consumes static volume intent but cannot change volume role,
destination, access mode, or encryption requirement.

### Generated identity and correlation framework

Generated identities are shared facts, not an independent source of
authorization. The common framework binds each value once and fragments reuse
it:

| Fact | Constraint |
| --- | --- |
| Bundle/container ID | Bounded hexadecimal ID extracted from the Kata root path or bundle annotation |
| Sandbox ID | Bounded hexadecimal ID from CRI annotation |
| Pod UID | UUID grammar bound to API evidence |
| Sandbox name | Controller grammar anchored to static workload name |
| Namespace | Static namespace or API default |
| Node name | Profile-bound or explicitly parameterized value |
| CNI namespace | Anchored profile path with bounded identifier |

Independent regular expressions for repeated identities are forbidden because
they lose relational integrity.

## Fragment Format

A fragment has one claim manifest used by both compiler-time materialization
and runtime validation. The materializer is deliberately data, not executable
Rego, so its write capability is constrained to adding declared values at
absent paths. Runtime Rego uses the same claims to validate the request.

```json title="containerd-2.3.3.fragment.json"
{
  "schema_version": 1,
  "category": "containerd-oci",
  "claims": [
    {
      "operation": "default",
      "target": {
        "subject": "container/workload",
        "path": "/OCI/Version"
      },
      "value": "1.3.0"
    }
  ]
}
```

The corresponding namespaced Rego exports metadata plus validators:

```rego title="containerd-2.3.3.rego"
package kata_fragment_containerd_2_3_3

fragment := {
    "framework_version": "0.1.0",
    "category": "containerd-oci",
    "issuer": "did:web:profiles.katacontainers.io",
    "feed": "kubernetes-1.33/containerd-2.3.3/linux-amd64-cgroup-v2",
    "svn": "1",
    "profile_identity": "sha256:<canonical-profile-hash>",
    "claims": data.fragment_claims,
}

validate(static, request, context) := {"allowed": true} if {
    request.OCI.Version == "1.3.0"
    allow_sysctls(request)
    allow_pause_annotation(static, request, context)
}
```

Issuer, feed, and minimum SVN adoption follows hcsshim. The base policy lists
the exact fragments it accepts:

```rego title="static-policy.rego"
fragments := [
    {
        "issuer": "did:web:profiles.katacontainers.io",
        "feed": "kubernetes-1.33/containerd-2.3.3/linux-amd64-cgroup-v2",
        "minimum_svn": "1",
        "category": "containerd-oci",
        "profile_identity": "sha256:<canonical-profile-hash>",
    },
]
```

The exact signing and distribution mechanism is independent of the mutation
taxonomy. A COSE envelope and transparency receipts can be added without
changing fragment validator semantics.

## Profile Identity

A fragment feed is readable metadata, not sufficient compatibility proof.
Composition binds two different identities:

Static base identity
:   Hashes the trusted workload inputs, digest-bound workload images, measured
    UVM image, and built-in pause artifact.

Mutation profile identity
:   Hashes only the components, configurations, and operating modes that can
    affect the selected fragment claims.

Separating them permits one reviewed containerd fragment to be reused across
UVM images when its claims do not depend on UVM content. A fragment declares
any static-base capability it consumes; a rootfs/storage fragment may depend on
UVM facilities even though a containerd OCI fragment does not. The composition
manifest binds both identities and rejects an undeclared dependency.

Across the selected fragments, mutation profile identities cover at least:

- Kubernetes, kubelet, containerd, runtime-rs, runc, CNI, and Agent versions;
- kubelet, containerd, Kata, CNI, and policy-framework configurations;
- architecture, cgroup mode, rootfs mode, and snapshotter;
- capture backend and request-authority implementation;
- enabled admission, controller, CSI, and device-plugin fragments;
- hashes of binaries and configuration artifacts used to derive the fragment.

The existing appliance `profile.json` and capture manifest provide the initial
canonicalization and artifact hashes.

## Composition And Conflict Rules

1. Each required category has exactly one selected fragment unless the category
   explicitly supports sub-fragments.
2. A claim has one owner. Duplicate claims fail composition.
3. Dependencies are explicit. For example, runtime-rs may consume a bundle ID
   bound by the common framework but cannot redefine it.
4. Static fields cannot be claimed by fragments.
5. A materialized claim only adds an absent path. Replace and delete operations
  are not part of the fragment format.
6. Unknown fields and unclaimed collection elements fail closed.
7. Missing required fragments, profile hash mismatch, unsupported framework
   versions, and SVN rollback fail before workload execution.

Composition produces a claim ledger that is retained beside the policy:

```json title="fragment-claims.json"
{
  "schema_version": 1,
  "claims": [
    {
      "category": "containerd-oci",
      "operation": "default",
      "path": "/OCI/Version",
      "fragment": "kata_fragment_containerd_2_3_3",
      "evidence": ["raw-oci/container.config.json"]
    }
  ]
}
```

The ledger also records the static subject ID and a digest of the materialized
value. This permits an auditor to reproduce composition without executing the
runtime validator.

## Executable Design Check

The compositor prototype lives in
`src/tools/genpolicy/appliance/scripts/compose_policy_fragments.py`, with tests
in `src/tools/genpolicy/appliance/tests/test_compose_policy_fragments.py`. It
uses the checked-in `run-complex` policy compiler output as a golden result.

The original test removed representative containerd and runtime-rs fields from
the compiler result. It remains a focused composition test, while
`prototype_fragment_coverage.py` now exercises an independently generated
static IR. The compositor demonstrates:

- complete expected-policy comparison with fail-closed missing-leaf detection;
- selectors that remain correct after subject-array reordering;
- semantic environment composition by variable name;
- typed normalization of environment, capability, and regex collections;
- non-materializing required-absence assertions;
- rejection of duplicate or overlapping parent/child claims;
- rejection when an addition would overwrite static data; and
- rejection of an unknown subject.

This proves the additive composition mechanics without Agent changes. The
coverage prototype additionally separates policy-data reconstruction from
runtime-request absence coverage; success at the first cannot hide a gap in the
second.

### Independently generated static slice

A second prototype in
`src/tools/genpolicy/appliance/scripts/prototype_static_policy.py` generates a
sparse static IR directly from capture-bundle `workload.yaml` and digest-bound
image configuration. It does not read Legacy or request-derived policy while
generating constraints. It then compares those constraints with both policy
outputs and uses the bundle only for mutation provenance.

The generator also accepts a separately measured UVM baseline through a strict
allowlist. It adds the pause command, environment, user, working directory,
no-new-privileges, root path relationship, and read-only root without reading a
containerd capture. The checked local containerd 1.7.29 and 2.3.3
complex-workload bundles produced the following result:

| Measurement | containerd 1.7.29 | containerd 2.3.3 |
| --- | ---: | ---: |
| Workload/image static constraints generated | 9 | 9 |
| UVM-static pause constraints generated | 7 | 7 |
| Matching Legacy constraints | 9 | 9 |
| Matching request-derived compiler constraints | 16 | 16 |
| Unresolved `valueFrom` anchors retained | 3 | 3 |

The constraints cover two workload containers. They include arguments,
environment subsets, working directories, no-new-privileges, and exec commands.
The result is evidence that these fields can move out of profile-specific
generation without changing either policy implementation.

### Complete candidate reconstruction

`prototype_fragment_coverage.py` builds sparse subjects only from the
independent static IR, derives a candidate claim for every remaining final
policy-data leaf, and invokes the compositor with the compiler policy as an
oracle. The expected policy supplies no static value. Environment entries are
keyed by name in the composition IR and materialized back to OCI arrays.

Both checked profiles reconstruct canonically:

| Measurement | containerd 1.7.29 | containerd 2.3.3 |
| --- | ---: | ---: |
| Static owned roles | 19 | 19 |
| Candidate fragment claims | 139 | 139 |
| Ambiguous kubelet-or-containerd claims | 73 | 73 |
| Exact canonical reconstruction | Pass | Pass |

The `19` static roles count environment variables individually, unlike the
earlier `16` constraint-object comparison. Candidate categories in each run are
`73` kubelet-or-containerd, `3` kubelet resolution, `37` policy-framework
settings, `11` runtime-rs rewrites, and `15` runtime-rs envelope claims.

After typed set normalization, only three claims differ between profiles: OCI
version for the sandbox and two workload containers, from `1.1.0` to `1.3.0`.
Capability and service-environment regex order differences are not mutations.

The CLI writes its report and exits nonzero by default while ownership or
absence coverage is incomplete. `--allow-incomplete` permits candidate
generation but leaves the report result as `incomplete`.

Each candidate fragment carries the capture profile identity and a canonical
digest of the complete static IR, including its measured UVM artifact. The
compositor requires every selected fragment to match both values; partial,
unbound, or mismatched fragment sets fail before claims are applied. Current
capture profile manifests do not contain `UVM_IMAGE_DIGEST`, so the measured
UVM input cannot yet be bound back to the captured profile and remains an
explicit blocker.

The PoC currently uses short container-name subjects for compatibility with the
request-derived compiler. It rejects duplicate static or final-policy subject
IDs rather than silently aliasing two workloads. Supporting repeated container
names across multiple workload objects requires a canonical
namespace/workload/container identity carried through capture and compiler
output.

### Runtime absence coverage

Policy-data reconstruction and final Agent-request coverage are separate
gates. Adjacent raw-OCI-to-Agent analysis observes four removals in each checked
profile:

- `Linux.Resources.Devices` is absent for the sandbox and both workload
  containers. The current Rego input gate enforces all three absences.
- Sandbox `Linux.Seccomp` is removed by runtime-rs but has no corresponding
  final-request absence rule in the current upstream Rego.

The current inventory therefore covers three of four observed removals and
fails closed on the uncovered Seccomp absence. This does not imply Seccomp must
always be absent: profiles that preserve guest Seccomp require an exact or
bounded positive claim instead. The profile configuration and Agent feature
set determine which branch applies. Every inventory rule has exactly one
explicit scope: all subjects, one exact subject, or one subject prefix. An
omitted or multiply declared scope is invalid.

### Legacy settings contribution

The prototype also merges `genpolicy-settings.json`, appliance and profile JSON
patches, and the patch derived from trusted Kata configuration in the same
order as Legacy GenPolicy. Comparison is performed at scalar leaf paths rather
than whole settings objects.

For the containerd 2.3.3 complex-workload policy:

| Destination | Exact settings leaves | Changed leaves | Not serialized |
| --- | ---: | ---: | ---: |
| Legacy policy | 111 | 0 | 5 |
| Request-derived policy | 96 | 15 | 5 |

The five non-serialized leaves are generator inputs: image-layer verification
and NVIDIA/VFIO matching configuration. The request-derived compiler changes
15 inherited `allow_env_regex` entries because it replaces broad Legacy service
environment patterns with capture-derived handling. Therefore a settings file
is useful mutation evidence, but its complete object is not itself a fragment.
Only emitted leaf constraints or explicit transformation rules can become
claims.

### Capture-layer evidence

For the same containerd 2.3.3 bundle, provenance analysis recorded:

| Layer | Evidence entries | Interpretation |
| --- | ---: | --- |
| Static image configuration | 4 | Direct image matches also found by capture analysis |
| Kubelet or containerd | 76 | Cannot be separated until the CRI boundary is captured |
| runtime-rs | 24 | Direct field evidence after comparing raw OCI with the Agent request |
| runtime-rs transformations | 28 | Added, changed, or removed request fields |

The controlled 1.7.29-to-2.3.3 comparison has equal static input hashes and can
be attributed to the containerd profile family. It still reports residual
generated IDs, paths, mounts, environment values, and storages. Those residuals
must be normalized by typed identity correlation before individual differences
become fragment claims. Component-family attribution alone is insufficient.

!!! warning "Current proof boundary"
  The PoC now proves canonical policy-data reconstruction for two controlled
  profiles, but it does not prove publishable fragment completeness. Seventy-
  three claims still cross the missing kubelet CRI capture boundary, the
  current profile manifests do not bind a measured UVM digest, and one
  observed sandbox Seccomp removal lacks runtime absence enforcement. The
  workload and profile matrices also remain incomplete.

## Capture And Fragment Derivation

Fragment candidates are derived only from controlled profile comparisons:

1. Hold workload YAML, image manifests, Kubernetes version, Kata configuration,
   and every unrelated profile dimension constant.
2. Change one component or configuration dimension.
3. Pair requests by workload identity and container role.
4. Normalize generated values by typed role and correlation, not broad regex.
5. Classify each residual difference by mutation operation and category.
6. Repeat across a workload matrix that exercises each relevant field.
7. Generate a candidate fragment and claim ledger.
8. Require review, negative tests, and replay before publication.

If more than one profile dimension changes, the result records candidate causes
and cannot automatically assign fragment ownership.

The required long-term capture boundaries are:

```mermaid
flowchart LR
    A[Submitted YAML] --> B[API-normalized objects]
    B --> C[Kubelet CRI requests]
    C --> D[containerd raw OCI]
    D --> E[runtime-rs Agent requests]
```

The appliance already captures all boundaries except kubelet CRI requests.
Until a recording CRI proxy is added, kubelet and containerd ownership is
partially ambiguous and must be reviewed conservatively.

## Evidence And Testing Strategy

No finite workload corpus can prove that a fragment captures every possible
mutation. Completeness is established by combining field coverage, controlled
experiments, source review, negative tests, and fail-closed handling of unknown
fields. Captures alone demonstrate observed behavior; source review alone does
not demonstrate the behavior of the deployed binary and configuration.

### Mutation completeness ledger

For each adjacent pipeline boundary, the analysis produces a typed field
ledger. A ledger entry records:

- request kind and stable workload subject;
- canonical field path or typed collection role;
- presence at the input and output boundary;
- operation: `default`, `generate`, `resolve`, `derive`, `normalize`,
  `rewrite`, `remove`, or `envelope`;
- owning category and fragment claim;
- static anchors and cross-field correlations;
- capture artifacts and profile identity;
- source-code evidence, when reviewed; and
- positive, negative, absence, and interaction tests covering the claim.

Presence and absence are both covered. A component that stops emitting a
sysctl or annotation has changed behavior even though no final value exists to
compare. Collections are inventoried by semantic role, such as mount
destination or environment-variable name, rather than array index.

For one request $Q$, let $L(Q)$ be all canonical final leaves and required
absences, $S(Q)$ the leaves owned by static policy, and $C_i(Q)$ the leaves
claimed by fragment $i$. The coverage gate is:

$$
L(Q) = S(Q) \dot{\cup} C_1(Q) \dot{\cup} \cdots \dot{\cup} C_n(Q)
$$

where $\dot{\cup}$ requires disjoint ownership. Composition fails if a leaf is
unclaimed, multiply claimed, or absent from the protocol schema inventory.
Schema inventory is generated from protocol descriptors and captured JSON, so
a newly introduced request field fails CI until it is classified.

Coverage is measured at three levels:

| Gate | Requirement |
| --- | --- |
| Request coverage | Every final leaf, collection role, and required absence has one owner |
| Transformation coverage | Every adjacent-boundary difference has one operation and category |
| Evidence coverage | Every claim has capture replay, negative tests, and reviewed evidence |

The current PoC measures complete final policy-data reconstruction for two
profiles and partial transformation and absence coverage. It reports
`incomplete`, never fragment completeness.

### Evidence hierarchy

Each claim requires more than one type of evidence:

| Evidence | What it establishes | Limitation |
| --- | --- | --- |
| Static derivation | Value follows from YAML, digest-bound image data, or a trusted object | Covers only implemented input forms |
| Same-profile repetition | Separates stable behavior from generated or nondeterministic values | Does not identify the producing component |
| Adjacent-boundary capture | Shows the stage at which a mutation occurred | Requires every relevant boundary |
| One-factor profile comparison | Attributes a behavior change to one component or configuration family | Misses unexercised branches |
| Pinned source review | Finds defaults, removals, feature gates, and branches absent from captures | Build flags, downstream patches, and runtime configuration can differ |
| Negative and metamorphic tests | Demonstrates that the proposed rule rejects widening and preserves correlations | Tests only stated properties |

No fragment is publishable from a single capture or a source-code reading
alone.

### Component source review

Source review is required before a fragment moves from experimental to
publishable. It is not required to start a capture-derived candidate. Review
uses the exact source commit, build configuration, patches, and configuration
hashes from the profile, and covers the code that owns each claim:

| Category | Source review focus |
| --- | --- |
| Kubernetes API/controller | Defaulting, generated names and UIDs, controller templates, feature gates |
| Kubelet resolution | Environment resolution, security-context projection, resources, DNS, and volume preparation |
| containerd OCI | CRI-to-OCI defaults, annotations, mounts, capabilities, namespaces, sysctls, and cgroups |
| runtime-rs | OCI-to-Agent rewrites, storage/device construction, annotation injection, and Seccomp handling |
| Rootfs/storage mode | Snapshotter metadata, guest-pull identity, shared-fs mode, dm-verity, and encryption options |
| UVM pause baseline | Built-in pause binary, process identity, packaging, and measured UVM-root relationship |

The claim ledger records repository, commit, file and symbol, controlling
configuration or feature gate, and reviewed branch conditions. Source review
must identify absence behavior and error paths, not only the branch observed in
the capture. A source branch without a workload test becomes an explicit
coverage gap.

### Workload corpus

Large YAML tests reduce missed-mutation risk only when their coverage is
structured. Repeating similar large manifests provides less evidence than
small single-feature workloads plus selected interaction workloads.

The corpus has three layers:

1. Minimal fixtures isolate one YAML or image feature and produce a small,
  attributable delta.
2. Pairwise fixtures combine features likely to interact at one component
  boundary.
3. Realistic workloads exercise ordering, repetition, multiple containers,
  controllers, and generated identities.

The existing matrix covers basic Pods, process overrides, environment sources,
service environment, probes, ConfigMap and Secret data, and several storage
classes. It needs additional fixtures for:

| Area | Required cases |
| --- | --- |
| Container lifecycle | Init, sidecar, ephemeral, lifecycle hooks, all probe types, TTY and stdin |
| Image semantics | Entrypoint/Cmd precedence, empty fields, numeric and named users, groups, supplementary groups |
| Security context | Privileged, capability add/drop, no-new-privileges, read-only root, Seccomp, AppArmor, SELinux |
| Pod sharing | Host network/PID/IPC, shared process namespace, hostname, DNS policy and options |
| Resources | CPU and memory requests/limits, huge pages, unified cgroup values, QoS classes |
| Volumes | Projected, downward API, service account, PVC, image, subPath, block device, read-only and mount propagation |
| Devices | VFIO, CDI, GPU count, volume devices, and conflicting device paths |
| Controllers | Deployment, StatefulSet, DaemonSet, Job, CronJob, generated names, and restart behavior |
| Networking | Multiple Services, named ports, IPv4/IPv6, host ports, CNI namespace, and no service links |
| Metadata | User annotations, runtime annotation allowlists, labels, namespaces, and admission mutation |

Pause testing is intentionally smaller than workload-image testing. One
canonical sandbox case per measured UVM image verifies the exact pause command,
process identity, and UVM-root relationship. The same pause static subject is
then reused across component profiles. Cross-profile tests require those static
leaves to remain identical while permitting only the claimed sandbox envelope
to differ.

Feature coverage is recorded against ledger claims and reviewed source
branches. Pairwise generation is preferred for broad interaction coverage;
full Cartesian products are reserved for interactions known to cross ownership
boundaries. Property-based tests vary ordering, omission, duplicate entries,
names, IDs, and valid boundary values without creating permanent YAML files for
every combination.

### Profile matrix

Additional profiles are required, but profile proliferation must remain
controlled. Static classification is provenance-first: a value is static
because it is derived only from trusted static inputs, not merely because it
remained unchanged in sampled profiles. Cross-profile invariance is a
falsification test for that classification.

Use one-factor-at-a-time comparisons from a fully pinned baseline, followed by
selected pairwise interactions:

| Axis | Minimum comparison |
| --- | --- |
| Kubernetes API and kubelet | Two supported minor versions with otherwise identical binaries and configuration |
| containerd | Current 1.7 and 2.x profiles, plus another supported 2.x release when behavior changes |
| runtime-rs and Agent | Two commits or releases with containerd and workload held constant |
| Runtime configuration | Seccomp on/off, annotation allowlist, sandbox sharing, and relevant feature gates |
| Rootfs/storage | Guest pull, EROFS/dm-verity, shared fs, Agent-local `emptyDir`, encrypted and plain block |
| UVM image | Two measured UVM builds when the built-in pause artifact changes; component-only changes reuse one UVM baseline |
| Host environment | cgroup v1/v2 where supported, at least amd64 and arm64, IPv4 and dual stack |
| Runtime baseline | runtime-rs capture and runc-native raw-OCI baseline |
| Extensions | Each admission webhook, CSI driver, CNI, and device plugin independently enabled |

Each profile is captured at least three times with generated identities and
resource creation order varied. Stable semantic output must be identical after
typed normalization. A difference between repetitions is classified as
nondeterminism and requires a grammar or correlation rule; it is never copied
as an exact fragment value.

Profile comparisons are accepted for automatic attribution only when static
artifact hashes match and all changed profile dimensions belong to one declared
component family. Version labels and profile names are metadata, not separate
causes. Changes spanning component families remain unassigned until a narrower
experiment is run.

### Falsifying the additive assumption

The additive model is a hypothesis to test, not a constraint imposed on
evidence. For every controlled run:

1. Generate static IR without loading profile settings or captures.
2. Verify that profile selection cannot change or delete a static IR leaf.
  This includes the UVM-static pause command and root relationship.
3. Derive mutation claims only from settings leaves, adjacent-boundary capture,
  and reviewed transformations.
4. Apply claims in multiple orders and require canonical output equality.
5. Require the composed policy data to equal request-derived policy-compiler
  output after documented order-insensitive normalization.
6. Replay all captured requests against the composed policy.
7. Compare with Legacy policy and explain every semantic difference; Legacy is
  a compatibility reference, not the security authority.

The hypothesis is falsified if a profile must overwrite or delete a trusted
static constraint, if composition order changes the result, or if final policy
requires an unclaimed value. A host-to-guest rewrite does not falsify the model
when static IR records host-independent intent and the fragment adds only the
final guest constraint. If static IR already contains the host representation,
the IR boundary is wrong and must be redesigned rather than granting fragments
replacement authority.

### Test phases and exit criteria

1. **Inventory:** enumerate request schemas, settings leaves, static-input
  forms, and reviewed source branches.
2. **Repeatability:** capture the baseline profile repeatedly and establish
  typed normalization for every nondeterministic value.
3. **Boundary attribution:** add the kubelet CRI capture boundary and require
  complete adjacent-stage ledgers.
4. **Workload coverage:** run minimal, pairwise, realistic, property-based, and
  negative workload tests until every known branch and claim is covered.
5. **Profile coverage:** run one-factor comparisons, then selected pairwise
  profile interactions.
6. **Reconstruction:** require static IR plus fragments to reproduce canonical
  policy-compiler output for every matrix cell.
7. **Enforcement:** replay positive requests and mutate every claim, anchor,
  absence, and correlation to demonstrate rejection.
8. **Review:** reconcile capture evidence with pinned source and configuration,
  then sign and publish the fragment and its evidence manifest.

A fragment can be labeled **experimental** after successful reconstruction for
one controlled profile. It becomes **reviewed** after source reconciliation,
complete claim/absence coverage, negative tests, and same-profile repetition.
It becomes **releasable** only after the required workload and profile matrix
passes with zero unknown or multiply owned leaves.

## Agent Integration

Kata Agent currently installs one policy in one Regorus engine.
`SetPolicyRequest` replaces that engine and does not add a module. There is no
current issuer/feed/SVN, signature, or additive-module API.

Implementation is therefore staged:

### Phase 1: build-time composition

- The appliance selects fragments by exact profile identity.
- GenPolicy emits a static policy IR containing no profile-owned fields.
- The compiler verifies claim ownership, framework compatibility, SVN, stable
  subject existence, and target-path absence.
- It additively materializes claim values and composes namespaced runtime Rego
  validators into one policy text.
- The existing `SetPolicyRequest` installs the resulting policy atomically.
- Fragment descriptors, hashes, claims, and evidence remain in provenance.

This phase provides the static/mutation separation and fragment reuse without
changing the Agent RPC API.

### Phase 2: authenticated runtime loading

- Extend the Agent protocol with a fragment envelope carrying issuer, feed,
  namespace, SVN, Rego, and optional signature evidence.
- Add Regorus module lifecycle support without replacing policy state.
- Perform pre-load identity and minimum-SVN checks.
- Load into an isolated namespace, evaluate post-load metadata and claims, and
  remove the module on any failure.
- Seal the required fragment set before processing workload requests.

The two-phase pre-load/post-load validation used by hcsshim is the preferred
model for this phase.

## Validation

Every fragment requires:

- positive replay of all paired requests in its capture matrix;
- rejection after changing every claimed exact value;
- rejection of extra and missing claimed fields;
- rejection of an extra mount, storage, device, namespace, environment entry,
  annotation, or sysctl;
- correlation tests that change only one occurrence of a repeated identity;
- static-anchor tests that substitute another digest, command, destination, or
  volume role;
- order permutation tests for set-like collections;
- profile hash, namespace, framework version, issuer, feed, and SVN failure
  tests;
- cross-version tests proving that a 1.7-only request is rejected by the 2.3
  fragment and conversely where their shapes differ.

The complete policy must also retain a coverage assertion: every final request
field and collection element is consumed by static policy or exactly one
fragment claim.

The build-time compositor additionally requires tests that permute fragment
and subject order, attempt to overwrite each static anchor, omit each required
claim, duplicate each claim, and compare canonical composed policy data with
policy-compiler output.

## Open Questions

- Should fragments be distributed with the Kata release, generated by cluster
  operators, or both under different issuers?
- Which profile dimensions require independent fragments rather than one
  combined feed?
- How should Regorus expose safe additive module loading and removal?
- Should API-server and kubelet fragments execute in Agent policy, or should a
  trusted compiler reduce them into final correlations before deployment?
- How should Secret-derived evidence be retained and reviewed without exposing
  plaintext in fragment provenance?
- Which admission, CSI, and device-plugin behaviors are stable enough to become
  reviewed fragments?

## Decision Summary

GenPolicy remains the authority for workload and image invariants. Fragments
add profile-owned final constraints and validate mutations by category:
Kubernetes API/controller, kubelet resolution, containerd OCI generation,
runtime-rs transformation, and rootfs/storage mode. Generated identities are
common correlated facts. Build-time composition is additive and conflict-free;
runtime composition is an intersection of validators with complete claim
coverage, never a union of permissions.

The first implementation composes fragments before installing the policy. The
hcsshim issuer/feed/SVN and runtime-loading mechanics can be adopted later
without changing the central mutation ownership model.
