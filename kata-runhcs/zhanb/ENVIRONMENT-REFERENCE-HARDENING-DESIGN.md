# GenPolicy Environment Reference Hardening

## Status

- **State:** design revised after implementation review. Generator-side
  `EnvRules` scaffolding exists, but it is not a security fix until Agent-side
  Rego consumes it. G1 is therefore incomplete.
- **Working branch:** `wip/genpolicy-env-ref-hardening`
- **Base:** `microsoft/manifold-cc` at `a4f7e7f416`
- **Primary implementation areas:**
  - `src/tools/genpolicy/src/pod.rs`
  - `src/tools/genpolicy/src/policy.rs`
  - `src/tools/genpolicy/src/registry.rs`
  - `src/tools/genpolicy/src/yaml.rs`
  - `src/tools/genpolicy/rules.rego`
  - `src/tools/genpolicy/genpolicy-settings.json`
  - `src/agent/src/rpc.rs`
  - `src/agent/src/plan_binding.rs`
  - `src/agent/rustjail/src/container.rs`

This document is the implementation contract for the environment-reference
hardening work. Code changes must cite the relevant design section in their
commit message or pull-request description. If implementation evidence requires
a different design, update this document before changing the behavior.

## Summary

GenPolicy currently represents all process environment entries as strings:

```text
NAME=value
```

The same string field carries several different security meanings:

- a literal value from the image or workload YAML;
- a value resolved from a ConfigMap or Secret;
- a Kubernetes downward-API reference;
- a resource-field reference;
- a PolicyGen placeholder such as `$(sandbox-name)` or `$(node-name)`;
- a value admitted by a global regular expression;
- a sealed-secret reference that Agent rewrites after authorization.

This loses provenance and value semantics before policy enforcement. Rego then
tries to reconstruct the meaning by searching for magic strings. Several rule
arms constrain only the variable name and accept any value. Global regex rules
also admit variables that the selected process did not declare. Agent later
performs trusted transformations, including sealed-secret unsealing, without a
rule-specific transform grant.

The proposed repair is to:

1. generate a typed, per-process environment policy;
2. key ordinary rules by exact variable name;
3. model dynamic platform families separately and explicitly;
4. reproduce the pinned Kubernetes/containerd environment semantics before
   enforcing completeness;
5. reject duplicate input names;
6. distinguish create and exec requirements;
7. bind dynamic references to exact values, Agent state, bounded types, or an
   explicit measured delegation;
8. authorize post-policy transformations separately from value matching.

Runtime request captures are compatibility and test evidence only. They must
never become policy-generation authority.

## Goals

### G1: Resolve exact values before choosing a matcher

Enforcement rule types are based on how a value is checked, not on every
possible Kubernetes source.

If PolicyGen can resolve a value from the image, YAML, ConfigMap, Secret,
`envFrom`, downward API, resource field, or generated workload data, it emits
one exact-string matcher. Those sources may retain consolidated, generator-only
provenance for diagnostics and compatibility tests, but they do not require
different policy rule types.

Only values that cannot be resolved before policy measurement retain a typed
runtime source. The runtime type exists because each unresolved class needs a
different secure resolution mechanism, such as comparison with concrete
sandbox state, membership in Agent network state, a bounded integer, or a
measured fragment.

A matcher type is not implemented merely because PolicyGen serializes it. G1
must be an end-to-end vertical slice:

1. PolicyGen emits the typed rule.
2. Agent-side Rego selects it by exact environment-variable name.
3. Rego obtains the expected value from policy data or previously established
   Agent policy state.
4. Rego compares the complete presented value and rejects a mismatch.
5. A typed rule for a name is authoritative; legacy regex or placeholder rules
   cannot authorize a second value for that same name.

The implemented G1 slice supports `Exact`, `SandboxHostname`, `SandboxName`,
`SandboxNamespace`, and pin-on-first-use `PodUid`. Other runtime source types
are not considered implemented until they have an equally strong Agent-side
resolver and negative tests.

### G2: Scope rules to the selected process

An environment rule belongs to one generated container/process. A rule for one
container must not authorize the same variable in another container.

This is separate from required-versus-optional cardinality. Scoping answers
*which process owns the rule*; requiredness answers *whether that process must
present it*.

### G3: Eliminate magic-placeholder interpretation of external text

Image, ConfigMap, Secret, label, annotation, and YAML literal content must not
gain special authority merely because it contains text such as
`$(node-name)`.

### G4: Make cardinality explicit

Policy must be able to express:

- required on create;
- optional on create;
- allowed on exec under the same value matcher;
- prohibited on exec;
- exactly one occurrence.

Kubernetes defines the container environment during create. However, Agent's
`ExecProcessRequest` carries a complete OCI `process.Env` for the new process;
existing tests show runtimes re-present values such as `PATH` and `HOSTNAME`.
Exec therefore needs authorization for entries that are supplied in that
request, but create-time requiredness does not apply to exec.

An exec command argument containing `$NAME`, `${NAME}`, or `$(...)` is not an
environment reference recognized by policy. It is literal argv until the
executed program or shell interprets it and does not grant permission to add or
change an environment entry.

### G5: Bind trusted transformations

Agent may rewrite an environment value only when policy authorization returned
an explicit transform grant for that exact variable and exact authorized
value.

Environment matching and environment rewriting are different operations:

- Rego may resolve a runtime-bound matcher against concrete Agent policy state
  for both `CreateContainerRequest` and `ExecProcessRequest`. This only decides
  whether the presented value is allowed; it does not rewrite the request.
- Agent may rewrite an environment entry only while processing
  `CreateContainerRequest`, after policy authorization and before the OCI
  process is handed to rustjail. The current required rewrite is sealed-secret
  unsealing. Measured CDI edits may also add entries during create under their
  separate authorization.
- `ExecProcessRequest` receives no environment transform grant. It may only
  re-present values allowed by `SameMatcher`; sealed-secret rules are denied for
  exec.
- No other Agent request may resolve, add, or rewrite process environment
  entries under this design.

### G6: Preserve compatibility intentionally

Tightening must not depend on an inaccurate reimplementation of kubelet or
containerd behavior. Requiredness and duplicate rejection are enabled only
after conformance tests and real request captures show that PolicyGen predicts
the final environment correctly.

## Non-goals

- Runtime captures will not be used to generate trusted policy values.
- GenPolicy will not attempt to authenticate arbitrary external services.
- Regex syntax alone will not be treated as authorization for identities,
  tenants, shards, secrets, files, commands, or protected guest-internal
  endpoints.
- This design does not make cluster configuration available at generation
  time.
- This design does not introduce or trust a host-provided deployment-time
  profile. Values supplied after policy measurement remain attacker-controlled
  unless they are bound by measured Agent state or a measured policy fragment.
- This design does not require exact pinning of unresolved Kubernetes Service
  IPs.
- This design does not change Kubernetes Secret confidentiality. A Secret
  supplied to PolicyGen is already visible to the policy-generation
  environment and host-side deployment pipeline.

## Threat model

The host constructs Agent requests and is untrusted. It may:

- add, remove, reorder, or duplicate environment entries;
- change values while preserving valid syntax;
- exploit a global rule not declared by the selected process;
- provide a value containing PolicyGen placeholder text;
- choose values that alter workload identity, tenant, shard, path, command, or
  guest-internal resource selection;
- provide a sealed-secret reference that triggers a guest-side transform.

The workload is responsible for authenticating ordinary external peers and
data. GenPolicy remains responsible for preventing host-provided values from
selecting protected guest-internal/control resources or changing workload
identity, command, secret, tenant, or shard authority.

The workload manifest, image identity, ConfigMaps, Secrets, and explicit
PolicyGen inputs available before policy measurement may define policy
authority. A deployment-time profile or other host-supplied value presented
after measurement cannot.

## Current implementation

### Generator

`KataProcess.Env` is `Vec<String>` in `src/tools/genpolicy/src/policy.rs`.
PolicyGen builds that list from:

- default/containerd environment;
- image `config.Env`;
- generated `HOSTNAME=$(host-name)`;
- explicit YAML environment entries;
- ConfigMap and Secret references;
- `envFrom`;
- downward-API references;
- resource-field references.

`pod.rs` converts unresolved references to magic values:

| Kubernetes source | Current policy value |
|---|---|
| `metadata.name` | `$(sandbox-name)` |
| absent `metadata.namespace` | `$(sandbox-namespace)` |
| `metadata.uid` | `$(pod-uid)` |
| `status.hostIP` | `$(host-ip)` |
| `status.podIP` | `$(pod-ip)` |
| `spec.nodeName` | `$(node-name)` |
| `resourceFieldRef` | `$(resource-field)` |
| missing annotation | `$(todo-annotation)` |

The generator now retains `resource`, `containerName`, and `divisor` in its
internal `ResourceField` matcher. Because Agent/Rego has no corresponding
resolver, the matcher is deliberately excluded from `EnvRules` and only the
legacy `NAME=$(resource-field)` entry is emitted.

The current `envFrom` implementation does not apply `prefix` and does not
honor optional-source behavior. It appends entries as strings and de-duplicates
only byte-identical complete strings, not variable names.

`substitute_env_variables` repeatedly searches the complete environment list
until no more substitutions occur. That behavior must not be assumed to match
the pinned kubelet expansion algorithm.

### Rego

`allow_env` checks every input entry through `allow_var`, but it does not
require policy entries to be present.

The rule arms currently include:

- exact complete-string equality;
- sandbox-name substitution using unanchored `regex.match`;
- global `allow_env_regex`;
- typed IPv4 syntax for pod and host IP;
- name-only acceptance for host name, node name, Pod UID, resource field, and
  missing annotation placeholders;
- exact namespace substitution;
- measured-fragment environment rules.

The global defaults include Kubernetes Service families,
`JOB_COMPLETION_INDEX`, Azure Workload Identity variables, `HOSTNAME`, and
`TERM`. They are not scoped to a variable declared by the selected process.

Create and exec both call `allow_env`, but they provide different sandbox-name
inputs. Create passes the validated concrete request name. Exec currently
passes the policy's sandbox-name regex. Tightening the substitution comparison
without first unifying this provenance would break generated-name exec.

### Agent and rustjail

After policy authorization, Agent may:

- append environment entries from measured CDI specifications;
- replace sealed-secret references with plaintext through CDH.

The current plan-binding rule permits a value rewrite whenever the authorized
value starts with `sealed.`. It does not know which Rego rule admitted that
value.

`cdh_handler_sealed_secrets` tries to unseal every environment value beginning
with `sealed.`. An unseal error is logged and container creation continues.

rustjail installs entries in list order with `set_var`. Duplicate names
therefore have last-value-wins behavior.

## Confirmed problems

### P1: Dynamic placeholders authorize unrestricted values

The `allow_var` arms for `$(host-name)`, `$(node-name)`, `$(pod-uid)`,
`$(resource-field)`, and `$(todo-annotation)` compare the variable name but do
not constrain the presented value.

This affects every non-pause container because PolicyGen adds
`HOSTNAME=$(host-name)`.

For `resourceFieldRef`, this means the untrusted host can select the complete
value of any declared resource-derived environment variable. Given:

```yaml
env:
  - name: CPU_LIMIT
    valueFrom:
      resourceFieldRef:
        resource: limits.cpu
        divisor: 1m
```

the generated legacy policy contains:

```text
CPU_LIMIT=$(resource-field)
```

The Rego arm checks only that the input name is `CPU_LIMIT` and that the policy
value contains the marker. It does not compare the input value with
`limits.cpu`, the selected container, the divisor, or OCI resource state.
Consequently `CPU_LIMIT=500`, `CPU_LIMIT=999999`,
`CPU_LIMIT=attacker-controlled`, and an empty value all receive the same
authorization. The implementation's requirement that the complete entry split
into exactly two `=`-separated components is an incidental parsing limitation,
not value validation.

This is security-significant whenever the workload uses the variable to select
memory or CPU behavior, construct a command, choose a path, size a buffer, or
make another security-sensitive decision. Capturing the complete selector in
generator metadata does not reduce this authority while enforcement still
uses the legacy placeholder.

### P2: Sandbox-name environment matching is not exact

The metadata-name arm computes the intended substituted string but does not use
it. Instead it evaluates:

```rego
regex.match(s_name, input_value)
```

On create, `s_name` is a concrete value and Rego performs an unanchored search.
An input value that merely contains the name is accepted.

### P3: Global rules admit undeclared variables

Global environment regexes are independent alternatives. They may introduce
Azure identity, Job index, Service, hostname, or terminal variables into a
container whose selected process did not declare them.

### P4: Missing and duplicate entries are not constrained

The input-to-policy check is one-way. A host may omit a policy value and cause
the application to use a fallback. The generator may also retain multiple
values for one name, while rustjail gives the final occurrence authority.

### P5: External values can forge PolicyGen placeholders

External text is copied into `KataProcess.Env` without distinguishing it from
generator-created placeholders. A pinned image containing:

```text
FEATURE=$(node-name)
```

can accidentally create a host-controlled policy value.

### P6: Sealed-secret transforms are authorized by prefix

A variable admitted through a broad dynamic rule can carry a `sealed.*` value.
Agent then treats the value as a CDH transform candidate. An invalid reference
fails to unseal, but a valid reference accepted by CDH can be substituted even
though the environment rule never explicitly authorized a sealed-secret
transform.

The fix must not assume that an attacker can forge a valid sealed object.
The security defect is the missing binding between the matched environment
rule and the decision to invoke CDH.

### P7: Literal object names are not regex-escaped

`name_regex_from_meta` escapes `generateName` but returns `metadata.name`
literally before it is embedded in an anchored regex. A legal Kubernetes name
containing `.` widens the accepted sandbox-name set.

### P8: Kubernetes environment construction is incomplete

Current PolicyGen handling is incomplete for:

- `envFrom.prefix`;
- optional ConfigMap and Secret sources;
- invalid environment names from `envFrom`;
- key ordering;
- override precedence by variable name;
- kubelet-compatible `$(VAR)` expansion;
- values containing `=`;
- `resourceFieldRef.containerName`;
- `resourceFieldRef.divisor`;
- resource-field behavior when a request/limit is absent;
- `spec.hostname`, `subdomain`, and `setHostnameAsFQDN`.

These are primarily compatibility defects today. They become security and
availability defects if strict completeness is enabled before PolicyGen
matches the pinned Kubernetes/containerd behavior.

## Security invariants

### I1: Exact-name ownership

Every ordinary environment rule is keyed by one exact variable name and belongs
to one selected process.

### I2: Unique effective value

An accepted request contains at most one entry for each environment name.

### I3: Complete create contract

Every rule marked required on create is present exactly once.

### I4: Explicit exec contract

Exec environment authority is separate from create requiredness. An exec
request does not inherit permission to add arbitrary values merely because the
container's create policy admitted them.

### I5: Typed dynamic value

Every non-literal value is constrained by an exact relation, finite set,
numeric range, parsed address class, or explicitly reviewed regex.

### I6: No host-to-host relation presented as authenticity

Relating two host-provided values provides consistency only. The design must
state when a value is merely validated and pinned on first use rather than
authenticated.

### I7: Explicit transform authority

Agent transforms an environment value only when the policy decision grants a
named transform for that exact authorized value.

### I8: Capture non-authority

Captured runtime values may create fixtures and compatibility reports. They do
not populate exact policy values or trusted finite sets.

## Policy data model

### Exact-name rules

Add an environment-rule map to `KataProcess`, serialized into generated policy
data:

```rust
pub struct KataProcess {
    // Existing fields.
    pub Env: Vec<String>,

    // New policy-only representation.
    pub EnvRules: BTreeMap<String, KataEnvRule>,
    pub EnvFamilyRules: Vec<KataEnvFamilyRule>,
}
```

`Env` remains during migration so old policies and diagnostics continue to
work. New enforcement uses `EnvRules` when present.

```rust
pub struct KataEnvRule {
    pub matcher: KataEnvMatcher,
}

pub enum KataEnvMatcher {
    Exact {
        value: String,
    },
    Runtime {
        template: String,
        sources: BTreeSet<KataEnvRuntimeSource>,
    },
}

pub enum KataEnvRuntimeSource {
    SandboxHostname,
    SandboxName,
    SandboxNamespace,
    PodUid,
    PodIp,
    HostIp,
    NodeName,
    ResourceField {
        resource: String,
        container_name: Option<String>,
        divisor: Option<String>,
    },
}
```

This is the G1 generator representation. A runtime template may carry more than
one source when an environment value composes references, for example:

```text
POD_ID=$(sandbox-namespace)/$(sandbox-name)
```

The template records where concrete values belong; `sources` records which
Agent-side state must be available. `HOSTNAME=$(host-name)` uses
`SandboxHostname`, while downward-API `metadata.name` uses `SandboxName`.
These must not be conflated: an explicit Kubernetes `spec.hostname` can differ
from the Pod/sandbox name.

Image, ConfigMap, Secret, and settings values remain literal `Exact` data even
when their text resembles a PolicyGen marker. Workload `$(NAME)` expansion is
deferred until pinned kubelet/containerd conformance work establishes the
correct order and escaping behavior; it must not be represented as enforceable
typed authority before an Agent-side resolver exists.

### Sandbox hostname trust and data flow

`CreateContainerRequest` is host supplied, so neither its environment nor its
OCI annotations are an independent source of truth for `SandboxHostname`.

The Agent receives `CreateSandboxRequest.hostname` first and, after policy
authorization, uses that exact value to configure `Sandbox.hostname` and the
guest UTS namespace. The `CreateSandboxRequest` policy decision must return a
state operation that records the accepted value under a dedicated
`sandbox_hostname` key. If policy data can derive an exact hostname, the
request must equal it before the state operation is emitted. Otherwise the
state value is explicitly a host-selected value pinned on first use; it
provides consistency with the guest's actual hostname, not independent
authentication.

For a later `CreateContainerRequest`, a rule such as:

```json
{
  "matcher": {
    "type": "runtime",
    "template": "$(sandbox-hostname)",
    "sources": [{"type": "sandbox_hostname"}]
  }
}
```

is satisfied only when the complete environment entry value equals the
recorded `sandbox_hostname`. The value is read from policy state established by
the earlier sandbox request; it is never taken from the container request
being authorized. Therefore `HOSTNAME=attacker-value` is rejected when the
actual accepted sandbox hostname is `workload-abc`.

The same rule applies to `ExecProcessRequest`: if it presents `HOSTNAME`, its
value must equal the already recorded sandbox hostname. Exec cannot establish
or replace that state.

### Runtime-source resolver matrix

Every runtime source requires a concrete Agent-side resolver. Syntax validation
alone is not a resolver, and relating two fields from the same
`CreateContainerRequest` does not make either field trusted.

### Source admission must be as narrow as the environment rule

Safe resolution of an environment reference is not sufficient when the rule
that admits the referenced source value is too broad. Exact enforcement of
`ENV == resolved_source` proves only consistency with that source. It does not
repair an unanchored, unescaped, generic, or otherwise attacker-selectable
source rule.

For example, if sandbox-name admission uses an unanchored regex and accepts
`attacker-pod` for a policy pattern intended to identify `pod`, then requiring
`POD_NAME == sandbox_name` still permits `POD_NAME=attacker-pod`. The resolver
has correctly enforced equality but has bound the environment to a value the
attacker was allowed to choose.

Every resolver therefore has two inseparable authorization obligations:

1. **Source admission:** establish the referenced value using an exact attested
   value or the narrowest intended full-match rule.
2. **Reference equality:** require the complete environment value to equal the
   admitted source and prevent fallback to broader legacy authority.

Source-admission regexes must be anchored as complete values. Literal names
must be regex-escaped before anchoring. Generated-name regexes may express only
the variability that Kubernetes itself introduces; they must not accept
arbitrary prefixes, suffixes, or substituted metacharacters. A pinned value is
immutable only after admission, so pin-on-first-use provides no stronger
identity property than its initial admission rule.

Negative tests must change the source and environment together, not just the
environment. If an attacker-selected source and its matching environment value
are both accepted, the resolver is not safe even though its equality check
passes.

| Source | Required enforcement value | Fail-closed behavior |
|---|---|---|
| `SandboxHostname` | `sandbox_hostname` recorded from the accepted `CreateSandboxRequest`; constrain it against an exact generated hostname when available | Deny when state is absent or the complete value differs |
| `SandboxName` | Exact generated Pod name when known; otherwise the sandbox name admitted by the workload-name policy and pinned in policy state | Deny a value that merely matches a generic DNS regex or differs from pinned state |
| `SandboxNamespace` | Exact namespace from generation input; only use pinned state for legacy inputs where generation lacks it | Deny when no exact/pinned namespace exists |
| `PodUid` | Exact attested Pod `metadata.uid` when available; otherwise a canonical lowercase UUID from `io.kubernetes.cri.sandbox-uid`, pinned on the first accepted create for a process that declares `PodUid` | Deny malformed values, environment/annotation disagreement, later annotation changes, or exec before runtime state exists; runtime pinning is consistency, not authentication |
| `PodIp` | Parsed address present in Agent-recorded sandbox interface/address state before create authorization | Deny when network state is unavailable or the address is not assigned to the sandbox |
| `HostIp` | Exact measured value or explicit policy-author-approved external address/set | IP syntax alone is insufficient and may redirect guest traffic; deny by default |
| `NodeName` | Exact `spec.nodeName` from generation input, or a measured/signed platform binding explicitly authorized for that variable | DNS-1123 syntax alone is insufficient; deny by default |
| `ResourceField` | Kubelet-compatible calculation from measured container requests/limits and the recorded divisor | Deny when calculation depends on unavailable node state and no explicit bound is declared |

Values that should normally be resolved before measurement do not need runtime
authority:

- `spec.serviceAccountName`, namespace, labels, and present annotations are
  exact from workload input;
- a missing downward-API annotation or label resolves to the kubelet-compatible
  empty value rather than a wildcard;
- ConfigMap, Secret, image, and explicit literal values are exact inputs;
- `$(OTHER_ENV)` expansion is resolved by a pinned kubelet-compatible
  generation algorithm, not by allowing the host to choose the referenced
  value at create time.

Platform-injected families require separate typed rules rather than being
misclassified as field references:

- Kubernetes Service host/port variables must bind to measured or signed
  Service endpoint data; an arbitrary syntactically valid IP/port can redirect
  traffic.
- `AZURE_CLIENT_ID` and `AZURE_TENANT_ID` must be exact or supplied by a
  measured, scoped identity fragment; UUID-shaped regexes do not identify the
  intended workload identity.
- `JOB_COMPLETION_INDEX` must be an integer bounded by the measured Job
  completion count.
- `TERM`, `AZURE_FEDERATED_TOKEN_FILE`, and `AZURE_AUTHORITY_HOST` are exact
  generated constants and need no broad regex.

### Reusable relational matcher pattern

The Pod UID relation generalizes to other reference values, but the policy
schema must expose a closed set of reviewed resolvers rather than an arbitrary
JSONPath expression.

Each resolver defines:

1. the exact source field or Agent state key;
2. when that source becomes available;
3. how the source is independently validated;
4. whether it is authenticated, measured, or only pinned on first use;
5. whether the resolved value may be used by create, exec, or both.

The common enforcement algorithm is:

```text
parse NAME=value using the first '='
look up EnvRules[NAME]
resolve every declared source from the resolver's fixed location
substitute the complete template
require byte equality with value
do not fall back to legacy authority for NAME
```

Initial resolver mappings:

| Typed source | Fixed resolver |
|---|---|
| `SandboxHostname` | Agent `Sandbox.hostname`, established by accepted `CreateSandboxRequest.hostname` |
| `SandboxName` | admitted and pinned `io.kubernetes.cri.sandbox-name` |
| `SandboxNamespace` | exact generated namespace or pinned `io.kubernetes.cri.sandbox-namespace` |
| `PodUid` | Exact attested Pod `metadata.uid` when present; otherwise canonical lowercase UUID-shaped `io.kubernetes.cri.sandbox-uid`, pinned on the first accepted create for a process that declares this resolver |
| `PodIp` | address membership in Agent-observed sandbox interface state |
| `ResourceField` | PolicyGen calculation from measured container resources |

For `PodUid`, a concrete UID carried by an attested Pod object is emitted as an
`Exact` rule and needs no runtime authority. Ordinary pre-deployment workload
YAML does not contain a Pod UID because the API server assigns it later. In that
case, the first accepted create for a process declaring `PodUid` validates and
pins the annotation. Create authorization for an environment reference
requires its value to equal the annotation, while every later relevant create
also requires its annotation to equal the pinned `pod_uid`. An exec request has
no OCI sandbox annotation, so it can only compare against the state established
by create. The fallback is consistency and substitution protection, not
authentication of the host-selected initial UID.

Do not add a generic `RequestField { path: String }` or
`RequestAnnotation { key: String }` matcher. Even though measured policy limits
who can author it, generic paths obscure trust classification and make it easy
to accidentally treat two host-controlled fields as authenticated. Add a
named resolver only after its source and lifecycle have been reviewed.

This pattern does not make every reference safe. `NodeName`, `HostIp`, Azure
identity selectors, and Kubernetes Service endpoints still need measured or
signed authority beyond the current request. Without that authority, their
resolvers remain unavailable and generation must fail rather than fall back to
shape validation.

Later goals extend `KataEnvRule` with operation and transform semantics:

```rust
pub struct KataEnvRule {
    pub matcher: KataEnvMatcher,
    pub required_on_create: bool,
    pub exec: KataExecEnvPolicy,
    pub transform: KataEnvTransform,
}

pub enum KataEnvMatcherExtension {
    IntegerRange { minimum: i64, maximum: Option<i64> },
    FiniteSet { values: Vec<String> },
    ExternalEndpoint,
    Re2 { pattern: String },
}

pub enum KataExecEnvPolicy {
    SameMatcher,
    Deny,
}

pub enum KataEnvTransform {
    None,
    SealedSecret,
}
```

The later extension may be folded into `KataEnvMatcher`; it is shown separately
to distinguish completed G1 representation work from future enforcement work.

Source provenance is not part of the enforcement rule when the matcher is
exact. PolicyGen may retain a compact internal origin such as `Image`,
`Workload`, `ReferencedObject`, or `Generated` to produce useful errors and
conformance reports. Unresolved runtime sources remain distinct only where they
select different matchers or Agent state.

### Dynamic family rules

Some kubelet-injected variable names are unavailable from Pod YAML, especially
Kubernetes Service variables. They cannot fit an exact-name map.

`EnvFamilyRules` is a separate, explicit compatibility mechanism:

```rust
pub struct KataEnvFamilyRule {
    pub name_pattern: String,
    pub matcher: KataEnvMatcher,
    pub required_on_create: bool,
    pub exec: KataExecEnvPolicy,
}
```

Requirements:

- family rules are generated only for a selected container that opts in;
- patterns are fully anchored;
- exact-name rules take precedence;
- zero matching family rules denies;
- more than one matching family rule denies;
- family rules cannot grant `SealedSecret`;
- family rules cannot authorize identity, tenant, shard, command, path, or
  secret selectors;
- generic `.*` and `.+` are rejected.

This follows the useful part of the C-ACI/VN2 model: environment rules are
attached to a selected container and carry requiredness. It intentionally does
not copy VN2's `value: ".+"` Azure identity rules.

## Generator behavior

### Source collection

PolicyGen first builds normalized value records rather than complete strings.
All generation-time-resolved inputs converge on `Exact`, regardless of their
original source. Compact source provenance may remain generator-internal for
diagnostics, but it does not create additional enforcement alternatives.

External values are always data. They are never parsed as PolicyGen markers.
During dual-schema migration, legacy `Env` emission must either escape the
reserved `$(` vocabulary or fail generation when an external value contains a
reserved marker.

### Effective environment construction

PolicyGen must reproduce the exact environment behavior of the pinned
Kubernetes and containerd versions used by the target release.

The implementation must be based on source and conformance fixtures, not an
assumed precedence list. At minimum the fixtures cover:

- image defaults;
- multiple `envFrom` sources;
- explicit `env`;
- repeated names across all sources;
- `envFrom.prefix`;
- invalid names;
- optional missing objects and keys;
- service variables;
- `$(VAR)` references to earlier, later, missing, and escaped variables;
- values containing one or more `=` characters.

During G1, the legacy whole-list, repeated-to-fixpoint substitution remains
unchanged so the new shadow representation cannot alter existing policy
behavior. Shadow rules conservatively retain declared `$(NAME)` references as
typed unresolved dependencies. A later compatibility phase must replace the
legacy expansion with behavior proven against the pinned kubelet
implementation, including ordering and escaping rules.

The final create contract contains unique names. PolicyGen emits the effective
value rule and may retain only consolidated diagnostic provenance outside the
enforcement data.

### Fail-closed handling of unresolved references

PolicyGen must classify every effective environment value before emitting a
policy:

1. **Generation-time exact:** the final value is available from measured policy
   inputs and is emitted as `Exact`.
2. **Implemented runtime resolver:** the source has a reviewed Agent/Rego
   resolver and is emitted as an authoritative typed runtime rule.
3. **Unsupported dynamic source:** the value cannot be established by either
   mechanism.

In strict mode, category 3 is a policy-generation error. PolicyGen must not
silently emit a placeholder, shape-only regex, or name-constrained wildcard.
The error identifies the workload, container, environment variable, reference
kind, and non-secret selector metadata needed to correct the workload. It must
not include Secret values or other resolved sensitive data. Generation fails
as a whole if any selected process contains an unsupported dynamic source, so
an apparently valid policy cannot omit the unsafe container or variable.

Legacy placeholder behavior may exist only behind an explicit compatibility
setting during migration. It is never selected implicitly, must produce a
prominent diagnostic for every widened variable, and must be unavailable to a
profile claiming strict or confidential-workload enforcement. Policies
generated in compatibility mode must carry a capability or metadata marker so
deployment tooling and audit output can distinguish them from fail-closed
policies.

The decision is per source, not a global disablement of downward-API
environment variables. Exact ConfigMap, Secret, label, annotation, namespace,
service-account, image, and literal values remain supported. Implemented typed
sources remain supported. Only references whose values cannot be established
with the required authority fail.

#### `resourceFieldRef`

PolicyGen may resolve a resource reference to `Exact` only when all of these
conditions hold:

- the policy input is the final admitted Pod object, or its provenance
  otherwise guarantees that no later admission defaulting can change the
  selected resources;
- the selected container is unambiguous (`containerName` names an existing
  container, or omission selects the container declaring the environment
  variable);
- the referenced request or limit is explicitly present;
- the resource and divisor are supported; and
- PolicyGen reproduces the pinned kubelet's `resource.Quantity` parsing,
  division, rounding, and output formatting exactly.

For example, an explicit `limits.cpu: 500m` with divisor `1m` can become the
exact value `500` after conformance tests prove matching kubelet behavior.

PolicyGen must fail closed rather than emit `$(resource-field)` when:

- the request or limit is absent and Kubernetes may derive the value from node
  allocatable resources;
- a named container or resource does not exist;
- the selector, quantity, or divisor is unsupported or invalid;
- admission defaulting may still change the value; or
- PolicyGen cannot prove byte-for-byte agreement with the pinned kubelet.

An Agent-side runtime implementation is a separate future option. It must bind
the selector to independently admitted or measured container resource state
and implement the same quantity semantics. Reading another host-controlled
field from the same request is not sufficient.

### ConfigMap and Secret references

- A resolved non-optional key becomes an exact rule required on create.
- An unresolved non-optional object or key fails generation.
- An unresolved optional object or key emits no required rule.
- `envFrom.prefix` is applied before name validation.
- Invalid names are handled the same way as the pinned kubelet behavior and are
  recorded in a generation diagnostic.
- Text containing `$(` remains literal data.

### Field references

#### `metadata.name`

Use `SandboxName`. The input value must equal the concrete sandbox name already
validated against the generated workload-name constraint and stored in policy
state.

For generated names this is consistency and pin-on-first-use, not independent
authentication.

#### `metadata.namespace`

If the namespace is present in trusted generation input, emit an exact rule.

If the namespace is absent and a namespace-derived environment variable is
requested, emit `SandboxNamespace`. Create authorization requires the
environment value to equal the admitted sandbox-namespace annotation and pins
that value as `namespace` state; exec resolves only from the pinned state. This
fallback is consistency and pin-on-first-use, not independent authentication.

#### `metadata.uid`

When generation input is an attested Pod object carrying `metadata.uid`, emit
an `Exact` rule for that UID. Do not grant runtime authority merely because the
value has UUID syntax.

Ordinary pre-deployment YAML has no Pod UID because the API server assigns it
after creation. For an explicit downward-API `metadata.uid` environment
reference in that input, emit typed `PodUid`. The first accepted create for a
process declaring that resolver must:

1. require a canonical lowercase UUID in
   `io.kubernetes.cri.sandbox-uid`;
2. require the environment value to equal that annotation;
3. pin the value as `pod_uid` policy state.

Every later relevant create must present the same annotation. Exec has no OCI
annotation and resolves only from `pod_uid` state. The fallback provides syntax
validation and cross-request consistency only; it must not be documented as an
authenticated Pod identity.

#### `status.podIP`

Prefer a relation to Agent-recorded sandbox network state. The implementation
must handle dual-stack and multiple addresses.

Before enforcing this relation, integration tests must confirm that the
relevant network state exists before every create path. If ordering cannot be
guaranteed, the compatibility mode is explicit pin-on-first-use with parsed IP
syntax, not a global IP regex.

#### `status.hostIP`

Treat as an explicitly opted-in parsed external address. Exclude protected
guest-internal/control ranges. This is not an authenticated host identity.

#### `spec.nodeName`

Treat as an explicitly opted-in DNS-1123 value. Syntax is insufficient when the
application uses node name as identity, authorization, path, command, tenant,
or shard input. Those uses must fail policy generation unless an exact/finite
trusted value is available.

#### `spec.serviceAccountName`

This value is derivable from Pod YAML, including the Kubernetes `default`
service-account behavior. Emit an exact rule.

#### labels and annotations

An existing value in generation input is exact.

A missing label or annotation must never become `$(todo-annotation)`. Follow
the pinned kubelet behavior and emit an exact empty value.

### Resource-field references

Retain:

- resource name;
- referenced container;
- divisor;
- source request/limit.

When the referenced quantity is present in the workload, calculate the exact
kubelet-formatted value and emit an exact rule.

When kubelet derives the value from node allocatable state or another
generation-time unknown, require an explicit typed numeric rule. The rule must
record the resource and divisor and may include a policy-author-approved upper
bound. Do not silently emit an unrestricted value.

The initial G1 slice records `spec.nodeName` and resource selectors as typed
`Runtime` values. It preserves the resource name, referenced container, and
divisor, but does not calculate resource quantities. Exact resolution and
quantity formatting remain deferred until kubelet conformance work proves the
effective value.

### Generated `HOSTNAME`

Do not authorize `HOSTNAME` through a global regex.

- If `spec.hostname` is set, derive its exact value.
- Otherwise bind it to the concrete sandbox/pod name.
- Model `subdomain` and `setHostnameAsFQDN` according to the pinned kubelet
  behavior.
- Mark it required on create and prohibited as a sealed-secret transform.

### Platform-injected variables

#### Kubernetes Service variables

If `enableServiceLinks: false`, do not emit general Service-family rules.

If compatibility requires Service variables:

- opt in per container;
- match only Kubernetes Service variable name families;
- parse protocols, IP addresses, and ports structurally;
- enforce numeric port range;
- exclude protected guest-internal/control destinations using Agent-known
  state where available;
- prohibit sealed-secret transformation;
- do not treat runtime captures as the Service allowlist.

Choosing among ordinary external destinations remains the workload's
responsibility.

#### Azure Workload Identity

Remove `AZURE_CLIENT_ID` and `AZURE_TENANT_ID` from global defaults.

These are identity and tenant selectors. Accept only:

- exact values available to PolicyGen before policy measurement;
- a finite approved set;
- exact/finite rules contributed by a measured platform fragment with a base
  policy ceiling over the exact variable names.

`AZURE_FEDERATED_TOKEN_FILE` is an exact path. `AZURE_AUTHORITY_HOST` is an
exact or finite approved authority set.

Do not copy C-ACI/VN2's optional `.+` identity rules as the secure design. They
are useful evidence of the same late-injection compatibility challenge, not
proof that arbitrary identities are security-equivalent.

#### Indexed Job

Generate `JOB_COMPLETION_INDEX` only for an Indexed Job. Use an integer rule
bounded to `0..spec.completions-1`. Scope it to the selected Job container.

#### Terminal

`TERM=xterm` is exact and generated only when the process requests a terminal.
It does not require a global regex.

## Rego enforcement

### Parsing

Use one helper that splits an entry at the first `=`:

```rego
parse_env(entry) := {"name": name, "value": value} if {
    eq := indexof(entry, "=")
    eq > 0
    name := substring(entry, 0, eq)
    value := substring(entry, eq + 1, -1)
}
```

Values may contain additional `=` characters.

Malformed names are denied. Bare entries without `=` are denied unless the
pinned OCI/containerd behavior proves a required compatibility case and the
design is updated explicitly.

### Duplicate rejection

Parse all input names and require:

```text
count(input entries) == count(distinct input names)
```

This is enabled in strict enforcement only after real containerd captures
confirm that legitimate requests are name-unique.

### Exact-name lookup

For an ordinary rule:

```text
rule := p_process.EnvRules[name]
```

Do not search a list of rules. A keyed object makes ambiguity structurally
impossible.

### Match obligations

| Matcher | Enforcement |
|---|---|
| `Exact` | byte equality |
| `Runtime` + `SandboxHostname` | substitute the hostname recorded from the accepted `CreateSandboxRequest`, then compare the complete template |
| `Runtime` + `SandboxName` | substitute concrete sandbox-name state, then compare the complete template |
| `Runtime` + `SandboxNamespace` | substitute policy-pinned/state namespace, then compare the complete template |
| `Runtime` + `PodUid` | on create, validate and substitute the CRI sandbox-UID annotation while pinning it; on later create/exec, require the pinned `pod_uid` value |
| `Runtime` + `PodIp` | substitute an address from Agent-recorded sandbox addresses |
| `Runtime` + `HostIp` | substitute a parsed address after protected-range exclusion |
| `Runtime` + `NodeName` | substitute an anchored DNS-1123 value under an explicit grant |
| `Runtime` + `ResourceField` | calculate or bound the recorded resource/container/divisor selector |
| `IntegerRange` | parsed integer and range |
| `FiniteSet` | exact membership |
| `ExternalEndpoint` | parsed protocol/address/port plus internal exclusion |
| `Re2` | fully anchored, explicitly reviewed pattern |

The existing `fragment_anchored` helper is reused for every Rego pattern.

### Create completeness

For create:

- every input entry must match its exact-name or one unambiguous family rule;
- every `required_on_create` exact-name rule must appear once;
- no duplicate input names are allowed;
- a family rule is never implicitly required unless policy data says so.

### Exec behavior

Create requiredness is not reused for exec.

An `ExecProcessRequest` may re-present a subset of the container's create-time
environment. Every presented entry must use a create rule whose exec policy is
`SameMatcher`, and it must satisfy the same exact or runtime-bound matcher.
Create-required entries may be omitted from exec.

PolicyGen uses `SameMatcher` by default for non-transform create rules to
preserve the current Kubernetes/containerd exec behavior. It uses `Deny` for
sealed-secret transform rules until an exec-specific secret lifecycle is
designed. An allowed exec command may later carry a separate exact-name rule map
if it needs environment authority not present in the container create policy.

Exec obtains concrete sandbox name and namespace from policy state. It must not
pass a policy regex as though it were a concrete substitution value.

Policy evaluates the `process.Env` field actually carried by the exec request.
It does not inspect argv for shell syntax and does not infer an environment
grant from `$NAME`, `${NAME}`, or `$(...)` text in a command argument.

### Legacy rules

During migration:

- old policy data continues through the old arms;
- for an environment name present in `EnvRules`, only the typed rule may
  authorize that name;
- legacy `Env` handling remains available only for names that have no typed
  rule, so one name cannot combine both paths to obtain the union of their
  authority;
- global Azure, Job, hostname, and terminal rules are removed when their typed
  producers are active;
- legacy placeholder arms are deleted after the compatibility period.

## Agent transformation contract

### Request scope

Post-authorization environment mutation is restricted to
`CreateContainerRequest`. The transform operates on the authorized OCI process
after measured CDI handling and before bundle setup/rustjail execution.

`ExecProcessRequest` is authorization-only for environment entries. Agent does
not unseal, substitute, or otherwise rewrite its `process.Env`. Other Agent RPCs
do not carry environment-transform authority.

### Authorization result

Policy authorization returns a transform plan that contains no plaintext:

```rust
pub struct EnvTransformGrant {
    pub name: String,
    pub authorized_value_digest: String,
    pub transform: EnvTransform,
}
```

The implementation may retain the exact sealed reference in guest memory
instead of a digest if required for direct comparison, but it must never expose
the value in logs, denial responses, or host-visible decision objects.

The grant is keyed semantically by variable name and exact authorized value,
not by environment-list index. CDI processing may insert entries before CDH
processing, so authorization-time indices are unstable.

### Sealed-secret processing

Agent unseals an entry only when:

1. the entry name matches a grant;
2. its current value is byte-identical to the value authorized for that grant;
3. the grant's transform is `SealedSecret`.

An environment family rule or regex rule cannot grant sealed-secret
transformation.

If an explicitly granted sealed secret cannot be unsealed, container creation
fails. Agent must not warn and continue with a success-shaped result.

### Plan binding

`assert_env_within_bounds` consults the transform plan. It must not authorize a
rewrite solely because the old value starts with `sealed.`.

CDI-added environment entries remain permitted only when their source CDI spec
has passed the existing measured-digest authorization.

## Migration plan

### Phase 0: Compatibility groundwork

Implement independently safe changes:

1. parse environment values at the first `=`;
2. escape literal Kubernetes names before regex construction;
3. make exec use concrete sandbox-name state;
4. remove unanchored sandbox-name environment matching;
5. reserve or escape legacy placeholder vocabulary in external values;
6. add kubelet/containerd environment conformance fixtures;
7. capture a workload where image and YAML environment use the same name.

**Exit criteria:** no policy-schema change; all existing tests pass; conformance
fixtures document current mismatches.

### Phase 1: Typed rules, end-to-end enforcement

Add `EnvRules` and `EnvFamilyRules` alongside legacy `Env`.

The first vertical slice supports:

- `Exact`, using byte equality;
- `Runtime` + `SandboxHostname`, using `sandbox_hostname` captured from the
  accepted `CreateSandboxRequest`;
- `Runtime` + `SandboxName`, using the admitted create annotation and the
  resulting pinned `sandbox_name` state for exec;
- `Runtime` + `SandboxNamespace`, using the admitted create annotation and the
  resulting pinned `namespace` state for exec;
- `Runtime` + `PodUid`, using a canonical UUID annotation during the first
  accepted create and pinned `pod_uid` state thereafter.

For a name present in `EnvRules`, typed evaluation is authoritative and failure
does not fall back to legacy `Env`, global regexes, or placeholder rules.
Names without typed rules continue through legacy handling during migration.
Do not yet enforce requiredness or duplicate rejection outside strict/shadow
mode.

The generator must emit a runtime `EnvRules` entry only for a source implemented
by this vertical slice. `PodIp`, `HostIp`, `NodeName`, `ResourceField`, and
workload `EnvironmentReference` currently retain their manifold-cc legacy
`Env` placeholders/templates and do not receive authoritative typed entries.
The internal source metadata may be retained for later implementation work, but
it must not alter authorization until a matching Agent-side resolver and
negative tests exist. This preservation is transitional compatibility behavior,
not the fail-closed target: strict generation must reject these sources unless
PolicyGen can reduce them to `Exact`.

Remove global identity/shard rules when their typed equivalents exist.

**Exit criteria:** positive tests accept the exact sandbox hostname, sandbox
name, namespace, and Pod UID for create and exec; negative tests reject
different values even if a legacy wildcard or placeholder would accept them;
later creates cannot change the pinned Pod UID; captures show every migrated
name has one typed authorization.

### Phase 2: Explicit Agent transforms

Return transform grants and bind CDH unsealing to exact rule/value authority.
Tighten plan binding and fail create on a granted-transform failure.

**Exit criteria:** an exact sealed reference succeeds; a different valid sealed
reference under the same variable name is denied; a `sealed.*` value admitted
by a non-transform rule remains opaque or is denied according to the explicit
rule.

### Phase 3: Create completeness and unique names

Enable:

- required create rules;
- duplicate-name rejection;
- exact effective-environment comparison.

Start with shadow diagnostics under `strict-policy`, then enforce after
compatibility evidence is clean.

**Exit criteria:** pinned Kubernetes/containerd fixtures and appliance captures
show no unexplained mismatch.

### Phase 4: Dynamic semantic bindings

Add:

- PodIP-to-Agent-network-state relation;
- resource-field calculation and bounded fallback;
- generated hostname/FQDN behavior;
- Service external-endpoint family;
- measured Azure identity fragment rules;
- bounded Indexed Job rules.

**Exit criteria:** each dynamic class has positive and security-boundary
negative tests.

### Phase 5: Remove legacy authority

Delete:

- marker-based `allow_var` arms;
- global identity, shard, hostname, and terminal regexes;
- `$(todo-annotation)`;
- the whole-argument `$(node-name)` bypass;
- legacy external-text marker interpretation.

**Exit criteria:** all generated policies use typed environment rules and the
legacy path cannot widen authority.

## Test plan

### Generator tests

- image literal containing `$(node-name)` remains literal;
- ConfigMap, Secret, label, and annotation values containing marker text remain
  literal;
- literal Kubernetes name `web.0` becomes `web\\.0` in regex context;
- values containing `=` round-trip;
- image/YAML duplicate-name precedence matches pinned containerd;
- multiple `envFrom` sources match pinned kubelet order and precedence;
- `envFrom.prefix` is applied;
- optional missing refs do not create required rules;
- non-optional missing refs fail generation;
- invalid `envFrom` names match kubelet behavior;
- `$(VAR)` ordering and `$$(` escaping match kubelet;
- `resourceFieldRef` retains resource, container, and divisor;
- explicit `resourceFieldRef` values are calculated exactly with pinned-kubelet
  quantity semantics;
- strict generation rejects missing resources, unknown containers, unsupported
  divisors, node-allocatable fallback, and post-generation admission defaulting;
- compatibility mode is explicit and reports every emitted
  `$(resource-field)` placeholder;
- `spec.hostname`, subdomain, and FQDN cases produce expected rules.

### Rego tests

- undeclared variable denied;
- missing required create variable denied;
- missing optional variable allowed;
- duplicate name denied;
- exact value containing `=` allowed;
- `metadata.name` must equal concrete sandbox name;
- create and exec use the same concrete sandbox identity;
- changing both a referenced source and its environment value cannot bypass
  the source's exact or anchored admission rule;
- namespace-derived env denied when policy namespace is unresolved;
- malformed Pod UID, environment/annotation disagreement, and later Pod UID changes denied;
- exec Pod UID denied before a relevant create establishes `pod_uid` state;
- attested Pod `metadata.uid` emitted and enforced as an exact value;
- arbitrary node name denied without explicit typed authority;
- arbitrary `resourceFieldRef` value denied even when its variable name is
  declared;
- a resource-field value differing from the exact generated calculation is
  denied on create and exec;
- Azure client and tenant injection denied;
- alternate Azure client and tenant denied;
- Job index outside completions denied;
- Service address in a protected guest-internal/control range denied;
- ordinary permitted external Service address allowed;
- more than one family rule match denies;
- family rules cannot authorize sealed transforms.

### Agent tests

- exact authorized sealed reference is unsealed;
- a different sealed reference under the same name is not unsealed;
- an ungranted `sealed.*` value is not transformed;
- transform matching survives CDI environment insertion;
- granted unseal failure fails create;
- plan-binding errors never expose environment values;
- duplicate post-authorization insertion is rejected;
- non-sealed value rewrite remains denied.

### Integration tests

- capture image/YAML duplicate-name behavior;
- capture `envFrom` ordering and prefix behavior;
- capture create and exec environment shapes;
- exercise generated-name Deployment;
- exercise namespace supplied through normal workload input;
- exercise dual-stack PodIP if supported;
- exercise Indexed Job;
- exercise Service links enabled and disabled;
- exercise Azure Workload Identity only with measured identity authority;
- confirm captures are never consumed by policy generation.

## C-ACI/VN2 reference

The C-ACI/OpenGCS model provides useful patterns:

- environment rules belong to one container;
- literal and RE2 strategies are distinct;
- regexes are automatically anchored;
- rules carry requiredness;
- create and exec commands use exact ordered arrays.

It does not provide a runtime environment-reference matcher. The hcsshim
framework evaluates either a whole `name=value` string or separate name and
value patterns using only `string` or `re2` strategies. It does not resolve a
value from another request field, OpenGCS metadata, or previously established
policy state. Platform rules and fragment parameters can contribute literal or
regex rules, but they do not add cross-field runtime relations.

The current VN2 generator also demonstrates unresolved compatibility problems:

- Kubernetes Service values use broad wildcard rules;
- Azure Workload Identity client and tenant IDs use optional `.+` rules;
- downward-API `fieldRef` values are emitted as `NAME=.*`; the source contains a
  comment acknowledging that wildcard behavior and a commented-out
  generation-time lookup attempt;
- `resourceFieldRef` is read from workload resources as a literal but does not
  establish a general runtime-reference mechanism.

This design adopts per-container typed rules and requiredness. It does not adopt
wildcard identity selectors.

Command authorization and environment authorization must not be reviewed as
independent security properties when the command interprets environment data.
C-ACI exact-matches each command argument and separately applies environment
literal or RE2 rules. It does not track data flow between them. Consequently,
an exact command such as `["/bin/sh", "-c", "$ACTION"]` combined with an
`ACTION=.*` rule authorizes the host to select arbitrary shell code. The same
issue applies to interpreters and applications that execute an environment
value, even without shell syntax.

Typed environment references close only the authority represented by their
resolver. Policy generation must reject or explicitly flag exec commands that
consume a wildcard environment value as code. A literal `$NAME` argument passed
directly to a non-interpreting executable is not expanded by `execve`, but it
must not be assumed safe when a shell, interpreter, entrypoint wrapper, or the
application itself interprets it.

Reference revisions:

- `Azure/azure-cli-extensions` at
  `b83265924dfe09f09de83636d0746e5b16e8d4b1`
- `microsoft/hcsshim` at
  `5eab3ce17fd710d44b14d9e9ae2d72fb04e23870`

## Implementation checklist

Every implementation change must identify the phase and checklist items it
completes.

- [x] G1 end-to-end `Exact`, `SandboxHostname`, `SandboxName`,
  `SandboxNamespace`, and pin-on-first-use `PodUid` enforcement.
- [x] G1a generator emits the initial `EnvRules` shadow representation.
- [x] G1b `CreateSandboxRequest` records accepted `sandbox_hostname` state.
- [x] G1c create and exec enforce typed rules without same-name legacy fallback.
- [ ] Phase 0 environment parser uses first `=`.
- [ ] Phase 0 object-name regex escaping.
- [ ] Phase 0 source-admission regexes are escaped, anchored, and no broader
  than the identity they establish.
- [x] Phase 0 create/exec concrete sandbox-name unification.
- [ ] Phase 0 external marker neutralization.
- [ ] Phase 0 kubelet/containerd conformance fixtures.
- [x] Phase 1 typed exact-name rules.
- [ ] Phase 1 explicit family rules.
- [x] Phase 1 no union of legacy and typed authority.
- [ ] Strict generation rejects unsupported dynamic environment references.
- [ ] Strict `resourceFieldRef` generation emits `Exact` only for selectors
  reproducible from final admitted resource values.
- [ ] Legacy environment-reference compatibility is explicit, diagnosed, and
  distinguishable in policy metadata.
- [ ] Phase 2 transform grants.
- [ ] Phase 2 CDH fail-closed behavior.
- [ ] Phase 2 plan-binding transform enforcement.
- [ ] Phase 3 create requiredness.
- [ ] Phase 3 duplicate-name rejection.
- [ ] Phase 4 dynamic semantic bindings.
- [ ] Phase 5 legacy marker/global-rule removal.

## Implementation file map

| Area | Expected change |
|---|---|
| `src/tools/genpolicy/src/pod.rs` | Normalize exact values, retain consolidated diagnostic provenance, preserve `envFrom` options, and preserve complete unresolved field/resource selectors |
| `src/tools/genpolicy/src/policy.rs` | Build the effective environment, emit typed rules, remove fixpoint substitution, and derive hostname rules |
| `src/tools/genpolicy/src/registry.rs` | Parse image environment at the first `=` and feed normalized exact values rather than opaque strings |
| `src/tools/genpolicy/src/yaml.rs` | Escape literal object names before regex construction |
| `src/tools/genpolicy/src/containerd.rs` | Emit typed rules for default/pause-container environment where applicable |
| `src/tools/genpolicy/rules.rego` | Parse, reject duplicates, perform keyed lookup, enforce create/exec cardinality, and emit transform decisions |
| `src/tools/genpolicy/genpolicy-settings.json` | Remove global identity, Job, hostname, and terminal regex authority; retain only deliberately scoped compatibility settings |
| `src/tools/genpolicy/tests/policy/` | Add generator/Rego conformance and adversarial fixtures |
| `src/agent/src/policy.rs` | Extend the policy decision interface to carry an internal transform result |
| `src/agent/src/rpc.rs` | Apply exact environment transform grants and fail closed on an authorized unseal failure |
| `src/agent/src/plan_binding.rs` | Bind post-authorization rewrites to exact grants instead of the `sealed.` prefix |
| `src/agent/src/confidential_data_hub/mod.rs` | Preserve strict unseal errors and avoid value disclosure |
| `src/agent/rustjail/src/container.rs` | Defensively reject duplicate effective names before installing the environment |

## Rollout and rollback

### Rollout gates

1. Phase 0 fixes land without changing the generated policy schema.
2. Typed rules are emitted with a new framework/policy capability so an older
   Agent cannot silently ignore them.
3. One-way typed authorization is exercised in tests and appliance captures
   before completeness is enforced.
4. Duplicate and requiredness failures are first observable through test-only
   or explicitly enabled diagnostics. There is no production fail-open mode.
5. Strict enforcement is enabled only after the pinned Kubernetes/containerd
   conformance suite and retained compatibility captures have no unexplained
   mismatch.
6. Legacy marker and global-regex authority is removed only after every
   supported dynamic source has a typed producer or an explicit fail-closed
   diagnostic.

### Rollback criteria

Rollback or disable the new capability before release if:

- PolicyGen and the pinned runtime disagree about legitimate effective
  environment names or values;
- an Agent version can accept typed policy while ignoring typed enforcement;
- transform grants can be replayed for another name or value;
- a supported create/exec lifecycle lacks the concrete state required by a
  matcher;
- denial diagnostics disclose Secret, sealed-reference, token, or identity
  values.

Rollback means selecting the previous policy framework capability before policy
measurement. It must not mean accepting a typed policy through legacy marker or
global-regex fallbacks.

## Unresolved implementation questions

These questions require source tracing or compatibility evidence during the
corresponding phase. They do not authorize a weaker default.

1. Which exact pinned kubelet functions and containerd paths define the final
   environment for each supported runtime path, and what is the smallest
   durable conformance-fixture format?
2. Should typed environment rules increment the existing policy framework
   version or use a separately declared capability?
3. What is the least invasive internal Agent interface for returning transform
   grants from Rego without making authorized values host-visible?
4. Is sandbox network state always populated before create-container
   authorization on every supported runtime path, including dual-stack?
5. What user-facing PolicyGen option enables compatibility rules for node name,
   host IP, Service variables, and bounded resource values without becoming a
   trusted deployment-time profile?
6. Do any legitimate containerd requests contain duplicate environment names
   or bare entries without `=` after all OCI mutations?
7. Which protected guest-internal/control address ranges and interfaces can be
   derived from Agent state rather than maintained as static regexes?

Implementation must not begin until this design has been reviewed.

The design was reviewed before implementation. The first implementation
produced only generator-side shadow data; review established that this did not
meet G1's security objective. G1 now requires the end-to-end Agent-side
enforcement described above before it is considered complete.
