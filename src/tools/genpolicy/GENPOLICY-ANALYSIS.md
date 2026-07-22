# genpolicy — Implementation & Policy-Enforcement Analysis

> **Status:** working notes (local, not tracked in git).
> **Branch analyzed:** `cc` (commit `0bc9fc12a`).
> **Scope:** How `genpolicy` translates Kubernetes YAML into a kata-agent policy, empirical
> testing of its YAML coverage, and a field-by-field comparison of what the generated policy
> actually enforces vs. the design intent in the "Confidential Kata Container – System Design
> Specification" ([SharePoint][design-doc]; sections 6.2.1 OCI Runtime Specification Derivation,
> 6.2.2 OCI config.json Security Implication, 6.2.3 Security Policy Design).
>
> [design-doc]: https://microsoft.sharepoint.com/:w:/t/ACCKata-CCConf.ContainerWG/cQr_7phbAO6HTL2zLutCSO7YEgUCQ-FiKFvUWr6RWqFe6AwdwQ

---

## 1. What genpolicy is

`genpolicy` (`src/tools/genpolicy/`) is a Rust CLI that:

1. Reads a Kubernetes YAML (Pod, Deployment, DaemonSet, Job, CronJob, ReplicaSet,
   ReplicationController, StatefulSet, Pod template, List).
2. Infers the container runtime configuration the kata-agent will receive.
3. Generates a kata-agent policy in **Open Policy Agent (Rego)** format.
4. gzip + base64-encodes it and appends it as the annotation
   `io.katacontainers.config.agent.policy` to the YAML.

At runtime the kata-agent enforces this policy on `CreateContainerRequest` /
`ExecProcessRequest` / etc., rejecting agent API calls inconsistent with the policy. This is
the core of the CoCo trust split between the (untrusted) shim/host and the (trusted) agent.

**Build:** `tools/packaging/kata-deploy/local-build/kata-deploy-binaries.sh --build=genpolicy`
(or `cargo build --release` after generating `src/version.rs` from `src/version.rs.in`).

---

## 2. How it is implemented

- **Hand-rolled types, not the versioned K8s crate.** Each resource has its own serde struct
  (`pod.rs` `PodSpec`/`Container`, `deployment.rs`, `job.rs`, …). It does **not** depend on
  `k8s-openapi`/`kube`. YAML is parsed with `serde_yaml 0.8`; the original document is retained
  in a `doc_mapping` (`serde_yaml::Value`) so the base64 policy can be re-appended.
- **Dispatch by `apiVersion` + `kind`** (`yaml.rs`) to the matching resource handler
  (trait with `get_containers` / `generate_policy`).
- **It predicts the OCI runtime spec the agent will receive** by merging three sources:
  1. **containerd/CRI defaults** — `containerd.rs` hardcodes `get_process`, `get_mounts`,
     default caps, default unix env (a replica of containerd's defaulting).
  2. **Container image config from the registry** — `registry.rs` pulls
     entrypoint/env/user/workingdir/layer digests.
  3. **User YAML fields** — command/args/env/securityContext/volumes/…
- **It also replicates specific API-server behaviors**: `name`/`generateName` → regex
  (`name_regex_from_meta`), GID → `AdditionalGids`, `allowPrivilegeEscalation` →
  `NoNewPrivileges`, etc.
- **Output**: Rego (`rules.rego` template + generated data), gzip+base64, into the policy
  annotation.
- **Tunable via `genpolicy-settings.json` + drop-in JSON patches** (`settings.rs`):
  `oci_version`, `request_defaults`, allowed commands, caps, env allowlists.

### Unknown-field handling (`serde_ignored`)

Deserialization uses `serde_ignored::deserialize` with a callback
(`handle_unused_field`, `yaml.rs:393`):

```rust
fn handle_unused_field(path: &str, silent_unsupported_fields: bool) {
    if !silent_unsupported_fields {
        panic!("Unsupported field: {path}");
    }
}
```

- **Default (strict):** any YAML field the hand-written structs do not model → **panic** (no
  policy produced).
- **`-s` / `--silent-unsupported-fields`:** downgrade to a silent drop (help text warns: *"not
  recommended unless you understand exactly how genpolicy works"*).

---

## 3. Fragility: raw YAML vs. runtime spec

genpolicy runs **client-side on the raw YAML, before the API server touches it**. The agent
enforces against the **fully-defaulted spec** delivered via kubelet → CRI → containerd.
Correctness depends on genpolicy's hand-maintained model matching that whole chain.

- The policy is **fail-closed**: if the runtime-delivered spec differs from what genpolicy
  predicted, the agent **rejects the request → container won't start**. A translation change is
  a *denial/availability* risk, not a silent security bypass.
- **Server-side defaulting changes or mutating admission webhooks** (injected env, mounts,
  sidecars, securityContext, sysctls) are invisible to genpolicy → mismatch → rejection.
- **Settings + drop-in patches** absorb *expected* variance (`request_defaults`, allowed
  commands, env allowlists) without recompiling. Anything structural (new defaulting semantics,
  new fields that reach the container spec) requires updating genpolicy itself
  (`containerd.rs` defaults, the resource structs, or settings) and regenerating policies.

---

## 4. Empirical test: complex Pod YAML

Built `genpolicy` (release) from branch `cc` and fed it a realistic complex Pod (init
container, projected/configMap/emptyDir/PVC volumes, probes, lifecycle hooks, security
contexts, sysctls, affinity, topology spread, DNS config, downward/secret/resource env), image
`busybox:1.36`.

### 4.1 Default mode hard-panics on unmodeled fields

Iteratively stripping each offending field, **10 distinct standard PodSpec fields** each crash
the tool (`yaml.rs:395 "Unsupported field: …"`):

| # | Field | Note |
|---|-------|------|
| 1 | `spec.subdomain` | DNS |
| 2 | `spec.automountServiceAccountToken` | |
| 3 | `spec.hostAliases` | /etc/hosts |
| 4 | `spec.securityContext.seccompProfile` | pod-level seccomp (**security**) |
| 5 | `spec.volumes[].configMap.defaultMode` | file perms |
| 6 | `spec.volumes[].projected.sources` | projected volumes |
| 7 | `spec.containers[].workingDir` | **runtime-affecting, very common** |
| 8 | `spec.containers[].env[].valueFrom.resourceFieldRef.containerName` | |
| 9 | `spec.containers[].securityContext.runAsNonRoot` | **security, very common** |
| 10 | `spec.containers[].lifecycle.postStart.httpGet` | postStart hook |

### 4.2 Second failure class: unresolved references

Even for *modeled* fields, genpolicy **panics** when it cannot resolve external references not
co-supplied in the input: `envFrom.configMapRef` (`pod.rs:810`), `secretKeyRef`
(`pod.rs:885`), `resourceFieldRef`.

### 4.3 Silent mode trades a crash for a latent mismatch

With `-s`, the 10 unsupported fields are silently dropped and (external refs removed) a policy
is generated (exit 0, ~18 KB). Decoding the gzip+base64 policy confirmed the dropped fields are
**absent**, with a concrete consequence:

- YAML `workingDir: /work` → dropped → policy has **`"Cwd": "/"`** (image default). At runtime
  kubelet sets `process.cwd=/work`, so the agent's exact-match check **fails → CreateContainer
  denied**.
- `runAsNonRoot`, `hostAliases`, `subdomain`, projected sources, `defaultMode`, `postStart`
  → all **absent** from the policy.
- Supported fields *were* reflected (e.g. sysctl `net.core.somaxconn`;
  `allowPrivilegeEscalation:false` → `NoNewPrivileges:true`).

**Root cause:** genpolicy maintains its own hand-written serde structs (not `k8s-openapi`), so
any field the authors did not model — or any future API-server field — either crashes the tool
(default) or is silently omitted (`-s`), yielding policy mismatches. `serde_ignored` gives
awareness of unmodeled fields, but the only responses are "panic" or "ignore".

---

## 5. Policy-enforcement cross-matrix (config.json field × design 6.2.2 × genpolicy)

Ground truth taken from the generated policy structs (`policy.rs`: `KataProcess`, `KataUser`,
`KataLinux`, `KataLinuxCapabilities`, `KataMount`) and the enforcement rules in `rules.rego`.

**Legend**
- **6.2.2 class:** `policy` = design says needs a policy check; `None` = host-hardening,
  MVP-deprioritized; `?` = open in the doc.
- **genpolicy:** `exact` = policy value must equal runtime value; `absent` =
  `allow_create_container_input` requires the field empty/null (fail-closed); `allowlist` =
  matched against rules; `—` = not modeled and not constrained.

| config.json field | 6.2.2 class | genpolicy | Rego / struct evidence | Verdict |
|---|---|---|---|---|
| `root.readonly` | None | **exact** | `p_oci.Root.Readonly == i_oci.Root.Readonly` (rego:102) | stricter than design |
| `mounts` (dest/type/opts/source) | policy | **exact, all-must-match** | `count(p_matches)==count(i_oci.Mounts)`, `check_mount` (807–810, 1102+) | ✅ aligned |
| `process.terminal` | policy | **exact** | `p_process.Terminal == i_process.Terminal` (838) | ✅ aligned |
| `process.env` | policy | **allowlist (string/regex)** | `allow_env`, per-var rules (931+) | ✅ aligned |
| `process.cwd` | policy | **exact** | `p_process.Cwd == i_process.Cwd` (822) | ⚠️ enforced but **value mis-derived** (ignores YAML `workingDir`; image-only) |
| `process.args` | policy | **exact (count+match)** | `allow_args` (884–920) | ✅ aligned |
| `process.user` uid/gid/addlGids | policy (umask) | **exact** | `allow_user` (867–877) | partial |
| `process.user.umask` | **policy** (flagged risky) | **—** | not in `KataUser` | ❌ **GAP** |
| `process.capabilities` | None | **exact (all 5 sets)** | `allow_caps` (1438) | stricter |
| `process.noNewPrivileges` | (implied) | **exact** | `==` (823) | ✅ |
| `process.selinuxLabel` | None | **absent** | `count(i_process.SelinuxLabel)==0` (150) | stricter (fail-closed) |
| `process.apparmorProfile` | None | **—** | not modeled, not required-absent | not enforced |
| `process.rlimits` | (n/a) | **—** | not modeled | not enforced |
| `hostname` | None | **—** | not checked | ✅ aligned (don't rely on hostname) |
| `namespaces` | None | **exact** (minus network/cgroup) | `allow_linux` normalize + compare | stricter |
| `uidMappings` / `gidMappings` | None | **absent** | `count(...UIDMappings/GIDMappings)==0` (138,142) | stricter → **breaks user namespaces** |
| `devices` | policy | **exact** | `allow_devices` / `allow_linux_devices` (110) | ✅ aligned |
| `cgroups` / Resources | None | **partly absent** | `Resources.Devices==0`, BlockIO/Network/Pids null (140,144–146) | stricter |
| `sysctl` | None | **exact** | `allow_linux_sysctl` (+ `Sysctl` map modeled) | stricter |
| `seccomp` | None | **absent** | `is_null(i_linux.Seccomp)` (147) | stricter → **breaks seccompProfile** |
| `rootfsPropagation` | None | **absent** | `count(...RootfsPropagation)==0` (141) | stricter |
| `maskedPaths` / `readonlyPaths` | None | **exact** | `allow_masked_paths` / `allow_readonly_paths` | stricter |
| `mountLabel` (SELinux) | None | **absent** | `count(i_linux.MountLabel)==0` (139) | stricter → **breaks SELinux mountLabel** |
| `personality` | ? | **—** | not modeled, not required-absent | ❌ potential **GAP** (LINUX32 exec change undetected) |
| `annotations` | policy | **allowlist** | `allow_anno` rejects unexpected keys (230–261) | ✅ aligned |
| `Hooks` / `Solaris` / `Windows` / `IntelRdt` | (n/a) | **absent** | `is_null(...)` (134–143) | defense-in-depth |

---

## 6. Findings

1. **genpolicy is broadly *stricter* than the 6.2.2 MVP triage.** Nearly every field the design
   marked "None / deprioritized" (seccomp, SELinux label, uid/gid mappings, rootfsPropagation,
   mountLabel, namespaces, masked/readonly paths, sysctl, `root.readonly`) is in fact
   **fail-closed** — the agent rejects the container unless the field is absent or exactly
   matches. The design's "defer host-hardening" was superseded by a stricter "forbid it
   entirely" implementation. Good for security.

2. **That strictness = compatibility breaks.** Because those fields are `absent`-required, a Pod
   using **seccompProfile, SELinux `mountLabel`, user namespaces (uid/gid mappings), or
   `rootfsPropagation`** is **denied at CreateContainer** even if genpolicy produced a policy
   (silent mode). This is the runtime-side counterpart to the strict-mode *parser* panics on
   `securityContext.seccompProfile`.

3. **Genuine enforcement gaps** (design says security-relevant; genpolicy neither pins nor
   forbids):
   - **`process.user.umask`** — 6.2.2 explicitly flags it (can flip R/O → R/W); not in
     `KataUser` → **unconstrained**.
   - **`process.cwd`** — enforced by exact match, but the policy value is derived **from the
     image only**, ignoring `spec.containers[].workingDir` (which has no field in the
     `Container` struct). Only `registry.rs` sets `Cwd` (`process.Cwd = docker_config.WorkingDir`,
     else `/`). Passes only when the workload doesn't set workingDir; otherwise mismatch/denial.
   - **`personality`** — neither modeled nor required-absent → a `LINUX32` personality that
     alters execution behavior would pass undetected.
   - **`apparmorProfile`, `rlimits`** — not modeled and not required-absent (lower security
     weight, but still un-pinned).

4. **Design vs. implementation inconsistency for seccomp/sysctl.** 6.2.2 classes both as "None",
   yet genpolicy **forbids** seccomp (absent-required) while it **models and exact-matches**
   sysctls — divergent from the design in both directions.

**Net:** the engine is well-aligned with 6.2.2 on the *execution-affecting* fields it was
designed to pin (mounts, env, args, devices, terminal, user ids, annotations), *stricter* than
the design on host-hardening fields (fail-closed absence), but has **four real gaps** —
`umask`, `cwd`-derivation (`workingDir`), `personality`, and `apparmor/rlimits` — where a
security-relevant OCI field is neither pinned nor forbidden.

---

## 7. Key source references

- CLI / config: `src/utils.rs` (`silent_unsupported_fields`, `raw_out`, `base64_out`,
  `containerd_socket_path`).
- YAML dispatch + unknown-field handling: `src/yaml.rs` (`serde_ignored::deserialize`,
  `handle_unused_field:393`, OCI derivation helpers).
- Container model (note: **no `workingDir` field**): `src/pod.rs` (`struct Container`).
- Defaulting replicas: `src/containerd.rs` (`get_process`, `get_mounts`, default caps/env).
- Image-derived values incl. `Cwd`: `src/registry.rs` (`process.Cwd = docker_config.WorkingDir`).
- Policy data model: `src/policy.rs` (`KataProcess`, `KataUser`, `KataLinux`,
  `KataLinuxCapabilities`, `KataMount`, `RequestDefaults`).
- Enforcement rules: `rules.rego` (`CreateContainerRequest`, `allow_create_container_input`,
  `allow_linux`, `allow_process(_common)`, `allow_user`, `allow_args`, `allow_env`,
  `allow_caps`, `allow_mount`/`check_mount`, `allow_anno`).
- Settings: `genpolicy-settings.json`, `src/settings.rs`, `drop-in-examples/`.

Design doc cross-reference: "Confidential Kata Container – System Design Specification"
([SharePoint](https://microsoft.sharepoint.com/:w:/t/ACCKata-CCConf.ContainerWG/cQr_7phbAO6HTL2zLutCSO7YEgUCQ-FiKFvUWr6RWqFe6AwdwQ)),
§6.2.1 (OCI Runtime Specification Derivation), §6.2.2 (OCI config.json Security Implication),
§6.2.3 (Security Policy Design).

---

## 8. Can genpolicy reuse the upstream YAML→OCI libraries instead of hand-rolled logic?

The current design hand-rolls the K8s input structs (`pod.rs` etc.) and replicates
containerd defaulting (`containerd.rs`). The question: could it instead reuse the *same*
libraries the API-server, kubelet, and containerd use? Answer: **partially, and it is worth
doing for the deterministic stages — but a pattern-based ("default policy") layer is
architecturally required and cannot be removed by any amount of library reuse.**

### 8.1 The translation is a three-stage Go chain, not one library

| Stage | Owner / Go lib | Reusable? | Effect if reused |
|-------|----------------|-----------|------------------|
| 1. YAML → defaulted/mutated PodSpec | api-server: `k8s.io/api`, `k8s.io/apimachinery` (`SetObjectDefaults_Pod`) | ✅ types + defaulting are real libs | Kills struct drift, unmodeled-field panics, wrong defaults |
| 1b. Mutating admission webhooks | dynamic, per-cluster | ❌ no library | Unknowable offline |
| 2. PodSpec → CRI ContainerConfig | kubelet: `pkg/kubelet/kuberuntime` (`makeMounts`, `makeEnvironmentVariables`) | ⚠️ internal, needs live cluster clients | Resolves Secrets/ConfigMaps, injects Service env + Downward API — **runtime state** |
| 3. CRI → OCI runtime spec | containerd: `containerd/oci`, `opencontainers/runtime-tools` | ✅ generator is a lib (but reads `config.toml` + platform) | Matches deterministic OCI assembly |

The "hard part" is **not** the struct definitions — it is that stage 2 depends on **live
cluster/node state** (Services present at pod-creation, pod IP / node name via Downward API,
resolved Secret/ConfigMap values, webhook injections). genpolicy runs **client-side, before
the cluster acts**, so those values are fundamentally unknowable and *must* be expressed as
regex/allowlist rules — which is exactly what the current "default policy" does.

### 8.2 What version-controlled worker nodes change

When the fleet's kubelet/containerd versions are **centrally controlled and pinned**, the
main objection to reusing the Go libraries — perpetual version drift per cluster — largely
disappears. genpolicy can pin its libraries to the **same controlled versions** the nodes run,
so the deterministic stages match *by construction*:

- **Fixes (now closed, not just mitigated):**
  - Stage-1 defaulting matches exactly (`k8s.io/api` pinned to the node's minor) → closes the
    "what if the API-server changes its defaulting" risk.
  - Stage-3 OCI assembly matches exactly (`containerd/oci` + the node's `config.toml`).
  - Parser/struct drift and the **unmodeled-field panic class (§4.1)** disappear — the schema
    version is known and complete.
  - Several §5 gaps become derivable from the *same* code the node uses: `cwd`/`workingDir`,
    `personality`, and defaulted `umask`.
- **Still NOT fixed (irreducible floor):** Service env vars, Downward API, resolved
  Secret/ConfigMap values, and mutating webhooks — these are functions of **runtime state**,
  not of the pinned library version, and remain regex/allowlist territory.

Residual operational requirement: genpolicy's pinned lib versions must be kept **in lockstep
with the controlled fleet version** — a single CI/release-pipeline bump, not per-cluster drift.

### 8.3 Options, lowest to highest effort

1. **Rust — swap input structs to `k8s-openapi`** *(lowest risk, recommended first step)*.
   genpolicy already uses the real `oci-spec` crate for OCI types and `k8s-cri` for CRI
   protobufs, but hand-rolls the **K8s input** types. Replacing those with the versioned,
   complete `k8s-openapi` crate directly eliminates the drift/unmodeled-field panics (§4.1).
   Gives **types + (de)serialization only** — *not* defaulting or CRI→OCI logic (those exist
   only in Go), so the derivation gaps in §5 remain.
2. **Go helper / sidecar** that links the pinned `k8s.io/api` + `containerd/oci` to emit the
   *predicted* OCI spec, consumed by the Rust policy generator. High fidelity for stages 1 & 3;
   adds a Go dependency; still needs the pattern layer for stage 2.
3. **Rewrite the derivation in Go** end-to-end against the controlled versions. Best
   deterministic fidelity; largest change; the kubelet-mapping / runtime-injection gaps still
   require the regex/allowlist default policy.

### 8.4 Recommendation

Given controlled node versions, adopt a **hybrid built around the pinned node libraries**:

1. **Input side** — parse with `k8s-openapi`/`k8s.io/api` pinned to the node's K8s version and
   run the real defaulting. Kills drift, panics, and wrong defaults.
2. **Deterministic OCI side** — reuse `containerd/oci` pinned to the node's containerd version,
   fed the node's `config.toml`, so derivable fields (incl. the §5 `cwd`/`personality`/`umask`
   gaps) come from the *same* code the node runs.
3. **Non-deterministic side** — keep the regex/allowlist default policy for Service env,
   Downward API, resolved Secrets/ConfigMaps, and webhook-injected content. This layer is an
   architectural requirement, not a shortcut.

Start with option 1: it is the cheapest, removes the largest correctness/robustness risk
(parser drift + panics), and is independent of the Go-side stages, so it can ship on its own.

### 8.5 Design §6.2.3 env-variable pipeline — confirmation and genpolicy mapping

Design §6.2.3 ("Security Policy Design") decomposes the environment-variable pipeline in its
**Container Default Policy** table by *Verifiable Source*, which is exactly the
deterministic-vs-runtime split §8 relies on. genpolicy implements this table almost verbatim.

**Design §6.2.3 env sources → genpolicy implementation**

| Design §6.2.3 source | Determinism | genpolicy implementation (verified) |
|----------------------|-------------|--------------------------------------|
| Default `PATH` (hard-coded) | deterministic | `containerd.rs:175` pushes the identical `PATH=/usr/local/sbin:...:/bin` string rule (via `get_default_unix_env`, used when image env is empty — `registry.rs:419-425`) |
| Image-specification env | deterministic | `registry.rs:420-422` copies `docker_config.Env` into `process.Env` as exact-string rules |
| `HOSTNAME` (hard-coded) | runtime | `policy.rs:903` pushes `HOSTNAME=$(host-name)` (string) **and** `^HOSTNAME=$(dns_label)$` regex (settings.json:347) |
| `TERM=xterm` (tty) | deterministic | `policy.rs:898` (only when `tty` set), plus `^TERM=xterm$` regex |
| K8S service injections `${NAME}_SERVICE_HOST/PORT`, `_PORT_<n>_<PROTO>_{ADDR,PORT,PROTO}` | **runtime (cluster state)** | `allow_env_regex` (settings.json:348-355), enforced by `rules.rego:974` `allow_var` (branch 3) after substituting `$(ipv4_a)`,`$(ip_p)`,`$(svc_name_downward_env)`,`$(dns_label)` |
| User `env` / `envFrom` (per §6.2.1, user policy) | deterministic (from YAML) | `pod.rs:get_env_variables` → exact-string rules; `env.valueFrom` resolved from ConfigMaps/Secrets/fieldRef, else the pod-IP `fieldRef` branch (`rules.rego` `allow_var` branch 4) |

**Enforcement path (verified):** `allow_env` requires **every** input env var to satisfy
`allow_var`, which succeeds via one of: (1) exact `p_var == i_var`; (2) `$(sandbox-name)`
substitution + regex; (3) a `request_defaults…allow_env_regex` entry with macro substitution;
(4) a pod-IP `fieldRef`. Macros defined in `common` (settings.json:265-268):
`ip_p=[0-9]{1,5}`, `ipv4_a=<dotted-quad>`, `svc_name_downward_env=[A-Z](?:[A-Z0-9_]{0,61}[A-Z0-9])?`,
`dns_label=[a-zA-Z0-9_\.\-]+`.

**genpolicy is stricter / more complete than the §6.2.3 draft:**
- Design listed `[A-Z0-9]+_SERVICE_HOST=.+` and marked "TODO: regex for IPv4/IPv6"; genpolicy
  **pins the value** to `$(ipv4_a)` and the port to `$(ip_p)`, closing that TODO.
- Design used the loose service-name class `[A-Z0-9]+`; genpolicy uses the tighter
  `svc_name_downward_env` (a valid K8s env-ified service name).
- genpolicy adds rules **not** present in §6.2.3: Azure Workload Identity
  (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_FEDERATED_TOKEN_FILE`, `AZURE_AUTHORITY_HOST`)
  and indexed-Job `JOB_COMPLETION_INDEX`.

**Implication for §8 (library reuse):** §6.2.3 *pre-classifies* the env pipeline along the exact
deterministic/non-deterministic boundary §8 identifies. Reusing K8s/containerd libraries (or
`k8s-openapi` + the image pull genpolicy already does) would derive the **deterministic** env
vars (default `PATH`, image env, user `env`) precisely; the **K8S service-injection + HOSTNAME**
vars are runtime/cluster-state and remain regex-allowlisted **by design** — the `allow_env_regex`
block is the direct realization of the §6.2.3 default-policy EnvRule table. Library reuse
therefore *scopes* the improvement; it does not remove the env-regex layer.

### 8.6 ConfigMap/Secret as env vars — value is pinned at generation time (a runtime-mismatch failure mode)

The one place configMap/secret **content** is embedded into the policy is when a value is
consumed as an **environment variable** (as opposed to a volume mount, which is delivered
content-blind via `CopyFile` — see SECURITY-ANALYSIS §10). genpolicy resolves the value at
generation time and bakes it into the container's env allow-list:

- `env.valueFrom.configMapKeyRef` / `secretKeyRef` → `config_map::get_value` /
  `secret::get_value` (`config_map.rs:41`, `pod.rs:685-694`).
- `envFrom.configMapRef` / `secretRef` → `get_key_value_pairs` / `get_values`
  (`config_map.rs:60`, `pod.rs:708-710`).

Each resolved `key=value` becomes an **exact-string** env rule, enforced at
`CreateContainerRequest` by `allow_env`/`allow_var` (`rules.rego:974`, `allow_process_common`
`rules.rego:817`). This has three consequences:

1. **Consistent with K8s semantics.** Env vars from configMaps/secrets are resolved **once at
   container start** and never updated on a running container (only *volume* mounts get live
   updates). Pinning the value in the (measured) policy therefore matches K8s behavior — a
   configMap "that must change at runtime" is only meaningful as a **volume**, which genpolicy
   delivers content-blind and does **not** flag (the `immutable` field is parsed at
   `config_map.rs:35`/`secret.rs:34` but **never read** — genpolicy makes no decision on it).

2. **Failure mode = runtime denial, not a generation-time warning.** If the configMap/secret
   value at **deploy** time differs from what genpolicy saw at **generation** time (the object
   was edited in between, or a stale/wrong copy was supplied to genpolicy), the embedded
   exact-string rule no longer matches the injected env var → `allow_env` fails →
   **`CreateContainerRequest` is DENIED** and the container will not start. genpolicy emits no
   warning about this coupling; the divergence surfaces only as an opaque runtime policy
   rejection.

3. **Resolution dependency at generation time.** The referenced configMap/secret must be
   provided to genpolicy (via `-c`/YAML) for `get_value` to resolve it; otherwise the value
   cannot be embedded and the same runtime mismatch/denial results. (This is the
   "unresolved references" failure class of §4.2, applied to env sources.)

**Practical guidance.** Values that are authenticated-but-not-secret and immutable-per-pod can
ride the env path safely (they are pinned in the measured policy). Anything that must **change
at runtime** must be a **volume** mount — accepting that its content is host-controlled and
unpinned (SECURITY-ANALYSIS §C.2) — and anything that must stay **confidential** must use
sealed secrets / CDH rather than a plain configMap/secret env or volume. Regenerate the policy
whenever a policy-embedded configMap/secret value changes, or the pod will be denied admission
by the agent.

---

## 9. Cross-reference: `az confcom acipolicygen` (ACI / Virtual Node) — complex-YAML robustness vs kata genpolicy

The ACI / AKS **Virtual Node** CCE policy is generated by a *different* tool — the **confcom Azure
CLI extension** (`az confcom acipolicygen`), developed in the open at
`Azure/azure-cli-extensions` → `src/confcom/azext_confcom/`. The generated policy plugs into the
hcsshim Rego framework (`microsoft/hcsshim` `pkg/securitypolicy/`), the ACI analogue of kata's
`rules.rego`. This section compares its complex-YAML handling with kata genpolicy (§4), because the
two tools front the same class of Kubernetes input but fail very differently. (See also
SECURITY-ANALYSIS §C.6.)

### 9.1 Parsing model — selective extraction, not schema deserialization

`load_policy_from_virtual_node_yaml_str` (`security_policy.py`) and its helpers pull **specific
known keys** via `case_insensitive_dict_get()` (`template_util.py:47`) rather than deserializing
the whole object into a typed model. Consequences:

- **Unknown / unmodeled fields are silently ignored** — there is no typed struct to reject them, so
  arbitrary extra fields never crash generation. This is the **opposite** of kata genpolicy's
  default mode, which *hard-panics* on any unmodeled field (§4.1). confcom therefore needs no
  `serde_ignored`-style escape hatch and no `--silent-unsupported-fields` flag.
- **Multi-document bundles and multiple workload kinds are supported.**
  `filter_non_pod_resources` accepts `Pod, Deployment, StatefulSet, DaemonSet, Job, CronJob,
  ReplicaSet` (`template_util.py:498`); `convert_to_pod_spec_helper` recursively unwraps
  `spec → template → jobTemplate` (`:478`) to reach the pod spec; `ConfigMap`/`Secret` docs in the
  same file are harvested for env resolution; other kinds (Service, etc.) are dropped.
- **initContainers** are parsed and policy-treated as containers (`security_policy.py`).
- **StatefulSet `volumeClaimTemplates`** are folded into volumes; `configMap/secret/downwardAPI/
  projected` mounts are force-`readOnly`.

### 9.2 Reference resolution — three real gaps on "complex" YAML

Where kata genpolicy resolves references against the YAML and pins values, confcom's
`process_env_vars_from_yaml` (`template_util.py:278`) has narrower coverage and lossier failure
modes:

1. **`envFrom` is not handled at all.** Only per-key `env[].valueFrom` (`configMapKeyRef`,
   `secretKeyRef`, `fieldRef`, `resourceFieldRef`) is processed — there is **no `envFrom` /
   bulk `configMapRef` / `secretRef` branch**. Env vars injected via `envFrom` are **silently
   omitted** from the policy, so at runtime they are present but not allow-listed →
   **CreateContainer denied**. This is the ACI counterpart to §8.6, but worse: a *silent drop*
   rather than a pinned-value mismatch.
2. **Un-inlined ConfigMap/Secret refs are interactive and lossy.** confcom resolves a ref only if
   the ConfigMap/Secret document is **inlined in the same YAML**
   (`get_value_from_configmap`/`get_value_from_secret`). Otherwise:
   - `configMapKeyRef` → **prompts** `"Would you like to use a wildcard value for ConfigMap X?
     (y/n)"`; `--approve-wildcards` → `.*` (re2); declining → env pinned to **empty string `""`**
     (guaranteed runtime mismatch → deny).
   - `secretKeyRef` → same prompt; declining → **hard exit** (`Secret needs a value…`).
   → In CI you **must** inline the referenced resources or pass `-y --approve-wildcards`, or
   generation stalls on stdin / exits non-zero.
3. **`fieldRef` → `.*` (re2 wildcard)** (pod IP/name are dynamic — reasonable but unpinned);
   cross-container `resourceFieldRef` is unsupported (hard error if `containerName` ≠ current).

### 9.3 Failure style — `sys.exit(1)`, not silent latent mismatch

confcom's `eprint` calls `sys.exit(1)` (`errors.py`), so missing `spec` / `containers` / `image`,
a declined secret wildcard, or an unsupported `resourceFieldRef` **terminate the whole run**. There
is no silent-mode analogue to kata's "trade a crash for a latent mismatch" (§4.3) — confcom either
tolerates the input (unknown fields), pins/wildcards it, or hard-exits. Values that *are* inlined
are pinned exactly (same regenerate-on-change constraint as §8.6).

### 9.4 Summary — the two generators fail in opposite directions

| Aspect | kata `genpolicy` (§4) | confcom `acipolicygen` |
|---|---|---|
| Unmodeled / unknown field | **hard panic** (default) or silent mismatch (silent mode) | **silently ignored** (tolerant) |
| Multi-kind / multi-doc bundle | per-resource (one YAML → policy) | Pod/Deployment/StatefulSet/DaemonSet/Job/CronJob/ReplicaSet, multi-doc |
| `env[].valueFrom` configMap/secret | resolved from YAML; else gap | resolved if inlined; else **prompt → wildcard / empty / exit** |
| `envFrom` (bulk) | handled | **silently dropped** → runtime deny |
| `fieldRef` | pinned/allow-listed | `.*` wildcard |
| Failure style | Rust **panic** / latent mismatch | **`sys.exit(1)`** or interactive stdin stall |
| Runtime-mutable value | denied unless regenerated (§8.6) | denied unless regenerated (same) |

**Net:** confcom "handles complex YAML" in that it does not choke on unknown fields and accepts
realistic multi-resource bundles — but it will **quietly under-generate** (`envFrom`) or
**stall / hard-exit** (un-inlined secrets) unless referenced ConfigMaps/Secrets are inlined and it
is run with `--approve-wildcards`. kata genpolicy is stricter up front (panics early) but does not
silently omit an env source. Both share the same *deploy-vs-generate divergence ⇒ denial* property
for pinned values (§8.6).

> **Source (public, not ADO):** `Azure/azure-cli-extensions`
> `src/confcom/azext_confcom/{security_policy.py,template_util.py,container.py,custom.py,errors.py}`;
> Rego templates in `azext_confcom/data/`; enforcement framework in `microsoft/hcsshim`
> `pkg/securitypolicy/`.
