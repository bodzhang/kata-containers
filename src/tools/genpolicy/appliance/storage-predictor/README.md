# storage-predictor

Predicts the Kata Agent `storages` and `devices` a workload would produce,
**without booting a VM**. It exists because the captured OCI `config.json`
records containerd's mount view, not the Agent `storages`/`devices` that the Kata
shim synthesizes downstream.

The report is audit-only. Policy generation consumes the final captured
`CreateContainerRequest`, whose OCI, storages, devices, request flags, and
rootfs identity were assembled by the real runtime-rs container-create path.
The predictor remains useful for diagnostics and focused no-VM testing of
storage handlers; it is not a compiler fallback.

**ConfigMap / Secret (Kata-CC), at a glance.** These are delivered two ways
depending on the deployment's `shared_fs`. Under **`shared_fs = "none"`** — the
default Kata-CC config — there is no virtio-fs: the shim copies the projected
files into the container rootfs via the agent `CopyFile` RPC and rewrites the
container OCI mount to a guest path `<cpath>/<cid>-<16 hex>-<name>`. With
**virtio-fs** the shim instead emits a `watchable-bind` `Storage` and rewrites
the mount to a `.../watchable/sandbox-<hash>-<name>` path (the agent copies the
files into a guest `tmpfs` and watches for updates). The appliance drives
**both** end to end: the predictor runs the shim's own volume handler under the
sourced `shared_fs` (so it reproduces whichever mechanism the deployment uses,
no VM), and the compiler pins the resulting OCI mount by **following the
predictor output** — wildcarding only the non-deterministic cid / UUID segments
and pinning the volume name, never re-encoding the shim's naming in a genpolicy
template. The `CopyFile` destinations are confined to the shared-fs domain and
authorized by the default `CopyFileRequest` rule. In all cases the file
*content* is host-supplied and unattested, so confidential secrets must come
through a trusted channel (KBS / CDH / guest-pull), not plain K8s Secrets. See
*ConfigMap / Secret: storage + mount pinning*.

## Design

The design rationale — what "storage" is in a Kata-CC UVM and who decides it, the
Confidential Containers threat model the storage policy addresses, and the design
choices that follow (dry-run the real shim mutation pipeline instead of
reimplementing it, skip the VM at the `Hypervisor` seam, feed the deployment's
Kata-CC configuration, keep the YAML authoritative for intent) — is in
[DESIGN.md](DESIGN.md#design).

## Usage

```
storage-predictor \
  --config <oci config.json> \
  --output <predicted.json> \
  --sid <sandbox-id> \
  --cid <container-id> \
  --emptydir-mode <mode> \
  [--disable-guest-empty-dir]
```

In the appliance, `scripts/predict_storages.py` drives it per captured container
and assembles `storages-devices-predicted.json`.

## Requirements

The predictor and compiler are pure transforms over the captured OCI bundle and
the workload YAML, but two paths carry **external tooling / configuration
dependencies** — deployment prerequisites, *not* policy gaps:

- **erofs / single-layer block rootfs diagnostics.** `--rootfs-mounts` accepts
  an explicitly supplied Kata mount artifact for focused handler tests and
  diagnostics. The authoritative appliance EROFS path does not generate or
  consume this artifact; it records the final request produced from the real
  containerd snapshotter mounts.
- **Kata-CC configuration.** `emptydir_mode` and the hypervisor `blockdev_info`
  are sourced from the deployment's `configuration.toml` via `--kata-config`
  (`GENPOLICY_KATA_CONFIG`), loaded raw (no hypervisor-binary validation);
  otherwise they fall back to `--block-driver`. The synthesized guest device address
  (`pci_path` / `scsi_addr` / `ccw_addr`) only needs a valid *shape* — the policy
  wildcards it via the base64url device id.

## Coverage

- Authoritative (real pure handlers, no reproduction): `shm`, `local`,
  `ephemeral`, `hugepage`, passthrough `default`.
- Shared-filesystem classes (`ConfigMap`, `Secret`, `projected`, `downwardAPI`,
  regular `hostPath`): under **virtio-fs**, via a reproduced `ShareFs`/`ShareFsMount`
  stub — watchable `ConfigMap`/`Secret` mounts yield a `watchable-bind` storage,
  others a shared mount with no storage (see "Drift risk"). Under
  **`shared_fs = "none"`** (the default Kata-CC config), the real shim's
  copy-to-rootfs branch runs no-VM (`share_fs = None`, `CopyFile` to the stub
  `Agent`), producing the rewritten OCI mount with no storage (see *ConfigMap /
  Secret: storage + mount pinning*).
- Raw block `volumeDevices[]` (block PVC): **supported** by Kata-CC and the
  generated policy — pinned **per container** (`spec.containers[].volumeDevices[]`)
  by `container_path`, driven from the workload YAML by the compiler (not the
  no-VM predictor, which cannot `stat` a real `S_IFBLK` device). The policy bounds
  the device *set / path* the host may present, **not** its identity or content:
  the bytes are host-supplied and **mutable/tamperable**, so the container code
  must treat a raw block volume as **untrusted input that can change underneath
  it** and protect it at the application layer (integrity/confidentiality). This
  is by design under the CoCo threat model — a raw block device is baseline-
  untrusted content — not a gap. (dm-verity root-hash pinning would make a
  read-only *data* volume trusted, but no runtime handler emits verity options
  for data volumes yet; see *Known gaps*.)
- Rootfs classes: **guest-pull**, **multi-layer erofs dm-verity**, and
  **single-layer dm-verity block** are all predicted and pinned (see *Rootfs
  prediction*). **Nydus rootfs is out of scope** (an excluded path, not a gap):
  `NydusRootfs` shares a host-prepared nydus bootstrap + blobs into the guest
  over virtio-fs (`NydusShareFs`) — the *host* supplies the rootfs content, which
  is incompatible with the confidential trust model (the image must be pulled and
  verified **inside** the TEE via guest-pull, or pinned by a dm-verity root hash).
  A CC deployment therefore never routes its rootfs through `NydusRootfs`, so it
  is deliberately not predicted.

## Comparing policy inputs

The report is an audit artifact for comparing predicted storage behavior with
the final captured `CreateContainerRequest`. The policy compiler does not read
it: the captured request is authoritative for OCI, storages, devices, request
flags, and rootfs identity.

### Rootfs: dm-verity pinning (erofs multi-layer and single-layer block)

The compiler records dm-verity **root hashes** in each container's synthetic
`dmverity-roothashes` marker storage, covering two rootfs shapes:

- **multi-layer erofs**: each read-only **lower** layer is pinned by its root
  hash; the writable `ext4` upper is allowed by shape.
- **single-layer block**: one verity-protected block device mounted read-only as
  the container rootfs (`BlockRootfs`), pinned by its root hash. It is
  distinguished from an erofs lower by the absence of the `X-kata.multi-layer`
  marker, and allowed by a dedicated `rules.rego` clause.

A coverage gate fails generation if any dm-verity-enabled rootfs storage lacks a
root hash (it would fail closed at runtime). Both shapes are counted out of the
`allow_storages` balance (like guest pull) since they are validated by dedicated
clauses rather than `p_storages`. Legacy `genpolicy` emits no rootfs storages at
all, so verity-protected containers fail closed under it — this is a capability
the drive adds.

The single-layer path reuses the shim's own dm-verity translation
(`kata_types::gpt_disk::extract_dmverity_annotation` /
`parse_dmverity_metadata_file` / `generate_dmverity_options`): `BlockRootfs` now
honors the `X-containerd.dmverity` mount annotation and emits the same
`X-kata.dmverity.*` storage options the erofs path does, so the predictor
reproduces it with no VM (see the `dry_run_single_layer_dmverity_emits_roothash`
test).


### Image references must be digest-pinned

Every appliance rootfs solution (erofs dm-verity, single-layer dm-verity, guest
pull) exists to bind the generated policy to the **workload author's declared
image**. dm-verity pins the layer *bytes* and guest pull pins the image
*reference*, but that only faithfully encodes intent if the manifest names the
image by digest: a mutable tag (`nginx:1.27`) can be repointed by whoever
controls the registry, so it cannot specify which image the author meant. The
appliance enforces this at the **input YAML** — the artifact it processes and
annotates — in `scripts/submit_workload.py` (`validate_image_references`), which
rejects any container (init / regular / ephemeral, across Pod and the workload
kinds) whose `image:` is not a `name@sha256:<digest>` reference, before the
workload is ever run or captured. The generated policy therefore only ever pins
digest-anchored images.

### Rootfs: guest-pull image pinning

For the mainstream CoCo rootfs (guest pull), the predictor reuses the shim's own
`adjust_rootfs_mounts` to synthesize the guest-pull `KataVirtualVolume` and runs
it through the real `handler_rootfs` with no `ShareFs` (`--guest-pull-rootfs`;
the appliance selects this through the guest-pull profile). The resulting `image_guest_pull`
`Storage` carries `source` = the image reference from
`io.kubernetes.cri.image-name` (digest-pinned, per above). The compiler collects
each container's reference into its synthetic `guest-pull-images` marker, and
the `rules.rego` `image_guest_pull` clause pins the pulled image to that marker.
A missing marker fails closed. The huge, non-deterministic `driver_options`
metadata blob is intentionally not pinned; the image reference is the
security-relevant field (the guest pulls and verifies it by digest inside the
TEE).

### Volume storages: templated injection

Each container's predicted `volumes[].storages` are injected into
`ContainerPolicy.storages`, keyed by CRI container name (the predictor emits
`container_name` for the mapping). Concrete guest paths are re-templated to the
policy variables that `rules.rego`'s `allow_storage` clauses substitute at
enforcement, with literal file names regex-escaped and anchored so each storage
is pinned:

| Class | `fs_type` | Templated `mount_point` | Clause |
|---|---|---|---|
| ephemeral emptyDir | `tmpfs` | `^/run/kata-containers/sandbox/ephemeral/<file>$` | `tmpfs` |
| local emptyDir | `local` | `^$(cpath)/$(sandbox-id)/rootfs/local/<file>$` | `local` |
| hugepage emptyDir | `hugetlbfs` | `^/run/kata-containers/sandbox/ephemeral/<file>$` | `hugetlbfs` (added) |
| watchable configMap/secret/projected/downwardAPI | `bind` | `^$(cpath)/watchable/sandbox-[0-9a-f]{8}-<name>$` | `bind` |
| block-encrypted / block-plain emptyDir | `ext4` | `$(spath)/$(b64_device_id)` | `blk` / `scsi` device-id |

The block emptyDir row is the one device-backed volume the compiler drives. The
predictor models it no-VM (the dry-run device manager plus the synthesized
PCI/SCSI address — see *Dry-run block device address synthesis*), emitting a
virtio-blk/scsi `Storage` whose `driver_options` carry `create_filesystem` (plus
`encryption_key=ephemeral` when encrypted). The compiler recognizes that gate and
templates it exactly like legacy genpolicy's `emptyDir_encrypted` /
`emptyDir_plain` settings: the policy `p_storage` carries an **empty** `driver`
and `source` (the shared `rules.rego` `allow_storage with blk`/`with scsi`
clauses match by the runtime input driver and wildcard the device address), the
`mount_point` becomes the device-id template `$(spath)/$(b64_device_id)`, and
`driver_options`, `fstype`, `fs_group`, `options` and `shared` are pinned
exactly. `fs_group` mirrors the pod `securityContext.fsGroup` (the emptyDir
directory GID) so the agent's exact-equality check passes.

The watchable case deliberately does **not** reuse genpolicy's `$(sfprefix)`
(`<bundle-id>-[a-z0-9]{16}-`): runtime-rs names the shared file
`sandbox-<8 hex>-<name>` via a random UUID segment
(`share_fs_volume::generate_mount_path`), so the compiler wildcards the hash as
`[0-9a-f]{8}` and pins the escaped name, and keeps the real `watchable-bind`
driver (not the legacy `local`). Legacy genpolicy's configMap policy therefore
does not match runtime-rs — another reason the drive is predictor-authoritative.

### ConfigMap / Secret: storage + mount pinning

A ConfigMap/Secret (also projected/downwardAPI) is delivered by one of two shim
mechanisms depending on the sourced `shared_fs`, and the appliance drives both.
The predictor runs the shim's own `handler_volumes` with the deployment's
`shared_fs`, so it reproduces the exact mechanism no-VM; the compiler then pins
the resulting OCI mount by **following the predictor output** (wildcarding only
the non-deterministic segments) rather than re-encoding the shim's naming in a
genpolicy template — the same drift-avoidance rationale as the rest of the drive.

- **`shared_fs = "none"` (default Kata-CC).** There is no `ShareFs`, so the shim
  runs `ShareFsVolume::new`'s `None` branch: it computes a deterministic guest
  path `<cpath>/<cid>-<16 hex>-<dest_base>` (`generate_guest_path`), copies the
  projected files there via the agent `CopyFile` RPC, and sets that path as the
  container OCI mount `source` (`type = bind`), emitting **no `Storage`**. In the
  predictor this whole branch runs with no VM: `VolumeManager` and
  `generate_guest_path` are pure host-side, and the `CopyFile` calls hit the stub
  `Agent` (which returns `Ok` — the shim only needs the call to succeed to finish
  rewriting the mount). The compiler templates the mount as
  `^$(cpath)/$(bundle-id)-[0-9a-f]{16}-<dest_base>$` — `$(cpath)` / `$(bundle-id)`
  are shared `rules.rego` substitutions (the cid becomes the per-instance
  container id at enforcement), `[0-9a-f]{16}` is the *actual* hex pattern the
  shim emits (tighter than legacy genpolicy's `[a-z0-9]{16}`), and `<dest_base>`
  is pinned. The matching `CopyFile` destinations are confined to the shared-fs
  domain and authorized by the default `request_defaults.CopyFileRequest`
  (`["$(sfprefix)"]`) rule; no `CopyFile` rule generation is required.

- **virtio-fs.** The shim emits a `watchable-bind` `Storage` (source + mount_point)
  **and** rewrites the OCI mount `source` from the captured runc host bind path
  (`/var/lib/kubelet/.../kubernetes.io~configmap/...`) to the watchable guest path
  (`.../watchable/sandbox-<8 hex>-<name>`). Both are needed because the agent
  checks the `storages` list (`allow_storages`) **and** each OCI mount
  (`allow_mount`). The predictor emits both (via `handler_volumes` / `map_mount`);
  the compiler injects the storage (`template_volume_storage`) and the mount
  (`template_volume_mount`), templating the mount source the same way as the
  storage `mount_point` — `^$(cpath)/watchable/sandbox-[0-9a-f]{8}-<name>$` — so
  `allow_mount` (`check_mount` → `mount_source_allows`, substituting `$(cpath)`)
  matches, and `allow_mount` clause 2 additionally binds the mount to the
  `watchable-bind` storage's `mount_point`. **No `CopyFile` rule is needed here**:
  the agent's `BindWatcher` copies the files into a guest `tmpfs` *internally*,
  with no `CopyFile` ttRPC.

Before this drive, the compiler's `normalize_mounts` **failed** on the
dynamically-destined ConfigMap/Secret bind mount (no static template existed) and
*no policy was generated at all*; the predictor already emitted the correct
mount, but the compiler ignored it.

**Content is host-supplied and unattested** in every path — the policy pins the
storage/mount *shape*, never the file bytes — so under CoCo a ConfigMap/Secret is
untrusted input; deliver confidential secrets through a trusted channel (KBS /
CDH / guest-pull), not plain K8s Secret/ConfigMap.

### Devices: `volumeDevices` and VFIO GPU (pinned from the YAML)

Device *intent* comes from the workload YAML, not the no-VM predictor, and is
pinned **per container**, at parity with legacy genpolicy (no predictor or shim
change):

- **Raw block `volumeDevices[]`.** The compiler emits one
  `agent::Device{container_path}` per declared `spec.containers[].volumeDevices[]`,
  matched by the `rules.rego` `allow_volume_devices` clause — bounding the device
  set/path, not content (see *Coverage*).
- **NVIDIA passthrough GPU (VFIO).** The compiler counts `nvidia.com/pgpu` limits
  per container and emits one VFIO `agent::Device{container_path=<vfio prefix>,
  type, vm_path=""}` per GPU plus the CDI-annotation `runtime_anno_pattern`,
  matched by the `rules.rego` `allow_vfio_devices` clause (device number ↔ CDI
  annotation correlation, PCI-address regex).

### Coverage gate

Storage classes the compiler cannot yet template are logged and omitted by
default; the container then fails closed at runtime, exactly as it does without a
predicted report (no silent loosening). Pass `--strict-storage-coverage true`
(or set `STRICT_STORAGE_COVERAGE=1` in the appliance entrypoint) to make an
unsupported class a hard generation error instead — the fail-closed-at-generation
choice for operators who want to guarantee full coverage.

### Rootfs: per-container image identity

Rootfs identity is always bound to one container policy for all three
mechanisms: multi-layer erofs dm-verity, single-layer dm-verity block, and guest
pull. The compiler injects each workload container's own identity as a synthetic
marker storage in its `ContainerPolicy.storages`: `dmverity-roothashes` carries
that container's root hashes and `guest-pull-images` carries its image digests.
The pod-level `policy_data.dmverity.allowed_roothashes` and
`policy_data.guest_pull.allowed_images` fields remain empty and cannot authorize
a runtime storage.

The markers are excluded from the shared `allow_storages` count balance because
the Agent never sends them. `rules.rego` requires the runtime rootfs identity to
match a marker in that container policy; a missing marker, a different
container's identity, or a populated legacy global field cannot authorize it.
The Agent is unaffected and still emits the same `X-kata.dmverity.*` or
`image_guest_pull` storage. Layer ordering and multiplicity are matched by set
membership, so the binding scopes identity per container but does not enforce
layer order.

The sandbox/pause container has no workload container-name key and receives no
marker. It uses the trusted built-in `/pause_bundle` from the attested guest
image rather than a workload rootfs identity.

## Drift risk and mitigation

Unlike the volume handlers, the share-fs path cannot be reused as-is: the real
`VirtiofsShareMount` is entangled with virtiofsd/hypervisor setup and performs a
real host bind mount, which is incompatible with the no-VM design. The stub
therefore *reproduces* `VirtiofsShareMount::share_volume`
(`runtime-rs/crates/resource/src/share_fs/virtio_fs_share_mount.rs`).

Reused directly from the shim (kept aligned automatically):

- guest path — `resource::share_fs::do_get_guest_path` (same result as
  `share_to_guest`, without the mount);
- watchable detection — `kata_types::k8s::is_watchable_mount`;
- shared-dir root — `kata_guest_share_dir()` and `PASSTHROUGH_FS_DIR`.

Mirrored rather than reused (the drift surface):

- the constants `watchable` and `watchable-bind` (private upstream);
- the ~15-line `share_volume` control flow that assembles the `watchable-bind`
  `Storage`.

Residual risk:

- Security-relevant `Storage` fields (`driver`, `fs_type`, `options`) are exact.
  Path strings are policy-generalized by the compiler when injected (the random
  `sandbox-<8 hex>-<name>` component is wildcarded to `[0-9a-f]{8}` and the name
  pinned; see *Driving policy generation*), so the non-deterministic hash does
  not break enforcement.
- If upstream renames the constants or changes `share_volume`'s storage shape,
  the stub diverges silently.

Mitigation options (not yet implemented):

- Make the two constants public in `virtio_fs_share_mount.rs` and import them.
- Upstream a side-effect-free `predict_share_volume` helper in `resource` and call
  it directly, removing the reproduction entirely.
- Add an alignment test that fails if the upstream storage shape changes.

## Known gaps

**Known gaps** are narrowed to two kinds — a missing enforcement *capability* and
*fidelity assumptions* where the no-VM prediction could diverge from a real CC
run. Tooling/config prerequisites are in *Requirements*; out-of-scope paths
(nydus rootfs, raw block *content*, host DoS, side channels) are in *Coverage* /
the [threat model](DESIGN.md#threat-model-the-storage-policy-addresses). Items *enforced at parity* — raw `volumeDevices[]`, VFIO/NVIDIA
GPU (see *Devices*), and block emptyDir (see *Volume storages*) — are not gaps
and are not repeated here.

### Missing enforcement capability

- **dm-verity pinning of read-only *data* block volumes.** Raw block
  `volumeDevices[]` are pinned only by `container_path` (bounding the device
  set/path; see *Coverage* / *Devices*), so a host can swap a read-only data
  volume for a different device and the policy allows it. Making such volumes
  dm-verity-pinned (so a swap is *denied*) is the security-meaningful follow-up,
  but it is **blocked upstream, not by the appliance**: no runtime volume handler
  emits `X-kata.dmverity.*` for a data volume (the `KataVirtualVolume.dm_verity`
  field is unused), and `is_block_volume` requires a real `S_IFBLK` device the
  no-VM predictor cannot reproduce. Under the CoCo threat model raw block content
  is already treated as untrusted, so this raises the bar rather than closing an
  active hole.

### Fidelity assumptions (could diverge from a real CC run)

- **Runc-captured bundle vs the kata handler.** The predictor consumes
  containerd's OCI bundle captured from the **runc** handler, assuming
  CRI-equivalence of the container mount list — containerd builds it from the
  runtime-agnostic CRI `ContainerConfig`, and the kata handler runs the same
  `handler_volumes` over the same bundle (see
  `virt_container/.../container_manager/container.rs`). Residual,
  non-repo-verifiable risk: a containerd kata-handler-specific spec option that
  adds/removes/retypes a container mount. An authoritative capture of the
  kata-handler bundle (or the CRI `ContainerConfig`) would close it. Device
  requests are unaffected — the device set is pinned from the YAML, not the
  captured spec.
- **Live host mount-state coupling (`update_ephemeral_storage_type`).** To
  classify an emptyDir as `ephemeral` (tmpfs) vs `local`, the predictor reuses the
  shim's `update_ephemeral_storage_type`, which inspects the **live host mount
  table** (`mountinfo`/`stat`) — so it is currently run co-located with the
  capture, while the emptyDir host dirs still exist. **This is an implementation
  coupling, not an inherent requirement**: the classification intent is already in
  the workload YAML (`emptyDir.medium: Memory` → tmpfs) and in the captured mount
  source, so deriving it from the YAML / captured metadata would remove the
  "volumes still mounted" assumption. It affects only disk-vs-memory emptyDir
  classification — **rootfs and device-set prediction do not depend on live volume
  state** (rootfs from the captured `rootfs_mounts`, device set from the YAML).
- **virtio-fs ConfigMap/Secret with > 8 files.** `is_watchable_mount` caps
  "watchable" at 8 files; above that the shim emits a plain `virtio-fs-mount` with
  no `Storage` rather than `watchable-bind`. The predictor classifies by the
  **live host file count**, so this one class depends on capture fidelity.
  (`block_device_discard_supported` is likewise left false; it only affects the
  e2e-only block-volume path.)
- **Share-fs reproduction drift** (see *Drift risk*): the `watchable-bind`
  `share_volume` path is *mirrored* rather than reused, so an upstream
  storage-shape change could diverge silently until an alignment test exists.

## Rootfs prediction (design)

The rootfs is the one storage the appliance cannot capture from the runc bundle.
How the predictor reproduces it with no VM — guest-pull digest pinning,
multi-layer and single-layer erofs/block dm-verity root-hash pinning, and the
dry-run block-device address synthesis — is in
[DESIGN.md](DESIGN.md#rootfs-prediction-design).

## Validation

Because the emptyDir disk-vs-memory classification currently depends on live host
mount state (see *Known gaps: fidelity assumptions*), the authoritative
validation of that path is `make e2e`. `make validate` exercises the unit tests
and the offline transform path (`tests/predict.rs`, `tests/test_predict_storages.py`).
