package agent_policy

# Tests for predicted volume-storage injection: the policy compiler templates
# each container's ephemeral/local volume storages into p_storages, and these
# must be accepted by the rules.rego allow_storages / allow_storage clauses when
# matched against the runtime CreateContainerRequest storages. Run via
# `opa test`.
#
# As in erofs_dmverity_test.rego, provide a default policy_data (typed `any` via
# json.unmarshal so rules.rego's other policy_data.* refs type-check) and
# override it per-test with `with`. common.cpath mirrors genpolicy-settings.json.
policy_data := json.unmarshal(`{
	"common": {
		"cpath": "/run/kata-containers/shared/containers(?:/passthrough)?",
		"sfprefix": "^$(cpath)/(watchable/)?$(bundle-id)-[a-z0-9]{16}-",
		"spath": "/run/kata-containers/sandbox/storage"
	},
	"dmverity": {"allowed_roothashes": []}
}`)

sandbox_id := "aaaabbbbccccdddd"

# Runtime i_storage for an ephemeral emptyDir (tmpfs), as produced by the shim's
# ephemeral_volume handler.
ephemeral_runtime(file) := {
	"driver": "ephemeral", "driver_options": [], "source": "tmpfs",
	"fstype": "tmpfs", "fs_group": null, "shared": false, "options": [],
	"mount_point": concat("", ["/run/kata-containers/sandbox/ephemeral/", file]),
}

# Templated p_storage the compiler emits for that ephemeral volume.
ephemeral_policy(file) := {
	"driver": "ephemeral", "driver_options": [], "source": "tmpfs",
	"fstype": "tmpfs", "fs_group": null, "shared": false, "options": [],
	"mount_point": concat("", ["^/run/kata-containers/sandbox/ephemeral/", file, "$"]),
}

# Runtime i_storage for a local emptyDir, as produced by the shim's local_volume
# handler (path carries the sandbox id).
local_runtime(file) := {
	"driver": "local", "driver_options": [], "source": "local",
	"fstype": "local", "fs_group": null, "shared": false,
	"options": ["mode=0777"],
	"mount_point": concat("", [
		"/run/kata-containers/shared/containers/passthrough/",
		sandbox_id, "/rootfs/local/", file,
	]),
}

# Templated p_storage the compiler emits for that local volume.
local_policy(file) := {
	"driver": "local", "driver_options": [], "source": "local",
	"fstype": "local", "fs_group": null, "shared": false,
	"options": ["mode=0777"],
	"mount_point": concat("", ["^$(cpath)/$(sandbox-id)/rootfs/local/", file, "$"]),
}

# Runtime i_storage for a watchable configMap/secret bind, as produced by the
# shim's virtio_fs_share_mount handler. The shared file is named
# "sandbox-<8 hex>-<name>" (a random UUID segment).
watchable_runtime(name) := {
	"driver": "watchable-bind", "driver_options": [], "fstype": "bind",
	"fs_group": null, "shared": false, "options": ["ro"],
	"source": concat("", [
		"/run/kata-containers/shared/containers/passthrough/sandbox-86d776af-", name,
	]),
	"mount_point": concat("", [
		"/run/kata-containers/shared/containers/passthrough/watchable/sandbox-86d776af-", name,
	]),
}

# Templated p_storage the compiler emits: the 8-hex hash is a wildcard, the name
# is pinned. source matches allow_storage_source clause 2, mount_point the bind
# allow_mount_point clause (both substitute $(cpath)).
watchable_policy(name) := {
	"driver": "watchable-bind", "driver_options": [], "fstype": "bind",
	"fs_group": null, "shared": false, "options": ["ro"],
	"source": concat("", ["^$(cpath)/sandbox-[0-9a-f]{8}-", name, "$"]),
	"mount_point": concat("", ["^$(cpath)/watchable/sandbox-[0-9a-f]{8}-", name, "$"]),
}

# Runtime i_storage for a hugepage-backed emptyDir (hugetlbfs), guest-local under
# the ephemeral path.
hugepage_runtime(file) := {
	"driver": "ephemeral", "driver_options": [], "source": "nodev",
	"fstype": "hugetlbfs", "fs_group": null, "shared": false,
	"options": ["pagesize=2097152,size=524288000"],
	"mount_point": concat("", ["/run/kata-containers/sandbox/ephemeral/", file]),
}

# Templated p_storage the compiler emits for that hugepage volume.
hugepage_policy(file) := {
	"driver": "ephemeral", "driver_options": [], "source": "nodev",
	"fstype": "hugetlbfs", "fs_group": null, "shared": false,
	"options": ["pagesize=2097152,size=524288000"],
	"mount_point": concat("", ["^/run/kata-containers/sandbox/ephemeral/", file, "$"]),
}

# An ephemeral volume storage is admitted when its templated p_storage matches.
test_ephemeral_storage_allowed if {
	allow_storages(
		[ephemeral_policy("cache-volume")],
		[ephemeral_runtime("cache-volume")],
		"bid", sandbox_id,
	)
}

# A local volume storage is admitted; $(cpath)/$(sandbox-id) are substituted and
# the escaped file name is pinned.
test_local_storage_allowed if {
	allow_storages(
		[local_policy("data-volume")],
		[local_runtime("data-volume")],
		"bid", sandbox_id,
	)
}

# The file name is pinned: a runtime storage for a different file is rejected.
test_local_storage_wrong_file_denied if {
	not allow_storages(
		[local_policy("data-volume")],
		[local_runtime("other-volume")],
		"bid", sandbox_id,
	)
}

# The ephemeral file name is pinned too.
test_ephemeral_storage_wrong_file_denied if {
	not allow_storages(
		[ephemeral_policy("cache-volume")],
		[ephemeral_runtime("scratch-volume")],
		"bid", sandbox_id,
	)
}

# An empty p_storages (no injection) fails closed against a real volume storage.
test_missing_injection_denied if {
	not allow_storages([], [ephemeral_runtime("cache-volume")], "bid", sandbox_id)
}

# Both classes together in one container are admitted (count balances).
test_mixed_volume_storages_allowed if {
	allow_storages(
		[ephemeral_policy("cache-volume"), local_policy("data-volume")],
		[ephemeral_runtime("cache-volume"), local_runtime("data-volume")],
		"bid", sandbox_id,
	)
}

# A watchable configMap/secret bind is admitted; the random hash is wildcarded
# and the name pinned via $(cpath) substitution.
test_watchable_bind_storage_allowed if {
	allow_storages(
		[watchable_policy("myconfig")],
		[watchable_runtime("myconfig")],
		"bid", sandbox_id,
	)
}

# The watchable name is pinned: a different configMap name is rejected.
test_watchable_bind_wrong_name_denied if {
	not allow_storages(
		[watchable_policy("myconfig")],
		[watchable_runtime("othermap")],
		"bid", sandbox_id,
	)
}

test_literal_storage_source_is_not_regex if {
	p_storage := {"source": "literal.name"}
	i_storage := {"source": "literalXname"}
	not allow_storage_source(p_storage, i_storage, "bid")
}

test_literal_mount_source_is_not_regex if {
	p_mount := {"source": "/run/literal.name"}
	i_mount := {"source": "/run/literalXname"}
	not mount_source_allows(p_mount, i_mount, "bid", sandbox_id)
}

# A hugepage-backed emptyDir (hugetlbfs) is admitted by the new clause.
test_hugepage_storage_allowed if {
	allow_storages(
		[hugepage_policy("hugepage-vol")],
		[hugepage_runtime("hugepage-vol")],
		"bid", sandbox_id,
	)
}

# The hugepage mount path is pinned: a different file is rejected.
test_hugepage_storage_wrong_file_denied if {
	not allow_storages(
		[hugepage_policy("hugepage-vol")],
		[hugepage_runtime("other-vol")],
		"bid", sandbox_id,
	)
}

# Runtime i_storage for a guest-pull container rootfs (image_guest_pull).
guest_pull_runtime(image) := {
	"driver": "image_guest_pull", "fstype": "overlay", "fs_group": null,
	"shared": false, "options": [], "source": image,
	"driver_options": [concat("", ["image_guest_pull={\"metadata\":{}}"])],
	"mount_point": "/run/kata-containers/cid/rootfs",
}

# A legacy global allowlist cannot authorize guest-pull without a per-container
# marker.
test_guest_pull_global_allowlist_denied if {
	not allow_storages([], [guest_pull_runtime("evil.example/malware:latest")], "cid", sandbox_id)
		with data.agent_policy.policy_data as {"guest_pull": {"allowed_images": ["evil.example/malware:latest"]}}
}

# Missing per-container identity fails closed instead of allowing by shape.
test_guest_pull_without_marker_denied if {
	not allow_storages([], [guest_pull_runtime("docker.io/library/nginx:1.27")], "cid", sandbox_id)
		with data.agent_policy.policy_data as {}
}

# The compiler injects a `guest-pull-images` marker carrying only this
# container's image digests.
guest_pull_marker(images) := {
	"driver": "guest-pull-images", "source": "", "fstype": "",
	"fs_group": null, "shared": false, "driver_options": [],
	"mount_point": "", "options": images,
}

# The container's own image is admitted against its marker, union empty.
test_guest_pull_per_container_allowed if {
	allow_storages(
		[guest_pull_marker(["docker.io/library/nginx:1.27"])],
		[guest_pull_runtime("docker.io/library/nginx:1.27")], "cid", sandbox_id,
	) with data.agent_policy.policy_data as {"guest_pull": {"allowed_images": []}}
}

test_guest_pull_wrong_mount_point_denied if {
	storage := json.patch(
		guest_pull_runtime("docker.io/library/nginx:1.27"),
		[{"op": "replace", "path": "/mount_point", "value": "/run/kata-containers/other/rootfs"}],
	)
	not allow_storages(
		[guest_pull_marker(["docker.io/library/nginx:1.27"])],
		[storage], "cid", sandbox_id,
	) with data.agent_policy.policy_data as {"guest_pull": {"allowed_images": []}}
}

test_guest_pull_missing_driver_metadata_denied if {
	storage := json.patch(
		guest_pull_runtime("docker.io/library/nginx:1.27"),
		[{"op": "replace", "path": "/driver_options", "value": []}],
	)
	not allow_storages(
		[guest_pull_marker(["docker.io/library/nginx:1.27"])],
		[storage], "cid", sandbox_id,
	) with data.agent_policy.policy_data as {"guest_pull": {"allowed_images": []}}
}

# Cross-container isolation: presenting another container's image ("api") is
# rejected even though it is a valid pod image, because the union is empty and
# the marker is missing it. This also confirms the empty union does NOT fall
# back to allow-by-shape while a marker is present.
test_guest_pull_per_container_isolation if {
	not allow_storages(
		[guest_pull_marker(["docker.io/library/nginx:1.27"])],
		[guest_pull_runtime("ghcr.io/app/api:2")], "cid", sandbox_id,
	) with data.agent_policy.policy_data as {"guest_pull": {"allowed_images": []}}
}

# Runtime i_storage for a block-encrypted emptyDir as produced by the shim's
# block_emptydir_volume handler: a virtio-blk device whose source is the guest
# PCI address and whose mount_point is $(spath)/base64url(source). base64url("01")
# is "MDE=".
block_encrypted_runtime(source, b64) := {
	"driver": "blk",
	"driver_options": ["encryption_key=ephemeral", "create_filesystem"],
	"source": source, "fstype": "ext4", "fs_group": null, "shared": true,
	"options": [],
	"mount_point": concat("", ["/run/kata-containers/sandbox/storage/", b64]),
}

# Templated p_storage the compiler emits: empty driver and source (the rego
# matches by the runtime driver and wildcards the address), device-id mount
# template, driver_options/fstype/fs_group/options/shared pinned exactly.
block_encrypted_policy := {
	"driver": "", "driver_options": ["encryption_key=ephemeral", "create_filesystem"],
	"source": "", "fstype": "ext4", "fs_group": null, "shared": true, "options": [],
	"mount_point": "$(spath)/$(b64_device_id)",
}

# A block-encrypted emptyDir is admitted: the runtime "blk" driver is matched,
# the device address wildcarded through $(b64_device_id), and the encryption
# driver_options pinned.
test_block_encrypted_emptydir_allowed if {
	allow_storages([block_encrypted_policy], [block_encrypted_runtime("01", "MDE=")], "bid", sandbox_id)
}

# The mount_point is bound to the device id: a runtime mount_point whose base64
# does not encode the runtime source is rejected (host cannot redirect the
# device to a different guest path).
test_block_encrypted_emptydir_wrong_device_id_denied if {
	not allow_storages(
		[block_encrypted_policy],
		[block_encrypted_runtime("02", "MDE=")],
		"bid", sandbox_id,
	)
}

# The encryption driver_options are pinned: a plaintext (no encryption_key)
# runtime storage is rejected against the encrypted policy.
test_block_encrypted_emptydir_missing_key_denied if {
	not allow_storages(
		[block_encrypted_policy],
		[json.patch(
			block_encrypted_runtime("01", "MDE="),
			[{"op": "replace", "path": "/driver_options", "value": ["create_filesystem"]}],
		)],
		"bid", sandbox_id,
	)
}

# fs_group is validated exactly: a runtime storage carrying a pod fsGroup is
# rejected against a policy that pins none.
test_block_encrypted_emptydir_fs_group_mismatch_denied if {
	not allow_storages(
		[block_encrypted_policy],
		[json.patch(
			block_encrypted_runtime("01", "MDE="),
			[{"op": "replace", "path": "/fs_group", "value": {"group_id": 1000, "group_change_policy": 0}}],
		)],
		"bid", sandbox_id,
	)
}

# A block-plain emptyDir over virtio-scsi is admitted: the runtime "scsi" driver
# is matched, the SCSI address (SCSI-id:LUN) wildcarded, and the "discard"
# option and "create_filesystem"-only driver_options pinned. base64url("0:0") is
# "MDow".
block_plain_scsi_runtime := {
	"driver": "scsi", "driver_options": ["create_filesystem"],
	"source": "0:0", "fstype": "ext4", "fs_group": null, "shared": true,
	"options": ["discard"],
	"mount_point": "/run/kata-containers/sandbox/storage/MDow",
}

block_plain_scsi_policy := {
	"driver": "", "driver_options": ["create_filesystem"], "source": "",
	"fstype": "ext4", "fs_group": null, "shared": true, "options": ["discard"],
	"mount_point": "$(spath)/$(b64_device_id)",
}

test_block_plain_emptydir_scsi_allowed if {
	allow_storages([block_plain_scsi_policy], [block_plain_scsi_runtime], "bid", sandbox_id)
}

# --- ConfigMap/Secret OCI mount (watchable-bind) enforcement ---
# The shim rewrites the container's configMap bind mount source to the watchable
# guest path; the compiler templates it into a policy OCI mount whose source
# wildcards the random UUID segment and pins the name. rules.rego allow_mount
# (check_mount 2 -> mount_source_allows, substituting $(cpath)) must accept the
# runtime mount.
configmap_mount_policy(name) := {"Mounts": [{
	"destination": "/etc/config", "type_": "bind",
	"source": concat("", ["^$(cpath)/watchable/sandbox-[0-9a-f]{8}-", name, "$"]),
	"options": ["rbind", "rprivate", "ro"],
}]}

configmap_mount_runtime(name) := {
	"destination": "/etc/config", "type_": "bind",
	"source": concat("", [
		"/run/kata-containers/shared/containers/passthrough/watchable/sandbox-86d776af-", name,
	]),
	"options": ["rbind", "rprivate", "ro"],
}

configmap_mount_allowed(p_oci, i_mount) if {
	allow_mount(p_oci, i_mount, [], "bid", sandbox_id) == 0
}

# The configMap mount is admitted: the random hash is wildcarded and the name
# pinned via $(cpath) substitution.
test_watchable_configmap_mount_allowed if {
	configmap_mount_allowed(configmap_mount_policy("my-cm"), configmap_mount_runtime("my-cm"))
}

# The name is pinned: a different configMap name is rejected (the host cannot
# redirect the container mount to another volume).
test_watchable_configmap_mount_wrong_name_denied if {
	not configmap_mount_allowed(configmap_mount_policy("my-cm"), configmap_mount_runtime("evil-cm"))
}

# The mount options are pinned exactly: an rw runtime mount is rejected against
# an ro policy mount.
test_watchable_configmap_mount_wrong_options_denied if {
	not configmap_mount_allowed(
		configmap_mount_policy("my-cm"),
		json.patch(configmap_mount_runtime("my-cm"), [{"op": "replace", "path": "/options", "value": ["rbind", "rprivate", "rw"]}]),
	)
}

# --- shared_fs="none" ConfigMap/Secret (copy-to-rootfs) enforcement ---
# The default Kata-CC config has no ShareFs: the shim copies the projected files
# into the container rootfs and rewrites the OCI mount to the guest path
# <cpath>/<cid>-<16 hex>-<name> (generate_guest_path). The compiler follows the
# predictor output (NOT legacy $(sfprefix)): $(cpath) prefix, $(bundle-id) cid,
# real [0-9a-f]{16} hex, pinned name. allow_mount must accept the runtime mount,
# and the agent CopyFile destinations (under the confined shared dir) are
# authorized by the default request_defaults.CopyFileRequest rule.
bundle_id := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

sfnone_mount_policy(name) := {"Mounts": [{
	"destination": "/etc/config", "type_": "bind",
	"source": concat("", ["^$(cpath)/$(bundle-id)-[0-9a-f]{16}-", name, "$"]),
	"options": ["rbind", "rprivate", "ro"],
}]}

sfnone_mount_runtime(bid, name) := {
	"destination": "/etc/config", "type_": "bind",
	"source": concat("", [
		"/run/kata-containers/shared/containers/", bid, "-0011223344556677-", name,
	]),
	"options": ["rbind", "rprivate", "ro"],
}

mount_allowed_bid(p_oci, i_mount, bid) if {
	allow_mount(p_oci, i_mount, [], bid, sandbox_id) == 0
}

# The shared_fs="none" configMap mount is admitted: the cid is $(bundle-id), the
# random hex is [0-9a-f]{16}, and the name is pinned.
test_shared_fs_none_configmap_mount_allowed if {
	mount_allowed_bid(sfnone_mount_policy("config"), sfnone_mount_runtime(bundle_id, "config"), bundle_id)
}

# The name is still pinned under the copy scheme.
test_shared_fs_none_configmap_mount_wrong_name_denied if {
	not mount_allowed_bid(sfnone_mount_policy("config"), sfnone_mount_runtime(bundle_id, "evil"), bundle_id)
}

# The random segment must be 16 hex: a mount whose hex segment is a different
# length is rejected (the host cannot fabricate an arbitrary shared-dir name).
test_shared_fs_none_configmap_mount_bad_hex_denied if {
	not mount_allowed_bid(
		sfnone_mount_policy("config"),
		json.patch(sfnone_mount_runtime(bundle_id, "config"), [{
			"op": "replace", "path": "/source",
			"value": concat("", ["/run/kata-containers/shared/containers/", bundle_id, "-00-config"]),
		}]),
		bundle_id,
	)
}

# The agent CopyFile destinations (the projected files copied into the rootfs)
# are confined to the shared dir, so the default CopyFileRequest rule authorizes
# them.
copy_policy_data := {
	"common": {
		"cpath": "/run/kata-containers/shared/containers(?:/passthrough)?",
		"sfprefix": "^$(cpath)/(watchable/)?$(bundle-id)-[a-z0-9]{16}-",
	},
	"request_defaults": {"CopyFileRequest": ["$(sfprefix)"]},
}

test_shared_fs_none_configmap_copy_allowed if {
	CopyFileRequest with input as {
		"file_type": "Regular",
		"path": concat("", [
			"/run/kata-containers/shared/containers/", bundle_id, "-0011223344556677-config/token",
		]),
	}
		with data.agent_policy.policy_data as copy_policy_data
}

# A copy outside the shared-fs domain (arbitrary host path) is rejected.
test_copy_outside_shared_fs_denied if {
	not CopyFileRequest with input as {"file_type": "Regular", "path": "/etc/passwd"}
		with data.agent_policy.policy_data as copy_policy_data
}



