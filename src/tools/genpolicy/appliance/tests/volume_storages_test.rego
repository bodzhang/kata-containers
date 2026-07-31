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
		"sfprefix": "^$(cpath)/(watchable/)?$(bundle-id)-[a-z0-9]{16}-"
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

# A guest-pull rootfs is admitted when its image is on the predicted allowlist.
test_guest_pull_allowed_by_allowlist if {
	allow_storages([], [guest_pull_runtime("docker.io/library/nginx:1.27")], "bid", sandbox_id)
		with data.agent_policy.policy_data as {"guest_pull": {"allowed_images": ["docker.io/library/nginx:1.27"]}}
}

# A guest-pull image not on the allowlist is rejected.
test_guest_pull_wrong_image_denied if {
	not allow_storages([], [guest_pull_runtime("evil.example/malware:latest")], "bid", sandbox_id)
		with data.agent_policy.policy_data as {"guest_pull": {"allowed_images": ["docker.io/library/nginx:1.27"]}}
}

# With no allowlist (predictor not run / legacy genpolicy) guest-pull is allowed
# by shape, preserving the historical behavior.
test_guest_pull_fallback_by_shape if {
	allow_storages([], [guest_pull_runtime("docker.io/library/nginx:1.27")], "bid", sandbox_id)
		with data.agent_policy.policy_data as {}
}
