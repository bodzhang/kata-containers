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
	"common": {"cpath": "/run/kata-containers/shared/containers(?:/passthrough)?"},
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
