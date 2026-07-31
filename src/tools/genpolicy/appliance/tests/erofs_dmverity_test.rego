package agent_policy

# Tests for the EROFS multi-layer dm-verity storage rules in
# ../../rules.rego (allow_storages / allow_storage). Run via `opa test`.
#
# In a generated policy `policy_data := {...}` is prepended; provide a default
# here (typed `any` via json.unmarshal so rules.rego's other policy_data.* refs
# type-check) and override it per-test with `with`.
policy_data := json.unmarshal(`{"dmverity": {"allowed_roothashes": []}}`)

erofs_storages(roothash) := [
	{
		"driver": "mmioblk", "source": "/dev/vda", "fstype": "ext4",
		"fs_group": null, "shared": false, "driver_options": [],
		"mount_point": "/run/kata-containers/foo/rootfs",
		"options": ["rw", "X-kata.overlay-upper", "X-kata.multi-layer=true"],
	},
	{
		"driver": "mmioblk", "source": "/dev/vdb", "fstype": "erofs",
		"fs_group": null, "shared": false, "driver_options": [],
		"mount_point": "/run/kata-containers/foo/rootfs",
		"options": [
			"ro", "X-kata.overlay-lower", "X-kata.multi-layer=true",
			"X-kata.dmverity-enabled=true",
			concat("", ["X-kata.dmverity.roothash=", roothash]),
			"X-kata.gpt-partitioned=true", "X-kata.partition-number=1",
		],
	},
]

# A lower layer whose root hash is on the pod allowlist is admitted.
test_erofs_dmverity_allowed if {
	allow_storages([], erofs_storages("aa11"), "bid", "sid")
		with data.agent_policy.policy_data as {"dmverity": {"allowed_roothashes": ["aa11", "cc33"]}}
}

# A root hash not on the allowlist is rejected.
test_erofs_dmverity_wrong_roothash_denied if {
	not allow_storages([], erofs_storages("deadbeef"), "bid", "sid")
		with data.agent_policy.policy_data as {"dmverity": {"allowed_roothashes": ["aa11"]}}
}

# No allowlist at all -> rejected (fail closed).
test_erofs_dmverity_no_allowlist_denied if {
	not allow_storages([], erofs_storages("aa11"), "bid", "sid")
		with data.agent_policy.policy_data as {}
}

# An erofs lower without dm-verity enabled is rejected.
test_erofs_without_verity_denied if {
	storages := [{
		"driver": "mmioblk", "source": "/dev/vdb", "fstype": "erofs",
		"fs_group": null, "shared": false, "driver_options": [],
		"mount_point": "/run/kata-containers/foo/rootfs",
		"options": ["ro", "X-kata.overlay-lower", "X-kata.multi-layer=true"],
	}]
	not allow_storages([], storages, "bid", "sid")
		with data.agent_policy.policy_data as {"dmverity": {"allowed_roothashes": ["aa11"]}}
}
