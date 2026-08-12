package agent_policy

# Tests for the EROFS multi-layer dm-verity storage rules in
# ../../rules.rego (allow_storages / allow_storage). Run via `opa test`.
#
# In a generated policy `policy_data := {...}` is prepended; provide a default
# here (typed `any` via json.unmarshal so rules.rego's other policy_data.* refs
# type-check) and override it per-test with `with`.
policy_data := json.unmarshal(`{
	"common": {
		"substitutions": {
			"bundle_id": "$(bundle-id)",
			"unresolved_token_regex": "\\$\\([^)]+\\)"
		}
	},
	"cluster_config": {
		"rootfs_compatibility": {
			"multi_layer_option": "X-kata.multi-layer=true",
			"overlay_upper_option": "X-kata.overlay-upper",
			"overlay_lower_option": "X-kata.overlay-lower",
			"dmverity_enabled_option": "X-kata.dmverity-enabled=true",
			"dmverity_roothash_option_prefix": "X-kata.dmverity.roothash=",
			"guest_pull_fstype": "overlay",
			"guest_pull_driver_option_prefix": "image_guest_pull=",
			"erofs_upper_fstype": "ext4",
			"erofs_lower_fstype": "erofs",
			"block_transports": [
				{"driver": "blk", "source_regex": "^[0-9a-f]{2}(/[0-9a-f]{2})?$"},
				{"driver": "scsi", "source_regex": "^[0-9]+:[0-9]+$"},
				{"driver": "mmioblk", "source_regex": "^/dev/vd[a-z]+$"},
				{"driver": "blk-ccw", "source_regex": "^0\\.0\\.[0-9a-f]{4}$"},
				{"driver": "nvdimm", "source_regex": "^/dev/pmem[0-9]+$"}
			],
			"rootfs_mount_points": [
				"/run/kata-containers/$(bundle-id)/rootfs",
				"/run/kata-containers/shared/containers/passthrough/$(bundle-id)/rootfs"
			],
			"overlayfs_driver": "overlayfs",
			"overlayfs_source": "none",
			"local_fstype": "local",
			"bind_fstype": "bind",
			"tmpfs_fstype": "tmpfs",
			"hugetlbfs_fstype": "hugetlbfs"
		}
	},
	"dmverity": {"allowed_roothashes": []}
}`)

dmverity_policy(allowed_roothashes) := object.union(policy_data, {
	"dmverity": {"allowed_roothashes": allowed_roothashes},
})

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

erofs_storages_at(roothash, mount_point) := [
	json.patch(storage, [{"op": "replace", "path": "/mount_point", "value": mount_point}]) |
	storage := erofs_storages(roothash)[_]
]

# A lower layer whose root hash is in this container's marker is admitted.
test_erofs_dmverity_allowed if {
	allow_storages([marker(["aa11"])], erofs_storages("aa11"), "foo", "sid")
		with data.agent_policy.policy_data as dmverity_policy([])
}

# A root hash not in this container's marker is rejected.
test_erofs_dmverity_wrong_roothash_denied if {
	not allow_storages([marker(["aa11"])], erofs_storages("deadbeef"), "foo", "sid")
		with data.agent_policy.policy_data as dmverity_policy([])
}

test_erofs_dmverity_wrong_mount_point_denied if {
	not allow_storages(
		[marker(["aa11"])],
		erofs_storages_at("aa11", "/run/kata-containers/other/rootfs"),
		"foo", "sid",
	) with data.agent_policy.policy_data as dmverity_policy([])
}

test_erofs_dmverity_non_block_driver_denied if {
	storages := [
		json.patch(storage, [{"op": "replace", "path": "/driver", "value": "ephemeral"}]) |
		storage := erofs_storages("aa11")[_]
	]
	not allow_storages([marker(["aa11"])], storages, "foo", "sid")
		with data.agent_policy.policy_data as dmverity_policy([])
}

test_erofs_dmverity_bad_block_source_denied if {
	storages := [
		json.patch(storage, [{"op": "replace", "path": "/source", "value": "/dev/shm"}]) |
		storage := erofs_storages("aa11")[_]
	]
	not allow_storages([marker(["aa11"])], storages, "foo", "sid")
		with data.agent_policy.policy_data as dmverity_policy([])
}

# A legacy pod-wide allowlist cannot authorize a root hash without a
# per-container marker.
test_erofs_dmverity_global_allowlist_denied if {
	not allow_storages([], erofs_storages("aa11"), "foo", "sid")
		with data.agent_policy.policy_data as dmverity_policy(["aa11"])
}

# An erofs lower without dm-verity enabled is rejected.
test_erofs_without_verity_denied if {
	storages := [{
		"driver": "mmioblk", "source": "/dev/vdb", "fstype": "erofs",
		"fs_group": null, "shared": false, "driver_options": [],
		"mount_point": "/run/kata-containers/foo/rootfs",
		"options": ["ro", "X-kata.overlay-lower", "X-kata.multi-layer=true"],
	}]
	not allow_storages([], storages, "foo", "sid")
		with data.agent_policy.policy_data as dmverity_policy(["aa11"])
}

# A single-layer verity block rootfs (BlockRootfs): one ext4 device pinned by its
# dm-verity root hash, no multi-layer/overlay markers.
single_layer_verity(roothash) := [{
	"driver": "mmioblk", "source": "/dev/vda", "fstype": "ext4",
	"fs_group": null, "shared": false, "driver_options": [],
	"mount_point": "/run/kata-containers/foo/rootfs",
	"options": [
		"ro", "X-kata.dmverity-enabled=true",
		concat("", ["X-kata.dmverity.roothash=", roothash]),
		"X-kata.dmverity.hashoffset=4096", "X-kata.dmverity.no-superblock=true",
	],
}]

# A single-layer verity rootfs whose hash is in this container's marker is admitted.
test_single_layer_dmverity_allowed if {
	allow_storages([marker(["cafe1234"])], single_layer_verity("cafe1234"), "foo", "sid")
		with data.agent_policy.policy_data as dmverity_policy([])
}

# A single-layer verity rootfs with a hash absent from the marker is rejected.
test_single_layer_dmverity_wrong_roothash_denied if {
	not allow_storages([marker(["cafe1234"])], single_layer_verity("deadbeef"), "foo", "sid")
		with data.agent_policy.policy_data as dmverity_policy([])
}

test_single_layer_dmverity_wrong_mount_point_denied if {
	storages := [json.patch(
		single_layer_verity("cafe1234")[0],
		[{"op": "replace", "path": "/mount_point", "value": "/run/kata-containers/other/rootfs"}],
	)]
	not allow_storages([marker(["cafe1234"])], storages, "foo", "sid")
		with data.agent_policy.policy_data as dmverity_policy([])
}

test_single_layer_dmverity_non_block_driver_denied if {
	storage := json.patch(
		single_layer_verity("cafe1234")[0],
		[{"op": "replace", "path": "/driver", "value": "ephemeral"}],
	)
	not allow_storages([marker(["cafe1234"])], [storage], "foo", "sid")
		with data.agent_policy.policy_data as dmverity_policy([])
}

# A legacy global allowlist cannot authorize a single-layer rootfs.
test_single_layer_dmverity_global_allowlist_denied if {
	not allow_storages([], single_layer_verity("cafe1234"), "foo", "sid")
		with data.agent_policy.policy_data as dmverity_policy(["cafe1234"])
}

# The compiler injects a `dmverity-roothashes`
# marker storage into THIS container's p_storages carrying only its own root
# hashes. The marker count is excluded from the Agent storage count balance.
marker(hashes) := {
	"driver": "dmverity-roothashes", "source": "", "fstype": "",
	"fs_group": null, "shared": false, "driver_options": [],
	"mount_point": "", "options": hashes,
}

# A lower whose root hash is in the container's own marker is admitted, with an
# empty pod-wide union.
test_erofs_dmverity_per_container_allowed if {
	allow_storages([marker(["aa11"])], erofs_storages("aa11"), "foo", "sid")
		with data.agent_policy.policy_data as dmverity_policy([])
}

# Cross-container isolation: container A (marker ["aa11"]) presenting container
# B's image ("bb22") is rejected, even though bb22 is a valid pod image — the
# union is empty, so only A's own hash is accepted.
test_erofs_dmverity_per_container_isolation if {
	not allow_storages([marker(["aa11"])], erofs_storages("bb22"), "foo", "sid")
		with data.agent_policy.policy_data as dmverity_policy([])
}

# A single-layer verity rootfs pinned by the container's own marker is admitted.
test_single_layer_dmverity_per_container_allowed if {
	allow_storages([marker(["cafe1234"])], single_layer_verity("cafe1234"), "foo", "sid")
		with data.agent_policy.policy_data as dmverity_policy([])
}

# ...and another container's single-layer hash is rejected.
test_single_layer_dmverity_per_container_isolation if {
	not allow_storages([marker(["cafe1234"])], single_layer_verity("deadbeef"), "foo", "sid")
		with data.agent_policy.policy_data as dmverity_policy([])
}

test_dmverity_roothashes_reordered_denied if {
	storages := array.concat(single_layer_verity("bb22"), single_layer_verity("aa11"))
	not allow_storages([marker(["aa11", "bb22"])], storages, "foo", "sid")
		with data.agent_policy.policy_data as policy_data
}

test_dmverity_roothash_missing_denied if {
	not allow_storages(
		[marker(["aa11", "bb22"])],
		single_layer_verity("aa11"),
		"foo", "sid",
	) with data.agent_policy.policy_data as policy_data
}

test_dmverity_roothash_additional_denied if {
	storages := array.concat(single_layer_verity("aa11"), single_layer_verity("bb22"))
	not allow_storages([marker(["aa11"])], storages, "foo", "sid")
		with data.agent_policy.policy_data as policy_data
}

test_dmverity_roothash_prefix_mutation_denied if {
	mutated := object.union(policy_data, {
		"cluster_config": {
			"rootfs_compatibility": {
				"dmverity_roothash_option_prefix": "X-kata.changed.roothash=",
			},
		},
	})
	not allow_storages(
		[marker(["aa11"])], erofs_storages("aa11"), "foo", "sid",
	) with data.agent_policy.policy_data as mutated
}
