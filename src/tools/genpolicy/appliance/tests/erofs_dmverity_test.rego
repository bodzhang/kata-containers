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

# A single-layer verity rootfs whose root hash is allowlisted is admitted.
test_single_layer_dmverity_allowed if {
	allow_storages([], single_layer_verity("cafe1234"), "bid", "sid")
		with data.agent_policy.policy_data as {"dmverity": {"allowed_roothashes": ["cafe1234"]}}
}

# A single-layer verity rootfs with an unlisted root hash is rejected.
test_single_layer_dmverity_wrong_roothash_denied if {
	not allow_storages([], single_layer_verity("deadbeef"), "bid", "sid")
		with data.agent_policy.policy_data as {"dmverity": {"allowed_roothashes": ["cafe1234"]}}
}

# No allowlist -> single-layer verity rootfs rejected (fail closed).
test_single_layer_dmverity_no_allowlist_denied if {
	not allow_storages([], single_layer_verity("cafe1234"), "bid", "sid")
		with data.agent_policy.policy_data as {}
}

# Per-container (tarfs style): the compiler injects a `dmverity-roothashes`
# marker storage into THIS container's p_storages carrying only its own root
# hashes, and the pod-wide union is left empty. The per-container clause matches
# the lower against the marker; verity_marker_count keeps the count balanced.
marker(hashes) := {
	"driver": "dmverity-roothashes", "source": "", "fstype": "",
	"fs_group": null, "shared": false, "driver_options": [],
	"mount_point": "", "options": hashes,
}

# A lower whose root hash is in the container's own marker is admitted, with an
# empty pod-wide union.
test_erofs_dmverity_per_container_allowed if {
	allow_storages([marker(["aa11"])], erofs_storages("aa11"), "bid", "sid")
		with data.agent_policy.policy_data as {"dmverity": {"allowed_roothashes": []}}
}

# Cross-container isolation: container A (marker ["aa11"]) presenting container
# B's image ("bb22") is rejected, even though bb22 is a valid pod image — the
# union is empty, so only A's own hash is accepted.
test_erofs_dmverity_per_container_isolation if {
	not allow_storages([marker(["aa11"])], erofs_storages("bb22"), "bid", "sid")
		with data.agent_policy.policy_data as {"dmverity": {"allowed_roothashes": []}}
}

# A single-layer verity rootfs pinned by the container's own marker is admitted.
test_single_layer_dmverity_per_container_allowed if {
	allow_storages([marker(["cafe1234"])], single_layer_verity("cafe1234"), "bid", "sid")
		with data.agent_policy.policy_data as {"dmverity": {"allowed_roothashes": []}}
}

# ...and another container's single-layer hash is rejected.
test_single_layer_dmverity_per_container_isolation if {
	not allow_storages([marker(["cafe1234"])], single_layer_verity("deadbeef"), "bid", "sid")
		with data.agent_policy.policy_data as {"dmverity": {"allowed_roothashes": []}}
}
