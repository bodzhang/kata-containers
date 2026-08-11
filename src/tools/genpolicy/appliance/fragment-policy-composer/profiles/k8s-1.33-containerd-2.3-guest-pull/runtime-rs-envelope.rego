package profile_runtime_rs_envelope

# Builds non-OCI Agent request policy owned by runtime-rs: emptyDir storage
# envelopes and exact CopyFile roots for declared ConfigMap and Secret volumes.
resource_volume_transport := "copy-to-rootfs"
vfio_device_path := "/dev/vfio/devices/vfio"
vfio_device_type := "vfio-pci-gk"
vfio_annotation_key := "^cdi\\.k8s\\.io/vfio[0-9]+$"
vfio_annotation_value := "^nvidia\\.com/gpu=[0-9]+$"

empty_dir_storage(volume) := {
	"driver": "ephemeral",
	"driver_options": [],
	"source": "tmpfs",
	"fstype": "tmpfs",
	"options": [],
	"mount_point": sprintf("^/run/kata-containers/sandbox/ephemeral/%s$", [volume.name]),
	"fs_group": null,
	"shared": false,
} if {
	volume.medium == "memory"
}

empty_dir_storage(volume) := {
	"driver": "local",
	"driver_options": [],
	"source": "local",
	"fstype": "local",
	"options": ["mode=0777"],
	"mount_point": sprintf("^$(cpath)/$(sandbox-id)/rootfs/local/%s$", [volume.name]),
	"fs_group": null,
	"shared": false,
} if {
	volume.medium == "node-default"
}

volume_supported(volume) if {
	volume.role == "empty-dir"
	volume.medium in {"memory", "node-default"}
	object.get(volume, "size_limit", "") == ""
	object.get(volume, "sub_path", "") == ""
	object.get(volume, "mount_propagation", "") == ""
	object.get(volume, "recursive_read_only", false) == false
}

volume_supported(volume) if {
	volume.role == "direct-volume"
	volume.uvm.transport == "shared-fs"
	volume.uvm.content_trust == "untrusted-runtime"
	regex.match("^[A-Za-z0-9_-]+$", volume.destination_basename)
	object.get(volume, "sub_path", "") == ""
	object.get(volume, "mount_propagation", "") == ""
	object.get(volume, "recursive_read_only", false) == false
}

volume_supported(volume) if {
	volume.role in {"config-map", "secret"}
	resource_volume_transport == "copy-to-rootfs"
	volume.source.content_trust == "untrusted-runtime"
	regex.match("^[A-Za-z0-9_-]+$", volume.destination_basename)
	object.get(volume, "sub_path", "") == ""
	object.get(volume, "mount_propagation", "") == ""
	object.get(volume, "recursive_read_only", false) == false
}

volumes_supported(subject) if {
	every volume in subject.volumes {
		volume_supported(volume)
	}
}

rootfs_identity_storages(subject) := [subject.rootfs_identity_storage] if {
	subject.rootfs_identity_storage.driver in {"dmverity-roothashes", "guest-pull-images"}
}

rootfs_identity_storages(subject) := [] if {
	not subject.rootfs_identity_storage.driver in {"dmverity-roothashes", "guest-pull-images"}
}

# Replaces /storages for each fully supported subject. Memory emptyDir becomes
# guest tmpfs, node-default emptyDir becomes local storage, and copy-to-rootfs
# ConfigMap/Secret volumes intentionally add no Storage object.
volume_storage_claims(ir) := [claim |
	some subject in ir.subjects
	volumes_supported(subject)
	volume_storages := [empty_dir_storage(volume) |
		some volume in subject.volumes
		volume.role == "empty-dir"
	]
	storages := array.concat(rootfs_identity_storages(subject), volume_storages)
	claim := {
		"addition": {"storages": storages},
		"category": "runtime-rs-envelope",
		"operation": "envelope",
		"subject": subject.id,
		"target": {"path": "/storages"},
	}
]

# Derives deduplicated CopyFile root prefixes from declared ConfigMap and Secret
# destination basenames. Content delivered beneath these roots is untrusted and
# mutable. The prefix deliberately carries no end anchor: the
# Agent builds its symlink rule by concatenating ".*/.+" onto each entry, so a
# trailing "$" would make symlinks unmatchable and a trailing "/" would consume
# the separator that suffix needs, denying the "..data" and per-key symlinks
# that the shim copies directly beneath each resource root. A sibling resource
# whose name extends a declared basename therefore also matches; the exact,
# end-anchored /OCI/Mounts source regex is what pins the mounted resource.
copy_file_patterns(ir) := sort({pattern |
	some subject in ir.subjects
	some volume in subject.volumes
	volume.role in {"config-map", "secret"}
	volume.source.content_trust == "untrusted-runtime"
	regex.match("^[A-Za-z0-9_-]+$", volume.destination_basename)
	pattern := sprintf(
		"^$(cpath)/$(bundle-id)-[0-9a-f]{16}-%s",
		[volume.destination_basename],
	)
})

# Replaces the policy-wide CopyFileRequest allowlist with the roots derived
# above; absent resources contribute no authorization.
copy_file_claims(ir) := [{
	"addition": {"request_defaults": {"CopyFileRequest": copy_file_patterns(ir)}},
	"category": "runtime-rs-envelope",
	"operation": "envelope",
	"subject": "policy",
	"target": {"path": "/request_defaults/CopyFileRequest"},
}]

volume_devices(subject) := [{
	"container_path": request.device_path,
	"id": "",
	"options": [],
	"type_": "",
	"vm_path": "",
} | some request in subject.device_requests.volume_devices]

gpu_devices(subject) := [device |
	some request in subject.device_requests.extended_resources
	request.resource in {"nvidia.com/gpu", "nvidia.com/pgpu"}
	request.count > 0
	some _ in numbers.range(1, request.count)
	device := {
		"container_path": vfio_device_path,
		"id": "",
		"options": [],
		"type_": vfio_device_type,
		"vm_path": "",
	}
]

device_claims(ir) := [claim |
	some subject in ir.subjects
	devices := array.concat(volume_devices(subject), gpu_devices(subject))
	claim := {
		"addition": {"devices": devices},
		"category": "runtime-rs-envelope",
		"operation": "envelope",
		"subject": subject.id,
		"target": {"path": "/devices"},
	}
]

application_runtime_patterns(subject) := patterns if {
	subject.role == "application"
	base := {
		"^io\\.kubernetes\\.container\\.terminationMessagePath$": "^/.*$",
		"^io\\.kubernetes\\.container\\.terminationMessagePolicy$": "^(File|FallbackToLogsOnError)$",
	}
	has_gpu := count(gpu_devices(subject)) > 0
	patterns := object.union(base, {vfio_annotation_key: vfio_annotation_value})
	has_gpu
}

application_runtime_patterns(subject) := {
	"^io\\.kubernetes\\.container\\.terminationMessagePath$": "^/.*$",
	"^io\\.kubernetes\\.container\\.terminationMessagePolicy$": "^(File|FallbackToLogsOnError)$",
} if {
	subject.role == "application"
	count(gpu_devices(subject)) == 0
}

application_runtime_patterns(subject) := {} if { subject.role == "sandbox" }

runtime_pattern_claims(ir) := [claim |
	some subject in ir.subjects
	claim := {
		"addition": {"runtime_anno_patterns": application_runtime_patterns(subject)},
		"category": "runtime-rs-envelope",
		"operation": "envelope",
		"subject": subject.id,
		"target": {"path": "/runtime_anno_patterns"},
	}
]

# Other non-OCI request fields remain behind a narrow materialization contract
# until runtime-rs envelope transformations are modeled from typed inputs.
fragment := {
	"applies_to": {
		"rootfs_mode": ["guest-pull"]
	},
	"capture_provenance": "8b0ae298134cf114935b140f42fc2ca8a8294a674ecbeb58d4727ee2f33f00d2",
	"category": "runtime-rs-envelope",
	"claims": [],
	"materialization_contracts": [
		{
			"operations": ["envelope"],
			"path_regex": "^/(sandbox_pidns|exec_commands)$"
		}
	],
	"schema_version": 1,
	"scope": "profile"
}
