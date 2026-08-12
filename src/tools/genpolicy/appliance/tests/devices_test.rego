package agent_policy

# Tests for block-device volume pinning (allow_devices / allow_volume_devices) in
# ../../rules.rego. A workload container's volumeDevices are pinned by their
# container_path (parity with legacy genpolicy): the set of device paths the host
# may present is bounded, though the device content stays untrusted by the guest
# under the CC model. Run via `opa test`.
#
# allow_devices splits volume vs VFIO devices using policy_data.devices.vfio; the
# VFIO device_path here mirrors genpolicy-settings.json.
fixture_policy_data := json.unmarshal(`{"devices": {"vfio": {"device_path": "/dev/vfio/devices/vfio", "cdi_annotation_prefix": "cdi.k8s.io/vfio", "device_number_regex": "^[0-9]+$", "device_id_prefix": "vfio", "pci_address_regex": "^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[01][0-9a-fA-F]\\.[0-7]=[0-9a-fA-F]{2}/[0-9a-fA-F]{2}$"}}}`)

policy_data := fixture_policy_data

vfio_operand_policy(key, value) := {
	"devices": {
		"vfio": object.union(fixture_policy_data.devices.vfio, {key: value}),
	},
}

oci := {"Annotations": {}}

# A request whose device path matches the declared volumeDevice is admitted.
test_volume_device_allowed if {
	allow_devices(
		[{"container_path": "/dev/xvdb"}],
		[{"container_path": "/dev/xvdb"}],
		oci,
	)
}

# A request presenting a device at an UNDECLARED path is rejected — the device
# set is bounded to the container's declared volumeDevices.
test_volume_device_undeclared_denied if {
	not allow_devices(
		[{"container_path": "/dev/xvdb"}],
		[{"container_path": "/dev/xvdb"}, {"container_path": "/dev/sneaky"}],
		oci,
	)
}

# A request whose device path does not match the declared path is rejected.
test_volume_device_wrong_path_denied if {
	not allow_devices(
		[{"container_path": "/dev/xvdb"}],
		[{"container_path": "/dev/other"}],
		oci,
	)
}

# Every declared path is required; a subset cannot satisfy the policy.
test_volume_device_missing_denied if {
	not allow_devices(
		[{"container_path": "/dev/xvdb"}, {"container_path": "/dev/xvdc"}],
		[{"container_path": "/dev/xvdb"}],
		oci,
	)
}

# Captured non-empty fields are exact, while legacy path-only entries remain
# compatible through the empty-field behavior in allow_volume_device.
test_captured_volume_device_field_change_denied if {
	not allow_devices(
		[{
			"container_path": "/dev/xvdb", "id": "disk-1", "type_": "blk",
			"vm_path": "/dev/vdb", "options": ["ro"],
		}],
		[{
			"container_path": "/dev/xvdb", "id": "disk-2", "type_": "blk",
			"vm_path": "/dev/vdb", "options": ["ro"],
		}],
		oci,
	)
}

test_captured_volume_device_exact_allowed if {
	device := {
		"container_path": "/dev/xvdb", "id": "disk-1", "type_": "blk",
		"vm_path": "/dev/vdb", "options": ["ro"],
	}
	allow_devices([device], [device], oci)
}

# Multiple declared devices, all matched, are admitted.
test_multiple_volume_devices_allowed if {
	allow_devices(
		[{"container_path": "/dev/xvdb"}, {"container_path": "/dev/xvdc"}],
		[{"container_path": "/dev/xvdc"}, {"container_path": "/dev/xvdb"}],
		oci,
	)
}

# A container with no devices is admitted (unchanged baseline).
test_no_devices_allowed if {
	allow_devices([], [], oci)
}

# --- VFIO / NVIDIA passthrough GPU (parity with legacy genpolicy) ---

# The policy device the compiler emits per requested pGPU: the container_path
# prefix, the device type, and an empty vm_path.
vfio_policy_device := {"container_path": "/dev/vfio/devices/vfio", "type_": "vfio-pci-gk", "vm_path": ""}

# A runtime VFIO device: prefix + device number suffix, id "vfio<n>", a PCI-address
# option, matched/correlated against the CDI annotation for the same number.
vfio_request_device(n, pci) := {
	"container_path": concat("", ["/dev/vfio/devices/vfio", n]),
	"id": concat("", ["vfio", n]),
	"type_": "vfio-pci-gk",
	"vm_path": "",
	"options": [pci],
}

gpu_oci(n) := {"Annotations": {concat("", ["cdi.k8s.io/vfio", n]): "nvidia.com/gpu=0"}}

# A single requested pGPU is admitted when the VFIO device + CDI annotation correlate.
test_vfio_gpu_allowed if {
	allow_devices(
		[vfio_policy_device],
		[vfio_request_device("0", "0000:00:05.0=10/de")],
		gpu_oci("0"),
	)
}

test_vfio_cdi_prefix_mutation_denied if {
	mutated := vfio_operand_policy("cdi_annotation_prefix", "cdi.example/vfio")
	not allow_devices(
		[vfio_policy_device],
		[vfio_request_device("0", "0000:00:05.0=10/de")],
		gpu_oci("0"),
	) with data.agent_policy.policy_data as mutated
}

test_vfio_number_regex_mutation_denied if {
	mutated := vfio_operand_policy("device_number_regex", "^1$")
	not allow_devices(
		[vfio_policy_device],
		[vfio_request_device("0", "0000:00:05.0=10/de")],
		gpu_oci("0"),
	) with data.agent_policy.policy_data as mutated
}

test_vfio_id_prefix_mutation_denied if {
	mutated := vfio_operand_policy("device_id_prefix", "iommu")
	not allow_devices(
		[vfio_policy_device],
		[vfio_request_device("0", "0000:00:05.0=10/de")],
		gpu_oci("0"),
	) with data.agent_policy.policy_data as mutated
}

test_vfio_pci_regex_mutation_denied if {
	mutated := vfio_operand_policy("pci_address_regex", "^ffff:")
	not allow_devices(
		[vfio_policy_device],
		[vfio_request_device("0", "0000:00:05.0=10/de")],
		gpu_oci("0"),
	) with data.agent_policy.policy_data as mutated
}

# A malformed PCI-address option is rejected.
test_vfio_gpu_bad_pci_denied if {
	not allow_devices(
		[vfio_policy_device],
		[vfio_request_device("0", "not-a-pci-address")],
		gpu_oci("0"),
	)
}

# A request presenting more VFIO devices than the policy allows is rejected.
test_vfio_gpu_count_mismatch_denied if {
	not allow_devices(
		[vfio_policy_device],
		[
			vfio_request_device("0", "0000:00:05.0=10/de"),
			vfio_request_device("1", "0000:00:06.0=10/df"),
		],
		{"Annotations": {"cdi.k8s.io/vfio0": "nvidia.com/gpu=0", "cdi.k8s.io/vfio1": "nvidia.com/gpu=1"}},
	)
}

# The device number must correlate with the CDI annotation suffix.
test_vfio_gpu_cdi_mismatch_denied if {
	not allow_devices(
		[vfio_policy_device],
		[vfio_request_device("0", "0000:00:05.0=10/de")],
		gpu_oci("1"),
	)
}
