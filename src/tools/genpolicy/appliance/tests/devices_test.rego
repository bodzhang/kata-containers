package agent_policy

# Tests for block-device volume pinning (allow_devices / allow_volume_devices) in
# ../../rules.rego. A workload container's volumeDevices are pinned by their
# container_path (parity with legacy genpolicy): the set of device paths the host
# may present is bounded, though the device content stays untrusted by the guest
# under the CC model. Run via `opa test`.
#
# allow_devices splits volume vs VFIO devices using policy_data.devices.vfio; the
# VFIO device_path here never matches the volume paths under test.
policy_data := json.unmarshal(`{"devices": {"vfio": {"device_path": "/dev/vfio/"}}}`)

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
