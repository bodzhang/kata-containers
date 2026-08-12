package profile_kubelet_or_containerd

# Lowers typed workload IR into OCI values jointly determined by kubelet and
# containerd, such as annotations, Linux defaults, and process capabilities.
container_type(subject) := "pod_container" if { subject.role == "application" }
container_type(subject) := "pod_sandbox" if { subject.role == "sandbox" }

common_annotation_specs(subject) := [
  {
    "key": "io.katacontainers.pkg.oci.bundle_path",
    "path": "/OCI/Annotations/io.katacontainers.pkg.oci.bundle_path",
    "value": "/run/containerd/io.containerd.runtime.v2.task/k8s.io/$(bundle-id)",
  },
  {
    "key": "io.katacontainers.pkg.oci.container_type",
    "path": "/OCI/Annotations/io.katacontainers.pkg.oci.container_type",
    "value": container_type(subject),
  },
  {
    "key": "io.kubernetes.cri.sandbox-id",
    "path": "/OCI/Annotations/io.kubernetes.cri.sandbox-id",
    "value": "^[0-9a-f]{64}$",
  },
  {
    "key": "io.kubernetes.cri.sandbox-namespace",
    "path": "/OCI/Annotations/io.kubernetes.cri.sandbox-namespace",
    "value": subject.namespace,
  },
]

annotation_specs(subject) := common_annotation_specs(subject) if {
  subject.role == "application"
}

annotation_specs(subject) := array.concat(common_annotation_specs(subject), [
  {
    "key": "io.kubernetes.cri.sandbox-log-directory",
    "path": "/OCI/Annotations/io.kubernetes.cri.sandbox-log-directory",
    "value": "^/var/log/pods/$(sandbox-namespace)_$(sandbox-name)_[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
  },
  {
    "key": "nerdctl/network-namespace",
    "path": "/OCI/Annotations/nerdctl~1network-namespace",
    "value": "^/var/run/netns/cni-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
  },
]) if {
  subject.role == "sandbox"
}

# Adds the runtime bundle path, Kata/CRI role, sandbox identity, and namespace
# annotations to every subject. Sandbox subjects also receive constrained log
# directory and network namespace annotations.
annotation_claims(ir) := [claim |
  some subject in ir.subjects
  some spec in annotation_specs(subject)
  claim := {
    "addition": {"OCI": {"Annotations": {spec.key: spec.value}}},
    "category": "kubelet-or-containerd",
    "operation": "default",
    "subject": subject.id,
    "target": {"path": spec.path},
  }
]

application_masked_paths := [
  "/proc/asound",
  "/proc/acpi",
  "/proc/interrupts",
  "/proc/kcore",
  "/proc/keys",
  "/proc/latency_stats",
  "/proc/timer_list",
  "/proc/timer_stats",
  "/proc/sched_debug",
  "/proc/scsi",
  "/sys/firmware",
  "/sys/devices/virtual/powercap",
]

sandbox_masked_paths := [
  "/proc/acpi",
  "/proc/asound",
  "/proc/kcore",
  "/proc/keys",
  "/proc/latency_stats",
  "/proc/timer_list",
  "/proc/timer_stats",
  "/proc/sched_debug",
  "/sys/firmware",
  "/sys/devices/virtual/powercap",
  "/proc/scsi",
]

masked_paths(subject) := application_masked_paths if { subject.role == "application" }
masked_paths(subject) := sandbox_masked_paths if { subject.role == "sandbox" }

common_default_specs(subject) := [
  {
    "addition": {"OCI": {"Linux": {"MaskedPaths": masked_paths(subject)}}},
    "path": "/OCI/Linux/MaskedPaths",
  },
  {
    "addition": {"OCI": {"Linux": {"ReadonlyPaths": [
      "/proc/bus",
      "/proc/fs",
      "/proc/irq",
      "/proc/sys",
      "/proc/sysrq-trigger",
    ]}}},
    "path": "/OCI/Linux/ReadonlyPaths",
  },
  {
    "addition": {"OCI": {"Linux": {"Sysctl": {"net.ipv4.ip_unprivileged_port_start": "0"}}}},
    "path": "/OCI/Linux/Sysctl/net.ipv4.ip_unprivileged_port_start",
  },
  {
    "addition": {"OCI": {"Linux": {"Sysctl": {"net.ipv4.ping_group_range": "0 2147483647"}}}},
    "path": "/OCI/Linux/Sysctl/net.ipv4.ping_group_range",
  },
]

role_default_specs(subject) := [{
  "addition": {"OCI": {"Process": {"Terminal": false}}},
  "path": "/OCI/Process/Terminal",
}] if {
  subject.role == "application"
}

role_default_specs(subject) := [] if { subject.role == "sandbox" }

# Adds deterministic OCI Linux and process defaults selected by subject role:
# devices, masked/read-only paths, network sysctls, and application terminal.
constant_default_claims(ir) := [claim |
  some subject in ir.subjects
  some spec in array.concat(common_default_specs(subject), role_default_specs(subject))
  claim := {
    "addition": spec.addition,
    "category": "kubelet-or-containerd",
    "operation": "default",
    "subject": subject.id,
    "target": {"path": spec.path},
  }
]

# Defaults NoNewPrivileges to false only when trusted workload IR does not own
# the field, preserving an explicit Kubernetes security-context value.
no_new_privileges_claims(ir) := [claim |
  some subject in ir.subjects
  subject.role == "application"
  not "/OCI/Process/NoNewPrivileges" in subject.owned_paths
  claim := {
    "addition": {"OCI": {"Process": {"NoNewPrivileges": false}}},
    "category": "kubelet-or-containerd",
    "operation": "default",
    "subject": subject.id,
    "target": {"path": "/OCI/Process/NoNewPrivileges"},
  }
]

# Defaults the application root filesystem to writable only when trusted
# workload IR does not already require a read-only root filesystem.
root_readonly_claims(ir) := [claim |
  some subject in ir.subjects
  subject.role == "application"
  not "/OCI/Root/Readonly" in subject.owned_paths
  claim := {
    "addition": {"OCI": {"Root": {"Readonly": false}}},
    "category": "kubelet-or-containerd",
    "operation": "default",
    "subject": subject.id,
    "target": {"path": "/OCI/Root/Readonly"},
  }
]

default_capabilities := [
  "CAP_CHOWN",
  "CAP_DAC_OVERRIDE",
  "CAP_FSETID",
  "CAP_FOWNER",
  "CAP_MKNOD",
  "CAP_NET_RAW",
  "CAP_SETGID",
  "CAP_SETUID",
  "CAP_SETFCAP",
  "CAP_SETPCAP",
  "CAP_NET_BIND_SERVICE",
  "CAP_SYS_CHROOT",
  "CAP_KILL",
  "CAP_AUDIT_WRITE",
]

default_capability_set := {capability: true | some capability in default_capabilities}

capability_drop_set(subject) := {capability | some capability in subject.capability_drops}

allowed_default_capabilities(subject) := set() if {
  count({"ALL"} & capability_drop_set(subject)) == 1
}

allowed_default_capabilities(subject) := allowed if {
  count({"ALL"} & capability_drop_set(subject)) == 0
  allowed := {capability | some capability in default_capabilities} - capability_drop_set(subject)
}

base_capabilities(subject) := [capability |
  some capability in default_capabilities
  capability in allowed_default_capabilities(subject)
]

capability_add_set(subject) := {
  capability |
  some capability in subject.capability_adds
  capability != "ALL"
}

new_capability_add_set(subject) := capability_add_set(subject) - allowed_default_capabilities(subject)

capability_additions(subject) := [capability |
  some capability in subject.capability_adds
  capability in new_capability_add_set(subject)
]

effective_capabilities(subject) := array.concat(
  base_capabilities(subject),
  capability_additions(subject),
)

capability_specs(subject) := [
  {"field": "Ambient", "value": []},
  {"field": "Bounding", "value": effective_capabilities(subject)},
  {"field": "Effective", "value": effective_capabilities(subject)},
  {"field": "Inheritable", "value": []},
  {"field": "Permitted", "value": effective_capabilities(subject)},
]

# Materializes all five OCI capability arrays after applying Kubernetes add/drop
# intent to the reviewed containerd default capability set.
capability_claims(ir) := [claim |
  some subject in ir.subjects
  subject.role == "application"
  some spec in capability_specs(subject)
  claim := {
    "addition": {"OCI": {"Process": {"Capabilities": {spec.field: spec.value}}}},
    "category": "kubelet-or-containerd",
    "operation": "default",
    "subject": subject.id,
    "target": {"path": sprintf("/OCI/Process/Capabilities/%s", [spec.field])},
  }
]

# Returns the complete kubelet/containerd mutation set as one generated claim
# stream for composition and overlap validation.
generated_claims(ir) := array.concat(annotation_claims(ir), array.concat(
  constant_default_claims(ir),
  array.concat(
    no_new_privileges_claims(ir),
    array.concat(root_readonly_claims(ir), capability_claims(ir)),
  ),
))

# Every OCI field this fragment covers is now produced by a reviewed rule above
# or owned by the typed static IR, so it holds no materialization authority.
fragment := {
  "applies_to": {
    "containerd": ["v2.3.3"],
    "kubernetes": ["v1.33.13"]
  },
  "capture_provenance": "8b0ae298134cf114935b140f42fc2ca8a8294a674ecbeb58d4727ee2f33f00d2",
  "category": "kubelet-or-containerd",
  "claims": [],
  "materialization_contracts": [],
  "schema_version": 1,
  "scope": "profile"
}