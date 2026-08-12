package profile_policy_framework_settings

# Defines profile-wide Agent framework constants and request defaults that do
# not depend on a particular workload or disposable cluster identity. These are
# the values GenPolicy would otherwise bake in from its own compiler settings;
# stating them as reviewable claims makes the profile, not the compiler, their
# owner.
#
# How the composer consumes each claim:
# - target.scope is "policy" throughout, so every claim lands in the single
#   shared policy_data object rather than fanning out per container subject.
# - target.path is the JSON pointer this fragment takes ownership of. The whole
#   policy fails closed if the static IR already owns that path or if another
#   fragment claims one that overlaps it, so ownership here is exclusive.
# - addition must be the one object branch that reaches target.path; a claim
#   cannot mutate anything outside the path it declares.
# - value restates the leaf that addition places, so a reviewer can diff intent
#   against effect without walking the nested object.
# - operation is "default" throughout: this fragment only establishes
#   baselines and never rewrites a value some other owner produced.
# - evidence records provenance, distinguishing a value read from compiler
#   settings from one chosen to be deliberately restrictive.
#
# applies_to is what the composer checks to accept this fragment, against the
# environment recorded in the static IR. It spans three dimensions because the
# claims below answer to three independent owners: containerd and runc supply
# the capability baselines and cgroup and pause conventions, Kubernetes supplies
# the Service-derived variable shape and pause image, and the remainder is Kata
# and Agent owned. Any one of the three moving invalidates the whole fragment,
# which is the cost of keeping them together.
#
# capture_provenance records which capture profile these mutations were
# discovered from. It is recorded for review, not enforced, so that this
# fragment can be replaced without regenerating the static IR.
#
# The fragment declares no materialization_contracts, so this category grants
# no authority to generated claims; every path below is fixed at review time.
#
# Claims whose value is an empty list are deny-by-default rather than
# placeholders: they clear a permission surface that the framework would
# otherwise apply globally, forcing workload-scoped rules to grant it
# explicitly. This is why allow_env_regex, both ExecProcessRequest lists,
# dmverity/allowed_roothashes, and guest_pull/allowed_images start empty.
#
# Keep comments above "fragment :=". Everything after that marker is parsed as
# JSON by scripts/generate_regorus_fragment_inputs.py and must stay JSON-valid.
#
# Common path and syntax mutations:
# - /framework parameterizes annotation names, role values, and the Pod log
#   directory format consumed by the version-independent RPC evaluator.
# - /common/cpath constrains the runtime shared-container directory.
# - /common/root_path parameterizes the container rootfs by bundle ID.
# - /common/root_bundle_id_regex constrains and captures root-path bundle IDs.
# - /common/copy_file_bundle_id_regex constrains CopyFile path bundle IDs.
# - /common/sfprefix constrains runtime-generated shared-file names.
# - /common/spath pins the sandbox storage directory.
# - /common/ipv4_a constrains IPv4 values accepted by framework rules.
# - /common/ip_p constrains network port values.
# - /common/svc_name_downward_env constrains Service-derived variable names.
# - /common/dns_label constrains DNS-label values.
# - /common/default_caps defines the unprivileged container capability baseline.
# - /common/privileged_caps defines the reviewed privileged capability set.
#
# Sandbox and request-default mutations:
# - /sandbox/storages pins the sandbox shared-memory tmpfs.
# - /request_defaults/AddARPNeighborsRequest/allowed_flags limits neighbor
#   updates to the reviewed netlink flag bits.
# - /request_defaults/AddARPNeighborsRequest/required_ip_address_mask requires
#   the runtime neighbor address shape expected by this profile.
# - /request_defaults/AddARPNeighborsRequest/allowed_states limits neighbor
#   updates to the reviewed NUD states.
# - /request_defaults/AddARPNeighborsRequest/forbidden_cidrs_regex blocks
#   loopback neighbor addresses.
# - /request_defaults/AddARPNeighborsRequest/forbidden_device_names blocks the
#   loopback device.
# - /request_defaults/CloseStdinRequest disables closing standard input.
# - /request_defaults/CreateContainerRequest/allow_env_regex clears the global
#   environment regex allowlist so workload-scoped rules own dynamic values.
# - /request_defaults/ExecProcessRequest/allowed_commands clears globally
#   allowed exact exec commands.
# - /request_defaults/ExecProcessRequest/regex clears globally allowed exec
#   command regexes.
# - /request_defaults/GetDiagnosticDataRequest disables diagnostic collection.
# - /request_defaults/ReadStreamRequest disables stream reads.
# - /request_defaults/UpdateEphemeralMountsRequest disables ephemeral updates.
# - /request_defaults/UpdateInterfaceRequest/allow_raw_flags permits only the
#   reviewed raw interface flag mask.
# - /request_defaults/UpdateInterfaceRequest/forbidden_hw_addrs blocks the null
#   hardware address.
# - /request_defaults/UpdateInterfaceRequest/forbidden_names blocks loopback.
# - /request_defaults/UpdateRoutesRequest/forbidden_device_names blocks routes
#   through loopback.
# - /request_defaults/UpdateRoutesRequest/forbidden_source_regex blocks IPv4
#   and IPv6 loopback route sources.
# - /request_defaults/WriteStreamRequest disables stream writes.
#
# Device, cluster, and rootfs mutations:
# - /devices/vfio/device_path pins the Kata VFIO device path prefix.
# - /devices/vfio/cdi_annotation_prefix pins the CDI VFIO annotation prefix.
# - /devices/vfio/device_number_regex constrains VFIO path and CDI suffixes.
# - /devices/vfio/device_id_prefix pins the Agent VFIO device ID prefix.
# - /devices/vfio/pci_address_regex constrains VFIO PCI mapping options.
# - /devices/vfio/nvidia initializes reviewed NVIDIA VFIO settings.
# - /cluster_config/pause_container_image pins the profile pause image.
# - /cluster_config/guest_pull enables the selected guest-pull transport.
# - /cluster_config/pause_container_id_policy selects pause ID policy v1.
# - /cluster_config/emptydir_type selects encrypted block emptyDir by default.
# - /cluster_config/cgroup_mount_extras_allowed limits accepted cgroup options.
# - /cluster_config/mount_compatibility parameterizes sysfs and cgroup mount
#   compatibility operands.
# - /cluster_config/rootfs_compatibility parameterizes runtime rootfs storage
#   representations while stable marker semantics remain evaluator-owned.
# - /dmverity/allowed_roothashes starts with no global dm-verity authorization.
# - /guest_pull/allowed_images starts with no global image authorization.
fragment := {
  "applies_to": {
    "containerd": ["v2.3.3"],
    "kubernetes": ["v1.33.13"],
    "runc": ["v1.2.8"]
  },
  "capture_provenance": "8b0ae298134cf114935b140f42fc2ca8a8294a674ecbeb58d4727ee2f33f00d2",
  "category": "policy-framework-settings",
  "claims": [
    {
      "addition": {"evaluator_schema_version": 1},
      "evidence": "evaluator-contract",
      "operation": "default",
      "scope": "profile",
      "target": {"path": "/evaluator_schema_version", "scope": "policy"},
      "value": 1
    },
    {
      "addition": {
        "framework": {
          "annotations": {
            "container_name": "io.kubernetes.cri.container-name",
            "cri_container_type": "io.kubernetes.cri.container-type",
            "cri_prefix": "io.kubernetes.cri.",
            "kata_container_type": "io.katacontainers.pkg.oci.container_type",
            "network_namespace": "nerdctl/network-namespace",
            "sandbox_id": "io.kubernetes.cri.sandbox-id",
            "sandbox_log_directory": "io.kubernetes.cri.sandbox-log-directory",
            "sandbox_name": "io.kubernetes.cri.sandbox-name",
            "sandbox_namespace": "io.kubernetes.cri.sandbox-namespace",
            "sandbox_uid": "io.kubernetes.cri.sandbox-uid"
          },
          "paths": {
            "pod_log_directory_format": "/var/log/pods/%s_%s_%s"
          },
          "roles": {
            "cri_container": "container",
            "cri_sandbox": "sandbox",
            "kata_container": "pod_container",
            "kata_sandbox": "pod_sandbox"
          }
        }
      },
      "evidence": "profile-compatibility-contract",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/framework",
        "scope": "policy"
      },
      "value": {
        "annotations": {
          "container_name": "io.kubernetes.cri.container-name",
          "cri_container_type": "io.kubernetes.cri.container-type",
          "cri_prefix": "io.kubernetes.cri.",
          "kata_container_type": "io.katacontainers.pkg.oci.container_type",
          "network_namespace": "nerdctl/network-namespace",
          "sandbox_id": "io.kubernetes.cri.sandbox-id",
          "sandbox_log_directory": "io.kubernetes.cri.sandbox-log-directory",
          "sandbox_name": "io.kubernetes.cri.sandbox-name",
          "sandbox_namespace": "io.kubernetes.cri.sandbox-namespace",
          "sandbox_uid": "io.kubernetes.cri.sandbox-uid"
        },
        "paths": {
          "pod_log_directory_format": "/var/log/pods/%s_%s_%s"
        },
        "roles": {
          "cri_container": "container",
          "cri_sandbox": "sandbox",
          "kata_container": "pod_container",
          "kata_sandbox": "pod_sandbox"
        }
      }
    },
    {
      "addition": {"common": {"substitutions": {
        "cpath": "$(cpath)", "root_path": "$(root_path)",
        "bundle_id": "$(bundle-id)", "sandbox_id": "$(sandbox-id)",
        "sandbox_name": "$(sandbox-name)", "sandbox_namespace": "$(sandbox-namespace)",
        "sfprefix": "$(sfprefix)", "spath": "$(spath)",
        "b64_device_id": "$(b64_device_id)", "node_name": "$(node-name)",
        "host_name": "$(host-name)", "pod_uid": "$(pod-uid)",
        "resource_field": "$(resource-field)", "todo_annotation": "$(todo-annotation)",
        "pod_ip": "$(pod-ip)", "host_ip": "$(host-ip)",
        "ipv4_a": "$(ipv4_a)", "ip_p": "$(ip_p)",
        "svc_name_downward_env": "$(svc_name_downward_env)", "dns_label": "$(dns_label)",
        "escape_marker": "$$", "escaped_value": "$",
        "unresolved_token_regex": "\\$\\([^)]+\\)"
      }}},
      "evidence": "profile-compatibility-contract",
      "operation": "default",
      "scope": "profile",
      "target": {"path": "/common/substitutions", "scope": "policy"},
      "value": {
        "cpath": "$(cpath)", "root_path": "$(root_path)",
        "bundle_id": "$(bundle-id)", "sandbox_id": "$(sandbox-id)",
        "sandbox_name": "$(sandbox-name)", "sandbox_namespace": "$(sandbox-namespace)",
        "sfprefix": "$(sfprefix)", "spath": "$(spath)",
        "b64_device_id": "$(b64_device_id)", "node_name": "$(node-name)",
        "host_name": "$(host-name)", "pod_uid": "$(pod-uid)",
        "resource_field": "$(resource-field)", "todo_annotation": "$(todo-annotation)",
        "pod_ip": "$(pod-ip)", "host_ip": "$(host-ip)",
        "ipv4_a": "$(ipv4_a)", "ip_p": "$(ip_p)",
        "svc_name_downward_env": "$(svc_name_downward_env)", "dns_label": "$(dns_label)",
        "escape_marker": "$$", "escaped_value": "$",
        "unresolved_token_regex": "\\$\\([^)]+\\)"
      }
    },
    {
      "addition": {"common": {"request_shape": {
        "copy_file_default_size": 0,
        "copy_file_default_offset": 0,
        "copy_file_minimum_value": 0,
        "create_sandbox_pidns": false,
        "exec_process_default_port": 0
      }}},
      "evidence": "profile-compatibility-contract",
      "operation": "default",
      "scope": "profile",
      "target": {"path": "/common/request_shape", "scope": "policy"},
      "value": {
        "copy_file_default_size": 0,
        "copy_file_default_offset": 0,
        "copy_file_minimum_value": 0,
        "create_sandbox_pidns": false,
        "exec_process_default_port": 0
      }
    },
    {
      "addition": {
        "common": {
          "cpath": "/run/kata-containers/shared/containers(?:/passthrough)?"
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/common/cpath",
        "scope": "policy"
      },
      "value": "/run/kata-containers/shared/containers(?:/passthrough)?"
    },
    {
      "addition": {
        "common": {
          "root_path": "/run/kata-containers/$(bundle-id)/rootfs"
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/common/root_path",
        "scope": "policy"
      },
      "value": "/run/kata-containers/$(bundle-id)/rootfs"
    },
    {
      "addition": {
        "common": {
          "root_bundle_id_regex": "([0-9a-f]{64}|[a-z0-9][a-z0-9.-]*)"
        }
      },
      "evidence": "profile-compatibility-contract",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/common/root_bundle_id_regex",
        "scope": "policy"
      },
      "value": "([0-9a-f]{64}|[a-z0-9][a-z0-9.-]*)"
    },
    {
      "addition": {
        "common": {
          "copy_file_bundle_id_regex": "[a-z0-9]{64}"
        }
      },
      "evidence": "profile-compatibility-contract",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/common/copy_file_bundle_id_regex",
        "scope": "policy"
      },
      "value": "[a-z0-9]{64}"
    },
    {
      "addition": {"common": {"namespace_compatibility": {
        "aliases": {"mount": "mnt"},
        "ignored_input_types": ["network", "cgroup"],
        "network_type": "network"
      }}},
      "evidence": "profile-compatibility-contract",
      "operation": "default",
      "scope": "profile",
      "target": {"path": "/common/namespace_compatibility", "scope": "policy"},
      "value": {
        "aliases": {"mount": "mnt"},
        "ignored_input_types": ["network", "cgroup"],
        "network_type": "network"
      }
    },
    {
      "addition": {"common": {"capability_compatibility": {
        "prefix": "CAP_",
        "default_marker": "$(default_caps)",
        "privileged_marker": "$(privileged_caps)"
      }}},
      "evidence": "profile-compatibility-contract",
      "operation": "default",
      "scope": "profile",
      "target": {"path": "/common/capability_compatibility", "scope": "policy"},
      "value": {
        "prefix": "CAP_",
        "default_marker": "$(default_caps)",
        "privileged_marker": "$(privileged_caps)"
      }
    },
    {
      "addition": {"common": {"copy_file_compatibility": {
        "regular_type": "Regular",
        "directory_type": "Directory",
        "symlink_type": "Symlink",
        "traversal_regex": "(^|/)\\.\\.($|/)",
        "symlink_path_suffix": ".*/.+"
      }}},
      "evidence": "profile-compatibility-contract",
      "operation": "default",
      "scope": "profile",
      "target": {"path": "/common/copy_file_compatibility", "scope": "policy"},
      "value": {
        "regular_type": "Regular",
        "directory_type": "Directory",
        "symlink_type": "Symlink",
        "traversal_regex": "(^|/)\\.\\.($|/)",
        "symlink_path_suffix": ".*/.+"
      }
    },
    {
      "addition": {
        "common": {
          "sfprefix": "^$(cpath)/(watchable/)?$(bundle-id)-[a-z0-9]{16}-"
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/common/sfprefix",
        "scope": "policy"
      },
      "value": "^$(cpath)/(watchable/)?$(bundle-id)-[a-z0-9]{16}-"
    },
    {
      "addition": {
        "common": {
          "spath": "/run/kata-containers/sandbox/storage"
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/common/spath",
        "scope": "policy"
      },
      "value": "/run/kata-containers/sandbox/storage"
    },
    {
      "addition": {
        "common": {
          "ipv4_a": "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/common/ipv4_a",
        "scope": "policy"
      },
      "value": "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
    },
    {
      "addition": {
        "common": {
          "ip_p": "[0-9]{1,5}"
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/common/ip_p",
        "scope": "policy"
      },
      "value": "[0-9]{1,5}"
    },
    {
      "addition": {
        "common": {
          "svc_name_downward_env": "[A-Z](?:[A-Z0-9_]{0,61}[A-Z0-9])?"
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/common/svc_name_downward_env",
        "scope": "policy"
      },
      "value": "[A-Z](?:[A-Z0-9_]{0,61}[A-Z0-9])?"
    },
    {
      "addition": {
        "common": {
          "dns_label": "[a-zA-Z0-9_\\.\\-]+"
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/common/dns_label",
        "scope": "policy"
      },
      "value": "[a-zA-Z0-9_\\.\\-]+"
    },
    {
      "addition": {
        "common": {
          "default_caps": [
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
            "CAP_AUDIT_WRITE"
          ]
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/common/default_caps",
        "scope": "policy"
      },
      "value": [
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
        "CAP_AUDIT_WRITE"
      ]
    },
    {
      "addition": {
        "common": {
          "privileged_caps": [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_DAC_READ_SEARCH",
            "CAP_FOWNER",
            "CAP_FSETID",
            "CAP_KILL",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETPCAP",
            "CAP_LINUX_IMMUTABLE",
            "CAP_NET_BIND_SERVICE",
            "CAP_NET_BROADCAST",
            "CAP_NET_ADMIN",
            "CAP_NET_RAW",
            "CAP_IPC_LOCK",
            "CAP_IPC_OWNER",
            "CAP_SYS_MODULE",
            "CAP_SYS_RAWIO",
            "CAP_SYS_CHROOT",
            "CAP_SYS_PTRACE",
            "CAP_SYS_PACCT",
            "CAP_SYS_ADMIN",
            "CAP_SYS_BOOT",
            "CAP_SYS_NICE",
            "CAP_SYS_RESOURCE",
            "CAP_SYS_TIME",
            "CAP_SYS_TTY_CONFIG",
            "CAP_MKNOD",
            "CAP_LEASE",
            "CAP_AUDIT_WRITE",
            "CAP_AUDIT_CONTROL",
            "CAP_SETFCAP",
            "CAP_MAC_OVERRIDE",
            "CAP_MAC_ADMIN",
            "CAP_SYSLOG",
            "CAP_WAKE_ALARM",
            "CAP_BLOCK_SUSPEND",
            "CAP_AUDIT_READ",
            "CAP_PERFMON",
            "CAP_BPF",
            "CAP_CHECKPOINT_RESTORE"
          ]
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/common/privileged_caps",
        "scope": "policy"
      },
      "value": [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_DAC_READ_SEARCH",
        "CAP_FOWNER",
        "CAP_FSETID",
        "CAP_KILL",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETPCAP",
        "CAP_LINUX_IMMUTABLE",
        "CAP_NET_BIND_SERVICE",
        "CAP_NET_BROADCAST",
        "CAP_NET_ADMIN",
        "CAP_NET_RAW",
        "CAP_IPC_LOCK",
        "CAP_IPC_OWNER",
        "CAP_SYS_MODULE",
        "CAP_SYS_RAWIO",
        "CAP_SYS_CHROOT",
        "CAP_SYS_PTRACE",
        "CAP_SYS_PACCT",
        "CAP_SYS_ADMIN",
        "CAP_SYS_BOOT",
        "CAP_SYS_NICE",
        "CAP_SYS_RESOURCE",
        "CAP_SYS_TIME",
        "CAP_SYS_TTY_CONFIG",
        "CAP_MKNOD",
        "CAP_LEASE",
        "CAP_AUDIT_WRITE",
        "CAP_AUDIT_CONTROL",
        "CAP_SETFCAP",
        "CAP_MAC_OVERRIDE",
        "CAP_MAC_ADMIN",
        "CAP_SYSLOG",
        "CAP_WAKE_ALARM",
        "CAP_BLOCK_SUSPEND",
        "CAP_AUDIT_READ",
        "CAP_PERFMON",
        "CAP_BPF",
        "CAP_CHECKPOINT_RESTORE"
      ]
    },
    {
      "addition": {
        "sandbox": {
          "storages": [
            {
              "driver": "ephemeral",
              "driver_options": [],
              "fs_group": null,
              "fstype": "tmpfs",
              "mount_point": "/run/kata-containers/sandbox/shm",
              "options": [
                "noexec",
                "nosuid",
                "nodev",
                "mode=1777",
                "size=67108864"
              ],
              "shared": false,
              "source": "shm"
            }
          ]
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/sandbox/storages",
        "scope": "policy"
      },
      "value": [
        {
          "driver": "ephemeral",
          "driver_options": [],
          "fs_group": null,
          "fstype": "tmpfs",
          "mount_point": "/run/kata-containers/sandbox/shm",
          "options": [
            "noexec",
            "nosuid",
            "nodev",
            "mode=1777",
            "size=67108864"
          ],
          "shared": false,
          "source": "shm"
        }
      ]
    },
    {
      "addition": {
        "request_defaults": {
          "AddARPNeighborsRequest": {
            "allowed_flags": 136
          }
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/AddARPNeighborsRequest/allowed_flags",
        "scope": "policy"
      },
      "value": 136
    },
    {
      "addition": {
        "request_defaults": {
          "AddARPNeighborsRequest": {
            "required_ip_address_mask": ""
          }
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/AddARPNeighborsRequest/required_ip_address_mask",
        "scope": "policy"
      },
      "value": ""
    },
    {
      "addition": {
        "request_defaults": {
          "AddARPNeighborsRequest": {
            "allowed_states": [
              2,
              128
            ]
          }
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/AddARPNeighborsRequest/allowed_states",
        "scope": "policy"
      },
      "value": [
        2,
        128
      ]
    },
    {
      "addition": {
        "request_defaults": {
          "AddARPNeighborsRequest": {
            "forbidden_cidrs_regex": [
              "^127\\.(?:[0-9]{1,3}\\.){2}[0-9]{1,3}$"
            ]
          }
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/AddARPNeighborsRequest/forbidden_cidrs_regex",
        "scope": "policy"
      },
      "value": [
        "^127\\.(?:[0-9]{1,3}\\.){2}[0-9]{1,3}$"
      ]
    },
    {
      "addition": {
        "request_defaults": {
          "AddARPNeighborsRequest": {
            "forbidden_device_names": [
              "lo"
            ]
          }
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/AddARPNeighborsRequest/forbidden_device_names",
        "scope": "policy"
      },
      "value": [
        "lo"
      ]
    },
    {
      "addition": {
        "request_defaults": {
          "CloseStdinRequest": false
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/CloseStdinRequest",
        "scope": "policy"
      },
      "value": false
    },
    {
      "addition": {
        "request_defaults": {
          "CreateContainerRequest": {
            "allow_env_regex": []
          }
        }
      },
      "evidence": "compiler-security-default",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/CreateContainerRequest/allow_env_regex",
        "scope": "policy"
      },
      "value": []
    },
    {
      "addition": {
        "request_defaults": {
          "ExecProcessRequest": {
            "allowed_commands": []
          }
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/ExecProcessRequest/allowed_commands",
        "scope": "policy"
      },
      "value": []
    },
    {
      "addition": {
        "request_defaults": {
          "ExecProcessRequest": {
            "regex": []
          }
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/ExecProcessRequest/regex",
        "scope": "policy"
      },
      "value": []
    },
    {
      "addition": {
        "request_defaults": {
          "GetDiagnosticDataRequest": false
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/GetDiagnosticDataRequest",
        "scope": "policy"
      },
      "value": false
    },
    {
      "addition": {
        "request_defaults": {
          "ReadStreamRequest": false
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/ReadStreamRequest",
        "scope": "policy"
      },
      "value": false
    },
    {
      "addition": {
        "request_defaults": {
          "UpdateEphemeralMountsRequest": false
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/UpdateEphemeralMountsRequest",
        "scope": "policy"
      },
      "value": false
    },
    {
      "addition": {
        "request_defaults": {
          "UpdateInterfaceRequest": {
            "allow_raw_flags": 128
          }
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/UpdateInterfaceRequest/allow_raw_flags",
        "scope": "policy"
      },
      "value": 128
    },
    {
      "addition": {
        "request_defaults": {
          "UpdateInterfaceRequest": {
            "forbidden_hw_addrs": [
              "00:00:00:00:00:00"
            ]
          }
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/UpdateInterfaceRequest/forbidden_hw_addrs",
        "scope": "policy"
      },
      "value": [
        "00:00:00:00:00:00"
      ]
    },
    {
      "addition": {
        "request_defaults": {
          "UpdateInterfaceRequest": {
            "forbidden_names": [
              "lo"
            ]
          }
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/UpdateInterfaceRequest/forbidden_names",
        "scope": "policy"
      },
      "value": [
        "lo"
      ]
    },
    {
      "addition": {
        "request_defaults": {
          "UpdateRoutesRequest": {
            "forbidden_device_names": [
              "lo"
            ]
          }
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/UpdateRoutesRequest/forbidden_device_names",
        "scope": "policy"
      },
      "value": [
        "lo"
      ]
    },
    {
      "addition": {
        "request_defaults": {
          "UpdateRoutesRequest": {
            "forbidden_source_regex": [
              "^(?:0{0,4}:){0,7}0{0,3}1$",
              "^127\\.(?:[0-9]{1,3}\\.){2}[0-9]{1,3}$"
            ]
          }
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/UpdateRoutesRequest/forbidden_source_regex",
        "scope": "policy"
      },
      "value": [
        "^(?:0{0,4}:){0,7}0{0,3}1$",
        "^127\\.(?:[0-9]{1,3}\\.){2}[0-9]{1,3}$"
      ]
    },
    {
      "addition": {
        "request_defaults": {
          "WriteStreamRequest": false
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/request_defaults/WriteStreamRequest",
        "scope": "policy"
      },
      "value": false
    },
    {
      "addition": {
        "devices": {
          "vfio": {
            "device_path": "/dev/vfio/devices/vfio"
          }
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/devices/vfio/device_path",
        "scope": "policy"
      },
      "value": "/dev/vfio/devices/vfio"
    },
    {
      "addition": {
        "devices": {
          "vfio": {
            "cdi_annotation_prefix": "cdi.k8s.io/vfio"
          }
        }
      },
      "evidence": "profile-compatibility-contract",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/devices/vfio/cdi_annotation_prefix",
        "scope": "policy"
      },
      "value": "cdi.k8s.io/vfio"
    },
    {
      "addition": {
        "devices": {
          "vfio": {
            "device_number_regex": "^[0-9]+$"
          }
        }
      },
      "evidence": "profile-compatibility-contract",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/devices/vfio/device_number_regex",
        "scope": "policy"
      },
      "value": "^[0-9]+$"
    },
    {
      "addition": {
        "devices": {
          "vfio": {
            "device_id_prefix": "vfio"
          }
        }
      },
      "evidence": "profile-compatibility-contract",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/devices/vfio/device_id_prefix",
        "scope": "policy"
      },
      "value": "vfio"
    },
    {
      "addition": {
        "devices": {
          "vfio": {
            "pci_address_regex": "^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[01][0-9a-fA-F]\\.[0-7]=[0-9a-fA-F]{2}/[0-9a-fA-F]{2}$"
          }
        }
      },
      "evidence": "profile-compatibility-contract",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/devices/vfio/pci_address_regex",
        "scope": "policy"
      },
      "value": "^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[01][0-9a-fA-F]\\.[0-7]=[0-9a-fA-F]{2}/[0-9a-fA-F]{2}$"
    },
    {
      "addition": {
        "devices": {
          "vfio": {
            "nvidia": {}
          }
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/devices/vfio/nvidia",
        "scope": "policy"
      },
      "value": {}
    },
    {
      "addition": {
        "cluster_config": {
          "pause_container_image": "genpolicy.local:5000/pause:3.10"
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/cluster_config/pause_container_image",
        "scope": "policy"
      },
      "value": "genpolicy.local:5000/pause:3.10"
    },
    {
      "addition": {
        "cluster_config": {
          "guest_pull": true
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/cluster_config/guest_pull",
        "scope": "policy"
      },
      "value": true
    },
    {
      "addition": {
        "cluster_config": {
          "pause_container_id_policy": "v1"
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/cluster_config/pause_container_id_policy",
        "scope": "policy"
      },
      "value": "v1"
    },
    {
      "addition": {
        "cluster_config": {
          "emptydir_type": "block-encrypted"
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/cluster_config/emptydir_type",
        "scope": "policy"
      },
      "value": "block-encrypted"
    },
    {
      "addition": {
        "cluster_config": {
          "cgroup_mount_extras_allowed": [
            "nsdelegate",
            "memory_recursiveprot"
          ]
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/cluster_config/cgroup_mount_extras_allowed",
        "scope": "policy"
      },
      "value": [
        "nsdelegate",
        "memory_recursiveprot"
      ]
    },
    {
      "addition": {
        "cluster_config": {
          "mount_compatibility": {
            "sysfs_type": "sysfs",
            "sysfs_policy_read_write_option": "rw",
            "sysfs_request_read_only_option": "ro",
            "cgroup_type": "cgroup"
          }
        }
      },
      "evidence": "profile-compatibility-contract",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/cluster_config/mount_compatibility",
        "scope": "policy"
      },
      "value": {
        "sysfs_type": "sysfs",
        "sysfs_policy_read_write_option": "rw",
        "sysfs_request_read_only_option": "ro",
        "cgroup_type": "cgroup"
      }
    },
    {
      "addition": {
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
        }
      },
      "evidence": "profile-compatibility-contract",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/cluster_config/rootfs_compatibility",
        "scope": "policy"
      },
      "value": {
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
    {
      "addition": {
        "dmverity": {
          "allowed_roothashes": []
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/dmverity/allowed_roothashes",
        "scope": "policy"
      },
      "value": []
    },
    {
      "addition": {
        "guest_pull": {
          "allowed_images": []
        }
      },
      "evidence": "compiler-settings",
      "operation": "default",
      "scope": "profile",
      "target": {
        "path": "/guest_pull/allowed_images",
        "scope": "policy"
      },
      "value": []
    }
  ],
  "schema_version": 1,
  "scope": "profile"
}
