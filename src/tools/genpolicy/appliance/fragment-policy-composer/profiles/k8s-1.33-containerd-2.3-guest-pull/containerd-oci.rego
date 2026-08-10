package profile_containerd_oci

# Supplies profile-wide containerd OCI defaults, including the OCI version and
# the CRI container role for application and sandbox subjects.
#
# Mutations:
# - /OCI/Version pins the OCI specification version emitted by containerd.
# - /OCI/Annotations/io.kubernetes.cri.container-type marks application
#   subjects as CRI containers.
# - /OCI/Annotations/io.kubernetes.cri.container-type marks sandbox subjects
#   as CRI sandboxes.
fragment := {
  "applies_to": {
    "containerd": ["v2.3.3"]
  },
  "capture_provenance": "8b0ae298134cf114935b140f42fc2ca8a8294a674ecbeb58d4727ee2f33f00d2",
  "category": "containerd-oci",
  "claims": [
    {
      "addition": {
        "OCI": {
          "Version": "1.1.0"
        }
      },
      "evidence": "captured-oci",
      "operation": "default",
      "scope": "profile",
      "target": {
        "cardinality": "all",
        "path": "/OCI/Version",
        "role": "all",
        "scope": "container"
      },
      "value": "1.1.0"
    },
    {
      "addition": {
        "OCI": {
          "Annotations": {
            "io.kubernetes.cri.container-type": "container"
          }
        }
      },
      "evidence": "cri-container-role",
      "operation": "default",
      "scope": "profile",
      "target": {
        "cardinality": "all",
        "path": "/OCI/Annotations/io.kubernetes.cri.container-type",
        "role": "application",
        "scope": "container"
      },
      "value": "container"
    },
    {
      "addition": {
        "OCI": {
          "Annotations": {
            "io.kubernetes.cri.container-type": "sandbox"
          }
        }
      },
      "evidence": "cri-container-role",
      "operation": "default",
      "scope": "profile",
      "target": {
        "cardinality": "all",
        "path": "/OCI/Annotations/io.kubernetes.cri.container-type",
        "role": "sandbox",
        "scope": "container"
      },
      "value": "sandbox"
    }
  ],
  "schema_version": 1,
  "scope": "profile"
}
