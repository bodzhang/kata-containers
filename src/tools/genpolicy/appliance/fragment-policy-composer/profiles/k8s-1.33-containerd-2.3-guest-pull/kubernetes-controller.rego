package profile_kubernetes_controller

# Derives the names Kubernetes controllers generate for the Pods they own. The
# sandbox-name annotation is a function of typed controller identity -- the kind
# and name of the workload object -- so it is produced here rather than copied
# out of a host capture.

sandbox_name_path := "/OCI/Annotations/io.kubernetes.cri.sandbox-name"

# rand.SafeEncodeString draws from an alphabet chosen to avoid accidental words.
# https://github.com/kubernetes/kubernetes/blob/b35c5c0a301d326fdfa353943fca077778544ac6/pkg/controller/controller_utils.go#L541
#
# The quantifier is unbounded because that is what the generator emits today.
# Both the pod-template-hash and the Pod suffix are in fact fixed-width, so this
# grammar is looser than the controllers can actually produce; tightening it is
# a change to the generator that has to land together with a regenerated capture.
generate_name_suffix := "[bcdfghjklmnpqrstvwxz2456789]+"

# The workload name is spliced into a regular expression, so a name carrying
# metacharacters would widen the pattern rather than narrow it. Only RFC 1123
# subdomains are accepted and their single legal metacharacter -- the dot -- is
# escaped. An unexpected name leaves this undefined, no claim is emitted, and
# composition fails closed on the uncovered path.
escaped_name(name) := replace(name, ".", "\\.") if {
	regex.match("^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$", name)
}

# A Deployment names a ReplicaSet after itself plus the pod-template-hash, and
# the ReplicaSet then names the Pod after itself plus a generated suffix.
pod_name_pattern("Deployment", name) := sprintf("^%s-%s-%s$", [escaped_name(name), generate_name_suffix, generate_name_suffix])

pod_name_pattern("ReplicaSet", name) := sprintf("^%s-%s$", [escaped_name(name), generate_name_suffix])

pod_name_pattern("ReplicationController", name) := sprintf("^%s-%s$", [escaped_name(name), generate_name_suffix])

pod_name_pattern("DaemonSet", name) := sprintf("^%s-%s$", [escaped_name(name), generate_name_suffix])

# StatefulSet Pods are ordinal, not random.
pod_name_pattern("StatefulSet", name) := sprintf("^%s-[0-9]+$", [escaped_name(name)])

# Indexed Jobs insert the completion index between the Job name and the suffix.
# https://github.com/kubernetes/kubernetes/blob/b35c5c0a301d326fdfa353943fca077778544ac6/pkg/controller/job/indexed_job_utils.go#L501
pod_name_pattern("Job", name) := sprintf("^%s(-[0-9]+)?-%s$", [escaped_name(name), generate_name_suffix])

# A CronJob names the Job after itself plus the schedule timestamp, and the Job
# then names the Pod.
pod_name_pattern("CronJob", name) := sprintf("^%s-[0-9]+(-[0-9]+)?-%s$", [escaped_name(name), generate_name_suffix])

# A bare Pod carries the name it was submitted with.
pod_name_pattern("Pod", name) := sprintf("^%s$", [escaped_name(name)])

sandbox_name_claims(ir) := [claim |
	some subject in ir.subjects
	not sandbox_name_path in subject.owned_paths
	pattern := pod_name_pattern(subject.workload.kind, subject.workload.name)
	claim := {
		"addition": {"OCI": {"Annotations": {"io.kubernetes.cri.sandbox-name": pattern}}},
		"category": "kubernetes-controller",
		"operation": "derive",
		"subject": subject.id,
		"target": {"path": sandbox_name_path},
	}
]

fragment := {
  "applies_to": {
    "rootfs_mode": ["guest-pull"]
  },
  "capture_provenance": "8b0ae298134cf114935b140f42fc2ca8a8294a674ecbeb58d4727ee2f33f00d2",
  "category": "kubernetes-controller",
  "claims": [],
  "materialization_contracts": [],
  "schema_version": 1,
  "scope": "profile"
}
