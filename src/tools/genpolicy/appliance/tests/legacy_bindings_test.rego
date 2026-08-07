package agent_policy

policy_data := {}

legacy_sandbox_id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
legacy_pod_uid := "12345678-1234-4234-8234-123456789abc"
legacy_other_pod_uid := "87654321-4321-4321-8321-cba987654321"
legacy_pod_name := "demo-abcde"
legacy_pod_namespace := "default"

legacy_identity := {
	"pod_name": legacy_pod_name,
	"pod_namespace": legacy_pod_namespace,
	"pod_uid": legacy_pod_uid,
}

legacy_binding_state := {
	pod_identity_state_key(legacy_sandbox_id): legacy_identity,
}

legacy_request(container_type, pod_uid, pod_name, pod_namespace) := {
	"Annotations": {
		"io.kubernetes.cri.container-type": container_type,
		S_ID_KEY: legacy_sandbox_id,
		S_LOG_DIRECTORY_KEY: sprintf(
			"/var/log/pods/%s_%s_%s",
			[pod_namespace, pod_name, pod_uid],
		),
		S_NAME_KEY: pod_name,
		S_NAMESPACE_KEY: pod_namespace,
		S_UID_KEY: pod_uid,
	},
}

test_legacy_first_request_binds_pod_identity if {
	action := bind_or_match_pod_identity(legacy_request("sandbox", legacy_pod_uid, legacy_pod_name, legacy_pod_namespace)) with data.pstate as {}
	action == {
		"op": "add",
		"path": concat("", ["/pstate/pod_identity.", legacy_sandbox_id]),
		"value": legacy_identity,
	}
}

test_legacy_matching_application_reuses_pod_identity if {
	action := bind_or_match_pod_identity(legacy_request("container", legacy_pod_uid, legacy_pod_name, legacy_pod_namespace)) with data.pstate as legacy_binding_state
	action == null
}

test_legacy_different_valid_pod_uid_is_denied if {
	not bind_or_match_pod_identity(legacy_request("container", legacy_other_pod_uid, legacy_pod_name, legacy_pod_namespace)) with data.pstate as legacy_binding_state
}

test_legacy_different_valid_pod_name_is_denied if {
	not bind_or_match_pod_identity(legacy_request("container", legacy_pod_uid, "demo-fghij", legacy_pod_namespace)) with data.pstate as legacy_binding_state
}

test_legacy_different_valid_namespace_is_denied if {
	not bind_or_match_pod_identity(legacy_request("container", legacy_pod_uid, legacy_pod_name, "other")) with data.pstate as legacy_binding_state
}

test_legacy_sandbox_log_directory_must_match_identity if {
	request := legacy_request("sandbox", legacy_pod_uid, legacy_pod_name, legacy_pod_namespace)
	forged := object.union(request, {
		"Annotations": object.union(request.Annotations, {
			S_LOG_DIRECTORY_KEY: "/var/log/pods/default_other_12345678-1234-4234-8234-123456789abc",
		}),
	})
	not bind_or_match_pod_identity(forged) with data.pstate as {}
}

test_legacy_request_without_pod_uid_binds_available_identity if {
	request := legacy_request("container", legacy_pod_uid, legacy_pod_name, legacy_pod_namespace)
	annotations := object.remove(request.Annotations, {S_UID_KEY})
	action := bind_or_match_pod_identity({"Annotations": annotations}) with data.pstate as {}
	action.value == {
		"pod_name": legacy_pod_name,
		"pod_namespace": legacy_pod_namespace,
		"pod_uid": null,
	}
}
