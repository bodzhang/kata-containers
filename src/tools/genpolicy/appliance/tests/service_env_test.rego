package agent_policy

policy_data := json.unmarshal(`{
	"common": {
		"ipv4_a": "(?:[0-9]{1,3}\\.){3}[0-9]{1,3}",
		"ip_p": "[0-9]{1,5}",
		"svc_name_downward_env": "[A-Z_]+",
		"dns_label": "[a-zA-Z0-9.-]+",
		"substitutions": {
			"ipv4_a": "$(ipv4_a)",
			"ip_p": "$(ip_p)",
			"svc_name_downward_env": "$(svc_name_downward_env)",
			"dns_label": "$(dns_label)",
			"unresolved_token_regex": "\\$\\([^)]+\\)"
		}
	},
	"request_defaults": {"CreateContainerRequest": {"allow_env_regex": []}}
}`)

service_env := "BACKEND_SERVICE_HOST=10.100.65.106"

test_captured_service_environment_allowed_for_selected_container if {
	process := {
		"Env": [],
		"EnvRegex": ["^BACKEND_SERVICE_HOST=(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$"],
	}
	allow_var(process, {}, service_env, "pod", "default")
}

test_captured_service_environment_denied_for_other_container if {
	process := {"Env": [], "EnvRegex": []}
	not allow_var(process, {}, service_env, "pod", "default")
}

test_undeclared_service_environment_name_denied if {
	process := {
		"Env": [],
		"EnvRegex": ["^BACKEND_SERVICE_HOST=(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$"],
	}
	not allow_var(
		process,
		{},
		"ATTACKER_SERVICE_HOST=10.100.65.106",
		"pod",
		"default",
	)
}

test_generated_service_environment_operand_allowed if {
	generated := object.union(policy_data, {
		"request_defaults": {"CreateContainerRequest": {
			"allow_env_regex": ["^BACKEND_SERVICE_HOST=$(ipv4_a)$"],
		}},
	})
	allow_var({"Env": [], "EnvRegex": []}, {}, service_env, "pod", "default")
		with data.agent_policy.policy_data as generated
}

test_unresolved_service_environment_token_denied if {
	generated := object.union(policy_data, {
		"request_defaults": {"CreateContainerRequest": {
			"allow_env_regex": ["^BACKEND_SERVICE_HOST=$(unknown)$"],
		}},
	})
	not allow_var({"Env": [], "EnvRegex": []}, {}, service_env, "pod", "default")
		with data.agent_policy.policy_data as generated
}
