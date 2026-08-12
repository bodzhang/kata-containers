package fragment_composer

semantic_operations := {"default", "derive", "envelope", "generate", "normalize", "resolve", "rewrite"}

selected_fragments := array.concat(
	data.selected_profile_fragments.fragments,
	data.selected_materializations.materializations,
)

profile_generated_claims(ir) := array.concat(
	data.profile_kubelet_or_containerd.generated_claims(ir),
	array.concat(
		data.profile_kubelet_resolution.service_link_claims(ir),
		array.concat(
			array.concat(
				data.profile_runtime_rs.volume_mount_claims(ir),
				data.profile_runtime_rs.device_claims(ir),
			),
			array.concat(
				array.concat(
					data.profile_runtime_rs_envelope.volume_storage_claims(ir),
					data.profile_runtime_rs_envelope.copy_file_claims(ir),
				),
				array.concat(
					data.profile_runtime_rs_envelope.device_claims(ir),
					data.profile_runtime_rs_envelope.runtime_pattern_claims(ir),
				),
			),
		),
	),
)

contract_path_valid(contract, path) if {
	path in object.get(contract, "paths", [])
}

contract_path_valid(contract, path) if {
	pattern := object.get(contract, "path_regex", "^$")
	startswith(pattern, "^")
	endswith(pattern, "$")
	regex.match(pattern, path)
}

materialization_contract_valid(profile_fragments, fragment, claim) if {
	fragment.scope == "static-base-materialization"
	some profile_fragment in profile_fragments
	profile_fragment.category == fragment.category
	some contract in object.get(profile_fragment, "materialization_contracts", [])
	claim.operation in contract.operations
	contract_path_valid(contract, claim.target.path)
}

category_claim_valid("policy-framework-settings", claim) if {
	claim.target.path != "/containers"
	startswith(claim.target.path, "/")
}

category_claim_valid("containerd-oci", claim) if {
	claim.operation in {"default", "normalize"}
	startswith(claim.target.path, "/OCI/")
}

category_claim_valid("kubernetes-controller", claim) if {
	claim.operation in {"derive", "generate"}
	startswith(claim.target.path, "/OCI/Annotations/")
}

kubelet_resolution_path(path) if startswith(path, "/OCI/Process/Env/")

kubelet_resolution_path(path) if path == "/OCI/Process/EnvRegex"

category_claim_valid("kubelet-resolution", claim) if {
	claim.operation in {"derive", "resolve"}
	kubelet_resolution_path(claim.target.path)
}

category_claim_valid("kubelet-or-containerd", claim) if {
	claim.operation in {"default", "resolve"}
	startswith(claim.target.path, "/OCI/")
}

category_claim_valid("runtime-rs", claim) if {
	claim.operation == "rewrite"
	startswith(claim.target.path, "/OCI/")
}

category_claim_valid("runtime-rs-envelope", claim) if {
	claim.operation == "envelope"
	not startswith(claim.target.path, "/OCI/")
}

paths_overlap(first, second) if first == second
paths_overlap(first, second) if startswith(first, sprintf("%s/", [second]))
paths_overlap(first, second) if startswith(second, sprintf("%s/", [first]))

pointer_tokens(path) := [token |
	some raw in split(substring(path, 1, -1), "/")
	token := replace(replace(raw, "~1", "/"), "~0", "~")
]

# The applied mutation is the addition, so it must be the single-branch object
# rooted exactly at target.path; otherwise the path-based checks inspect
# metadata while an unrelated field is silently overwritten.
addition_rooted_at_target(claim) if {
	tokens := pointer_tokens(claim.target.path)
	count(tokens) > 0
	every index, token in tokens {
		object.keys(object.get(claim.addition, array.slice(tokens, 0, index), {})) == {token}
	}
}

# A profile fragment is accepted on declared applicability rather than on the
# capture hash, so a fragment can be replaced when the deployment profile moves
# without regenerating the static IR. Safety does not rest on this: claim
# ownership and overlap checks already stop any fragment from reaching an
# IR-owned path.
environment_satisfies(environment, applies_to) if {
	every dimension, allowed in applies_to {
		object.get(environment, [dimension], "") in allowed
	}
}

fragment_binding_valid(ir, fragment) if {
	fragment.schema_version == 1
	fragment.scope == "profile"
	not fragment.static_base_digest
	is_object(fragment.applies_to)
	environment_satisfies(ir.environment, fragment.applies_to)
}

# Materializations are derived from the static IR, so they stay pinned to it and
# are not runtime-replaceable.
fragment_binding_valid(ir, fragment) if {
	fragment.schema_version == 1
	fragment.scope == "static-base-materialization"
	fragment.static_base_digest == ir.static_base_digest
}

missing_required_categories(ir, fragments) := missing if {
	required := {category | some category in ir.requires.categories}
	present := {fragment.category | some fragment in fragments}
	missing := required - present
}

role_matches(subject, "all") if subject.role in {"application", "sandbox"}

role_matches(subject, role) if {
	role in {"application", "sandbox"}
	subject.role == role
}

target_subjects(_ir, target) := ["policy"] if {
	target.scope == "policy"
	object.keys(target) == {"path", "scope"}
}

target_subjects(ir, target) := subjects if {
	target.scope == "container"
	target.role in {"all", "application", "sandbox"}
	target.cardinality == "all"
	subjects := [subject.id |
		some subject in ir.subjects
		role_matches(subject, target.role)
	]
	count(subjects) > 0
}

target_subjects(ir, target) := subjects if {
	target.scope == "container"
	target.role in {"all", "application", "sandbox"}
	target.cardinality == "one"
	subjects := [subject.id |
		some subject in ir.subjects
		role_matches(subject, target.role)
	]
	count(subjects) == 1
}

target_subjects(ir, target) := [target.subject] if {
	is_string(target.subject)
	object.keys(target) == {"path", "subject"}
	selected := [subject |
		some subject in ir.subjects
		subject.id == target.subject
	]
	count(selected) == 1
}

target_subjects(_ir, target) := ["policy"] if {
	target.subject == "policy"
	object.keys(target) == {"path", "subject"}
}

target_valid(ir, target) if {
	count(target_subjects(ir, target)) > 0
}

claim_shape_valid(claim) if {
	claim.operation in semantic_operations
	is_string(claim.target.path)
	startswith(claim.target.path, "/")
	claim.target.path != "/"
	is_object(claim.addition)
	addition_rooted_at_target(claim)
}

generated_subject_valid(_ir, subject_id) if subject_id == "policy"

generated_subject_valid(ir, subject_id) if {
	some subject in ir.subjects
	subject.id == subject_id
}

expanded_claims(ir, fragments) := claims if {
	claims := [expanded |
		some fragment in fragments
		some claim in fragment.claims
		claim_shape_valid(claim)
		some subject in target_subjects(ir, claim.target)
		expanded := object.union(claim, {"category": fragment.category, "subject": subject})
	]
}

owned_paths(ir, "policy") := ir.policy_owned_paths

owned_paths(ir, subject_id) := paths if {
	some subject in ir.subjects
	subject.id == subject_id
	paths := subject.owned_paths
}

claim_overwrites_static(ir, claim) if {
	some path in owned_paths(ir, claim.subject)
	paths_overlap(path, claim.target.path)
}

claims_overlap(first, second) if {
	first.subject == second.subject
	paths_overlap(first.target.path, second.target.path)
}

has_invalid_claim(ir, claims) if {
	some claim in claims
	claim_overwrites_static(ir, claim)
}

has_invalid_claim(_ir, claims) if {
	some first_index, second_index
	first_index < second_index
	claims_overlap(claims[first_index], claims[second_index])
}

invalid_claims(ir, claims) if {
	has_invalid_claim(ir, claims)
}

invalid_claims(ir, claims) := false if {
	not has_invalid_claim(ir, claims)
}

materialize_collections(subject, policy) := result if {
	subject.collection_encodings["/OCI/Process/Env"] == "env-map"
	environment := policy.OCI.Process.Env
	entries := [sprintf("%s=%s", [name, environment[name]]) |
		some name in object.keys(environment)
	]
	process := object.union(policy.OCI.Process, {"Env": entries})
	oci := object.union(policy.OCI, {"Process": process})
	result := object.union(policy, {"OCI": oci})
}

materialize_collections(subject, policy) := policy if {
	not subject.collection_encodings["/OCI/Process/Env"]
}

materialized_subject(subject, claims) := result if {
	additions := [claim.addition |
		some claim in claims
		claim.subject == subject.id
	]
	patched := object.union_n(array.concat([subject.policy], additions))
	result := materialize_collections(subject, patched)
}

final_policy := result if {
	ir := data.static_policy_ir.ir
	ir.composition_schema_version == 1
	profile_fragments := data.selected_profile_fragments.fragments
	materializations := data.selected_materializations.materializations
	fragments := selected_fragments
	count(fragments) > 0
	count(missing_required_categories(ir, profile_fragments)) == 0
	every fragment in fragments {
		fragment_binding_valid(ir, fragment)
		is_string(fragment.category)
		claims := object.get(fragment, "claims", [])
		contracts := object.get(fragment, "materialization_contracts", [])
		count(claims) + count(contracts) > 0
		every claim in fragment.claims {
			claim_shape_valid(claim)
			target_valid(ir, claim.target)
			category_claim_valid(fragment.category, claim)
		}
	}
	every fragment in materializations {
		every claim in fragment.claims {
			materialization_contract_valid(profile_fragments, fragment, claim)
		}
	}
	generated := profile_generated_claims(ir)
	every claim in generated {
		claim_shape_valid(claim)
		category_claim_valid(claim.category, claim)
		generated_subject_valid(ir, claim.subject)
	}
	claims := array.concat(
		expanded_claims(ir, fragments),
		generated,
	)
	not has_invalid_claim(ir, claims)
	policy_additions := [claim.addition |
		some claim in claims
		claim.subject == "policy"
	]
	policy_data := object.union_n(array.concat([ir.policy_data], policy_additions))
	containers := [container |
		some index
		subject := ir.subjects[index]
		container := materialized_subject(subject, claims)
	]
	result := object.union(policy_data, {"containers": containers})
}

diagnostics := {
	"binding_failures": [fragment.category |
		some fragment in selected_fragments
		not fragment_binding_valid(data.static_policy_ir.ir, fragment)
	],
	"invalid_target_categories": [fragment.category |
		some fragment in selected_fragments
		some claim in fragment.claims
		not target_valid(data.static_policy_ir.ir, claim.target)
	],
	"invalid_targets": [claim.target |
		some fragment in selected_fragments
		some claim in fragment.claims
		not target_valid(data.static_policy_ir.ir, claim.target)
	],
	"expanded_claim_count": count(expanded_claims(data.static_policy_ir.ir, selected_fragments)),
	"invalid_claims": invalid_claims(
		data.static_policy_ir.ir,
		expanded_claims(data.static_policy_ir.ir, selected_fragments),
	),
}
