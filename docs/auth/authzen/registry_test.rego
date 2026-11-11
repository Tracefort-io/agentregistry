package authzen_test

import rego.v1

import data.authzen

user(roles) := {"type": "user", "id": "alice", "properties": {"iss": "https://idp.example.com", "roles": roles, "groups": []}}

client(roles) := {"type": "client", "id": "ci-bot", "properties": {"iss": "https://idp.example.com", "roles": roles, "groups": []}}

agent := {"type": "agent", "id": "team/econresearch", "properties": {"kind": "Agent", "namespace": "team", "name": "econresearch"}}

secret := {"type": "secret", "id": "team/openai", "properties": {"kind": "Secret", "namespace": "team", "name": "openai"}}

registry := {"type": "registry", "id": "agentregistry"}

req(subject, action, resource) := {"subject": subject, "action": {"name": action}, "resource": resource}

test_admin_may_do_everything if {
	authzen.allow with input as req(user(["registry-admin"]), "delete", agent)
	authzen.allow with input as req(user(["registry-admin"]), "admin", registry)
	authzen.allow with input as req(user(["registry-admin"]), "read", secret)
}

test_admin_from_keycloak_group_path if {
	subject := {"type": "user", "id": "alice", "properties": {"roles": [], "groups": ["/registry-admin"]}}
	authzen.allow with input as req(subject, "admin", registry)
}

test_writer if {
	authzen.allow with input as req(user(["registry-writer"]), "apply", agent)
	authzen.allow with input as req(user(["registry-writer"]), "deploy", agent)
	authzen.allow with input as req(user(["registry-writer"]), "delete", secret)
	not authzen.allow with input as req(user(["registry-writer"]), "admin", registry)
}

test_reader if {
	authzen.allow with input as req(user(["registry-reader"]), "read", agent)
	authzen.allow with input as req(user(["registry-reader"]), "list", agent)
	not authzen.allow with input as req(user(["registry-reader"]), "apply", agent)
	not authzen.allow with input as req(user(["registry-reader"]), "deploy", agent)
	not authzen.allow with input as req(user(["registry-reader"]), "read", secret)
}

test_no_role_is_denied if {
	not authzen.allow with input as req(user([]), "read", agent)
}

test_anonymous_is_denied if {
	anonymous := {"type": "anonymous", "id": "anonymous"}
	not authzen.allow with input as req(anonymous, "read", agent)
	not authzen.allow with input as req(anonymous, "list", agent)
}

test_client_follows_its_roles if {
	authzen.allow with input as req(client(["registry-writer"]), "apply", agent)
	not authzen.allow with input as req(client([]), "read", agent)
}

test_unknown_resource_type_is_denied if {
	other := {"type": "something-else", "id": "x"}
	not authzen.allow with input as req(user(["registry-writer"]), "read", other)
}

test_empty_subject_id_is_denied if {
	subject := {"type": "user", "id": "", "properties": {"roles": ["registry-admin"]}}
	not authzen.allow with input as req(subject, "read", agent)
}

search(subject, action, type) := {"subject": subject, "action": {"name": action}, "resource": {"type": type}}

test_search_reader_reads_every_agent if {
	authzen.search_resource == {{"type": "agent", "id": "*"}} with input as search(user(["registry-reader"]), "read", "agent")
}

test_search_reader_reads_no_secrets if {
	count(authzen.search_resource) == 0 with input as search(user(["registry-reader"]), "read", "secret")
}

test_search_without_role_finds_nothing if {
	count(authzen.search_resource) == 0 with input as search(user([]), "read", "agent")
}

test_search_unknown_type_finds_nothing if {
	count(authzen.search_resource) == 0 with input as search(user(["registry-writer"]), "read", "something-else")
}
