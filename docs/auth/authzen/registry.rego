# Reference AuthZEN policy for agentregistry (docs/auth/authzen-contract.md).
#
# Serve it from any OPA-based AuthZEN PDP with path "authzen" and decision
# "allow", for example opa-authzen-plugin:
#   plugins:
#     authzen:
#       path: authzen
#       decision: allow
#
# Roles are read from subject.properties.roles and .groups (Keycloak group
# paths such as "/registry-admin" are accepted):
#   registry-admin   everything, including the registry-wide "admin" check
#   registry-writer  read, list, apply, delete and deploy registry resources
#   registry-reader  read and list registry resources, except Secrets
# Anonymous callers are allowed nothing. Clients (client-credentials tokens)
# get exactly what their roles allow.
#
# search_resource (below) answers Resource Search with wildcards.
package authzen

import rego.v1

default allow := false

registry_types := {
	"agent", "mcpserver", "skill", "prompt", "plugin",
	"model", "runtime", "deployment", "secret",
}

reader_actions := {"read", "list"}

writer_actions := {"read", "list", "apply", "delete", "deploy"}

identified if {
	input.subject.type in {"user", "client"}
	is_string(input.subject.id)
	input.subject.id != ""
}

roles contains role if {
	some role in input.subject.properties.roles
	is_string(role)
}

roles contains trim_prefix(group, "/") if {
	some group in input.subject.properties.groups
	is_string(group)
}

registry_resource if input.resource.type in registry_types

allow if {
	identified
	"registry-admin" in roles
}

allow if {
	identified
	"registry-writer" in roles
	registry_resource
	input.action.name in writer_actions
}

allow if {
	identified
	"registry-reader" in roles
	registry_resource
	input.resource.type != "secret"
	input.action.name in reader_actions
}

# Resource Search (configure the PDP with search.resource: search_resource).
# Access here depends on the role and the resource type, never on the row, so
# the answer is "*", every row of the type, when the subject may take the
# action on it. The registry turns "*" into no filter, and "<namespace>/*"
# into a namespace filter, so large catalogs list without per-row checks.
search_resource contains {"type": input.resource.type, "id": "*"} if {
	allow with input as object.union(input, {"resource": {"type": input.resource.type, "id": "*"}})
}
