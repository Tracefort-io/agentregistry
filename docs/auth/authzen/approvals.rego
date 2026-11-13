# Approval rules for agentregistry: which changes need approval, who
# approves them, and who may not. Served by an AuthZEN PDP with the Access
# Request Service (opa-authzen-plugin), configured with:
#
#   plugins:
#     authzen:
#       decision_context: decision_context
#       access_request:
#         binding_context_members: ["document_sha256"]
#         service:
#           rules: {caller: ars_caller, workflow: ars_workflow, approver: ars_approver}
#
# A registry-writer publishing a catalog entry (Agent, MCPServer, Skill,
# Prompt, Plugin) or applying a Deployment is denied with a requestable
# denial. The registry submits the request, an approver from
# data.registry.approvers approves it, and the registry applies the reviewed
# document, presenting the approval. The approval is bound to the document's
# SHA-256, so it cannot be used for different content. Admins act directly.
#
# Data (for example data.json):
#   {"registry": {"client_id": "agentregistry",
#                 "approvers": [{"sub": "<approver's sub>", "iss": "<issuer>"}]}}
package authzen

import rego.v1

# Kinds whose changes need approval: publishing to the catalog, and deploying.
approval_types := {"agent", "mcpserver", "skill", "prompt", "plugin", "deployment"}

needs_approval if {
	identified
	"registry-writer" in roles
	not "registry-admin" in roles
	input.resource.type in approval_types
	input.action.name in {"apply", "delete"}
}

# An approved change: the PDP has checked that the approval matches this
# subject, resource, action and document.
allow if {
	needs_approval
	input.context.approval.verified
}

decision_context := {"reason": "approval_required", "access_request": {"template": "registry_change"}} if {
	needs_approval
	not input.context.approval
}

decision_context := {
	"reason": input.context.approval.reason,
	"next_action": "request",
	"access_request": {"template": "registry_change"},
} if {
	needs_approval
	not input.context.approval.verified
	input.context.approval
}

# Only the registry submits, follows and cancels requests, for its users.
default registry_client := "agentregistry"

registry_client := data.registry.client_id

ars_caller if input.caller.client_id == registry_client

# One approval from any listed approver; the request lasts for 72h (the
# service's task_ttl), the approval for 24h.
ars_workflow := {
	"steps": [{"name": "registry_approval", "required": 1, "approvers": approvers}],
	"approved_until": time.format(time.add_date(time.now_ns(), 0, 0, 1)),
	"display": {"title": sprintf("%s %s %s", [item.action.name, item.resource.type, item.resource.id])},
} if {
	count(approvers) > 0
	item := input.submission.items[0]
}

approvers := [{"type": "user", "id": a.sub, "properties": {"iss": a.iss}} | some a in data.registry.approvers]

approver_listed if {
	some a in data.registry.approvers
	a.sub == input.approver.id
	a.iss == input.approver.properties.iss
}

ars_approver if {
	input.operation in {"list", "view"}
	approver_listed
}

# Nobody approves their own change.
ars_approver if {
	input.operation == "decide"
	approver_listed
	input.approver.id != input.task.subject.id
}
