package authzen_test

import rego.v1

import data.authzen

writer := {"type": "user", "id": "carol", "properties": {"iss": "https://idp", "roles": ["registry-writer"], "groups": []}}

admin := {"type": "user", "id": "alice", "properties": {"iss": "https://idp", "roles": ["registry-admin"], "groups": []}}

deployment := {"type": "deployment", "id": "prod/bot"}

approvers_data := {"client_id": "agentregistry", "approvers": [{"sub": "dave", "iss": "https://idp"}, {"sub": "carol", "iss": "https://idp"}]}

test_writer_publish_and_deploy_need_approval if {
	not authzen.allow with input as req(writer, "apply", deployment)
	not authzen.allow with input as req(writer, "apply", agent)
	not authzen.allow with input as req(writer, "delete", agent)
	authzen.decision_context.reason == "approval_required" with input as req(writer, "apply", deployment)
	authzen.decision_context.access_request.template == "registry_change" with input as req(writer, "apply", deployment)
}

test_writer_other_changes_need_none if {
	authzen.allow with input as req(writer, "deploy", agent)
	authzen.allow with input as req(writer, "apply", secret)
	authzen.allow with input as req(writer, "read", agent)
	not authzen.decision_context with input as req(writer, "apply", secret)
}

test_admin_acts_directly if {
	authzen.allow with input as req(admin, "apply", deployment)
	not authzen.decision_context with input as req(admin, "apply", deployment)
}

test_verified_approval_allows if {
	approved := object.union(req(writer, "apply", deployment), {"context": {"approval": {"id": "apr_1", "verified": true}}})
	authzen.allow with input as approved
}

test_unverified_approval_is_requestable_again if {
	stale := object.union(req(writer, "apply", deployment), {"context": {"approval": {"id": "apr_1", "verified": false, "reason": "out_of_scope"}}})
	not authzen.allow with input as stale
	authzen.decision_context.reason == "out_of_scope" with input as stale
	authzen.decision_context.next_action == "request" with input as stale
}

test_only_the_registry_submits if {
	authzen.ars_caller with input as {"operation": "submit", "caller": {"client_id": "agentregistry"}} with data.registry as approvers_data
	not authzen.ars_caller with input as {"operation": "submit", "caller": {"client_id": "someone-else"}} with data.registry as approvers_data
}

test_workflow_lists_the_approvers if {
	plan := authzen.ars_workflow with input as {"operation": "plan", "submission": {"items": [{"action": {"name": "apply"}, "resource": {"type": "deployment", "id": "prod/bot"}}]}}
		with data.registry as approvers_data
	plan.steps[0].required == 1
	count(plan.steps[0].approvers) == 2
	plan.display.title == "apply deployment prod/bot"
}

test_approvers_but_not_their_own_change if {
	task := {"subject": {"id": "carol"}}
	authzen.ars_approver with input as {"operation": "list", "approver": {"id": "dave", "properties": {"iss": "https://idp"}}} with data.registry as approvers_data
	authzen.ars_approver with input as {"operation": "decide", "approver": {"id": "dave", "properties": {"iss": "https://idp"}}, "task": task} with data.registry as approvers_data
	not authzen.ars_approver with input as {"operation": "decide", "approver": {"id": "carol", "properties": {"iss": "https://idp"}}, "task": task} with data.registry as approvers_data
	not authzen.ars_approver with input as {"operation": "list", "approver": {"id": "mallory", "properties": {"iss": "https://idp"}}} with data.registry as approvers_data
	not authzen.ars_approver with input as {"operation": "list", "approver": {"id": "dave", "properties": {"iss": "https://other"}}} with data.registry as approvers_data
}
