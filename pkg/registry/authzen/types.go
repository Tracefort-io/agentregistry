// Package authzen is a client for an OpenID AuthZEN 1.0 Policy Decision
// Point (PDP). It implements the Policy Enforcement Point side of the
// Authorization API: metadata discovery, single and batch access
// evaluations, and resource search. It contains no registry- or
// PDP-specific logic.
//
// Spec: https://openid.net/specs/authorization-api-1_0.html
package authzen

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Subject is the user or machine principal of an access request.
type Subject struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Action is the operation the subject attempts.
type Action struct {
	Name       string         `json:"name"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Resource is the target of an access request. ID is optional in a
// resource search request, where only Type is known.
type Resource struct {
	Type       string         `json:"type"`
	ID         string         `json:"id,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Context carries environmental attributes of an access request.
type Context map[string]any

// EvaluationRequest is the body of POST access_evaluation_endpoint.
type EvaluationRequest struct {
	Subject  Subject  `json:"subject"`
	Action   Action   `json:"action"`
	Resource Resource `json:"resource"`
	Context  Context  `json:"context,omitempty"`
}

// EvaluationResponse is a single access decision. Decision is decoded
// strictly: any value other than a JSON boolean is an error.
type EvaluationResponse struct {
	Decision bool           `json:"decision"`
	Context  map[string]any `json:"context,omitempty"`
}

// UnmarshalJSON decodes a decision, rejecting a missing or non-boolean
// "decision" member.
func (r *EvaluationResponse) UnmarshalJSON(data []byte) error {
	var raw struct {
		Decision json.RawMessage `json:"decision"`
		Context  map[string]any  `json:"context"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("decode evaluation response: %w", err)
	}
	decision, err := parseDecision(raw.Decision)
	if err != nil {
		return err
	}
	r.Decision = decision
	r.Context = raw.Context
	return nil
}

// ErrMalformedDecision reports a response whose "decision" is missing or
// not a JSON boolean.
var ErrMalformedDecision = errors.New("authzen: decision is not a JSON boolean")

func parseDecision(raw json.RawMessage) (bool, error) {
	switch string(bytes.TrimSpace(raw)) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, ErrMalformedDecision
	}
}

// EvaluationsSemantic controls how a PDP processes a batch.
type EvaluationsSemantic string

const (
	// ExecuteAll evaluates every request and returns every decision.
	ExecuteAll EvaluationsSemantic = "execute_all"
	// DenyOnFirstDeny stops at the first deny.
	DenyOnFirstDeny EvaluationsSemantic = "deny_on_first_deny"
	// PermitOnFirstPermit stops at the first permit.
	PermitOnFirstPermit EvaluationsSemantic = "permit_on_first_permit"
)

// EvaluationsOptions are the batch options.
type EvaluationsOptions struct {
	EvaluationsSemantic EvaluationsSemantic `json:"evaluations_semantic,omitempty"`
}

// EvaluationItem is one entry of a batch. Nil members inherit the
// top-level defaults of the EvaluationsRequest.
type EvaluationItem struct {
	Subject  *Subject  `json:"subject,omitempty"`
	Action   *Action   `json:"action,omitempty"`
	Resource *Resource `json:"resource,omitempty"`
	Context  Context   `json:"context,omitempty"`
}

// EvaluationsRequest is the body of POST access_evaluations_endpoint.
type EvaluationsRequest struct {
	Subject     *Subject            `json:"subject,omitempty"`
	Action      *Action             `json:"action,omitempty"`
	Resource    *Resource           `json:"resource,omitempty"`
	Context     Context             `json:"context,omitempty"`
	Evaluations []EvaluationItem    `json:"evaluations"`
	Options     *EvaluationsOptions `json:"options,omitempty"`
}

// EvaluationsResponse holds one decision per evaluated item, in request
// order. With a short-circuit semantic it may be shorter than the request.
type EvaluationsResponse struct {
	Evaluations []EvaluationResponse `json:"evaluations"`
}

// Semantic returns the batch semantic, defaulting to ExecuteAll.
func (r EvaluationsRequest) Semantic() EvaluationsSemantic {
	if r.Options == nil || r.Options.EvaluationsSemantic == "" {
		return ExecuteAll
	}
	return r.Options.EvaluationsSemantic
}

// Expand resolves item i against the request defaults. It errors when a
// subject, action or resource is defined neither on the item nor at the
// top level.
func (r EvaluationsRequest) Expand(i int) (EvaluationRequest, error) {
	item := r.Evaluations[i]
	var out EvaluationRequest
	switch {
	case item.Subject != nil:
		out.Subject = *item.Subject
	case r.Subject != nil:
		out.Subject = *r.Subject
	default:
		return out, fmt.Errorf("authzen: evaluation %d has no subject", i)
	}
	switch {
	case item.Action != nil:
		out.Action = *item.Action
	case r.Action != nil:
		out.Action = *r.Action
	default:
		return out, fmt.Errorf("authzen: evaluation %d has no action", i)
	}
	switch {
	case item.Resource != nil:
		out.Resource = *item.Resource
	case r.Resource != nil:
		out.Resource = *r.Resource
	default:
		return out, fmt.Errorf("authzen: evaluation %d has no resource", i)
	}
	if item.Context != nil {
		out.Context = item.Context
	} else {
		out.Context = r.Context
	}
	return out, nil
}

// PageRequest selects a page of search results.
type PageRequest struct {
	Token string `json:"token,omitempty"`
	Limit int    `json:"limit,omitempty"`
}

// PageResponse describes the page returned by a search.
type PageResponse struct {
	NextToken string `json:"next_token,omitempty"`
	Count     int    `json:"count,omitempty"`
	Total     int    `json:"total,omitempty"`
}

// ResourceSearchRequest is the body of POST search_resource_endpoint.
// Resource.ID is left empty: the PDP returns the matching IDs.
type ResourceSearchRequest struct {
	Subject  Subject      `json:"subject"`
	Action   Action       `json:"action"`
	Resource Resource     `json:"resource"`
	Context  Context      `json:"context,omitempty"`
	Page     *PageRequest `json:"page,omitempty"`
}

// ResourceSearchResponse is one page of resource search results.
type ResourceSearchResponse struct {
	Results []Resource    `json:"results"`
	Page    *PageResponse `json:"page,omitempty"`
}

// Metadata is the PDP metadata from /.well-known/authzen-configuration.
type Metadata struct {
	PolicyDecisionPoint       string `json:"policy_decision_point"`
	AccessEvaluationEndpoint  string `json:"access_evaluation_endpoint"`
	AccessEvaluationsEndpoint string `json:"access_evaluations_endpoint,omitempty"`
	SearchSubjectEndpoint     string `json:"search_subject_endpoint,omitempty"`
	SearchResourceEndpoint    string `json:"search_resource_endpoint,omitempty"`
	SearchActionEndpoint      string `json:"search_action_endpoint,omitempty"`
}
