// Package me serves GET /v0/me: who the caller is and what they may do, so
// clients such as the web UI can offer only the actions that will succeed.
package me

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

// allNamespaces selects every namespace, as on the list endpoints.
const allNamespaces = "all"

// Body is the GET /v0/me response.
type Body struct {
	Authenticated bool                `json:"authenticated" doc:"Whether the request carried a verified identity"`
	Subject       string              `json:"subject,omitempty" doc:"The caller's subject (token sub claim)"`
	Issuer        string              `json:"issuer,omitempty" doc:"The issuer of the caller's token"`
	Username      string              `json:"username,omitempty" doc:"A display name for the caller"`
	IsClient      bool                `json:"isClient,omitempty" doc:"Whether the caller is a client acting for itself"`
	Roles         []string            `json:"roles,omitempty"`
	Groups        []string            `json:"groups,omitempty"`
	Namespace     string              `json:"namespace" doc:"The namespace the permissions apply to; all for every namespace"`
	Enforced      bool                `json:"enforced" doc:"Whether permissions come from the authorization service; false means the registry enforces none"`
	Admin         bool                `json:"admin" doc:"Whether the caller is a registry admin"`
	Permissions   map[string][]string `json:"permissions" doc:"Actions the caller may take per kind: read, list, apply, delete, deploy"`
}

type input struct {
	Namespace string `query:"namespace" default:"default" doc:"Namespace to report permissions for; all for every namespace"`
}

// Config wires the endpoint.
type Config struct {
	// Permissions decides what the caller may do. Nil means the registry
	// enforces no authorization, so every action on Kinds is allowed.
	Permissions types.PermissionsFunc
	// Kinds are the kinds the registry serves.
	Kinds []string
}

// Register adds GET {pathPrefix}/me.
func Register(api huma.API, pathPrefix string, cfg Config) {
	kinds := slices.Sorted(slices.Values(cfg.Kinds))
	huma.Register(api, huma.Operation{
		OperationID: "get-me",
		Method:      http.MethodGet,
		Path:        pathPrefix + "/me",
		Summary:     "Get the caller's identity and permissions",
		Description: "Who the caller is and which actions they may take on each kind in a namespace. " +
			"Advisory, for showing only actions that will succeed: every request is still authorized on its own.",
		Tags: []string{"auth"},
	}, func(ctx context.Context, in *input) (*types.Response[Body], error) {
		namespace := strings.TrimSpace(in.Namespace)
		if namespace == "" {
			return nil, huma.Error400BadRequest("namespace must not be empty")
		}
		scope := namespace
		if namespace == allNamespaces {
			scope = ""
		}

		body := Body{Namespace: namespace}
		if s, ok := auth.AuthSessionFrom(ctx); ok {
			p := s.Principal()
			body.Authenticated = p.IsAuthenticated()
			body.Subject, body.Issuer, body.Username = p.Subject, p.Issuer, p.Username
			body.IsClient, body.Roles, body.Groups = p.IsClient, p.Roles, p.Groups
		}

		perms := types.AllPermissions(kinds)
		if cfg.Permissions != nil {
			var err error
			if perms, err = cfg.Permissions(ctx, scope); err != nil {
				return nil, err
			}
			body.Enforced = true
		}
		body.Admin = perms.Admin
		body.Permissions = perms.Kinds
		return &types.Response[Body]{Body: body}, nil
	})
}
