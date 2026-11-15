package policies

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	svc "github.com/agentregistry-dev/agentregistry/internal/registry/policies"
	"github.com/agentregistry-dev/agentregistry/internal/registry/policies/githost"
	"github.com/agentregistry-dev/agentregistry/internal/registry/policies/opaeval"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
)

type session struct{ p auth.Principal }

func (s session) Principal() auth.Principal { return s.p }

var ada = auth.Principal{Subject: "u-ada", Issuer: "https://idp", Username: "ada"}

// fakeService answers every call with err, or a fixed result.
type fakeService struct {
	err       error
	published svc.PublishRequest
	name, ref string
}

func (f *fakeService) List(context.Context) ([]svc.PolicySummary, error) {
	return []svc.PolicySummary{{Name: "authzen"}}, f.err
}

func (f *fakeService) Get(_ context.Context, name, ref string) (svc.Policy, error) {
	f.name, f.ref = name, ref
	return svc.Policy{PolicySummary: svc.PolicySummary{Name: name}, Commit: strings.Repeat("a", 40)}, f.err
}

func (f *fakeService) Versions(context.Context, string) ([]svc.PolicyVersion, error) {
	return []svc.PolicyVersion{{Version: "v2"}}, f.err
}

func (f *fakeService) Diff(_ context.Context, name, from, to string) ([]svc.PolicyChange, error) {
	f.name, f.ref = name, from+".."+to
	return []svc.PolicyChange{{Path: "a.rego"}}, f.err
}

func (f *fakeService) Pending(context.Context, string) ([]githost.PullRequest, error) {
	return []githost.PullRequest{{Number: 4}}, f.err
}

func (f *fakeService) Status(context.Context, string) (svc.PolicyStatus, error) {
	return svc.PolicyStatus{Checked: true, LiveVersion: "v2"}, f.err
}

func (f *fakeService) Publish(_ context.Context, name string, req svc.PublishRequest) (svc.PolicyPublishResult, error) {
	f.name, f.published = name, req
	return svc.PolicyPublishResult{PullRequest: githost.PullRequest{Number: 9, URL: "https://git/pr/9"}, Branch: "policy/x"}, f.err
}

func (f *fakeService) Format(_ context.Context, name, file, content string) (svc.PolicyFormatResult, error) {
	f.name, f.ref = name, file
	return svc.PolicyFormatResult{Content: strings.ToUpper(content), Problems: []opaeval.RegoProblem{}}, f.err
}

func (f *fakeService) CheckDraft(_ context.Context, name string, draft svc.PolicyDraft) ([]opaeval.RegoProblem, error) {
	f.name = name
	return []opaeval.RegoProblem{{File: name + "/a.rego", Row: 3, Message: "unsafe " + draft["a.rego"]}}, f.err
}

func (f *fakeService) EvaluateDraft(_ context.Context, name string, _ svc.PolicyDraft, query string, input any, _ map[string]any) (opaeval.RegoEvalResult, error) {
	f.name, f.ref = name, query
	return opaeval.RegoEvalResult{Query: query, Output: fmt.Sprint(input)}, f.err
}

func (f *fakeService) TestDraft(_ context.Context, name string, _ svc.PolicyDraft, _ map[string]any) (opaeval.RegoTestReport, error) {
	f.name = name
	return opaeval.RegoTestReport{Passed: 2, Results: []opaeval.RegoTestResult{}}, f.err
}

func newAPI(t *testing.T, s *fakeService, signedIn bool) humatest.TestAPI {
	t.Helper()
	_, api := humatest.New(t)
	if signedIn {
		api.UseMiddleware(func(ctx huma.Context, next func(huma.Context)) {
			next(huma.WithContext(ctx, auth.AuthSessionTo(ctx.Context(), session{ada})))
		})
	}
	Register(api, "/v0", Config{Service: s})
	return api
}

func TestEndpoints(t *testing.T) {
	s := &fakeService{}
	api := newAPI(t, s, true)
	for _, tt := range []struct {
		path, want string
	}{
		{"/v0/policies", `"name":"authzen"`},
		{"/v0/policies/authzen?ref=v1", `"commit":"aaaa`},
		{"/v0/policies/authzen/versions", `"version":"v2"`},
		{"/v0/policies/authzen/diff?from=v1&to=v2", `"path":"a.rego"`},
		{"/v0/policies/authzen/pending", `"number":4`},
		{"/v0/policies/authzen/status", `"liveVersion":"v2"`},
	} {
		resp := api.Get(tt.path)
		require.Equal(t, http.StatusOK, resp.Code, tt.path)
		assert.Contains(t, resp.Body.String(), tt.want, tt.path)
	}
	assert.Equal(t, "v1..v2", s.ref)
}

func TestPublish(t *testing.T) {
	s := &fakeService{}
	api := newAPI(t, s, true)
	base := strings.Repeat("b", 40)
	resp := api.Post("/v0/policies/authzen/publish", map[string]any{
		"baseCommit": base,
		"files":      map[string]any{"registry.rego": "package authzen\n", "old.rego": nil},
		"message":    "authzen: tighten",
	})
	require.Equal(t, http.StatusCreated, resp.Code, resp.Body.String())
	assert.Contains(t, resp.Body.String(), `"url":"https://git/pr/9"`)
	assert.Equal(t, "authzen", s.name)
	assert.Equal(t, base, s.published.BaseCommit)
	assert.Equal(t, "authzen: tighten", s.published.Message)
	require.Contains(t, s.published.Files, "old.rego")
	assert.Nil(t, s.published.Files["old.rego"])
	assert.Equal(t, "package authzen\n", *s.published.Files["registry.rego"])

	// The base must be a full commit SHA.
	resp = api.Post("/v0/policies/authzen/publish", map[string]any{"baseCommit": "main", "files": map[string]any{}, "message": "m"})
	assert.Equal(t, http.StatusUnprocessableEntity, resp.Code)
}

func TestTools(t *testing.T) {
	s := &fakeService{}
	api := newAPI(t, s, true)
	draft := map[string]any{"a.rego": "x"}

	resp := api.Post("/v0/policies/authzen/format", map[string]any{"path": "a.rego", "content": "package a"})
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	assert.Contains(t, resp.Body.String(), `"content":"PACKAGE A"`)
	assert.Equal(t, "a.rego", s.ref)

	resp = api.Post("/v0/policies/authzen/check", map[string]any{"files": draft})
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	assert.Contains(t, resp.Body.String(), `"message":"unsafe x"`)

	resp = api.Post("/v0/policies/authzen/evaluate", map[string]any{"files": draft, "query": "data.a.allow", "input": map[string]any{"u": "ada"}})
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	assert.Contains(t, resp.Body.String(), `"output":"map[u:ada]"`)
	assert.Equal(t, "data.a.allow", s.ref)

	resp = api.Post("/v0/policies/authzen/test", map[string]any{"files": draft})
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	assert.Contains(t, resp.Body.String(), `"passed":2`)
}

func TestErrors(t *testing.T) {
	for _, tt := range []struct {
		err  error
		want int
	}{
		{fmt.Errorf("x: %w", auth.ErrForbidden), http.StatusForbidden},
		{huma.Error503ServiceUnavailable("pdp down"), http.StatusServiceUnavailable},
		{fmt.Errorf("%w: v9", svc.ErrNotFound), http.StatusNotFound},
		{fmt.Errorf("%w: bad path", svc.ErrInvalid), http.StatusUnprocessableEntity},
		{fmt.Errorf("%w: nothing to change", svc.ErrConflict), http.StatusConflict},
		{errors.New("git host said token ghp_x is bad"), http.StatusBadGateway},
	} {
		resp := newAPI(t, &fakeService{err: tt.err}, true).Get("/v0/policies/authzen")
		assert.Equal(t, tt.want, resp.Code, tt.err.Error())
		assert.NotContains(t, resp.Body.String(), "ghp_x")
	}
}

func TestAnonymousRefused(t *testing.T) {
	api := newAPI(t, &fakeService{}, false)
	assert.Equal(t, http.StatusUnauthorized, api.Get("/v0/policies").Code)
	assert.Equal(t, http.StatusUnauthorized, api.Post("/v0/policies/authzen/publish", map[string]any{
		"baseCommit": strings.Repeat("b", 40), "files": map[string]any{"a.rego": "x"}, "message": "m",
	}).Code)
}
