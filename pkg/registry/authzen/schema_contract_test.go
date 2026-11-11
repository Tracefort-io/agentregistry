package authzen

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The OpenID AuthZEN JSON Schemas are not copied into this repository (they
// fall under the OpenID Foundation's IPR policy). `make test-authzen-contract`
// fetches them at a pinned commit and runs this test with
// AUTHZEN_SCHEMA_DIR set; otherwise it is skipped.
func loadSpecSchema(t *testing.T, name string) *jsonschema.Resolved {
	t.Helper()
	dir := os.Getenv("AUTHZEN_SCHEMA_DIR")
	if dir == "" {
		t.Skip("AUTHZEN_SCHEMA_DIR not set; run make test-authzen-contract")
	}
	raw, err := os.ReadFile(filepath.Join(dir, name))
	require.NoError(t, err)
	var s jsonschema.Schema
	require.NoError(t, json.Unmarshal(raw, &s))
	resolved, err := s.Resolve(&jsonschema.ResolveOptions{BaseURI: "https://openid.net/schemas/authzen/"})
	require.NoError(t, err)
	return resolved
}

func asJSON(t *testing.T, raw []byte) any {
	t.Helper()
	var v any
	require.NoError(t, json.Unmarshal(raw, &v))
	return v
}

// Every request the client sends to the evaluation endpoint, including the
// items it sends one by one for a PDP without batches, must be valid.
func TestSpecSchemaEvaluationRequests(t *testing.T) {
	schema := loadSpecSchema(t, "evaluation-request.schema.json")

	var mu sync.Mutex
	var bodies [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case WellKnownPath:
			// No batch endpoint: the client sends each item to the evaluation endpoint.
			_ = json.NewEncoder(w).Encode(Metadata{
				PolicyDecisionPoint:      "http://" + r.Host,
				AccessEvaluationEndpoint: "/access/v1/evaluation",
			})
		case "/access/v1/evaluation":
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			bodies = append(bodies, body)
			mu.Unlock()
			_, _ = io.WriteString(w, `{"decision": true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := New(Config{BaseURL: srv.URL})
	require.NoError(t, err)

	subject := Subject{Type: "user", ID: "alice-sub", Properties: map[string]any{
		"iss": "https://idp.example", "roles": []string{"registry-reader"}, "groups": []string{},
		"act": []map[string]any{{"sub": "agent", "iss": "https://idp.example"}},
	}}
	ctx := WithRequestID(context.Background(), "req-1")
	_, err = c.Evaluate(ctx, EvaluationRequest{
		Subject:  subject,
		Action:   Action{Name: "read"},
		Resource: Resource{Type: "agent", ID: "team/bot", Properties: map[string]any{"kind": "Agent", "namespace": "team", "name": "bot", "tag": "v1"}},
		Context:  Context{"pep": "agentregistry", "request_id": "req-1"},
	})
	require.NoError(t, err)
	_, err = c.Evaluations(ctx, EvaluationsRequest{
		Subject: &subject,
		Action:  &Action{Name: "read"},
		Context: Context{"pep": "agentregistry"},
		Options: &EvaluationsOptions{EvaluationsSemantic: ExecuteAll},
		Evaluations: []EvaluationItem{
			{Resource: &Resource{Type: "agent", ID: "team/*"}},
			{Action: &Action{Name: "admin"}, Resource: &Resource{Type: "registry", ID: "agentregistry"}},
		},
	})
	require.NoError(t, err)

	require.Len(t, bodies, 3)
	for _, body := range bodies {
		assert.NoError(t, schema.Validate(asJSON(t, body)), "request %s", body)
	}

	// The schema is enforced: a subject without an id is invalid.
	invalid := `{"subject": {"type": "user"}, "action": {"name": "read"}, "resource": {"type": "agent", "id": "team/bot"}}`
	assert.Error(t, schema.Validate(asJSON(t, []byte(invalid))))
}

// Every response the client accepts must be valid, and the schema must reject
// what the client rejects.
func TestSpecSchemaEvaluationResponses(t *testing.T) {
	schema := loadSpecSchema(t, "evaluation-response.schema.json")

	for _, body := range []string{
		`{"decision": true}`,
		`{"decision": false}`,
		`{"decision": false, "context": {"reason": "approval_required"}}`,
	} {
		var resp EvaluationResponse
		require.NoError(t, json.Unmarshal([]byte(body), &resp), "client accepts %s", body)
		assert.NoError(t, schema.Validate(asJSON(t, []byte(body))), "schema accepts %s", body)
	}
	for _, body := range []string{`{"decision": "true"}`, `{"decision": 1}`, `{}`} {
		var resp EvaluationResponse
		assert.Error(t, json.Unmarshal([]byte(body), &resp), "client rejects %s", body)
		assert.Error(t, schema.Validate(asJSON(t, []byte(body))), "schema rejects %s", body)
	}
}
