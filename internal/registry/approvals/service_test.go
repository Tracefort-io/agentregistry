package approvals

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/internal/registry/authz"
	arv0 "github.com/agentregistry-dev/agentregistry/pkg/api/v0"
	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/authzen"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/v1alpha1store"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

// memStore is an in-memory Store.
type memStore struct {
	mu   sync.Mutex
	rows map[string]v1alpha1store.ApprovalRequest
}

func newMemStore() *memStore { return &memStore{rows: map[string]v1alpha1store.ApprovalRequest{}} }

func (m *memStore) CreateApprovalRequest(_ context.Context, r v1alpha1store.ApprovalRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r.Status, r.CreatedAt, r.UpdatedAt = v1alpha1store.ApprovalPending, time.Now(), time.Now()
	m.rows[r.ID] = r
	return nil
}

func (m *memStore) GetApprovalRequest(_ context.Context, id string) (v1alpha1store.ApprovalRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[id]
	if !ok {
		return r, v1alpha1store.ErrApprovalNotFound
	}
	return r, nil
}

func (m *memStore) ListApprovalRequests(_ context.Context, q v1alpha1store.ApprovalQuery) ([]v1alpha1store.ApprovalRequest, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []v1alpha1store.ApprovalRequest
	for _, r := range m.rows {
		if q.RequesterSubject != "" && r.RequesterSubject != q.RequesterSubject {
			continue
		}
		if len(q.Statuses) > 0 && !contains(q.Statuses, r.Status) {
			continue
		}
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b v1alpha1store.ApprovalRequest) int { return strings.Compare(b.ID, a.ID) })
	return out, "", nil
}

func (m *memStore) TransitionApprovalRequest(_ context.Context, id string, from []string, to, approvalID, detail string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[id]
	if !ok || !contains(from, r.Status) {
		return false, nil
	}
	r.Status, r.UpdatedAt = to, time.Now()
	if approvalID != "" {
		r.ApprovalID = approvalID
	}
	if detail != "" {
		r.Detail = detail
	}
	m.rows[id] = r
	return true, nil
}

func (m *memStore) StuckApplyingBefore(context.Context, time.Time, int) ([]v1alpha1store.ApprovalRequest, error) {
	return nil, nil
}

func (m *memStore) status(id string) string {
	r, _ := m.GetApprovalRequest(context.Background(), id)
	return r.Status
}

func contains(list []string, v string) bool {
	return slices.Contains(list, v)
}

// fakeARS is the PDP: discovery plus the access request service.
type fakeARS struct {
	t      *testing.T
	srv    *httptest.Server
	mu     sync.Mutex
	status map[string]string // task id -> status
	posts  []map[string]any
	keys   []string
	tokens []string
	next   int
}

func newFakeARS(t *testing.T) *fakeARS {
	f := &fakeARS{t: t, status: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeARS) set(id, status string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status[id] = status
}

func (f *fakeARS) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens = append(f.tokens, r.Header.Get("Authorization"))
	w.Header().Set("Content-Type", "application/json")
	task := func(id string) map[string]any {
		out := map[string]any{"task": map[string]any{"id": id, "status": f.status[id], "status_endpoint": f.srv.URL + "/access/v1/requests/" + id}}
		if f.status[id] == TaskApproved {
			out["result"] = map[string]any{"mode": "reevaluate", "approval": map[string]any{"id": "apr_" + id}}
		}
		return out
	}
	switch {
	case r.URL.Path == authzen.WellKnownPath:
		_ = json.NewEncoder(w).Encode(map[string]any{
			"policy_decision_point": f.srv.URL, "access_evaluation_endpoint": f.srv.URL + "/access/v1/evaluation",
			"access_request_endpoint": f.srv.URL + "/access/v1/requests",
		})
	case r.URL.Path == "/access/v1/requests" && r.Method == http.MethodPost:
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.posts = append(f.posts, body)
		f.keys = append(f.keys, r.Header.Get("Idempotency-Key"))
		f.next++
		id := "arq_" + strconv.Itoa(f.next)
		f.status[id] = TaskPending
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(task(id))
	case strings.HasSuffix(r.URL.Path, "/cancel"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/access/v1/requests/"), "/cancel")
		f.status[id] = TaskCancelled
		_ = json.NewEncoder(w).Encode(task(id))
	case strings.HasPrefix(r.URL.Path, "/access/v1/requests/"):
		id := strings.TrimPrefix(r.URL.Path, "/access/v1/requests/")
		if _, ok := f.status[id]; !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"type":"urn:openid:authzen:access-request:error:unknown_task","title":"Unknown task"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(task(id))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// applier records the approved applies.
type applier struct {
	mu      sync.Mutex
	calls   int32
	ctxs    []context.Context
	objs    []v1alpha1.Object
	verbs   []string
	result  string
	failure string
}

func (a *applier) fn(verb string) func(context.Context, v1alpha1.Object) arv0.ApplyResult {
	return func(ctx context.Context, obj v1alpha1.Object) arv0.ApplyResult {
		atomic.AddInt32(&a.calls, 1)
		a.mu.Lock()
		defer a.mu.Unlock()
		a.ctxs, a.objs, a.verbs = append(a.ctxs, ctx), append(a.objs, obj), append(a.verbs, verb)
		if a.failure != "" {
			return arv0.ApplyResult{Status: arv0.ApplyStatusFailed, Error: a.failure}
		}
		return arv0.ApplyResult{Status: a.result}
	}
}

func newService(t *testing.T, ars *fakeARS, a *applier) (*Service, *memStore) {
	t.Helper()
	pdp, err := authzen.New(authzen.Config{BaseURL: ars.srv.URL})
	require.NoError(t, err)
	client, err := NewARSClient(pdp, ars.srv.URL, authzen.StaticToken("registry-token"), nil)
	require.NoError(t, err)
	store := newMemStore()
	s, err := New(Config{Store: store, ARS: client})
	require.NoError(t, err)
	if a.result == "" {
		a.result = arv0.ApplyStatusCreated
	}
	s.Bind(a.fn("apply"), a.fn("delete"))
	return s, store
}

var carol = auth.Principal{Subject: "carol-sub", Issuer: "https://idp", Username: "carol", Roles: []string{"registry-writer"}}

func carolCtx() context.Context { return auth.AuthSessionTo(context.Background(), session{carol}) }

func deployment() *v1alpha1.Deployment {
	d := &v1alpha1.Deployment{Metadata: v1alpha1.ObjectMeta{Namespace: "prod", Name: "bot"}}
	d.SetTypeMeta(v1alpha1.TypeMeta{APIVersion: v1alpha1.GroupVersion, Kind: v1alpha1.KindDeployment})
	return d
}

// approvalRequired is the PEP's error for a requestable denial.
func approvalRequired(t *testing.T) error {
	t.Helper()
	pdp := &stubDecider{}
	pep, err := authz.New(authz.Config{Client: pdp})
	require.NoError(t, err)
	err = pep.Authorize(carolCtx(), types.AuthorizeInput{Verb: "apply", Kind: v1alpha1.KindPrompt, Namespace: "prod", Name: "bot", Object: deployment()})
	var required *authz.ApprovalRequired
	require.ErrorAs(t, err, &required)
	return err
}

// stubDecider denies everything as requestable.
type stubDecider struct{}

func (stubDecider) Evaluate(_ context.Context, req authzen.EvaluationRequest) (authzen.EvaluationResponse, error) {
	return authzen.EvaluationResponse{Context: map[string]any{
		"reason": "approval_required", "evaluation_id": "eval_7",
		"access_request": map[string]any{"binding_token": "tok", "expires_at": "2026-11-12T10:00:00Z", "template": "deploy"},
	}}, nil
}

func (stubDecider) Evaluations(context.Context, authzen.EvaluationsRequest) (authzen.EvaluationsResponse, error) {
	return authzen.EvaluationsResponse{}, errors.New("unused")
}

func (stubDecider) SupportsResourceSearch(context.Context) (bool, error) { return false, nil }

func (stubDecider) SearchResources(context.Context, authzen.ResourceSearchRequest, int) ([]authzen.Resource, error) {
	return nil, nil
}

func TestStage(t *testing.T) {
	ars := newFakeARS(t)
	s, store := newService(t, ars, &applier{})

	_, staged, err := s.Stage(carolCtx(), types.ApprovalStageInput{Verb: "apply", Kind: v1alpha1.KindPrompt, Denial: errors.New("plain 403")})
	require.NoError(t, err)
	assert.False(t, staged, "an ordinary denial is not staged")

	_, staged, err = s.Stage(carolCtx(), types.ApprovalStageInput{Verb: "apply", Kind: v1alpha1.KindSecret, Denial: approvalRequired(t)})
	require.NoError(t, err)
	assert.False(t, staged, "Secrets are never held: their values would be stored")

	id, staged, err := s.Stage(carolCtx(), types.ApprovalStageInput{
		Verb: "apply", Kind: v1alpha1.KindDeployment, Namespace: "prod", Name: "bot", Object: deployment(), Denial: approvalRequired(t),
	})
	require.NoError(t, err)
	require.True(t, staged)
	assert.Equal(t, "arq_1", id)

	require.Len(t, ars.posts, 1)
	sub := ars.posts[0]
	assert.Equal(t, "carol-sub", sub["subject"].(map[string]any)["id"])
	assert.Equal(t, map[string]any{"name": "apply"}, sub["action"])
	assert.Equal(t, "tok", sub["denial"].(map[string]any)["binding_token"])
	assert.NotEmpty(t, sub["context"].(map[string]any)["document_sha256"])
	assert.Equal(t, "eval_7", ars.keys[0], "idempotent per evaluation")
	assert.Equal(t, "Bearer registry-token", ars.tokens[len(ars.tokens)-1], "the registry's own credentials")

	r, err := store.GetApprovalRequest(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, v1alpha1store.ApprovalPending, r.Status)
	assert.Equal(t, "carol-sub", r.RequesterSubject)
	assert.Contains(t, string(r.Document), `"name":"bot"`)
	assert.NotContains(t, string(r.Requester), "claims")
}

func TestReconcileAppliesApprovedChangesAsTheRequester(t *testing.T) {
	ars := newFakeARS(t)
	a := &applier{}
	s, store := newService(t, ars, a)
	id, _, err := s.Stage(carolCtx(), types.ApprovalStageInput{
		Verb: "apply", Kind: v1alpha1.KindDeployment, Namespace: "prod", Name: "bot", Object: deployment(), Denial: approvalRequired(t),
	})
	require.NoError(t, err)

	s.Reconcile(context.Background())
	assert.Equal(t, v1alpha1store.ApprovalPending, store.status(id), "still waiting")
	assert.Zero(t, a.calls)

	ars.set(id, TaskApproved)
	s.Reconcile(context.Background())
	assert.Equal(t, v1alpha1store.ApprovalApplied, store.status(id))
	require.EqualValues(t, 1, a.calls)
	assert.Equal(t, "apr_"+id, types.ApprovalIDFrom(a.ctxs[0]), "the approval is presented")
	sess, ok := auth.AuthSessionFrom(a.ctxs[0])
	require.True(t, ok)
	assert.Equal(t, carol, sess.Principal(), "applied as the requester, not as the system")
	assert.Equal(t, "bot", a.objs[0].GetMetadata().Name)

	r, _ := store.GetApprovalRequest(context.Background(), id)
	assert.Equal(t, "apr_"+id, r.ApprovalID)
	assert.Contains(t, r.Detail, "created with approval")

	s.Reconcile(context.Background())
	assert.EqualValues(t, 1, a.calls, "applied once")
}

func TestReconcileOutcomes(t *testing.T) {
	tests := []struct {
		task    string
		failure string
		want    string
	}{
		{TaskDenied, "", v1alpha1store.ApprovalDenied},
		{TaskExpired, "", v1alpha1store.ApprovalExpired},
		{TaskCancelled, "", v1alpha1store.ApprovalCancelled},
		{TaskApproved, "forbidden: approval required: apply deployment prod/bot", v1alpha1store.ApprovalFailed},
	}
	for _, tt := range tests {
		t.Run(tt.task+tt.failure, func(t *testing.T) {
			ars := newFakeARS(t)
			a := &applier{failure: tt.failure}
			s, store := newService(t, ars, a)
			id, _, err := s.Stage(carolCtx(), types.ApprovalStageInput{Verb: "apply", Kind: v1alpha1.KindDeployment, Namespace: "prod", Name: "bot", Object: deployment(), Denial: approvalRequired(t)})
			require.NoError(t, err)
			ars.set(id, tt.task)
			s.Reconcile(context.Background())
			assert.Equal(t, tt.want, store.status(id))
			if tt.failure != "" {
				r, _ := store.GetApprovalRequest(context.Background(), id)
				assert.Equal(t, tt.failure, r.Detail)
			}
		})
	}
}

func TestApprovedChangeAppliedOnceAcrossReplicas(t *testing.T) {
	ars := newFakeARS(t)
	a := &applier{}
	s, _ := newService(t, ars, a)
	id, _, err := s.Stage(carolCtx(), types.ApprovalStageInput{Verb: "apply", Kind: v1alpha1.KindDeployment, Namespace: "prod", Name: "bot", Object: deployment(), Denial: approvalRequired(t)})
	require.NoError(t, err)
	ars.set(id, TaskApproved)

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			s.Process(context.Background(), id)
		})
	}
	wg.Wait()
	assert.EqualValues(t, 1, a.calls)
}

func TestHeldDeleteAppliesTheDelete(t *testing.T) {
	ars := newFakeARS(t)
	a := &applier{result: arv0.ApplyStatusDeleted}
	s, store := newService(t, ars, a)
	id, _, err := s.Stage(carolCtx(), types.ApprovalStageInput{Verb: "delete", Kind: v1alpha1.KindDeployment, Namespace: "prod", Name: "bot", Denial: approvalRequired(t)})
	require.NoError(t, err)
	ars.set(id, TaskApproved)
	s.Reconcile(context.Background())
	assert.Equal(t, v1alpha1store.ApprovalApplied, store.status(id))
	require.Equal(t, []string{"delete"}, a.verbs)
	assert.Equal(t, "prod", a.objs[0].GetMetadata().Namespace)
}

func TestCancelAndVisibility(t *testing.T) {
	ars := newFakeARS(t)
	s, store := newService(t, ars, &applier{})
	id, _, err := s.Stage(carolCtx(), types.ApprovalStageInput{Verb: "apply", Kind: v1alpha1.KindDeployment, Namespace: "prod", Name: "bot", Object: deployment(), Denial: approvalRequired(t)})
	require.NoError(t, err)

	_, err = s.Get(context.Background(), id, "dave-sub", false)
	require.ErrorIs(t, err, v1alpha1store.ErrApprovalNotFound, "someone else's request does not exist for them")
	_, err = s.Get(context.Background(), id, "dave-sub", true)
	require.NoError(t, err, "an admin sees it")
	_, err = s.Cancel(context.Background(), id, "dave-sub", false, "")
	require.ErrorIs(t, err, v1alpha1store.ErrApprovalNotFound)

	r, err := s.Cancel(context.Background(), id, "carol-sub", false, "changed my mind")
	require.NoError(t, err)
	assert.Equal(t, v1alpha1store.ApprovalCancelled, r.Status)
	assert.Equal(t, v1alpha1store.ApprovalCancelled, store.status(id))
	_, err = s.Cancel(context.Background(), id, "carol-sub", false, "")
	require.ErrorIs(t, err, ErrNotPending)
}

func TestARSClientStaysOnThePDP(t *testing.T) {
	ars := newFakeARS(t)
	pdp, err := authzen.New(authzen.Config{BaseURL: ars.srv.URL})
	require.NoError(t, err)
	client, err := NewARSClient(pdp, ars.srv.URL, authzen.StaticToken("registry-token"), nil)
	require.NoError(t, err)
	_, err = client.Status(context.Background(), "https://attacker.example/access/v1/requests/arq_1")
	require.ErrorContains(t, err, "outside the PDP")
}

func TestCallbackSignature(t *testing.T) {
	secret := []byte(strings.Repeat("s", 32))
	body := []byte(`{"task":{"id":"arq_1","status":"approved"}}`)
	now := time.Unix(1_800_000_000, 0)
	sign := func(ts int64, b []byte) string {
		mac := hmac.New(sha256.New, secret)
		_, _ = fmt.Fprintf(mac, "%d.", ts)
		mac.Write(b)
		return fmt.Sprintf("t=%d,v1=%s", ts, hex.EncodeToString(mac.Sum(nil)))
	}
	tests := []struct {
		name    string
		header  string
		wantErr bool
	}{
		{"valid", sign(now.Unix(), body), false},
		{"tampered body", sign(now.Unix(), []byte(`{"task":{"id":"arq_2"}}`)), true},
		{"too old", sign(now.Add(-time.Hour).Unix(), body), true},
		{"wrong secret", "t=" + strconv.FormatInt(now.Unix(), 10) + ",v1=" + hex.EncodeToString(make([]byte, 32)), true},
		{"malformed", "v1=abc", true},
		{"missing", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifySignature(secret, tt.header, body, now)
			assert.Equal(t, tt.wantErr, err != nil, "error %v", err)
		})
	}

	// The handler only triggers a check; a bad signature is a 401.
	ars := newFakeARS(t)
	s, _ := newService(t, ars, &applier{})
	s.now = func() time.Time { return now }
	h := s.CallbackHandler(secret)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/approvals/callback", strings.NewReader(string(body)))
	req.Header.Set("X-AuthZEN-Signature", "t=1,v1=00")
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/approvals/callback", strings.NewReader(string(body)))
	req.Header.Set("X-AuthZEN-Signature", sign(now.Unix(), body))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNoContent, rec.Code)
}
