package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/agentregistry-dev/agentregistry/internal/registry/authz"
	arv0 "github.com/agentregistry-dev/agentregistry/pkg/api/v0"
	"github.com/agentregistry-dev/agentregistry/pkg/api/v1alpha1"
	"github.com/agentregistry-dev/agentregistry/pkg/logging"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/audit"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/auth"
	"github.com/agentregistry-dev/agentregistry/pkg/registry/v1alpha1store"
	"github.com/agentregistry-dev/agentregistry/pkg/types"
)

var logger = logging.New("approvals")

const (
	reconcileBatch = 100
	// stuckAfter is how long a request may stay applying before another
	// pass applies it again; applying the same document twice is harmless.
	stuckAfter = 5 * time.Minute
)

// Store keeps the registry's side of approval requests.
type Store interface {
	CreateApprovalRequest(ctx context.Context, r v1alpha1store.ApprovalRequest) error
	GetApprovalRequest(ctx context.Context, id string) (v1alpha1store.ApprovalRequest, error)
	ListApprovalRequests(ctx context.Context, q v1alpha1store.ApprovalQuery) ([]v1alpha1store.ApprovalRequest, string, error)
	TransitionApprovalRequest(ctx context.Context, id string, from []string, to, approvalID, detail string) (bool, error)
	StuckApplyingBefore(ctx context.Context, t time.Time, limit int) ([]v1alpha1store.ApprovalRequest, error)
}

// Service is the approvals component: it implements types.ApprovalStager
// for the apply endpoint, follows requests, and applies approved changes.
type Service struct {
	store  Store
	ars    *ARSClient
	audit  audit.Recorder
	scheme *v1alpha1.Scheme
	// callback, when set, is sent with every submission.
	callback *Callback
	now      func() time.Time

	apply  func(ctx context.Context, obj v1alpha1.Object) arv0.ApplyResult
	delete func(ctx context.Context, obj v1alpha1.Object) arv0.ApplyResult
}

var _ types.ApprovalStager = (*Service)(nil)

// Config wires a Service.
type Config struct {
	Store Store
	ARS   *ARSClient
	Audit audit.Recorder
	// CallbackURL, when set, is where the access request service reports
	// that a request ended (it must be https).
	CallbackURL string
}

// New returns a Service. Bind must be called before it applies anything.
func New(cfg Config) (*Service, error) {
	if cfg.Store == nil || cfg.ARS == nil {
		return nil, errors.New("approvals: a store and an access request client are required")
	}
	s := &Service{store: cfg.Store, ars: cfg.ARS, audit: cfg.Audit, scheme: v1alpha1.Default, now: time.Now}
	if cfg.CallbackURL != "" {
		s.callback = &Callback{Endpoint: cfg.CallbackURL}
	}
	return s, nil
}

// Bind gives the Service the production apply and delete paths, which
// authorize the change again (with the approval) and write it.
func (s *Service) Bind(apply, del func(ctx context.Context, obj v1alpha1.Object) arv0.ApplyResult) {
	s.apply, s.delete = apply, del
}

// Stage implements types.ApprovalStager: a write the PDP refused but marked
// requestable is submitted as an access request and held.
func (s *Service) Stage(ctx context.Context, in types.ApprovalStageInput) (string, bool, error) {
	var required *authz.ApprovalRequired
	if !errors.As(in.Denial, &required) || in.Kind == v1alpha1.KindSecret {
		return "", false, nil
	}
	session, ok := auth.AuthSessionFrom(ctx)
	if !ok || session == nil || !session.Principal().IsAuthenticated() {
		return "", false, nil
	}
	principal := session.Principal()
	requester, err := json.Marshal(storedPrincipalFrom(principal))
	if err != nil {
		return "", false, fmt.Errorf("encode requester: %w", err)
	}
	doc, err := s.document(in)
	if err != nil {
		return "", false, err
	}

	req := AccessRequest{
		Subject: required.Request.Subject, Resource: required.Request.Resource, Action: required.Request.Action,
		Context: required.Request.Context, Denial: required.Denial, Callback: s.callback,
	}
	key, _ := required.Denial["evaluation_id"].(string)
	task, err := s.ars.Submit(ctx, req, key)
	if err != nil {
		return "", false, err
	}
	sum, _ := required.Request.Context[authz.ContextDocumentSHA256].(string)
	row := v1alpha1store.ApprovalRequest{
		ID: task.Task.ID, Verb: in.Verb, Kind: in.Kind, Namespace: in.Namespace, Name: in.Name, Tag: in.Tag,
		Document: doc, DocumentSHA256: sum, Requester: requester,
		RequesterSubject: principal.Subject, RequesterUsername: principal.Username,
		StatusEndpoint: task.Task.StatusEndpoint,
	}
	if err := s.store.CreateApprovalRequest(ctx, row); err != nil {
		return "", false, err
	}
	audit.Record(ctx, s.audit, audit.Event{
		Action: audit.ActionRequestApproval, Outcome: audit.OutcomeSuccess, Detail: task.Task.ID,
		Resource: audit.Resource{Kind: in.Kind, Namespace: in.Namespace, Name: in.Name, Tag: in.Tag},
	})
	logger.InfoContext(ctx, "change held for approval", "request", task.Task.ID, "verb", in.Verb,
		"kind", in.Kind, "namespace", in.Namespace, "name", in.Name, "requester", principal.Subject)
	if task.Task.Status != TaskPending {
		// The workflow decided at once; act on it now.
		go s.Process(context.WithoutCancel(ctx), task.Task.ID)
	}
	return task.Task.ID, true, nil
}

// document is the JSON to apply later: the object for an apply, its
// identity for a delete.
func (s *Service) document(in types.ApprovalStageInput) (json.RawMessage, error) {
	var v any = in.Object
	if in.Object == nil {
		meta := map[string]string{"namespace": in.Namespace, "name": in.Name}
		if in.Tag != "" {
			meta["tag"] = in.Tag
		}
		v = map[string]any{"apiVersion": v1alpha1.GroupVersion, "kind": in.Kind, "metadata": meta}
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encode document: %w", err)
	}
	return raw, nil
}

// Run follows held requests every interval until ctx ends. Run it on one
// replica (the leader); every step is also safe to repeat on several.
func (s *Service) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		s.Reconcile(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Reconcile follows every held request once.
func (s *Service) Reconcile(ctx context.Context) {
	sys := auth.WithSystemContext(ctx)
	cursor := ""
	for ctx.Err() == nil {
		rows, next, err := s.store.ListApprovalRequests(sys, v1alpha1store.ApprovalQuery{
			Statuses: []string{v1alpha1store.ApprovalPending, v1alpha1store.ApprovalApproved},
			Limit:    reconcileBatch, Cursor: cursor,
		})
		if err != nil {
			logger.Error("list held requests", "error", err)
			return
		}
		for _, r := range rows {
			s.process(ctx, r)
		}
		if next == "" {
			break
		}
		cursor = next
	}
	stuck, err := s.store.StuckApplyingBefore(sys, s.now().Add(-stuckAfter), reconcileBatch)
	if err != nil {
		logger.Error("list stuck requests", "error", err)
		return
	}
	for _, r := range stuck {
		if ok, _ := s.store.TransitionApprovalRequest(sys, r.ID, []string{v1alpha1store.ApprovalApplying}, v1alpha1store.ApprovalApproved, "", ""); ok {
			r.Status = v1alpha1store.ApprovalApproved
			s.process(ctx, r)
		}
	}
}

// Process follows one request now, as when its callback arrives.
func (s *Service) Process(ctx context.Context, id string) {
	r, err := s.store.GetApprovalRequest(auth.WithSystemContext(ctx), id)
	if err != nil {
		if !errors.Is(err, v1alpha1store.ErrApprovalNotFound) {
			logger.Error("read held request", "request", id, "error", err)
		}
		return
	}
	s.process(ctx, r)
}

func (s *Service) process(ctx context.Context, r v1alpha1store.ApprovalRequest) {
	sys := auth.WithSystemContext(ctx)
	if r.Status == v1alpha1store.ApprovalPending {
		task, err := s.ars.Status(sys, r.StatusEndpoint)
		if errors.Is(err, ErrNotFound) {
			s.finish(sys, r, v1alpha1store.ApprovalExpired, "the access request no longer exists")
			return
		}
		if err != nil {
			logger.Warn("read access request status", "request", r.ID, "error", err)
			return
		}
		switch task.Task.Status {
		case TaskPending:
			return
		case TaskApproved:
			id := task.ApprovalID()
			if id == "" {
				s.finish(sys, r, v1alpha1store.ApprovalFailed, "approved without an approval id")
				return
			}
			if ok, err := s.store.TransitionApprovalRequest(sys, r.ID, []string{v1alpha1store.ApprovalPending}, v1alpha1store.ApprovalApproved, id, ""); err != nil || !ok {
				return
			}
			r.Status, r.ApprovalID = v1alpha1store.ApprovalApproved, id
		case TaskDenied:
			s.finish(sys, r, v1alpha1store.ApprovalDenied, "denied by the approver")
			return
		case TaskExpired:
			s.finish(sys, r, v1alpha1store.ApprovalExpired, "nobody decided before the request expired")
			return
		case TaskCancelled:
			s.finish(sys, r, v1alpha1store.ApprovalCancelled, "cancelled")
			return
		default:
			s.finish(sys, r, v1alpha1store.ApprovalFailed, "access request ended "+task.Task.Status)
			return
		}
	}
	if r.Status == v1alpha1store.ApprovalApproved {
		s.applyApproved(ctx, r)
	}
}

// applyApproved applies the held document as the requester, presenting the
// approval: the PDP verifies it matches the reviewed subject, resource,
// action and document hash. Only the replica that moves the request to
// applying applies it.
func (s *Service) applyApproved(ctx context.Context, r v1alpha1store.ApprovalRequest) {
	sys := auth.WithSystemContext(ctx)
	ok, err := s.store.TransitionApprovalRequest(sys, r.ID, []string{v1alpha1store.ApprovalApproved}, v1alpha1store.ApprovalApplying, "", "")
	if err != nil || !ok {
		return
	}
	if s.apply == nil || s.delete == nil {
		s.finish(sys, r, v1alpha1store.ApprovalFailed, "the registry cannot apply approved changes")
		return
	}
	decoded, err := s.scheme.Decode(r.Document)
	obj, isObj := decoded.(v1alpha1.Object)
	if err != nil || !isObj {
		s.finish(sys, r, v1alpha1store.ApprovalFailed, "the held document cannot be decoded")
		return
	}
	var stored storedPrincipal
	if err := json.Unmarshal(r.Requester, &stored); err != nil {
		s.finish(sys, r, v1alpha1store.ApprovalFailed, "the requester cannot be restored")
		return
	}
	actx := types.WithApprovalID(auth.AuthSessionTo(ctx, session{stored.principal()}), r.ApprovalID)

	var res arv0.ApplyResult
	if r.Verb == "delete" {
		res = s.delete(actx, obj)
	} else {
		res = s.apply(actx, obj)
	}
	if res.Status == arv0.ApplyStatusFailed || res.Status == arv0.ApplyStatusPendingApproval {
		detail := res.Error
		if detail == "" {
			detail = "the approval was not accepted"
		}
		s.finish(sys, r, v1alpha1store.ApprovalFailed, detail)
		return
	}
	s.finish(sys, r, v1alpha1store.ApprovalApplied, res.Status+" with approval "+r.ApprovalID)
	logger.InfoContext(ctx, "approved change applied", "request", r.ID, "approval", r.ApprovalID,
		"kind", r.Kind, "namespace", r.Namespace, "name", r.Name, "result", res.Status)
}

func (s *Service) finish(ctx context.Context, r v1alpha1store.ApprovalRequest, status, detail string) {
	from := []string{v1alpha1store.ApprovalPending, v1alpha1store.ApprovalApproved, v1alpha1store.ApprovalApplying}
	if ok, err := s.store.TransitionApprovalRequest(ctx, r.ID, from, status, "", detail); err != nil {
		logger.Error("update held request", "request", r.ID, "error", err)
	} else if ok {
		slog.Info("held request finished", "request", r.ID, "status", status, "detail", detail)
	}
}

// storedPrincipal is the requester's identity, without their raw claims.
type storedPrincipal struct {
	Subject  string       `json:"subject"`
	Issuer   string       `json:"issuer"`
	ClientID string       `json:"clientId,omitempty"`
	Username string       `json:"username,omitempty"`
	IsClient bool         `json:"isClient,omitempty"`
	Roles    []string     `json:"roles,omitempty"`
	Groups   []string     `json:"groups,omitempty"`
	Actor    []auth.Actor `json:"actor,omitempty"`
}

func storedPrincipalFrom(p auth.Principal) storedPrincipal {
	return storedPrincipal{Subject: p.Subject, Issuer: p.Issuer, ClientID: p.ClientID, Username: p.Username,
		IsClient: p.IsClient, Roles: p.Roles, Groups: p.Groups, Actor: p.Actor}
}

func (s storedPrincipal) principal() auth.Principal {
	return auth.Principal{Subject: s.Subject, Issuer: s.Issuer, ClientID: s.ClientID, Username: s.Username,
		IsClient: s.IsClient, Roles: s.Roles, Groups: s.Groups, Actor: s.Actor}
}

// session restores the requester for the approved apply.
type session struct{ p auth.Principal }

func (s session) Principal() auth.Principal { return s.p }

// ErrForbidden is a caller acting on a request that is not theirs.
var ErrForbidden = errors.New("not permitted")

// List returns held requests: the caller's own, or every request for an
// admin (all=true).
func (s *Service) List(ctx context.Context, subject string, all bool, statuses []string, limit int, cursor string) ([]v1alpha1store.ApprovalRequest, string, error) {
	q := v1alpha1store.ApprovalQuery{Statuses: statuses, Limit: limit, Cursor: cursor}
	if !all {
		q.RequesterSubject = subject
	}
	return s.store.ListApprovalRequests(auth.WithSystemContext(ctx), q)
}

// Get returns one held request to its requester or an admin.
func (s *Service) Get(ctx context.Context, id, subject string, admin bool) (v1alpha1store.ApprovalRequest, error) {
	r, err := s.store.GetApprovalRequest(auth.WithSystemContext(ctx), id)
	if err != nil {
		return r, err
	}
	if !admin && r.RequesterSubject != subject {
		return v1alpha1store.ApprovalRequest{}, v1alpha1store.ErrApprovalNotFound
	}
	return r, nil
}

// Cancel withdraws a pending request, for its requester or an admin.
func (s *Service) Cancel(ctx context.Context, id, subject string, admin bool, reason string) (v1alpha1store.ApprovalRequest, error) {
	r, err := s.Get(ctx, id, subject, admin)
	if err != nil {
		return r, err
	}
	if r.Status != v1alpha1store.ApprovalPending {
		return r, fmt.Errorf("%w: the request is %s", ErrNotPending, r.Status)
	}
	if _, err := s.ars.Cancel(ctx, r.StatusEndpoint, reason); err != nil {
		return r, err
	}
	s.finish(auth.WithSystemContext(ctx), r, v1alpha1store.ApprovalCancelled, "cancelled by "+subject)
	return s.store.GetApprovalRequest(auth.WithSystemContext(ctx), id)
}

// ErrNotPending is an action on a request that is no longer pending.
var ErrNotPending = errors.New("the request is no longer pending")

// ApprovalReview is a task awaiting the approver's decision, with the change it
// would apply.
type ApprovalReview struct {
	Task   map[string]any                 `json:"task"`
	Change *v1alpha1store.ApprovalRequest `json:"change,omitempty"`
}

// ReviewList returns the tasks awaiting the approver (the service decides
// which, with their token), each with the held change.
func (s *Service) ReviewList(ctx context.Context, approverToken string) ([]ApprovalReview, error) {
	var out struct {
		Tasks []map[string]any `json:"tasks"`
	}
	if err := s.ars.Admin(ctx, approverToken, http.MethodGet, "tasks?status=pending&limit=200", nil, &out); err != nil {
		return nil, err
	}
	reviews := make([]ApprovalReview, 0, len(out.Tasks))
	for _, t := range out.Tasks {
		reviews = append(reviews, s.withChange(ctx, t))
	}
	return reviews, nil
}

// ReviewGet returns one task the approver may see, with the held change.
func (s *Service) ReviewGet(ctx context.Context, approverToken, id string) (ApprovalReview, error) {
	var out struct {
		Task map[string]any `json:"task"`
	}
	if err := s.ars.Admin(ctx, approverToken, http.MethodGet, "tasks/"+url.PathEscape(id), nil, &out); err != nil {
		return ApprovalReview{}, err
	}
	return s.withChange(ctx, out.Task), nil
}

// Decide records the approver's decision ("approve" or "deny"); the
// service checks that they may decide, and refuses self-approval when the
// policy says so. An approval is applied right away.
func (s *Service) Decide(ctx context.Context, approverToken, id, decision, comment string) (ApprovalReview, error) {
	var out struct {
		Task map[string]any `json:"task"`
	}
	body := map[string]any{"decision": decision}
	if comment != "" {
		body["comment"] = comment
	}
	if err := s.ars.Admin(ctx, approverToken, http.MethodPost, "tasks/"+url.PathEscape(id)+"/decisions", body, &out); err != nil {
		return ApprovalReview{}, err
	}
	go s.Process(context.WithoutCancel(ctx), id)
	return s.withChange(ctx, out.Task), nil
}

func (s *Service) withChange(ctx context.Context, task map[string]any) ApprovalReview {
	rv := ApprovalReview{Task: task}
	if id, _ := task["id"].(string); id != "" {
		if r, err := s.store.GetApprovalRequest(auth.WithSystemContext(ctx), id); err == nil {
			rv.Change = &r
		}
	}
	return rv
}
