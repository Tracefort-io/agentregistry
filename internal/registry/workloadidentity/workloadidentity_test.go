package workloadidentity

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/agentregistry-dev/agentregistry/pkg/registry/v1alpha1store"
)

const (
	td          = "tracefort.localhost"
	depUID      = "9f8a7eb6-dbb1-4bcf-b884-91ec8d07cd42"
	podUID      = "4a189556-ba04-41c9-a6e0-287229318030"
	validID     = "spiffe://" + td + "/org/default/agent/credit/deployment/" + depUID + "/instance/" + podUID
	validPrefix = "spiffe://" + td + "/org/default/agent/credit/deployment/" + depUID + "/"
)

func TestParseAgentID(t *testing.T) {
	tests := []struct {
		name string
		id   string
		ok   bool
	}{
		{"valid", validID, true},
		{"other trust domain", "spiffe://evil.example/org/default/agent/credit/deployment/" + depUID + "/instance/" + podUID, false},
		{"trust domain as prefix of another", "spiffe://" + td + ".evil/org/default/agent/credit/deployment/" + depUID + "/instance/" + podUID, false},
		{"no instance", validPrefix, false},
		{"extra segment", validID + "/x", false},
		{"segments renamed", "spiffe://" + td + "/org/default/agents/credit/deployment/" + depUID + "/instance/" + podUID, false},
		{"org not a DNS label", "spiffe://" + td + "/org/De_fault/agent/credit/deployment/" + depUID + "/instance/" + podUID, false},
		{"agent not a DNS label", "spiffe://" + td + "/org/default/agent/../deployment/" + depUID + "/instance/" + podUID, false},
		{"deployment UID not a UUID", "spiffe://" + td + "/org/default/agent/credit/deployment/x/instance/" + podUID, false},
		{"upper-case UUID", "spiffe://" + td + "/org/default/agent/credit/deployment/9F8A7EB6-DBB1-4BCF-B884-91EC8D07CD42/instance/" + podUID, false},
		{"query", validID + "?a=b", false},
		{"empty segment", "spiffe://" + td + "/org//agent/credit/deployment/" + depUID + "/instance/" + podUID, false},
		{"not spiffe", "https://" + td + "/org/default", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := ParseAgentID(tt.id, td)
			if !tt.ok {
				require.ErrorIs(t, err, ErrMalformed)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, AgentID{TrustDomain: td, Org: "default", Agent: "credit", DeploymentUID: depUID, InstanceUID: podUID}, id)
			assert.Equal(t, validPrefix, id.Prefix(), "the prefix the runtime records")
			assert.Equal(t, validID, id.String())
		})
	}
}

func assigned(prefix string) v1alpha1store.IdentityEvent {
	return v1alpha1store.IdentityEvent{
		Event: v1alpha1store.IdentityAssigned, SPIFFEIDPrefix: prefix,
		DeploymentNamespace: "default", DeploymentName: "credit-desk", DeploymentUID: depUID,
		AgentNamespace: "default", AgentName: "credit", AgentTag: "1.2.0",
	}
}

func historyOf(events map[string][]v1alpha1store.IdentityEvent) HistoryFunc {
	return func(_ context.Context, prefix string) ([]v1alpha1store.IdentityEvent, error) {
		return events[prefix], nil
	}
}

func TestResolve(t *testing.T) {
	revoked := assigned(validPrefix)
	revoked.Event = v1alpha1store.IdentityRevoked
	otherAgent := assigned(validPrefix)
	otherAgent.AgentName = "payments"
	otherOrg := assigned(validPrefix)
	otherOrg.DeploymentNamespace = "team-b"
	otherUID := assigned(validPrefix)
	otherUID.DeploymentUID = "00000000-0000-4000-8000-000000000000"

	tests := []struct {
		name        string
		events      []v1alpha1store.IdentityEvent
		subject     string
		certificate string
		want        error
	}{
		{"resolved", []v1alpha1store.IdentityEvent{assigned(validPrefix)}, validID, validID, nil},
		{"no token subject", nil, "", validID, ErrMissing},
		{"no certificate", nil, validID, "", ErrMissing},
		{"token and certificate differ", []v1alpha1store.IdentityEvent{assigned(validPrefix)}, validID,
			"spiffe://" + td + "/org/default/agent/credit/deployment/" + depUID + "/instance/00000000-0000-4000-8000-000000000001", ErrMismatch},
		{"malformed", nil, "spiffe://" + td + "/x", "spiffe://" + td + "/x", ErrMalformed},
		{"never assigned", nil, validID, validID, ErrUnknown},
		{"revoked", []v1alpha1store.IdentityEvent{assigned(validPrefix), revoked}, validID, validID, ErrRevoked},
		{"record names another agent", []v1alpha1store.IdentityEvent{otherAgent}, validID, validID, ErrRecordMismatch},
		{"record in another org", []v1alpha1store.IdentityEvent{otherOrg}, validID, validID, ErrRecordMismatch},
		{"record of another Deployment UID", []v1alpha1store.IdentityEvent{otherUID}, validID, validID, ErrRecordMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := NewResolver(td, historyOf(map[string][]v1alpha1store.IdentityEvent{validPrefix: tt.events}))
			require.NoError(t, err)
			res, err := r.Resolve(context.Background(), tt.subject, tt.certificate)
			if tt.want != nil {
				require.ErrorIs(t, err, tt.want)
				assert.True(t, Rejected(err))
				return
			}
			require.NoError(t, err)
			assert.Equal(t, Resolution{
				SPIFFEID: validID, AgentNamespace: "default", AgentName: "credit", AgentTag: "1.2.0",
				DeploymentNamespace: "default", DeploymentName: "credit-desk", DeploymentUID: depUID,
			}, res)
		})
	}
}

func TestResolveRecordsUnreadable(t *testing.T) {
	r, err := NewResolver(td, func(context.Context, string) ([]v1alpha1store.IdentityEvent, error) {
		return nil, errors.New("database down")
	})
	require.NoError(t, err)
	_, err = r.Resolve(context.Background(), validID, validID)
	require.Error(t, err)
	assert.False(t, Rejected(err), "a read failure is not a verdict on the ID")
}

func check(t *testing.T, history HistoryFunc, headers map[string][]string) *httptest.ResponseRecorder {
	t.Helper()
	r, err := NewResolver(td, history)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, CheckPath, nil)
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	rec := httptest.NewRecorder()
	NewHandler(r, slog.New(slog.NewTextHandler(io.Discard, nil))).ServeHTTP(rec, req)
	return rec
}

func TestHandler(t *testing.T) {
	history := historyOf(map[string][]v1alpha1store.IdentityEvent{validPrefix: {assigned(validPrefix)}})

	rec := check(t, history, map[string][]string{HeaderTokenSubject: {validID}, HeaderCertificateID: {validID}})
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "default/credit:1.2.0", rec.Header().Get(HeaderAgent))
	assert.Equal(t, "default/credit-desk", rec.Header().Get(HeaderDeployment))
	assert.Equal(t, depUID, rec.Header().Get(HeaderDeploymentUID))
	assert.Equal(t, validID, rec.Header().Get(HeaderSPIFFEID))

	rec = check(t, historyOf(nil), map[string][]string{HeaderTokenSubject: {validID}, HeaderCertificateID: {validID}})
	assert.Equal(t, http.StatusForbidden, rec.Code, "unknown")
	assert.Empty(t, rec.Header().Get(HeaderAgent))
	assert.Empty(t, rec.Body.String(), "no detail")

	rec = check(t, history, map[string][]string{HeaderTokenSubject: {validID, validID}, HeaderCertificateID: {validID}})
	assert.Equal(t, http.StatusForbidden, rec.Code, "a repeated header is refused, not picked from")

	rec = check(t, history, map[string][]string{HeaderCertificateID: {validID}})
	assert.Equal(t, http.StatusForbidden, rec.Code, "no token subject")

	rec = check(t, func(context.Context, string) ([]v1alpha1store.IdentityEvent, error) {
		return nil, errors.New("database down")
	}, map[string][]string{HeaderTokenSubject: {validID}, HeaderCertificateID: {validID}})
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestHandlerServesOnlyTheCheck(t *testing.T) {
	r, err := NewResolver(td, historyOf(nil))
	require.NoError(t, err)
	rec := httptest.NewRecorder()
	NewHandler(r, slog.New(slog.NewTextHandler(io.Discard, nil))).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v0/agents", nil))
	assert.Equal(t, http.StatusNotFound, rec.Code)
}
