package workloadidentity

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/agentregistry-dev/agentregistry/pkg/registry/v1alpha1store"
)

func recordSpans(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder)))
	t.Cleanup(func() { otel.SetTracerProvider(noop.NewTracerProvider()) })
	return recorder
}

func spanAttrs(s sdktrace.ReadOnlySpan) map[string]string {
	out := map[string]string{}
	for _, kv := range s.Attributes() {
		out[string(kv.Key)] = kv.Value.AsString()
	}
	return out
}

func TestResolveSpans(t *testing.T) {
	revoked := assigned(validPrefix)
	revoked.Event = v1alpha1store.IdentityRevoked
	tests := []struct {
		name        string
		history     HistoryFunc
		subject     string
		wantOutcome string
		wantHistory bool
		wantError   bool
	}{
		{"resolved", historyOf(map[string][]v1alpha1store.IdentityEvent{validPrefix: {assigned(validPrefix)}}), validID, "resolved", true, false},
		{"revoked", historyOf(map[string][]v1alpha1store.IdentityEvent{validPrefix: {assigned(validPrefix), revoked}}), validID, "revoked", true, false},
		{"unknown", historyOf(nil), validID, "unknown", true, false},
		{"missing: no records read", historyOf(nil), "", "missing", false, false},
		{"records unreadable", func(context.Context, string) ([]v1alpha1store.IdentityEvent, error) {
			return nil, errors.New("database down")
		}, validID, "error", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := recordSpans(t)
			r, err := NewResolver(td, tt.history)
			require.NoError(t, err)
			_, _ = r.Resolve(context.Background(), tt.subject, tt.subject)

			byName := map[string]sdktrace.ReadOnlySpan{}
			for _, s := range recorder.Ended() {
				byName[s.Name()] = s
			}
			resolve := byName["identity.resolve"]
			require.NotNil(t, resolve)
			attrs := spanAttrs(resolve)
			assert.Equal(t, tt.wantOutcome, attrs["identity.outcome"])
			assert.Equal(t, tt.subject, attrs["spiffe.id"])
			if tt.wantOutcome == "resolved" {
				assert.Equal(t, "default/credit:1.2.0", attrs["agentregistry.agent"])
			} else {
				assert.NotContains(t, attrs, "agentregistry.agent")
			}
			// A rejection is the check working, not an error; failing to
			// read the records is.
			assert.Equal(t, tt.wantError, resolve.Status().Code == codes.Error)

			history, ok := byName["identity.history"]
			assert.Equal(t, tt.wantHistory, ok, "the records are read only for a well-formed ID")
			if ok {
				assert.Equal(t, resolve.SpanContext().SpanID(), history.Parent().SpanID(), "a child of identity.resolve")
				assert.Equal(t, validPrefix, spanAttrs(history)["spiffe.id.prefix"])
			}
		})
	}
}
