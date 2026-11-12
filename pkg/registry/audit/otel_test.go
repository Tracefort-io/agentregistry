package audit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/embedded"
)

type captureLogger struct {
	embedded.Logger
	records []otellog.Record
}

func (l *captureLogger) Emit(_ context.Context, r otellog.Record) { l.records = append(l.records, r) }

func (l *captureLogger) Enabled(context.Context, otellog.EnabledParameters) bool { return true }

func TestOTelRecorder(t *testing.T) {
	when := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	tests := []struct {
		name         string
		event        Event
		wantSeverity otellog.Severity
		wantBody     string
	}{
		{
			name: "success",
			event: Event{Time: when, RequestID: "r1", Action: ActionApply, Outcome: OutcomeSuccess, Detail: "created",
				Actor:    Actor{Subject: "alice-sub", Issuer: "https://idp", Username: "alice", Via: []string{"agent-1"}},
				Resource: Resource{Kind: "Prompt", Namespace: "default", Name: "p", Tag: "latest"}},
			wantSeverity: otellog.SeverityInfo,
			wantBody:     "alice apply Prompt default/p: success (created)",
		},
		{
			name:         "denied list by an anonymous caller",
			event:        Event{Time: when, Action: ActionList, Outcome: OutcomeDenied, Resource: Resource{Kind: "Secret", Namespace: "team"}},
			wantSeverity: otellog.SeverityWarn,
			wantBody:     "anonymous list Secret team/*: denied",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &captureLogger{}
			OTelRecorder(l).Record(context.Background(), tt.event)
			require.Len(t, l.records, 1)
			r := l.records[0]
			assert.Equal(t, EventName, r.EventName())
			assert.True(t, when.Equal(r.Timestamp()))
			assert.Equal(t, tt.wantSeverity, r.Severity())
			assert.Equal(t, tt.wantBody, r.Body().AsString())

			attrs := map[string]string{}
			r.WalkAttributes(func(kv attribute.KeyValue) bool {
				attrs[string(kv.Key)] = kv.Value.String()
				return true
			})
			assert.Equal(t, tt.event.Action, attrs["audit.action"])
			assert.Equal(t, tt.event.Outcome, attrs["audit.outcome"])
			assert.Equal(t, tt.event.Resource.Kind, attrs["audit.resource.kind"])
			assert.Equal(t, tt.event.Actor.Subject, attrs["enduser.id"])
			assert.Equal(t, tt.event.RequestID, attrs["audit.request_id"])
		})
	}
}
